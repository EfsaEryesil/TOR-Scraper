package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Target   string
	OK       bool
	Status   string
	Err      error
	OutFile  string
	Duration time.Duration
}

var logMu sync.Mutex

func main() {
	
	input := flag.String("input", "targets.yaml", "Path to targets file (txt/yaml lines)")
	outDir := flag.String("out", "output", "Output directory")
	proxyAddr := flag.String("proxy", "", "SOCKS5 proxy addr (default tries 127.0.0.1:9050 then 127.0.0.1:9150)")
	concurrency := flag.Int("c", 5, "Concurrency (worker count). Use 1 for sequential.")
	timeout := flag.Duration("timeout", 25*time.Second, "Per-request timeout")
	ua := flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36", "User-Agent header")
	verifyTor := flag.Bool("verify-tor", true, "Verify Tor exit IP via check.torproject.org API (over Tor)")
	addBase := flag.Bool("add-base", false, "Inject <base href> into saved HTML for proper relative assets")
	flag.Parse()

	
	htmlDir := filepath.Join(*outDir, "html")
	if err := os.MkdirAll(htmlDir, 0755); err != nil {
		fatal(err)
	}
	reportPath := filepath.Join(*outDir, "scan_report.log")
	reportF, err := os.OpenFile(reportPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fatal(err)
	}
	defer reportF.Close()

	
	targets, err := readTargets(*input)
	if err != nil {
		fatal(err)
	}
	if len(targets) == 0 {
		fatal(fmt.Errorf("no targets found in %s", *input))
	}
	logInfo(reportF, "Loaded %d targets from %s", len(targets), *input)

	
	client, usedProxy, err := buildTorHTTPClient(*proxyAddr, *timeout)
	if err != nil {
		fatal(err)
	}
	logInfo(reportF, "Using SOCKS5 proxy: %s", usedProxy)

	
	if *verifyTor {
		ip, ok, verr := checkTorIP(client, *ua)
		if verr != nil {
			logErr(reportF, "Tor check failed: %v", verr)
		} else {
			logInfo(reportF, "Tor check: ip=%s is_tor=%v", ip, ok)
		}
	}

	
	results := runScan(client, targets, htmlDir, reportF, *ua, *timeout, *concurrency, *addBase)

	
	var okCount, failCount int
	for _, r := range results {
		if r.OK {
			okCount++
		} else {
			failCount++
		}
	}
	logInfo(reportF, "DONE. success=%d fail=%d report=%s", okCount, failCount, reportPath)
	fmt.Printf("[DONE] success=%d fail=%d\n", okCount, failCount)
	fmt.Printf("Report: %s\n", reportPath)
	fmt.Printf("HTML  : %s\n", htmlDir)
}

func readTargets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		
		line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
		line = strings.TrimSpace(strings.TrimPrefix(line, "url:"))
		line = strings.Trim(line, `"'`)

		if line == "" {
			continue
		}

		
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			line = "http://" + line
		}

		
		u, perr := url.Parse(line)
		if perr != nil || u.Host == "" {
			continue
		}
		targets = append(targets, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}

func buildTorHTTPClient(forced string, timeout time.Duration) (*http.Client, string, error) {
	candidates := []string{}
	if forced != "" {
		candidates = append(candidates, forced)
	} else {
		candidates = append(candidates, "127.0.0.1:9050", "127.0.0.1:9150")
	}

	var lastErr error
	for _, addr := range candidates {
		dialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
		if err != nil {
			lastErr = err
			continue
		}

		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				type dialRes struct {
					c   net.Conn
					err error
				}
				ch := make(chan dialRes, 1)
				go func() {
					c, e := dialer.Dial(network, address)
					ch <- dialRes{c: c, err: e}
				}()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case r := <-ch:
					return r.c, r.err
				}
			},
			DisableKeepAlives:   false,
			MaxIdleConns:        50,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 15 * time.Second,
		}

		client := &http.Client{
			Transport: transport,
			Timeout:   timeout,
		}

		return client, addr, nil
	}
	return nil, "", fmt.Errorf("could not init SOCKS5 proxy client. last error: %v", lastErr)
}

func runScan(client *http.Client, targets []string, htmlDir string, report io.Writer, ua string, timeout time.Duration, workers int, addBase bool) []Result {
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan string)
	resultsCh := make(chan Result)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for t := range jobs {
			start := time.Now()
			r := fetchOne(client, t, htmlDir, report, ua, timeout, addBase)
			r.Duration = time.Since(start)
			resultsCh <- r
		}
	}

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}

	go func() {
		for _, t := range targets {
			jobs <- t
		}
		close(jobs)
		wg.Wait()
		close(resultsCh)
	}()

	var all []Result
	for r := range resultsCh {
		all = append(all, r)
	}
	return all
}

func fetchOne(client *http.Client, target, htmlDir string, report io.Writer, ua string, timeout time.Duration, addBase bool) Result {
	start := time.Now()

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		logErr(report, "[ERR] build req: %s -> %v", target, err)
		return Result{Target: target, OK: false, Status: "BUILD_REQ_ERR", Err: err}
	}

	// OpSec-ish browser headers:
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,tr;q=0.8")

	// Per-request context timeout (in addition to client.Timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		logErr(report, "[ERR] Scanning: %s -> %v (dur=%s)", target, err, time.Since(start))
		return Result{Target: target, OK: false, Status: "REQUEST_ERR", Err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // 5MB limit
	if err != nil {
		logErr(report, "[ERR] read body: %s -> %v (dur=%s)", target, err, time.Since(start))
		return Result{Target: target, OK: false, Status: "READ_ERR", Err: err}
	}

	// Save even if 4xx/5xx (intel)
	if addBase {
		body = injectBase(body, target)
	}

	out := filepath.Join(htmlDir, safeFileName(target)+".html")
	if werr := os.WriteFile(out, body, 0644); werr != nil {
		logErr(report, "[ERR] write file: %s -> %v (dur=%s)", target, werr, time.Since(start))
		return Result{Target: target, OK: false, Status: "WRITE_ERR", Err: werr}
	}

	ok := resp.StatusCode >= 200 && resp.StatusCode < 400
	if ok {
		logInfo(report, "[INFO] Scanning: %s -> SUCCESS (HTTP %d) saved=%s dur=%s",
			target, resp.StatusCode, filepath.Base(out), time.Since(start))
	} else {
		logErr(report, "[ERR] Scanning: %s -> HTTP_%d saved=%s dur=%s",
			target, resp.StatusCode, filepath.Base(out), time.Since(start))
	}

	return Result{
		Target:  target,
		OK:      ok,
		Status:  fmt.Sprintf("HTTP_%d", resp.StatusCode),
		OutFile: out,
	}
}

func safeFileName(s string) string {
	u, err := url.Parse(s)
	host := "unknown"
	if err == nil && u.Host != "" {
		host = strings.ReplaceAll(u.Host, ":", "_")
	}
	h := sha1.Sum([]byte(s))
	return host + "_" + hex.EncodeToString(h[:8])
}

type torAPIResp struct {
	IsTor bool   `json:"IsTor"`
	IP    string `json:"IP"`
}

func checkTorIP(client *http.Client, ua string) (ip string, isTor bool, err error) {
	req, _ := http.NewRequest("GET", "https://check.torproject.org/api/ip", nil)
	req.Header.Set("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", false, err
	}

	var tr torAPIResp
	if err := json.Unmarshal(b, &tr); err != nil {
		return "", false, err
	}
	if tr.IP == "" {
		tr.IP = "unknown"
	}
	return tr.IP, tr.IsTor, nil
}

func injectBase(body []byte, target string) []byte {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return body
	}
	base := u.Scheme + "://" + u.Host + "/"

	s := string(body)
	low := strings.ToLower(s)

	i := strings.Index(low, "<head")
	if i < 0 {
		return body
	}
	j := strings.Index(low[i:], ">")
	if j < 0 {
		return body
	}
	pos := i + j + 1

	tag := fmt.Sprintf("\n<base href=\"%s\">\n", base)
	return []byte(s[:pos] + tag + s[pos:])
}

func logInfo(w io.Writer, format string, a ...any) {
	logMu.Lock()
	defer logMu.Unlock()

	msg := fmt.Sprintf(format, a...)
	line := fmt.Sprintf("%s %s\n", time.Now().Format(time.RFC3339), msg)
	fmt.Print(line)
	_, _ = io.WriteString(w, line)
}

func logErr(w io.Writer, format string, a ...any) {
	logMu.Lock()
	defer logMu.Unlock()

	msg := fmt.Sprintf(format, a...)
	line := fmt.Sprintf("%s %s\n", time.Now().Format(time.RFC3339), msg)
	fmt.Fprint(os.Stderr, line)
	_, _ = io.WriteString(w, line)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "[FATAL]", err)
	os.Exit(1)
}
