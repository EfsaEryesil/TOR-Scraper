# TOR-Scraper

A simple Go tool that connects to `.onion` websites through the Tor network, downloads the HTML content, saves one HTML file per target, and logs everything to the console and a log file.

## What it does
- Reads targets from `targets.yaml` (txt/yaml line format)
- Sends HTTP GET requests through a Tor SOCKS5 proxy
- Saves HTML files into `output/html/`
- Writes logs into `output/scan_report.log`
- Does NOT crash if a target is offline (continues with the next one)

## Features
- ✅ Tor SOCKS5 proxy support (`127.0.0.1:9150` / `127.0.0.1:9050`)
- ✅ File I/O: reads targets line-by-line
- ✅ Error tolerance: no panic, continues scanning
- ✅ Concurrency with worker pool (`-c`)
- ✅ Logging (console + file)
- ✅ Browser-like headers (User-Agent / basic OpSec headers)
- ✅ Optional Tor IP check via `https://check.torproject.org/api/ip`

## Requirements
- Go 1.20+ (recommended)
- Tor must be running:
  - Tor Browser (usually): `127.0.0.1:9150`
  - Tor service (usually): `127.0.0.1:9050`

## Install
```bash
git clone https://github.com/EfsaEryesil/TOR-Scraper.git
cd TOR-Scraper
go mod tidy
```

Usage
Run with Tor Browser proxy (9150)
go run main.go -proxy 127.0.0.1:9150 -c 5

Increase timeout for slow onion sites
go run main.go -proxy 127.0.0.1:9150 -c 5 -timeout 45s

Disable Tor verification (optional)
go run main.go -proxy 127.0.0.1:9150 -verify-tor=false

Output

output/html/ → downloaded HTML pages

output/scan_report.log → scan logs (success/fail + errors + duration)

Example log:

Loaded 24 targets from targets.yaml
Using SOCKS5 proxy: 127.0.0.1:9150
Tor check: ip=2.58.56.43 is_tor=true
[INFO] Scanning: http://example.onion/ -> SUCCESS (HTTP 200) saved=...
[ERR] Scanning: http://example2.onion/ -> context deadline exceeded
DONE. success=20 fail=4

targets.yaml format

The file is read line-by-line. The program:

ignores empty lines and lines starting with #

removes simple YAML prefixes like - and url:

adds http:// if there is no scheme

Example:

# targets.yaml
- http://example1.onion/
- url: https://example2.onion/
example3.onion

Notes

Some .onion services can be unstable/offline. The program logs errors and continues.

Response size is limited to 5MB per target.
