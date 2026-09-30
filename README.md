# 🛡️ Brand Protection & Typosquatting Threat Scanner

A multi-threaded Python security tool designed to identify, analyze, and monitor domain typosquatting, bit-squatting, and brand impersonation threats in real-time.

By generating algorithmic domain mutations and actively inspecting live DNS records, web titles, and redirects, this script helps security teams and brand owners uncover malicious phishing pages, affiliate squatters, parked broker domains, and defensive registration gaps.

---

## ✨ Features

- **Algorithmic Domain Mutation Engine:**
  - **Omission:** Identifies missing characters (e.g., `amzon.com`).
  - **Transposition:** Catches swapped adjacent characters (e.g., `amzaon.com`).
  - **Fat-Finger (Key Proximity):** Simulates QWERTY keyboard mis-keys (e.g., `amszon.com`).
  - **Insertion & Duplication:** Detects double-typed or adjacent inserted characters.
  - **Bitsquatting:** Flips individual binary bits to catch hardware-level DNS resolution glitches.
  - **Dynamic TLD Generation:** Automatically sweeps popular TLDs (`.net`, `.org`, `.io`, `.xyz`, etc.) + the target's native TLD.
- **Fast DNS Filtering:** Drops unregistered domains at the OS/DNS level before making unnecessary web requests.
- **Resilient Probing & Fallbacks:** Seamlessly attempts secure HTTPS, falls back to insecure HTTPS (bypassing broken/self-signed SSL certs), and degrades gracefully to HTTP (Port 80).
- **Automated Category Classification:**
  - `SAFE`: Pointing to your official domain infrastructure.
  - `AFFILIATE_SQUATTING`: Monitored for unauthorized tracking tags (`tag=`, `ref=`).
  - `FOR_SALE_PARKED`: Identified broker platforms (Sedo, GoDaddy, HugeDomains, etc.).
  - `PARKED_META_REDIRECT` / `PARKED_JS_REDIRECT`: Uncovers silent client-side redirects.
  - `UNKNOWN_THIRD_PARTY`: Active third-party hosts with extracted HTML page titles.
- **Threat Intelligence Integration:** Optional lookup via [URLScan.io](https://urlscan.io/) API to highlight known malicious ratings and active community scan reports.
- **Multi-Threaded Execution:** Configurable worker pools (`ThreadPoolExecutor`) for high-speed scanning.
- **CSV Export Support:** Export actionable findings to a structured CSV file for reporting and remediation.

---

## 🚀 Quick Start

### 1. Prerequisites
Ensure you have Python 3.8+ installed along with the required `requests` library:

```bash
pip install requests urllib3
```

### 2. Basic Usage

Run a scan against a target domain using default settings (30 worker threads, 3-second timeout):

```bash
python scanner.py -u amazon.com
```

### 3. Full Command Example with CSV Export & Threat Intel

```bash
python scanner.py -u amazon.com -w 50 -t 5 -o findings.csv -us YOUR_URLSCAN_API_KEY
```

---

## ⚙️ Command-Line Arguments

| Flag | Long Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `-u` | `--url` | **(Required)** Target URL or domain name (e.g., `example.com`). | *None* |
| `-w` | `--workers` | Number of concurrent thread workers. | `30` |
| `-t` | `--timeout` | HTTP request timeout in seconds per attempt. | `3` |
| `-o` | `--output` | Save active findings to a target CSV file path. | *None* |
| `-us` | `--urlscan-key` | *(Optional)* URLScan.io API Key for automated threat intel lookups. | *None* |

---

## 📊 CSV Export Format

When exporting findings with the `-o` parameter, the CSV generates the following structure:

| Header | Description |
| :--- | :--- |
| `domain` | The mutated target domain (e.g., `amszon.com`). |
| `ip` | Resolved IPv4 address. |
| `status` | The automated category classification tag. |
| `details` | Final destination URL, page title, or URLScan report link. |
| `url` | HTTP response destination URL after all redirects. |
| `urlscan` | Raw URLScan result summary (if API key provided). |

---

## ⚠️ Disclaimer

This tool is designed strictly for **authorized security research, brand protection, and defensive threat analysis**. Always ensure you have appropriate authorization before assessing domains or infrastructure you do not own.
