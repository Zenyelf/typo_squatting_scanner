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
