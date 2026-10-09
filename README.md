# 🛡️ Brand Protection & Typosquatting Threat Scanner

A multi-threaded Python security tool designed to identify and analyze potential domain typosquatting, bitsquatting, and brand impersonation threats.

By generating algorithmic domain mutations and inspecting DNS resolution, HTTP/HTTPS responses, redirects, and HTML content, this tool helps security researchers and organizations discover suspicious lookalike domains, potential affiliate squatting, domain parking, and third-party websites.

The scanner also supports optional URLScan.io threat intelligence lookups and CSV reporting to assist with further security investigations.

---

## ✨ Features

### 1. Algorithmic Domain Mutation Engine

Generates domain variations using multiple mutation techniques:

- **Omission:** Removes individual characters (e.g., `amzon.com`).
- **Transposition:** Swaps adjacent characters (e.g., `amzaon.com`).
- **Fat-Finger (Keyboard Proximity):** Replaces characters with neighboring QWERTY keyboard keys (e.g., `amszon.com`).
- **Duplication:** Repeats individual characters (e.g., `amazonn.com`).
- **Adjacent-Key Insertion:** Inserts neighboring keyboard characters before or after existing characters.
- **Bitsquatting:** Generates variations by flipping individual bits in character representations, retaining valid lowercase letters and digits.
- **TLD Generation:** Generates variations across nine predefined TLDs: `.net`, `.org`, `.co`, `.io`, `.xyz`, `.cm`, `.info`, `.biz`, and `.com`.

A Python `set` automatically removes duplicate generated domains.

### 2. DNS Resolution Filtering

Uses Python's `socket.gethostbyname()` to resolve generated domains to IPv4 addresses.

- Skips domains that fail IPv4 DNS resolution.
- Reduces unnecessary HTTP requests to non-resolving domains.
- Records the resolved IPv4 address for each successfully resolved domain.

**Note:** A failed IPv4 lookup does not necessarily mean a domain is unregistered. The current implementation does not perform IPv6 resolution, WHOIS, or RDAP registration checks.

### 3. HTTP/HTTPS Website Inspection

Inspects successfully resolved domains using Python's `requests` library.

The current connection sequence is:

1. Attempt HTTPS with normal TLS certificate verification.
2. If the HTTPS request fails, attempt HTTP.
3. Follow HTTP redirects automatically.
4. If both requests fail, return a `TIMEOUT` classification.

The scanner collects the final response URL and inspects HTML content for indicators of domain parking and client-side redirects.

**Note:** The `TIMEOUT` classification can also represent other connection-related failures. The scanner does not retry HTTPS with disabled certificate verification.

### 4. Automated Domain Classification

Categorizes successfully inspected websites using rule-based analysis.

| Classification | Description |
|---|---|
| `SAFE` | Final hostname matches the target domain or its subdomains, without detected `tag=` or `ref=` URL strings. |
| `AFFILIATE_SQUATTING` | Final hostname matches the target domain or its subdomains and the final URL contains `tag=` or `ref=`. |
| `FOR_SALE_PARKED` | Final URL matches a known domain broker string, or HTML contains recognized domain-sale phrases. |
| `PARKED_META_REDIRECT` | HTML contains both `url=` and `refresh`, suggesting a possible meta-refresh redirect. |
| `PARKED_JS_REDIRECT` | HTML contains `window.location`, suggesting possible JavaScript redirection. |
| `UNKNOWN_THIRD_PARTY` | Website does not match the other classification rules. Its HTML title is extracted when available. |
| `TIMEOUT` | IPv4 DNS resolution succeeded, but both HTTPS and HTTP attempts failed. |

**Important:** These classifications are heuristic indicators, not definitive security verdicts.

A `SAFE` result does not verify ownership or authorization of the original domain. Similarly, affiliate parameters, redirect indicators, and domain parking do not independently prove malicious activity.

### 5. Threat Intelligence Integration

Supports optional lookups through the [URLScan.io](https://urlscan.io/) Search API.

When an API key is provided, the scanner queries existing scan results for domains not classified as `SAFE`.

Based on the first returned result, the scanner attempts to:

- Retrieve an overall malicious verdict and score.
- Report a potentially malicious result if the malicious field is true or the score is greater than zero.
- Include a scan report URL when available.
- Identify when no previous results are returned.
- Handle HTTP errors, rate limiting, and request failures.

**Limitations:**

- The scanner queries existing URLScan.io records; it does not submit new website scans.
- The implementation assumes the first search result represents
