#python scanner.py -u amazon.com

import socket
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import argparse
import csv
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

fat_words = {
    'a' : ['q', 'w', 's', 'z'],
    'b' : ['v', 'g', 'h', 'n'],
    'c' : ['x', 'd', 'f', 'v'],
    'd' : ['s', 'e', 'r', 'f', 'c', 'x'],
    'e' : ['w', 's', 'd', 'r'],
    'f' : ['d', 'r', 't', 'g', 'v', 'c'],
    'g' : ['f', 't', 'y', 'h', 'b', 'v'],
    'h' : ['g', 'y', 'u', 'j', 'n', 'b'],
    'i' : ['u', 'j', 'k', 'o'],
    'j' : ['h', 'u', 'i', 'k', 'm', 'n'],
    'k' : ['j', 'i', 'o', 'l', 'm'],
    'l' : ['k', 'o', 'p'],
    'm' : ['n', 'j', 'k'],
    'n' : ['b', 'h', 'j', 'm'],
    'o' : ['i', 'k', 'l', 'p'],
    'p' : ['o', 'l'],
    'q' : ['w', 'a'],
    'r' : ['e', 'd', 'f', 't'],
    's' : ['a', 'w', 'e', 'd', 'x', 'z'],
    't' : ['r', 'f', 'g', 'y'],
    'u' : ['y', 'h', 'j', 'i'],
    'v' : ['c', 'f', 'g', 'b'],
    'w' : ['q', 'a', 's', 'e'],
    'x' : ['z', 's', 'd', 'c'],
    'y' : ['t', 'g', 'h', 'u'],
    'z' : ['a', 's', 'x']
}

DOMAIN_BROKERS = [
    "domaineasy.com", "hugedomains.com", "dan.com", "sedo.com", 
    "afternic.com", "godaddy.com/forsale", "namecheap.com", 
    "domainnamesales.com", "squadhelp.com", "uniregistry.com",
    "networksolutions.com", "buydomains.com", "epimac.com"
]

def generate_mutation(base_url, tlds):
    mutated_domain = set()

    for tldx in tlds:
        mutated_domain.add(base_url + tldx)

    #Omission Engine
    for idx in range(len(base_url)):
        temp_word = base_url[:idx] + base_url[idx+1:]

        if not temp_word: 
            continue

        for tldx in tlds:
            mutated_domain.add(temp_word + tldx)

    #Transposition Engine
    for idx in range(len(base_url)-1): # youtube ->  yo ut ube
        temp_word = base_url[:idx] + base_url[idx+1] + base_url[idx] + base_url[idx+2:]

        for tldx in tlds:
            mutated_domain.add(temp_word + tldx)

    #Fat Finger Engine
    for idx, url_char in enumerate(base_url):
        for gnt in fat_words.get(url_char, []):
            temp_word = base_url[:idx] + gnt + base_url[idx+1:]

            for tldx in tlds:
                mutated_domain.add(temp_word + tldx)

    #Insertions Engine (duplicate)
    for idx in range(len(base_url)):
        temp_word = base_url[:idx+1] + base_url[idx] + base_url[idx+1:]

        for tldx in tlds:
            mutated_domain.add(temp_word + tldx)

    #Insertions Engine (adjacent fat_words) (after before)
    for idx, url_char in enumerate(base_url):
        for gnt in fat_words.get(url_char, []):
            temp_word = base_url[:idx+1] + gnt + base_url[idx+1:] #after
            temp_word2 = base_url[:idx] + gnt + base_url[idx:] #before

            for tldx in tlds:
                mutated_domain.add(temp_word + tldx)
                mutated_domain.add(temp_word2 + tldx)

    #Bitsquatting Engine
    for idx, char_url in enumerate(base_url):
        for bit in range(8):
            val = chr(ord(char_url) ^ (1 << bit))

            if ('a' <= val <= 'z') or ('0' <= val <= '9'):
                temp_word = base_url[:idx] + val + base_url[idx+1:]

                for tldx in tlds:
                    mutated_domain.add(temp_word + tldx)

    return mutated_domain

def check_urlscan(domain, api_key):
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    search_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    
    try:
        response = requests.get(search_url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            results = data.get("results", [])
            
            if not results:
                return "🔍 URLScan: No previous scans"
            
            latest_scan = results[0]
            verdicts = latest_scan.get("verdicts", {}).get("overall", {})
            malicious = verdicts.get("malicious", False)
            score = verdicts.get("score", 0)
            
            if malicious or score > 0:
                return f"🚨 URLScan: MALICIOUS (Score: {score})"
            
            report_url = latest_scan.get("result", "")
            return f"📸 URLScan: Clean (Scan: {report_url})"
            
        elif response.status_code == 429:
            return "⚠️ URLScan: Rate Limited"
        else:
            return f"⚠️ URLScan: HTTP {response.status_code}"
    except Exception:
        return "⚠️ URLScan: Request Failed"


headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
registered_domains = {}

def scanner(domain, sec_url, timeout_val, headers, urlscan_key=None):
    try:
        ip = socket.gethostbyname(domain)  
        r = None
        try:
            r = requests.get(f"https://{domain}", headers=headers, timeout=timeout_val, allow_redirects=True)
        except requests.exceptions.RequestException:
            try:
                r = requests.get(f"http://{domain}", headers=headers, timeout=timeout_val, allow_redirects=True, verify=False)
            except requests.exceptions.RequestException:
                return {"domain": domain, "ip": ip, "status": "TIMEOUT", "details": "HTTP/HTTPS timed out", "url": f"http://{domain}", "urlscan": "N/A"}

        if r is not None:    
            final_host = urlparse(r.url).hostname or ""
            details = r.url

            if final_host.endswith('.' + sec_url) or final_host == sec_url:
                if "tag=" in r.url or "ref=" in r.url:
                    status = "AFFILIATE_SQUATTING"
                else:
                    status = "SAFE"
            else:
                url_lower = r.url.lower()
                if any(broker in url_lower for broker in DOMAIN_BROKERS):
                    status = "FOR_SALE_PARKED"
                else:
                    html_content = r.text.lower()
                    if "url=" in html_content and "refresh" in html_content:
                        status = "PARKED_META_REDIRECT"
                    elif "window.location" in html_content:
                        status = "PARKED_JS_REDIRECT"
                    elif "domain is for sale" in html_content or "buy this domain" in html_content:
                        status = "FOR_SALE_PARKED"
                    else:
                        status = "UNKNOWN_THIRD_PARTY"

                        match = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.IGNORECASE | re.DOTALL)
                        page_title = match.group(1).strip() if match else "No Title Found"
                        
                        page_title = re.sub(r'\s+', ' ', page_title)

                        if len(page_title) > 40:
                            page_title = page_title[:37] + "..."
                            
                        details = f"{r.url} | Title: [{page_title}]"

            urlscan_result = "N/A"
            if urlscan_key and status != "SAFE":
                urlscan_result = check_urlscan(domain, urlscan_key)
                details = f"{details} | {urlscan_result}"

            return {"domain": domain, "ip": ip, "status": status, "details": details, "url": r.url, "urlscan": urlscan_result}

    except socket.gaierror:
        return None
    
def parse_args():
    """Defines and parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Brand Protection & Domain Typosquatting Threat Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL or domain name (e.g. youtube.com or https://www.youtube.com/)"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=30,
        help="Number of concurrent threads (default: 30)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=3,
        help="HTTP request timeout in seconds (default: 3)"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Save active findings to a CSV file (e.g. results.csv)"
    )

    parser.add_argument(
        "-us", "--urlscan-key", 
        type=str, default=None, 
        help="Optional: URLScan.io API Key for threat intel lookup"
    )
    
    return parser.parse_args()

def main():
    args = parse_args()

    url = args.url if args.url.startswith("http") else "http://" + args.url
    parsed = (urlparse(url).netloc.replace("www.", "").split("."))
    base_url = parsed[0]
    tld = "." + ".".join(parsed[1:])
    sec_url = base_url + tld

    tlds = [".net", ".org", ".co", ".io", ".xyz", ".cm", ".info", ".biz", ".com"]
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    print(f"[*] Target Base Domain: {sec_url}")
    print("[*] Generating domain mutations...")
    mutated_domain = generate_mutation(base_url, tlds)
    print(f"[*] Total domains to check: {len(mutated_domain)}")
    print(f"[*] Scanning with {args.workers} threads...\n" + "-" * 60)

    icons = {
        "SAFE": "🟩 SAFE",
        "AFFILIATE_SQUATTING": "🟥 AFFILIATE SQUATTING",
        "PARKED_META_REDIRECT": "🟥 PARKED DOMAIN (Meta Redirect)",
        "FOR_SALE_PARKED": "🏷️  DOMAIN FOR SALE (Broker)",
        "PARKED_JS_REDIRECT": "🟥 PARKED DOMAIN (JS Redirect)",
        "UNKNOWN_THIRD_PARTY": "🟨 UNKNOWN / THIRD-PARTY",
        "TIMEOUT": "⚠️  HTTP timed out"
    }

    active_results = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(scanner, domain, sec_url, args.timeout, headers, args.urlscan_key) for domain in mutated_domain]
        
        for future in futures:
            res = future.result()
            if res:
                active_results.append(res)
                icon_str = icons.get(res["status"], res["status"])
                print(f"{res['domain']:<18} -> {res['ip']:<15} | {icon_str} ({res['details']})")

    if args.output and active_results:
        with open(args.output, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["domain", "ip", "status", "details", "url", "urlscan"])
            writer.writeheader()
            writer.writerows(active_results)
        print("-" * 60)
        print(f"[+] Active findings exported to: {args.output}")

if __name__ == "__main__":
    main()