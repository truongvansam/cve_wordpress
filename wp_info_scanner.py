#!/usr/bin/env python3
"""
wp_info_scanner.py

Safe WordPress reconnaissance script (non-exploit). Run on Kali or any Linux
machine. Designed for use in a lab / systems you own or are authorized to test.

Features:
 - Fetch homepage and try to detect WordPress version via meta generator, readme.html,
   wp-includes/version.php (if accessible), and common patterns.
 - Probe for common plugin directories (lightweight checks) and try to detect plugin presence.
 - Rate-limited, concurrent, outputs CSV and JSON reports.
 - DOES NOT exploit any vulnerability.

Usage:
  python3 wp_info_scanner.py --targets targets.txt --out report.csv --json report.json
  python3 wp_info_scanner.py --target https://lab.example.local

Requirements:
  pip3 install requests bs4 tqdm
"""

import argparse
import concurrent.futures
import csv
import json
import re
import sys
import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

# ===== configuration =====
DEFAULT_TIMEOUT = 10
USER_AGENT = "WP-Info-Scanner/1.0 (+lab, for research)"
MAX_WORKERS = 8
DELAY_BETWEEN_REQUESTS = 0.2   # polite delay per worker (seconds)

# A short list of common plugins to probe (not exhaustive). You can extend this.
COMMON_PLUGINS = [
    "akismet", "contact-form-7", "woocommerce", "jetpack", "wordfence",
    "yoast", "all-in-one-seo-pack", "wp-super-cache", "w3-total-cache",
    "elementor", "revslider", "duplicator", "updraftplus", "mailchimp-for-wp"
]

# Common file paths to attempt to detect WP version
WP_PATHS = [
    "readme.html",
    "wp-includes/version.php",
    "wp-admin/",
]

# ===== helper functions =====

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

def polite_get(url, timeout=DEFAULT_TIMEOUT):
    """GET with basic error handling and polite behavior."""
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
        time.sleep(DELAY_BETWEEN_REQUESTS)
        return resp
    except requests.RequestException as e:
        return None

def normalize_url(u):
    # add scheme if missing
    p = urlparse(u)
    if not p.scheme:
        return "http://" + u
    return u

def detect_version_from_meta(html):
    if not html:
        return None
    soup = BeautifulSoup(html, "html.parser")
    meta = soup.find("meta", attrs={"name": "generator"})
    if meta and meta.get("content"):
        return meta["content"].strip()
    # sometimes generator is in a comment like <!-- generator: WordPress 5.8.1 -->
    comments = soup.find_all(string=lambda text: isinstance(text, str) and "WordPress" in text)
    for c in comments:
        m = re.search(r"WordPress\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", c, re.I)
        if m:
            return "WordPress " + m.group(1)
    return None

def detect_version_from_readme(html):
    if not html:
        return None
    # readme.html often contains "Stable tag: X.Y.Z" or "Version X.Y.Z" lines
    m = re.search(r"Stable tag:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", html, re.I)
    if m:
        return "WordPress " + m.group(1)
    m2 = re.search(r"Version\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", html, re.I)
    if m2:
        return "WordPress " + m2.group(1)
    return None

def detect_version_from_versionphp(text):
    if not text:
        return None
    # version.php defines $wp_version = '5.8.1';
    m = re.search(r"\$wp_version\s*=\s*'([0-9]+\.[0-9]+(?:\.[0-9]+)?)'", text)
    if m:
        return "WordPress " + m.group(1)
    return None

def probe_plugins(base_url):
    found = []
    for plugin in COMMON_PLUGINS:
        # check plugin readme or plugin root; try conventional file locations
        candidates = [
            f"wp-content/plugins/{plugin}/",
            f"wp-content/plugins/{plugin}/readme.txt",
            f"wp-content/plugins/{plugin}/{plugin}.php",
        ]
        for c in candidates:
            url = urljoin(base_url, c)
            r = polite_get(url)
            if r and r.status_code == 200 and len(r.content) > 0:
                # simplistic detection: presence of 200 and content; may false positive
                found.append({"plugin": plugin, "path": c, "url": r.url, "status": r.status_code})
                break
    return found

def gather_wp_info(target):
    result = {
        "target": target,
        "base": None,
        "reachable": False,
        "version_detection": [],
        "plugins": [],
        "notes": []
    }
    url = normalize_url(target)
    result["base"] = url

    # Fetch homepage
    r = polite_get(url)
    if not r:
        result["notes"].append("homepage-unreachable")
        return result
    result["reachable"] = True

    # detect version from generator meta
    vmeta = detect_version_from_meta(r.text)
    if vmeta:
        result["version_detection"].append({"method": "meta-generator", "value": vmeta})

    # try common WP paths
    for p in WP_PATHS:
        full = urljoin(url, p)
        r2 = polite_get(full)
        if not r2:
            continue
        # version via readme
        if p.endswith("readme.html"):
            vr = detect_version_from_readme(r2.text)
            if vr:
                result["version_detection"].append({"method": "readme", "path": p, "value": vr})
        # version via version.php
        if p.endswith("version.php") or "version.php" in p:
            vr = detect_version_from_versionphp(r2.text)
            if vr:
                result["version_detection"].append({"method": "version.php", "path": p, "value": vr})
        # if wp-admin present
        if p.endswith("wp-admin/") and r2.status_code in (200, 302):
            result["notes"].append("wp-admin-accessible")

    # probe for common plugins (lightweight)
    plugins = probe_plugins(url)
    if plugins:
        result["plugins"] = plugins

    # try to detect readme from plugins directory listing (if directory listing is enabled)
    # (we already checked plugin-specific files above)
    return result

# ===== CLI & orchestration =====

def scan_targets(targets, out_csv=None, out_json=None, workers=MAX_WORKERS):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(gather_wp_info, t): t for t in targets}
        for fut in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Scanning"):
            t = futures[fut]
            try:
                r = fut.result()
            except Exception as e:
                r = {"target": t, "error": str(e)}
            results.append(r)

    # write CSV
    if out_csv:
        with open(out_csv, "w", newline="", encoding="utf-8") as csvf:
            writer = csv.writer(csvf)
            writer.writerow(["target", "reachable", "version_methods", "plugins", "notes", "base"])
            for r in results:
                vmethods = "; ".join([f"{v['method']}:{v['value']}" for v in r.get("version_detection", [])]) or ""
                plugins = "; ".join([p["plugin"] for p in r.get("plugins", [])]) or ""
                notes = "; ".join(r.get("notes", [])) or ""
                writer.writerow([r.get("target", ""), r.get("reachable", False), vmethods, plugins, notes, r.get("base","")])
        print(f"[+] CSV report written to {out_csv}")

    # write JSON
    if out_json:
        with open(out_json, "w", encoding="utf-8") as jf:
            json.dump(results, jf, indent=2, ensure_ascii=False)
        print(f"[+] JSON report written to {out_json}")

    return results

def parse_args():
    p = argparse.ArgumentParser(description="Safe WP recon scanner (non-exploit).")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--targets", help="file with newline-separated targets (host or URL)")
    g.add_argument("--target", help="single target (e.g. https://lab.example.local)")
    p.add_argument("--out", help="CSV output file", default="wp_scan_report.csv")
    p.add_argument("--json", help="JSON output file", default="wp_scan_report.json")
    p.add_argument("--workers", type=int, default=4, help="concurrent workers")
    return p.parse_args()

def main():
    args = parse_args()
    if args.targets:
        with open(args.targets, "r", encoding="utf-8") as tf:
            targets = [line.strip() for line in tf if line.strip() and not line.strip().startswith("#")]
    else:
        targets = [args.target.strip()]
    print(f"[i] Targets: {targets}")
    results = scan_targets(targets, out_csv=args.out, out_json=args.json, workers=args.workers)
    print("[i] Done. Review reports and cross-check versions/plugins with vendor advisories / CVE DB.")

if __name__ == "__main__":
    # disable insecure request warnings on lab use
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
