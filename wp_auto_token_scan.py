#!/usr/bin/env python3
"""
wp_auto_token_scan.py

- Read targets from targets.txt (or single --target)
- Auto-load WPScan API token from ~/.wpscan_token (or prompt and optionally save)
- Detect WordPress core version, enumerate plugin/theme slugs from HTML and probe for versions
- Query WPScan API for vulnerabilities (core / plugins / themes)
- Aggregate CVEs, sort by CVSS (desc), output CSV + JSON, print top-3 per-target and overall

Usage:
  pip3 install requests beautifulsoup4 tqdm
  python3 wp_auto_token_scan.py --targets targets.txt --save-token
  python3 wp_auto_token_scan.py --target https://lab-wp.local

Security & Ethics:
 - Only run this script on hosts you own or are authorized to test.
 - The script does NOT perform exploits or destructive actions.

Author: defensive assistant
"""

import argparse
import concurrent.futures
import csv
import json
import os
import re
import stat
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

# ------------- Configuration -------------
USER_AGENT = "WP-Auto-Vuln-Scanner/1.0 (+lab)"
TIMEOUT = 12
DELAY = 0.25    # polite delay between requests
MAX_WORKERS = 6
WPSCAN_BASE = "https://wpscan.com/api/v3"
TOKEN_PATH = Path.home() / ".wpscan_token"   # default token store
# -----------------------------------------

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

# ---- utility: load/save token ----
def load_token(path=TOKEN_PATH):
    if path.exists():
        try:
            tok = path.read_text().strip()
            return tok if tok else None
        except Exception:
            return None
    return None

def save_token(token, path=TOKEN_PATH):
    try:
        path.write_text(token.strip())
        # set file mode to user-read/write only
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        print(f"[+] Token saved to {path} (perm 600).")
    except Exception as e:
        print(f"[!] Failed to save token: {e}")

# ---- HTTP helpers ----
def polite_get(url):
    try:
        r = session.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
        time.sleep(DELAY)
        return r
    except requests.RequestException:
        return None

def normalize_target(u):
    p = urlparse(u)
    if not p.scheme:
        return "http://" + u
    return u.rstrip("/")

# ---- detection helpers ----
def detect_wp_version(base_url):
    base = normalize_target(base_url)
    # try meta generator on homepage
    r = polite_get(base)
    if r and r.status_code == 200 and r.text:
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']WordPress\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)', r.text, re.I)
        if m:
            return ("meta", m.group(1))
    # try readme
    r2 = polite_get(urljoin(base + "/", "readme.html"))
    if r2 and r2.status_code == 200 and r2.text:
        m2 = re.search(r"Stable tag:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", r2.text, re.I)
        if m2:
            return ("readme", m2.group(1))
        m3 = re.search(r"Version\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", r2.text, re.I)
        if m3:
            return ("readme_version", m3.group(1))
    # try version.php
    r3 = polite_get(urljoin(base + "/", "wp-includes/version.php"))
    if r3 and r3.status_code == 200 and r3.text:
        m4 = re.search(r"\$wp_version\s*=\s*'([0-9]+\.[0-9]+(?:\.[0-9]+)?)'", r3.text)
        if m4:
            return ("version.php", m4.group(1))
    return (None, None)

def extract_plugins_themes_from_html(html):
    plugins = set()
    themes = set()
    if not html:
        return plugins, themes
    for m in re.finditer(r"/wp-content/plugins/([a-zA-Z0-9_-]+)/", html):
        plugins.add(m.group(1))
    for m in re.finditer(r"/wp-content/themes/([a-zA-Z0-9_-]+)/", html):
        themes.add(m.group(1))
    return plugins, themes

# attempt to probe plugin for version via readme.txt or main plugin file
def probe_plugin_version(base_url, slug):
    candidates = [
        f"wp-content/plugins/{slug}/readme.txt",
        f"wp-content/plugins/{slug}/{slug}.php",
        f"wp-content/plugins/{slug}/",
    ]
    for c in candidates:
        url = urljoin(normalize_target(base_url) + "/", c)
        r = polite_get(url)
        if not r:
            continue
        if r.status_code != 200:
            continue
        txt = r.text
        # stable tag
        m = re.search(r"Stable tag:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", txt, re.I)
        if m:
            return m.group(1), url
        # plugin header
        m2 = re.search(r"^\s*\*\s*Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", txt, re.I | re.M)
        if m2:
            return m2.group(1), url
        # generic Version:
        m3 = re.search(r"Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", txt, re.I)
        if m3:
            return m3.group(1), url
        # if dir index or file content present, return unknown version but url
        return None, url
    return None, None

def probe_theme_version(base_url, slug):
    candidates = [
        f"wp-content/themes/{slug}/style.css",
        f"wp-content/themes/{slug}/",
    ]
    for c in candidates:
        url = urljoin(normalize_target(base_url) + "/", c)
        r = polite_get(url)
        if not r:
            continue
        if r.status_code != 200:
            continue
        txt = r.text
        # style.css header
        m = re.search(r"^\s*Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", txt, re.I | re.M)
        if m:
            return m.group(1), url
        m2 = re.search(r"Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", txt, re.I)
        if m2:
            return m2.group(1), url
        return None, url
    return None, None

# ---- WPScan API wrappers ----
def wpscan_get(endpoint, name_or_id, token):
    """
    endpoint: 'wordpresses' or 'plugins' or 'themes'
    name_or_id: version for wordpresses, slug for plugins/themes
    """
    if not token:
        return []
    headers = {"Authorization": f"Token token={token}"}
    url = f"{WPSCAN_BASE}/{endpoint}/{name_or_id}"
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            return data.get("vulnerabilities", [])
        # else: 404 or others -> empty
    except requests.RequestException:
        pass
    return []

# ---- collect for single target ----
def analyze_target(target, token=None, probe_versions=True):
    base = normalize_target(target)
    result = {
        "target": target,
        "base": base,
        "reachable": False,
        "wp_version": None,
        "wp_version_source": None,
        "wp_vulns": [],
        "plugins": [],
        "themes": [],
        "notes": []
    }

    r = polite_get(base)
    if not r:
        result["notes"].append("unreachable")
        return result
    result["reachable"] = True

    # detect core
    src, ver = detect_wp_version(base)
    if ver:
        result["wp_version"] = ver
        result["wp_version_source"] = src
        # get core vulns
        core_vulns = wpscan_get("wordpresses", ver, token) if token else []
        for v in core_vulns:
            result["wp_vulns"].append({
                "cve": v.get("cve") or v.get("id"),
                "title": v.get("title"),
                "cvss": float(v.get("cvss") or 0),
                "disclosure_date": v.get("disclosure_date"),
                "refs": v.get("references") or []
            })
    else:
        result["notes"].append("version_not_detected")

    # parse HTML plugins/themes
    html = r.text or ""
    plugins, themes = extract_plugins_themes_from_html(html)

    # probe plugin versions and vulns
    for slug in sorted(plugins):
        ver_p, url_p = (None, None)
        if probe_versions:
            ver_p, url_p = probe_plugin_version(base, slug)
        pv = wpscan_get("plugins", slug, token) if token else []
        result["plugins"].append({
            "slug": slug,
            "version": ver_p,
            "probe_url": url_p,
            "vulns": [{"cve": v.get("cve") or v.get("id"),
                       "title": v.get("title"),
                       "cvss": float(v.get("cvss") or 0),
                       "disclosure_date": v.get("disclosure_date"),
                       "refs": v.get("references") or []} for v in pv]
        })

    # probe themes
    for slug in sorted(themes):
        ver_t, url_t = (None, None)
        if probe_versions:
            ver_t, url_t = probe_theme_version(base, slug)
        tv = wpscan_get("themes", slug, token) if token else []
        result["themes"].append({
            "slug": slug,
            "version": ver_t,
            "probe_url": url_t,
            "vulns": [{"cve": v.get("cve") or v.get("id"),
                       "title": v.get("title"),
                       "cvss": float(v.get("cvss") or 0),
                       "disclosure_date": v.get("disclosure_date"),
                       "refs": v.get("references") or []} for v in tv]
        })
    return result

# ---- orchestration ----
def scan_all(targets, token=None, workers=MAX_WORKERS):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(analyze_target, t, token): t for t in targets}
        for fut in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Scanning"):
            t = futures[fut]
            try:
                r = fut.result()
            except Exception as e:
                r = {"target": t, "error": str(e)}
            results.append(r)
    return results

def aggregate_vulns(results):
    all_v = []
    for r in results:
        tgt = r.get("target")
        # core
        for v in r.get("wp_vulns", []):
            all_v.append({
                "target": tgt, "component": "core", "name": "wordpress",
                "version": r.get("wp_version"), "cve": v.get("cve"),
                "title": v.get("title"), "cvss": v.get("cvss"), "refs": v.get("refs")
            })
        # plugins
        for p in r.get("plugins", []):
            for v in p.get("vulns", []):
                all_v.append({
                    "target": tgt, "component": "plugin", "name": p.get("slug"),
                    "version": p.get("version"), "cve": v.get("cve"),
                    "title": v.get("title"), "cvss": v.get("cvss"), "refs": v.get("refs")
                })
        # themes
        for titem in r.get("themes", []):
            for v in titem.get("vulns", []):
                all_v.append({
                    "target": tgt, "component": "theme", "name": titem.get("slug"),
                    "version": titem.get("version"), "cve": v.get("cve"),
                    "title": v.get("title"), "cvss": v.get("cvss"), "refs": v.get("refs")
                })
    # sort by CVSS desc
    all_v_sorted = sorted(all_v, key=lambda x: x.get("cvss", 0), reverse=True)
    return all_v_sorted

def write_outputs_per_target(results, out_json, out_csv):
    # write full JSON of results
    with open(out_json, "w", encoding="utf-8") as jf:
        json.dump(results, jf, indent=2, ensure_ascii=False)
    # write flattened CSV summary (one row per vulnerability)
    rows = []
    for r in results:
        tgt = r.get("target")
        # core
        for v in r.get("wp_vulns", []):
            rows.append([tgt, "core", "wordpress", r.get("wp_version"), v.get("cve"), v.get("title"), v.get("cvss")])
        for p in r.get("plugins", []):
            for v in p.get("vulns", []):
                rows.append([tgt, "plugin", p.get("slug"), p.get("version"), v.get("cve"), v.get("title"), v.get("cvss")])
        for titem in r.get("themes", []):
            for v in titem.get("vulns", []):
                rows.append([tgt, "theme", titem.get("slug"), titem.get("version"), v.get("cve"), v.get("title"), v.get("cvss")])
    with open(out_csv, "w", newline="", encoding="utf-8") as cf:
        writer = csv.writer(cf)
        writer.writerow(["target","component","name","detected_version","cve","title","cvss"])
        for row in rows:
            writer.writerow(row)
    print(f"[+] Wrote JSON -> {out_json} and CSV -> {out_csv}")

# ---- CLI / main ----
def main():
    parser = argparse.ArgumentParser(description="WP auto vuln scanner (loads token from file or prompt)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--targets", help="file with newline separated targets")
    group.add_argument("--target", help="single target URL")
    parser.add_argument("--api-token", help="WPScan API token (optional). If omitted, script will try ~/.wpscan_token or prompt you.", default=None)
    parser.add_argument("--save-token", action="store_true", help="If prompting for token, save to ~/.wpscan_token (mode 600).")
    parser.add_argument("--out-json", default="wp_scan_results.json", help="Output JSON file (full results)")
    parser.add_argument("--out-csv", default="wp_vulns_flat.csv", help="Output CSV file (flattened vuln list)")
    parser.add_argument("--top", type=int, default=3, help="Top N per target to display")
    parser.add_argument("--workers", type=int, default=4, help="Concurrency workers")
    parser.add_argument("--no-probe-versions", action="store_true", help="Don't probe plugin/theme for version files (fewer requests)")
    args = parser.parse_args()

    # token logic: precedence CLI -> ~/.wpscan_token -> prompt
    token = args.api_token or load_token()
    if not token:
        print("[i] No API token supplied or found.")
        token = input("Enter WPScan API token (or press Enter to continue without token): ").strip()
        if token == "":
            token = None
        else:
            if args.save_token:
                save_token(token)

    # load targets
    if args.targets:
        if not os.path.isfile(args.targets):
            print("[!] Targets file not found:", args.targets)
            sys.exit(1)
        with open(args.targets, "r", encoding="utf-8") as tf:
            targets = [line.strip() for line in tf if line.strip() and not line.strip().startswith("#")]
    else:
        targets = [args.target.strip()]

    print(f"[i] Scanning {len(targets)} target(s) with {args.workers} workers. Token: {'yes' if token else 'no'}")
    results = scan_all(targets, token=token, workers=args.workers)
    write_outputs_per_target(results, args.out_json, args.out_csv)

    all_v = aggregate_vulns(results)
    # summarize per-target top N
    per_target = {}
    for v in all_v:
        per_target.setdefault(v["target"], []).append(v)
    # print top-N per target
    print("\n=== Top results per target ===")
    for t, items in per_target.items():
        print(f"\nTarget: {t}")
        for i, it in enumerate(items[:args.top], start=1):
            print(f" [{i}] {it.get('component')} {it.get('name')} {it.get('version') or ''} - {it.get('cve')} - CVSS: {it.get('cvss')}")
            if it.get("refs"):
                print("      refs:", "; ".join(it.get("refs")[:3]))
    # print overall top N
    print("\n=== Overall top results ===")
    for i, it in enumerate(all_v[:args.top], start=1):
        print(f" [{i}] {it.get('target')} - {it.get('component')} {it.get('name')} - {it.get('cve')} - CVSS: {it.get('cvss')}")
    print("\n[i] Done. Review outputs and act accordingly (patch/mitigate/monitor).")

if __name__ == "__main__":
    # disable insecure warnings in lab
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
