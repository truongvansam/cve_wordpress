import requests
import csv
import os
from dotenv import load_dotenv
from urllib.parse import urlparse

# Load token từ file .env
load_dotenv()
API_TOKEN = os.getenv("WPSCAN_API_TOKEN")

if not API_TOKEN:
    print("[!] Không tìm thấy API token trong file .env")
    exit()

HEADERS = {"Authorization": f"Token token={API_TOKEN}"}

def get_wp_info(url):
    """Lấy thông tin core version, plugin, theme của WordPress site"""
    api_url = f"https://wpscan.com/api/v3/wordpresses/{urlparse(url).netloc}"
    r = requests.get(api_url, headers=HEADERS)
    if r.status_code != 200:
        return None
    return r.json()

def get_top_vulns(vulns_dict, top_n=3):
    """Trả về top N lỗ hổng theo điểm CVSS"""
    vulns = []
    for vuln_id, details in vulns_dict.items():
        score = details.get("cvss", 0) or 0
        vulns.append((vuln_id, score, details.get("title", ""), details.get("references", [])))
    vulns.sort(key=lambda x: x[1], reverse=True)
    return vulns[:top_n]

def main():
    results = []
    with open("targets.txt", "r") as f:
        targets = [line.strip() for line in f if line.strip()]

    for site in targets:
        print(f"\n[+] Quét: {site}")
        info = get_wp_info(site)
        if not info:
            print("    [-] Không lấy được dữ liệu từ WPScan API.")
            continue

        site_data = {"site": site, "core": [], "plugins": [], "themes": []}

        # Core vulnerabilities
        core_vulns = info.get("vulnerabilities", {})
        if core_vulns:
            site_data["core"] = get_top_vulns(core_vulns)
            print(f"    Core: {len(core_vulns)} lỗ hổng (Top 3 hiển thị)")

        # Plugins vulnerabilities
        plugins = info.get("plugins", {})
        for plugin_name, plugin_info in plugins.items():
            if "vulnerabilities" in plugin_info:
                top3 = get_top_vulns(plugin_info["vulnerabilities"])
                site_data["plugins"].append((plugin_name, top3))

        # Themes vulnerabilities
        themes = info.get("themes", {})
        for theme_name, theme_info in themes.items():
            if "vulnerabilities" in theme_info:
                top3 = get_top_vulns(theme_info["vulnerabilities"])
                site_data["themes"].append((theme_name, top3))

        results.append(site_data)

    # Xuất CSV
    with open("vulnerabilities.csv", "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Site", "Type", "Name", "Vuln ID", "CVSS Score", "Title", "References"])

        for site in results:
            for vuln in site["core"]:
                writer.writerow([site["site"], "Core", "WordPress", vuln[0], vuln[1], vuln[2], "; ".join(vuln[3])])

            for plugin_name, vulns in site["plugins"]:
                for vuln in vulns:
                    writer.writerow([site["site"], "Plugin", plugin_name, vuln[0], vuln[1], vuln[2], "; ".join(vuln[3])])

            for theme_name, vulns in site["themes"]:
                for vuln in vulns:
                    writer.writerow([site["site"], "Theme", theme_name, vuln[0], vuln[1], vuln[2], "; ".join(vuln[3])])

    print("\n[✅] Hoàn thành! Kết quả lưu tại vulnerabilities.csv")

if __name__ == "__main__":
    main()
