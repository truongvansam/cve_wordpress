import requests
import sys

# ====== CẤU HÌNH ======
API_TOKEN = "NHẬP_API_TOKEN_CỦA_BẠN_VÀO_ĐÂY"  # lấy từ https://wpscan.com/api
API_URL = "https://wpscan.com/api/v3/wordpresses"

def get_vulnerabilities(wp_version):
    headers = {
        "Authorization": f"Token token={API_TOKEN}"
    }
    url = f"{API_URL}/{wp_version}"
    
    print(f"[+] Đang tìm lỗ hổng cho WordPress {wp_version} ...")
    response = requests.get(url, headers=headers)

    if response.status_code == 404:
        print("[!] Không tìm thấy thông tin cho phiên bản này.")
        return

    if response.status_code != 200:
        print(f"[!] Lỗi API: {response.status_code}")
        return

    data = response.json()

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        print("[+] Không có lỗ hổng nào được ghi nhận.")
        return

    print(f"[+] Tìm thấy {len(vulns)} lỗ hổng:")
    for v in vulns:
        print("="*60)
        print(f"CVE: {v.get('cve')}")
        print(f"Mức độ: {v.get('cvss')}")
        print(f"Mô tả: {v.get('title')}")
        print(f"Ngày công bố: {v.get('disclosure_date')}")
        print(f"Link tham khảo: {v.get('references')}")
        print("="*60)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <phiên_bản_WordPress>")
        print(f"VD: python3 {sys.argv[0]} 6.5.2")
        sys.exit(1)

    wp_version = sys.argv[1]
    get_vulnerabilities(wp_version)
