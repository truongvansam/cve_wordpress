# cve_wordpress
Cài dependencies trên Kali:
sudo apt update
sudo apt install -y python3-pip
pip3 install requests bs4 tqdm

Tạo file targets.txt chứa danh sách hostname/URL (mỗi dòng một target). Ví dụ:
https://lab-wp.local
http://192.168.56.101

python3 wp_info_scanner.py --targets targets.txt --out lab_report.csv --json lab_report.json
