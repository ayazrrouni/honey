import threading
import logging
import sys
import os

# نخلي المشروع كامل في الـ PYTHONPATH
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)

# ===== IMPORT SERVICES =====
from services.http_service import start_http
from services.ftp_backdoor import start_ftp_server
from services.ssh_service import start_ssh   # إذا الاسم مختلف قولي

# ===== LOGGING CONFIG =====
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)

def main():
    threads = [
        threading.Thread(target=start_ssh, daemon=True),
        threading.Thread(target=start_ftp_server, daemon=True),
        threading.Thread(target=start_http, daemon=True),
    ]

    for t in threads:
        t.start()

    logging.info("[*] Honeypot running (SSH + FTP Backdoor + HTTP)")

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        logging.warning("[!] Honeypot stopped")

if __name__ == "__main__":
    main()
