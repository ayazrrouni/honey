import threading
import logging

from services.http_service import start_http
from services.ssh_service import start_ssh
from services.ftp_backdoor import start_backdoor_listener

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)

if __name__ == "__main__":

    t1 = threading.Thread(target=start_ssh, daemon=True)
    t2 = threading.Thread(target=start_backdoor_listener, daemon=True)
    t3 = threading.Thread(target=start_http, daemon=True)

    t1.start()
    t2.start()
    t3.start()

    logging.info("[*] Honeypot running (SSH + FTP Backdoor + HTTP)")

    try:
        t1.join()
        t2.join()
        t3.join()
    except KeyboardInterrupt:
        print("\n[!] Honeypot stopped")
