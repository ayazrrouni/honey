import threading
import logging

from services.ssh_service import start_ssh
from services.ftp_backdoor import start_ftp_server


logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)


if __name__ == "__main__":

    t1 = threading.Thread(target=start_ssh, daemon=True)
    t2 = threading.Thread(target=start_ftp_server, daemon=True)

    t1.start()
    t2.start()

    logging.info("[*] Honeypot running (SSH + FTP backdoor)")

    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        print("\n[!] Honeypot stopped")
