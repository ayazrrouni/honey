import threading
from services.ssh_service import start_ssh
from services.ftp_service import start_ftp
from services.ftp_backdoor import start_backdoor_listener
import logging

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)

if __name__ == "__main__":

    t1 = threading.Thread(target=start_ssh)
    t2 = threading.Thread(target=start_ftp)
    t3 = threading.Thread(target=start_backdoor_listener)

    t1.daemon = True
    t2.daemon = True
    t3.daemon = True

    t1.start()
    t2.start()
    t3.start()

    logging.info("[*] Honeypot running (SSH + FTP backdoor)")

    try:
        t1.join()
        t2.join()
        t3.join()
    except KeyboardInterrupt:
        print("\n[!] Honeypot stopped")
