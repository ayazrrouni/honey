import threading
import logging
import time
import signal
import sys

from services.http_service import start_http
from services.ssh_service import start_ssh
from services.ftp_backdoor import start_ftp_server
from dashboard.app import start_dashboard


# ========= LOGGING =========
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

log = logging.getLogger("HONEYPOT")


# ========= BANNER =========
BANNER = r"""
╔══════════════════════════════════════════════╗
║              H O N E Y P O T                 ║
╠══════════════════════════════════════════════╣
║  SSH        → port 2222                      ║
║  FTP        → port 21                        ║
║  HTTP       → port 80                        ║
║  Dashboard  → port 5000                     ║
╚══════════════════════════════════════════════╝
"""


# ========= THREAD WRAPPER =========
def run_service(name, target):
    try:
        log.info(f"[+] Starting {name} service")
        target()
    except Exception as e:
        log.error(f"[!] {name} crashed: {e}", exc_info=True)


# ========= MAIN =========
def main():
    print(BANNER)

    services = [
        ("SSH", start_ssh),
        ("FTP", start_ftp_server),
        ("HTTP", start_http),
        ("DASHBOARD", start_dashboard),
    ]

    threads = []
    for name, service in services:
        t = threading.Thread(
            target=run_service,
            args=(name, service),
            daemon=True,
            name=name
        )
        threads.append(t)
        t.start()

    log.info("[*] All services started successfully")

    # ===== Graceful shutdown =====
    def shutdown(sig, frame):
        log.warning("[!] Shutdown signal received")
        log.info("[*] Honeypot stopped cleanly")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
