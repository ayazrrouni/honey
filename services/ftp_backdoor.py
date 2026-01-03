import socket
import threading
import os
from datetime import datetime

from core.fake_shell import handle_command
from core.fake_fs import load_fs

LOG_FILE = "./logs/ftp_backdoor.log"


def log_event(ip, msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} - {ip} - {msg}\n")


def new_session():
    return {
        "user": "root",
        "cwd": "/root",
        "history": [],
        "fs": load_fs()
    }


def handle_shell(conn, addr):
    session = new_session()
    log_event(addr[0], "Backdoor shell opened")

    try:
        # ✔ هذا فقط ما ينتظره metasploit
        conn.send(b"uid=0(root) gid=0(root) groups=0(root)\n")

        while True:
            data = conn.recv(1024)
            if not data:
                break

            cmd = data.decode(errors="ignore").strip()
            log_event(addr[0], f"CMD: {cmd}")

            output, _ = handle_command(cmd, session)

            if output:
                conn.send(output.encode())

    except Exception as e:
        log_event(addr[0], f"ERROR: {e}")

    finally:
        conn.close()
        log_event(addr[0], "Backdoor closed")


def start_backdoor_listener():
    os.makedirs("logs", exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 6200))
    sock.listen(5)

    print("[+] VSFTPD backdoor shell listening on port 6200")

    while True:
        conn, addr = sock.accept()
        t = threading.Thread(target=handle_shell, args=(conn, addr))
        t.daemon = True
        t.start()
