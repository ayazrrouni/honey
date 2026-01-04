import socket
import threading
import uuid
import time

from core.fake_shell import handle_command, FakeShell
from core.logger import (
    start_session,
    log_command,
    end_session,
    log_ftp_credentials
)

BACKDOOR_PORT = 6200
backdoor_started = False
lock = threading.Lock()


# ===============================
# Fake root shell (backdoor)
# ===============================
def handle_shell(conn, addr):
    ip = addr[0]
    session_id = str(uuid.uuid4())

    start_session(ip, session_id, service="ftp")

    shell = FakeShell("root")
    conn.send(b"uid=0(root)\n")

    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break

            cmd = data.decode(errors="ignore").strip()
            if not cmd:
                continue

            log_command(ip, session_id, cmd)

            output, _ = handle_command(cmd, {"shell": shell})
            if output:
                conn.send(output.encode())

    finally:
        end_session(ip, session_id)
        conn.close()


def start_backdoor_listener():
    global backdoor_started

    with lock:
        if backdoor_started:
            return
        backdoor_started = True

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", BACKDOOR_PORT))
    sock.listen(5)

    print("[+] FTP backdoor listening on 6200")

    while True:
        c, a = sock.accept()
        threading.Thread(
            target=handle_shell,
            args=(c, a),
            daemon=True
        ).start()


# ===============================
# FTP service (port 21)
# ===============================
def handle_ftp_client(conn, addr):
    ip = addr[0]
    session_id = str(uuid.uuid4())

    start_session(ip, session_id, service="ftp")

    try:
        conn.send(b"220 (vsFTPd 2.3.4)\r\n")

        user_line = conn.recv(1024).decode(errors="ignore").strip()
        if user_line.upper().startswith("USER"):
            username = user_line.split(" ", 1)[1] if " " in user_line else ""
            log_ftp_credentials(ip, session_id, username=username)

        if ":)" in user_line:
            threading.Thread(
                target=start_backdoor_listener,
                daemon=True
            ).start()

        time.sleep(0.2)
        conn.send(b"331 Please specify the password.\r\n")

        pass_line = conn.recv(1024).decode(errors="ignore").strip()
        if pass_line.upper().startswith("PASS"):
            password = pass_line.split(" ", 1)[1] if " " in pass_line else ""
            log_ftp_credentials(ip, session_id, password=password)

        time.sleep(0.2)
        conn.send(b"530 Login incorrect.\r\n")

    except Exception:
        pass
    finally:
        end_session(ip, session_id)
        conn.close()


def start_ftp_server(host="0.0.0.0", port=21):
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)

    print("[+] FTP service listening on port 21")

    while True:
        c, a = sock.accept()
        threading.Thread(
            target=handle_ftp_client,
            args=(c, a),
            daemon=True
        ).start()


if __name__ == "__main__":
    start_ftp_server()
