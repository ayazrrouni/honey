import socket
import threading
from datetime import datetime

LOG_FILE = "./logs/attacks.log"

def log_event(ip, msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} - {ip} - {msg}\n")

def handle_client(conn, addr):
    log_event(addr[0], "FTP connection opened")

    try:
        conn.send(b"220 (vsFTPd 2.3.4)\r\n")

        while True:
            data = conn.recv(1024)
            if not data:
                break

            cmd = data.decode(errors="ignore").strip()
            log_event(addr[0], f"FTP CMD: {cmd}")

            # USER
            if cmd.upper().startswith("USER"):
                username = cmd.split(" ", 1)[1]

                # 🔥 VSFTPD BACKDOOR TRIGGER
                if ":)" in username:
                    log_event(addr[0], "VSFTPD backdoor triggered")

                    from services.ftp_backdoor import start_backdoor_listener
                    threading.Thread(
                        target=start_backdoor_listener,
                        daemon=True
                    ).start()

                conn.send(b"331 Please specify the password.\r\n")

            # PASS
            elif cmd.upper().startswith("PASS"):
                conn.send(b"230 Login successful.\r\n")

            # QUIT
            elif cmd.upper().startswith("QUIT"):
                conn.send(b"221 Goodbye.\r\n")
                break

            else:
                conn.send(b"500 Unknown command.\r\n")

    except Exception as e:
        log_event(addr[0], f"ERROR: {e}")

    finally:
        conn.close()
        log_event(addr[0], "FTP connection closed")

def start_ftp():
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 21))
    sock.listen(5)

    print("[+] Fake FTP (vsftpd 2.3.4) listening on port 21")

    while True:
        conn, addr = sock.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr))
        t.daemon = True
        t.start()
