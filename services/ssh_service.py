import socket
import threading
import logging
import paramiko
import uuid

from core.fake_shell import handle_command, FakeShell
from core.logger import start_session, log_command, end_session

HOST = "0.0.0.0"
PORT = 2222
HOST_KEY = "ssh_host_key"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s"
)


class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.username = "unknown"

    def check_auth_password(self, username, password):
        self.username = username
        logging.info(f"[SSH] Login attempt {username}:{password}")
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, *args):
        return False


def handle_client(client, addr):
    ip = addr[0]
    session_id = str(uuid.uuid4())

    logging.info(f"[SSH] Connection from {ip}")

  
    start_session(ip, session_id, service="ssh")

    transport = None
    chan = None

    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(paramiko.RSAKey(filename=HOST_KEY))

        server = FakeSSHServer()
        transport.start_server(server=server)

        chan = transport.accept(20)
        if chan is None:
            logging.warning(f"[SSH] No channel from {ip}")
            return

        username = server.username or "test"

        shell = FakeShell(username)

        session = {
            "shell": shell,
            "ip": ip,
            "user": username
        }

        chan.send(shell.prompt())

        while True:
            cmd = chan.recv(1024).decode(errors="ignore").strip()
            if not cmd:
                continue

            logging.info(f"[SSH] {ip} CMD: {cmd}")

            log_command(ip, session_id, cmd)

            output, exit_flag = handle_command(cmd, session)

            if exit_flag:
                break

            if output:
                chan.send(output)

            chan.send(shell.prompt())

    except Exception as e:
        logging.error(f"[SSH] Error {ip}: {e}")

    finally:
       
        end_session(ip, session_id)

        if chan:
            chan.close()
        if transport:
            transport.close()

        client.close()
        logging.info(f"[SSH] Connection closed {ip}")


def start_ssh():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(100)

    logging.info(f"[+] SSH Honeypot listening on port {PORT}")

    while True:
        client, addr = sock.accept()
        threading.Thread(
            target=handle_client,
            args=(client, addr),
            daemon=True
        ).start()
