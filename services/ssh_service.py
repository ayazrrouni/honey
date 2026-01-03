import socket
import threading
import logging
import paramiko

from core.fake_shell import handle_command

HOST = "0.0.0.0"
PORT = 2222
HOST_KEY = "ssh_host_key"

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)

class FakeSSHServer(paramiko.ServerInterface):

    def __init__(self):
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        logging.info(f"[SSH] Login attempt: {username}:{password}")
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

    # 🔴 رفض PTY بشكل صريح
    def check_channel_pty_request(
        self,
        channel,
        term,
        width,
        height,
        pixelwidth,
        pixelheight,
        modes
    ):
        return False


def handle_client(client, addr):
    logging.info(f"[SSH] Connection from {addr[0]}")
    transport = paramiko.Transport(client)
    transport.add_server_key(paramiko.RSAKey(filename=HOST_KEY))

    server = FakeSSHServer()
    transport.start_server(server=server)

    chan = transport.accept(20)
    if chan is None:
        return

    server.event.wait(10)

    session = {"user": "test"}

    # ✨ نطبع البرومبت مرة وحدة وبشكل نظيف
    from core.fake_shell import FakeShell
    shell = FakeShell(session["user"])
    session["shell"] = shell
    chan.send(shell.prompt())

    while True:
        try:
            cmd = chan.recv(1024).decode().strip()
            if not cmd:
                continue

            logging.info(f"[SSH] {addr[0]} command: {cmd}")

            output, should_exit = handle_command(cmd, session)
            if should_exit:
                break

            chan.send(output)
            chan.send(shell.prompt())

        except Exception:
            break

    chan.close()
    transport.close()


def start_ssh():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(100)
    logging.info(f"[+] SSH honeypot listening on port {PORT}")

    while True:
        client, addr = sock.accept()
        t = threading.Thread(target=handle_client, args=(client, addr))
        t.daemon = True
        t.start()
