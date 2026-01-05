import os
import json
import logging
import datetime

FAKE_FS_PATH = "core/fake_fs.json"
CMD_LOG_FILE = "logs/cmd_audits.log"

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)

# =============================
# Fake FileSystem Loader
# =============================
def load_fs():
    if not os.path.exists(FAKE_FS_PATH):
        return {
            "/home/test": {}
        }
    with open(FAKE_FS_PATH, "r") as f:
        return json.load(f)


def save_fs(fs):
    with open(FAKE_FS_PATH, "w") as f:
        json.dump(fs, f, indent=4)


# =============================
# Fake Shell Class
# =============================
class FakeShell:
    def __init__(self, username="test"):
        self.username = username
        self.cwd = f"/home/{username}"
        self.fs = load_fs()
        self.history = []

        if self.cwd not in self.fs:
            self.fs[self.cwd] = {}
            save_fs(self.fs)

    # -------------------------
    def prompt(self):
        if self.cwd == f"/home/{self.username}":
            return f"{self.username}@ubuntu:~$ "
        return f"{self.username}@ubuntu:{self.cwd}$ "

    # -------------------------
    def run(self, cmd):
        cmd = cmd.strip()
        if not cmd:
            return ""

     
        self.history.append(cmd)

        parts = cmd.split()
        base = parts[0]

        if base == "whoami":
            return self.username + "\n"

        if base == "id":
            return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username})\n"


        if base == "pwd":
            return self.cwd + "\n"

        if base == "ls":
            return self._ls()

        if base == "cd":
            return self._cd(parts)

        if base == "mkdir":
            return self._mkdir(parts)

        if base == "rmdir":
            return self._rmdir(parts)

        if base == "rm":
            return self._rm(parts)

        if base == "echo":
            return self._echo(parts)

        if base == "cat":
            return self._cat(parts)

        if base == "ifconfig":
            return self._ifconfig()

        if base == "clear":
            return "\033[2J\033[H"

        if base == "history":
            return self._history()

        if base in ("exit", "logout"):
            return "__exit__"
        
        if base == "ps":
            return self._ps(parts)

        if base == "netstat":
            return self._netstat(parts)

        if base == "sudo":
            return self._sudo(parts)

        if base == "df":
            return self._df()

        if base == "free":
            return self._free()

        if base == "ip":
            return self._ip(parts)

        if base == "uname":
            if "-a" in parts:
                return self._uname_a()
            return "Linux\n"
        
        if base == "touch":
            return self._touch(parts)

        if base == "chmod":
            return self._chmod(parts)

        if base == "chown":
            return self._chown(parts)

        # Fake execution attempts (high severity)
        if base.startswith("./"):
            return self._execute_fake(base)

        if base in ("sh", "bash"):
            return self._execute_fake(parts[-1])



        return f"{base}: command not found\n"

    # =========================
    # Commands implementation
    # =========================
    def _ls(self):
        output = []

        files = self.fs.get(self.cwd, {})
        for name in files.keys():
            output.append(name)

        for path in self.fs.keys():
            if path.startswith(self.cwd + "/"):
                dirname = path[len(self.cwd) + 1:]
                if "/" not in dirname:
                    output.append(dirname)

        if not output:
            return "\n"

        return "\n".join(sorted(set(output))) + "\n"

    def _cd(self, parts):
        if len(parts) < 2:
            return ""

        target = parts[1]

        if target == "..":
            if self.cwd != f"/home/{self.username}":
                self.cwd = "/".join(self.cwd.split("/")[:-1])
                if self.cwd == "":
                    self.cwd = f"/home/{self.username}"
            return ""

        new_path = self.cwd + "/" + target
        if new_path in self.fs:
            self.cwd = new_path
            return ""

        return f"cd: no such file or directory: {target}\n"

    def _mkdir(self, parts):
        if len(parts) < 2:
            return "mkdir: missing operand\n"

        name = parts[1]
        path = self.cwd + "/" + name

        if path in self.fs:
            return f"mkdir: cannot create directory '{name}': File exists\n"

        self.fs[path] = {}
        save_fs(self.fs)
        return ""

    def _rmdir(self, parts):
        if len(parts) < 2:
            return "rmdir: missing operand\n"

        name = parts[1]
        path = self.cwd + "/" + name

        if path not in self.fs:
            return f"rmdir: failed to remove '{name}': No such directory\n"

        if any(p.startswith(path + "/") for p in self.fs.keys()):
            return f"rmdir: failed to remove '{name}': Directory not empty\n"

        del self.fs[path]
        save_fs(self.fs)
        return ""

    def _rm(self, parts):
        if len(parts) < 2:
            return "rm: missing operand\n"

        if parts[1] == "-r":
            if len(parts) < 3:
                return "rm: missing operand\n"
            name = parts[2]
            path = self.cwd + "/" + name

            to_delete = [p for p in self.fs if p == path or p.startswith(path + "/")]
            if not to_delete:
                return f"rm: cannot remove '{name}': No such file or directory\n"

            for p in to_delete:
                del self.fs[p]

            save_fs(self.fs)
            return ""

        name = parts[1]
        files = self.fs.get(self.cwd, {})
        if name not in files:
            return f"rm: cannot remove '{name}': No such file\n"

        del files[name]
        save_fs(self.fs)
        return ""

    def _echo(self, parts):
        if ">" not in parts:
            return ""

        idx = parts.index(">")
        text = " ".join(parts[1:idx]).replace('"', "")
        filename = parts[idx + 1]

        files = self.fs.setdefault(self.cwd, {})
        files[filename] = text + "\n"
        save_fs(self.fs)
        return ""

    def _cat(self, parts):
        if len(parts) < 2:
            return ""

        filename = parts[1]
        files = self.fs.get(self.cwd, {})

        if filename not in files:
            return f"cat: {filename}: No such file\n"

        return files[filename]

    def _ifconfig(self):
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n"
            "        ether 08:00:27:aa:bb:cc  txqueuelen 1000  (Ethernet)\n"
            "        RX packets 12345  bytes 987654\n"
            "        TX packets 6789  bytes 123456\n\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\n"
        )

    def _history(self):
        out = []
        for i, cmd in enumerate(self.history, 1):
            out.append(f"{i}  {cmd}")
        return "\n".join(out) + "\n"
    
    def _ps(self, parts):
        return (
            "USER       PID %CPU %MEM COMMAND\n"
            "root         1  0.0  0.1 /sbin/init\n"
            "root       233  0.0  0.2 sshd\n"
            "www-data   412  0.1  0.3 apache2\n"
        )

    def _netstat(self, parts):
        return (
            "Proto Local Address   PID/Program\n"
            "tcp   0.0.0.0:22      233/sshd\n"
            "tcp   0.0.0.0:21      198/vsftpd\n"
            "tcp   0.0.0.0:80      412/apache2\n"
        )

    def _sudo(self, parts):
        if "-l" in parts:
            return (
                f"User {self.username} may run the following commands:\n"
                "    (ALL) NOPASSWD: ALL\n"
            )
        return "sudo: permission denied\n"

    def _df(self):
        return (
            "Filesystem      Size  Used Avail Use%\n"
            "/dev/sda1        20G   8G   11G  42%\n"
        )

    def _free(self):
        return (
            "              total   used   free\n"
            "Mem:           2048    512   1536\n"
            "Swap:          1024      0   1024\n"
        )

    def _ip(self, parts):
        if "a" in parts:
            return (
                "2: eth0: <UP> mtu 1500\n"
                "    inet 192.168.1.100/24\n"
            )
        return ""

    def _uname_a(self):
        return (
            "Linux ubuntu 5.15.0-84-generic #93-Ubuntu SMP x86_64 GNU/Linux\n"
        )
    
    def _touch(self, parts):
        if len(parts) < 2:
            return "touch: missing file operand\n"

        filename = parts[1]
        files = self.fs.setdefault(self.cwd, {})
        files.setdefault(filename, "")
        save_fs(self.fs)
        return ""

    def _chmod(self, parts):
        if len(parts) < 3:
            return "chmod: missing operand\n"

        filename = parts[-1]
        files = self.fs.get(self.cwd, {})

        if filename not in files:
            return f"chmod: cannot access '{filename}': No such file\n"

        return ""

    def _chown(self, parts):
        if len(parts) < 3:
            return "chown: missing operand\n"

        # Fake only
        return ""

    def _execute_fake(self, target):
        
        return f"{target}: Permission denied\n"


# =============================
# FTP / SSH Command Handler
# =============================
def handle_command(cmd, session):
    if "shell" not in session:
        session["shell"] = FakeShell(session.get("user", "root"))

    
    os.makedirs("logs", exist_ok=True)

    user = session.get("user", "unknown")
    ip = session.get("ip", "unknown")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(CMD_LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {ip} | {user} | {cmd}\n")

    shell = session["shell"]
    output = shell.run(cmd)

    if output == "__exit__":
        return "", True

    return output, False
