"""Self-contained root-side helpers, staged by the owner. No import-time effects."""
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

INSTALL = Path("/data/xiaomi-nas-ssh")
HOME = Path("/home/xiaomi-nas-ssh")
UNIT = Path("/etc/systemd/system/xiaomi-key-ssh.service")
PASSWD = Path("/etc/passwd")


def run(args, check=True):
    return subprocess.run(args, capture_output=True, timeout=25, check=check)


def atomic_bytes(path, value, mode=0o600):
    temporary = path.with_name(path.name + ".new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    os.fchmod(fd, mode)
    with os.fdopen(fd, "wb") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def patch_binary(data):
    marker = b"/usr/sbin/mi-shell\0"
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01" or struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError("unsupported_elf")
    if data.count(marker) != 1:
        raise ValueError("unsupported_shell_constant")
    return data.replace(marker, b"/bin/sh\0".ljust(len(marker), b"\0"))


def root_line():
    return next(x for x in PASSWD.read_text().splitlines() if x.startswith("root:"))


def replace_root(value):
    lines = [value if x.startswith("root:") else x for x in PASSWD.read_text().splitlines()]
    atomic_bytes(PASSWD, ("\n".join(lines) + "\n").encode(), 0o644)


def install(config, stage):
    if any(p.exists() for p in (INSTALL, HOME, UNIT)):
        raise ValueError("existing_installation_refused")
    before = root_line()
    fields = before.split(":")
    if len(fields) != 7 or fields[0] != "root" or fields[2:4] != ["0", "0"] or fields[5:] != ["/root", "/usr/sbin/mi-shell"]:
        raise ValueError("unexpected_root_account")
    data = Path("/usr/sbin/dropbearmulti").read_bytes()
    modified = patch_binary(data)
    public = config["public_key"]
    parts = public.split()
    if len(parts) != 2 or parts[0] != "ssh-ed25519":
        raise ValueError("unsupported_public_key")
    decoded = base64.b64decode(parts[1], validate=True)
    if len(decoded) != 51 or decoded[:19] != b"\0\0\0\x0bssh-ed25519\0\0\0\x20":
        raise ValueError("invalid_public_key")
    INSTALL.mkdir(mode=0o700)
    atomic_bytes(INSTALL / "setup-token", config["token"].encode())
    atomic_bytes(INSTALL / "root.before", before.encode())
    atomic_bytes(INSTALL / "stage-path", str(stage).encode())
    (HOME / ".ssh").mkdir(parents=True, mode=0o700)
    HOME.chmod(0o700)
    existing = Path("/root/.ssh/authorized_keys")
    previous = existing.read_bytes() if existing.is_file() else b""
    keys = previous + (b"\n" if previous and not previous.endswith(b"\n") else b"") + public.encode() + b"\n"
    atomic_bytes(HOME / ".ssh/authorized_keys", keys)
    atomic_bytes(INSTALL / "dropbear", modified, 0o700)
    fields[5] = str(HOME)
    replace_root(":".join(fields))
    key = INSTALL / "host_key"
    run(["dropbearkey", "-t", "ed25519", "-f", str(key)])
    key.chmod(0o600)
    public_lines = run(["dropbearkey", "-y", "-f", str(key)]).stdout.decode().splitlines()
    host_key = next(" ".join(x.split()[:2]) for x in public_lines if x.startswith("ssh-ed25519 "))
    unit = ("[Unit]\nDescription=Owner key-only Xiaomi NAS SSH\nAfter=network-online.target\n"
            "Wants=network-online.target\nConflicts=dropbear.socket\n\n[Service]\nType=simple\n"
            f"ExecStart={INSTALL}/dropbear -F -E -s -B -j -k -G root -r {key} "
            f"-p {config['host']}:{config['port']} -P /run/xiaomi-key-ssh.pid\n"
            "Restart=on-failure\nRestartSec=5\nKillMode=process\n\n[Install]\nWantedBy=multi-user.target\n")
    atomic_bytes(UNIT, unit.encode(), 0o644)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", UNIT.name])
    atomic_bytes(INSTALL / "binary-manifest.json", json.dumps({
        "original_sha256": hashlib.sha256(data).hexdigest(),
        "patched_sha256": hashlib.sha256(modified).hexdigest(),
    }).encode())
    atomic_bytes(stage / "status.json", json.dumps({"ready": True, "host_public_key": host_key}).encode())


def rollback(config):
    marker = INSTALL / "setup-token"
    if not marker.exists() or marker.read_text() != config["token"]:
        return
    before = INSTALL / "root.before"
    if before.exists():
        current = root_line().split(":")
        # Preserve subsequent changes to unrelated accounts and refuse an unexpected root home.
        original_fields = before.read_text().split(":")
        expected = original_fields.copy()
        expected[5] = str(HOME)
        if current not in (expected, original_fields):
            raise ValueError("root_account_changed_requires_manual_review")
        if current == expected:
            replace_root(before.read_text())
    if UNIT.exists():
        run(["systemctl", "disable", "--now", UNIT.name])
    archive = INSTALL / "rollback-archive"
    archive.mkdir(mode=0o700, exist_ok=True)
    if UNIT.exists():
        if (archive / UNIT.name).exists():
            raise ValueError("rollback_archive_conflict")
        shutil.move(str(UNIT), str(archive / UNIT.name))
    if HOME.exists():
        if (archive / "root-home").exists():
            raise ValueError("rollback_archive_conflict")
        shutil.move(str(HOME), str(archive / "root-home"))
    run(["systemctl", "daemon-reload"])


@contextmanager
def action_lock(stage):
    fd = os.open(stage / "action.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise ValueError("unsafe_action_lock")
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def is_committed(stage):
    marker = stage / "committed"
    if marker.is_symlink():
        raise ValueError("unsafe_commit_marker")
    if not marker.exists():
        return False
    if not marker.is_file() or marker.read_bytes() != b"verified\n":
        raise ValueError("unsafe_commit_marker")
    return True


def commit(config, stage):
    if (not (INSTALL / "setup-token").exists()
            or (INSTALL / "setup-token").read_text() != config["token"]
            or root_line().split(":")[5] != str(HOME) or not UNIT.is_file()):
        raise ValueError("installation_no_longer_active")
    run(["systemctl", "is-active", "--quiet", UNIT.name])
    atomic_bytes(stage / "committed", b"verified\n")


def cleanup(config, stage, undo=False):
    rollback_failed = False
    if undo:
        try:
            rollback(config)
        except Exception:
            rollback_failed = True
    loader = Path("/etc/ld.so.preload")
    if loader.exists():
        if loader.read_text() != str(stage / "trigger.so") + "\n":
            raise ValueError("foreign_loader_refused")
        loader.rename(stage / "preload.disarmed-by-cleanup")
    section = "u" + config["uid"] + "_2"
    account = run(["uci", "-q", "get", "sambauser." + section + ".name"], check=False)
    share_path = run(["uci", "-q", "get", "sambashare." + section + ".path"], check=False)
    if account.returncode not in (0, 1) or share_path.returncode not in (0, 1):
        raise ValueError("account_state_unavailable")
    if account.returncode == 0 or share_path.returncode == 0:
        if account.returncode != 0 or account.stdout.strip() != ("u" + config["uid"]).encode():
            raise ValueError("foreign_samba_account_refused")
        if share_path.returncode != 0 or share_path.stdout.strip() != b"/etc":
            raise ValueError("unexpected_share_path_refused")
        for kind in ("sambashare", "sambauser"):
            run(["uci", "-q", "delete", kind + "." + section])
            run(["uci", "-q", "commit", kind])
        for key in ("sambauser." + section + ".name", "sambashare." + section + ".path"):
            if run(["uci", "-q", "get", key], check=False).returncode != 1:
                raise ValueError("temporary_account_removal_not_verified")
        run(["/usr/bin/smb_mgr.sh", "user", "delete", "u" + config["uid"]])
        run(["/usr/bin/smb_mgr.sh", "reload"])
    source = Path("/home/u" + config["uid"] + "/pool0/data") / config["directory_name"]
    if source.is_symlink():
        raise ValueError("symlink_staging_directory_preserved")
    if source.is_dir():
        if any(source.iterdir()):
            raise ValueError("nonempty_staging_directory_preserved")
        # Preserve the empty directory outside the user share rather than delete anything.
        archive = Path("/data/xiaomi-nas-ssh-cleanup") / config["token"]
        archive.mkdir(parents=True, mode=0o700, exist_ok=True)
        if (archive / "empty-staging").exists():
            raise ValueError("cleanup_archive_conflict")
        shutil.move(str(source), str(archive / "empty-staging"))
    if rollback_failed:
        raise ValueError("temporary_account_removed_rollback_requires_review")
    atomic_bytes(stage / "cleanup-complete", b"ok\n")


def main():
    if len(sys.argv) != 3:
        raise SystemExit(2)
    config_path = Path(sys.argv[1])
    if config_path.name != "config.json" or config_path.is_symlink():
        raise SystemExit(2)
    stage = config_path.parent
    if os.getuid() != 0 or not re.fullmatch(r"/etc/\.nas-ssh-[0-9a-f]{12}", str(stage)):
        raise SystemExit(2)
    stage.chmod(0o700)
    config = json.loads(config_path.read_text())
    if not re.fullmatch(r"[0-9]+", config["uid"]) or config["token"] != stage.name.removeprefix(".nas-ssh-"):
        raise SystemExit(2)
    uid = config["uid"]
    expected_directory = ("N" * 30 + '\n"\n' + f"set sambashare.u{uid}_2.user_force=root\n"
                          f"set sambashare.u{uid}_2.create_mask=0644\n"
                          f"set sambashare.u{uid}_2.path=etc\n"
                          f"set sambashare.u{uid}_2.comment=")
    if config["directory_name"] != expected_directory:
        raise SystemExit(2)
    host = ipaddress.IPv4Address(config["host"])
    if not any(host in ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
        raise SystemExit(2)
    if type(config["port"]) is not int or not 1 <= config["port"] <= 65535:
        raise SystemExit(2)
    with action_lock(stage):
        dispatch(config, stage, sys.argv[2])


def dispatch(config, stage, action):
    try:
        if action == "install":
            install(config, stage)
        elif action == "commit":
            commit(config, stage)
        elif action == "recover":
            # Decide under the device lock, after any pending SSH commit finishes.
            cleanup(config, stage, undo=not is_committed(stage))
        elif action == "watchdog":
            if not (stage / "cleanup-complete").exists():
                cleanup(config, stage, undo=not is_committed(stage))
        elif action in ("cleanup", "rollback"):
            cleanup(config, stage, undo=action == "rollback")
        else:
            raise ValueError("unknown_action")
    except Exception:
        # Raw errors/configuration must remain on the owner's device, not in public diagnostics.
        if action == "install":
            try:
                rollback(config)
            except Exception:
                pass
            if not (stage / "status.json").exists():
                atomic_bytes(stage / "status.json", b'{"ready":false,"error":"install_failed"}')
        raise SystemExit(1)


if __name__ == "__main__":
    main()
