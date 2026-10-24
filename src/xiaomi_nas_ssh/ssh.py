"""Read-only SSH verification. Return booleans, never hostnames or raw transcripts."""
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .api import NasError, lan_ipv4


@dataclass(frozen=True, repr=False)
class SSHConfig:
    alias: str | None = None
    host: str | None = None
    identity: str | None = None
    known_hosts: str | None = None
    port: int = 22

    def arguments(self):
        if bool(self.alias) == bool(self.host):
            raise NasError("Provide one SSH alias or one LAN address.")
        args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=yes",
                "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no"]
        if not 1 <= self.port <= 65535:
            raise NasError("SSH port is outside the valid range.")
        if self.identity:
            args += ["-i", str(Path(self.identity).expanduser()), "-o", "IdentitiesOnly=yes"]
        if self.known_hosts:
            args += ["-o", "UserKnownHostsFile=" + str(Path(self.known_hosts).expanduser())]
        if self.alias:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", self.alias):
                raise NasError("Invalid SSH alias.")
            target = self.alias
        else:
            if not self.identity or not self.known_hosts:
                raise NasError("Address-based verification needs an identity and pinned known_hosts file.")
            target = "root@" + lan_ipv4(self.host)
            args += ["-p", str(self.port)]
        return args, target


def verify_ssh(config, runner=subprocess.run):
    base, target = config.arguments()
    tests = [
        ("root_identity", ["-T"], "id -u", b"", 0, b"0\n", None),
        ("command_stdout_stderr", ["-T"], "printf 'SSH_OK\\n'; printf 'SSH_ERR_OK\\n' >&2", b"", 0, b"SSH_OK\n", b"SSH_ERR_OK\n"),
        ("stdin_and_exit_status", ["-T"], "read value; printf '%s\\n' \"$value\"; exit 7", b"OWNER_INPUT\n", 7, b"OWNER_INPUT\n", b""),
        ("interactive_pty", ["-tt"], "test -t 0 && printf 'PTY_OK\\n'", b"", 0, b"PTY_OK\r\n", None),
        ("unauthenticated_rejected", ["-T", "-o", "PubkeyAuthentication=no"], "true", b"", 255, b"", b"publickey"),
    ]
    checks = {}
    for name, flags, command, data, status, stdout, stderr in tests:
        try:
            result = runner(base + flags + [target, command], input=data, capture_output=True, timeout=15)
            valid = result.returncode == status and result.stdout == stdout
            if stderr is not None:
                valid = valid and (stderr in result.stderr if name == "unauthenticated_rejected" else result.stderr == stderr)
            checks[name] = bool(valid)
        except (OSError, subprocess.TimeoutExpired):
            checks[name] = False
    return {"passed": all(checks.values()), "checks": checks}
