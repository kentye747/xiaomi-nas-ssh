import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .api import AdminAPI, NasError
from .bootstrap import bootstrap, inspect, recover
from .patch import patch_dropbear
from .ssh import SSHConfig, verify_ssh


def parser():
    root = argparse.ArgumentParser(description="Owner-operated Xiaomi NAS SSH tools; no telemetry.")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="Read-only checks for an existing SSH connection")
    target = verify.add_mutually_exclusive_group(required=True)
    target.add_argument("--ssh-alias")
    target.add_argument("--host")
    verify.add_argument("--identity")
    verify.add_argument("--known-hosts")
    verify.add_argument("--port", type=int, default=22)
    for name in ("inspect", "bootstrap", "cleanup"):
        command = commands.add_parser(name)
        command.add_argument("--host", required=True)
        command.add_argument("--cert-dir", required=True)
        if name == "bootstrap":
            command.add_argument("--identity", required=True)
            command.add_argument("--state-dir", default="~/.local/state/xiaomi-nas-ssh")
            command.add_argument("--port", type=int, default=22)
            command.add_argument("--apply", action="store_true")
            command.add_argument("--experimental", action="store_true")
        if name == "cleanup":
            command.add_argument("--state", required=True)
    patch = commands.add_parser("patch-copy", help="Patch a local owner-supplied binary copy, without device access")
    patch.add_argument("--input", required=True)
    patch.add_argument("--output", required=True)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "verify":
            result = verify_ssh(SSHConfig(alias=args.ssh_alias, host=args.host, identity=args.identity,
                                         known_hosts=args.known_hosts, port=args.port))
        elif args.command == "patch-copy":
            source = Path(args.input).expanduser()
            destination = Path(args.output).expanduser()
            if destination.exists() or destination.is_symlink() or source.resolve() == destination.resolve():
                raise NasError("Output must be a new file; the input is never overwritten.")
            data, result = patch_dropbear(source.read_bytes())
            with destination.open("xb") as output:
                output.write(data)
            destination.chmod(0o700)
        else:
            api = AdminAPI.from_directory(args.host, args.cert_dir)
            if args.command == "inspect":
                result = inspect(api)
            elif args.command == "bootstrap":
                result = bootstrap(api, args.identity, args.state_dir, apply=args.apply,
                                   experimental=args.experimental, port=args.port)
            else:
                result = recover(api, args.state)
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result.get("passed", True) else 1
    except NasError as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
    except Exception:
        print(json.dumps({"error": "Operation failed. Inspect inputs and private local state; raw details suppressed."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
