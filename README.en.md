# Xiaomi Smart Storage RP05 SSH tools

[中文说明](README.md) · [Architecture](docs/architecture.md) · [Security](SECURITY.md)

Owner-operated CLI/Python tools for verifying real SSH command execution and preparing a key-only SSH service on the reviewed RP05 firmware.

The original manual method worked on RP05 firmware `1.0.9.462.F24C26D24-REL`. The packaged read-only SSH verifier has also been run on an already configured device. **The refactored experimental bootstrap has not been replayed end-to-end on a clean, locked device.** Reboot/update persistence and other firmware versions are not verified.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
xiaomi-nas-ssh verify --ssh-alias owner-nas
```

The verifier checks root identity, stdout/stderr, stdin, a deliberate exit code, PTY, and rejection without a key. Results contain booleans rather than personal device transcripts. It enforces host-key checking.

For first-time setup, obtain your **own** authenticated desktop client's certificate directory and an Ed25519 identity. Set `NAS_HOST` and `CERT_DIR` locally. `inspect` and a bootstrap without `--apply` are read-only:

```sh
xiaomi-nas-ssh inspect --host "$NAS_HOST" --cert-dir "$CERT_DIR"
xiaomi-nas-ssh bootstrap --host "$NAS_HOST" --cert-dir "$CERT_DIR" \
  --identity "$HOME/.ssh/owner_nas_ed25519"
```

Actual changes require both `--apply` and `--experimental`. Read the [Chinese workflow and recovery details](README.md) first. Setup is restricted to one LAN address, one supported firmware and the reviewed single-account layout. Adding/repairing a temporary Samba account may briefly reconnect shares; use a maintenance window without active backups or transfers. It never formats disks, downgrades firmware or deletes existing user files.

The vendor program forces sessions into its menu shell. This tool edits one shell-path constant in a **separate owner-local binary copy**, and runs that copy with key-only authentication bound to the NAS LAN address. No firmware binary is distributed. The temporary root execution primitive disarms its loader before forking. No unauthenticated network shell is opened.

Recovery state is owner-only and local. A best-effort delayed cleanup is not a substitute for checking the temporary account was actually removed. Power loss, reboot, network failure or failure to obtain root execution may require manual owner recovery. Existing SSH listeners, loader configuration and unexpected layouts are refused.

```python
from xiaomi_nas_ssh.ssh import SSHConfig, verify_ssh
result = verify_ssh(SSHConfig(alias="owner-nas"))
```

The repository contains no real device addresses, IDs, credentials, certificates, keys, transcripts, personal files or vendor executables. Do not attach them to issues. Source is MIT licensed; public methodology references and third-party boundaries are in [NOTICE](NOTICE.md).

## v0.2.0 safety verification

Recovery journals are atomically replaced, owner-only, and protected by a local operation lock. Staged helper/configuration fingerprints are checked before recovery. A device-side lock serializes install, commit, cleanup and watchdog actions. Commit is acknowledged through verified SSH; SSH is checked again after cleanup. Root-field changes and archive conflicts are preserved for manual review. Failed rollback never creates a cleanup success marker.

Use one operator and the same private state directory per device. An unfinished session blocks another install. Older unfinished journals without helper fingerprints require manual review; do not discard journals to bypass this refusal. An absent temporary account does not establish rollback success.

Install `.[test]` for loopback mTLS tests and Unicorn AArch64 emulation. All syscall outcomes are synthetic and intercepted; no emulator operation touches host loader/account files. Controller/helper integration uses temporary trees and fakes the management, SMB, SSH, kernel and service-command boundaries. A real SMB server, firmware bootstrap, ELF dynamic loading, reboot and power loss remain unverified.
