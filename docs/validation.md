# Validation scope

## Observed on an owner-authorized device

- RP05 firmware `1.0.9.462.F24C26D24-REL`.
- Original staged method obtained authenticated management access, installed key-only SSH, and removed temporary entry points.
- Menu-only authentication was rejected as insufficient during verification.
- An owner-local independent executable copy ran normal commands with correct stdin, stdout, stderr, exit status and PTY.
- This repository's packaged read-only verifier passed on the existing SSH service.
- The local patcher output was compared privately with the working copy, without uploading either binary or the device transcript.

No real NAS address, UID, hostname, serial, key, fingerprint, certificate, account, private path or transcript is published as test data.

## Automated checks

Synthetic ELF mutation checks cover exact byte range, architecture guards, duplicate/missing marker refusal and agreement of local/device patchers. SSH tests reject a menu-only session, validate standard streams and deliberate exit status, enforce host-key checking, and suppress sensitive errors. Bootstrap guards cover read-only defaults, explicit experimental apply, firmware/account layout, existing listeners, ambiguous port timeouts, loader exclusivity, private state permissions, scope validation and recovery input.

The generated initializer is checked for ELF architecture, branch targets, string targets and disarm-before-fork ordering. Tests do not touch a real `/etc`, system service, user account or NAS.

## Not established

- Refactored bootstrap end-to-end on a clean locked device.
- Reboot/firmware-update persistence.
- Other firmware/model compatibility.
- Guaranteed cleanup after power loss, reboot, network failure or failure to trigger root execution.
- Windows/native GUI operation.

New observations should be recorded without personal data and without broadening these claims based only on unit-test success.

## v0.2.0 isolated verification

- The real controller and root helper run together against a temporary filesystem. Management API, encrypted SMB, SSH, kernel activation and OS/service commands are simulated boundaries. Existing synthetic backup bytes and original account records are checked after each scenario.
- Faults cover host-key generation, command verification, interruption, watchdog-before-commit, UCI deletion, extra accounts, SMB connection failure, staging collision, missing root execution, lost commit acknowledgement and post-cleanup verification failure.
- Real loopback TLS uses ephemeral synthetic CA/server/client keys. Successful mutual authentication, wrong server identity, missing client certificate and read-only planning are checked. No real certificates are fixtures.
- [Unicorn](https://www.unicorn-engine.org/docs/tutorial.html) executes the generated AArch64 instructions. Every syscall is intercepted: UID gates, failed atomic claim, parent return, clone failure, child argv/envp and failed-exec exit. The existing independent clang assembler comparison remains. This does not test a real kernel or the vendor dynamic loader.
- Local atomic replacement failure preserves the previous journal; hardlink/symlink guards, concurrent operation refusal and device-lock serialization across processes are checked.

No test restarts a real NAS service, creates a real NAS account/share/preload, reboots the device, writes to existing NAS files or changes backups. SMB wire-protocol compatibility and clean-device first activation remain experimental.
