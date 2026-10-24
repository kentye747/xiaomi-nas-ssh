# Contributing

Use synthetic data and temporary directories. Tests must not connect to a real NAS or modify real accounts, services or storage.

Run `python -m unittest discover -s tests -v` and `python tools/audit_release.py` before committing. A development machine with clang also compares generated AArch64 instructions against an independent assembler.

Do not commit certificates, keys, account responses, recovery journals, firmware executables, real NAS identifiers, local file paths or live transcripts. Do not attach screenshots showing personal information. A compatibility report should contain only the model, firmware, tool version and sanitized boolean checks, and must distinguish an already-enabled device from a clean-device bootstrap.

Preserve existing users' keys and accounts; treat unknown state as unknown. Do not broaden supported firmware based on a guessed binary offset. New destructive operations, network scanning, unauthenticated listeners and credential export are outside the project scope.

Project source is MIT licensed. Attribute original public methodology without copying code whose redistribution license has not been established.
