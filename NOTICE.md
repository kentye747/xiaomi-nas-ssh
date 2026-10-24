# Attribution and redistribution boundaries

This repository independently implements its Python client, safety checks, one-shot ELF generator, owner-local installer, verifier and tests. The project license applies to those files, not to Xiaomi firmware or other third-party software.

Public methodology and prior work:

- [lvmaple/minas_plugin: firmware 1.0.9.462 root-tool research](https://github.com/lvmaple/minas_plugin/tree/main/xiaomi-nas-root-tool-1.0.9.462): authenticated client-certificate access, newline/UCI temporary-share technique and root execution concept.
- [scruel/xiaomi-storage-minas-tool](https://github.com/scruel/xiaomi-storage-minas-tool) and its [firmware compatibility discussion](https://github.com/scruel/xiaomi-storage-minas-tool/issues/1): earlier owner-enablement workflow and patch history.
- [Dropbear](https://github.com/mkj/dropbear), including the [2022.83 authentication](https://github.com/mkj/dropbear/blob/DROPBEAR_2022.83/svr-auth.c), [session execution](https://github.com/mkj/dropbear/blob/DROPBEAR_2022.83/svr-chansession.c) and [license](https://github.com/mkj/dropbear/blob/DROPBEAR_2022.83/LICENSE) sources, were consulted to analyze behavior.
- [Linux generic syscall definitions](https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/unistd.h) document the AArch64 syscall numbers used by the generated initializer.

No third-party root-tool script, Xiaomi app archive, client certificate, CA chain, extracted firmware, Dropbear executable or modified firmware binary is included. If you independently redistribute any such binary, determine and meet its applicable third-party obligations. The local copy transformation changes one constant; it does not replace Xiaomi's original program or alter the SSH cryptographic implementation.

References are attribution and technical context, not endorsement. Testing described here is limited to the scope stated in the validation document.
