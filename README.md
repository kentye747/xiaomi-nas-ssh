# 小米智能存储 RP05 SSH 工具

[English](README.en.md) · [实现原理](docs/architecture.md) · [隐私与安全](SECURITY.md) · [测试范围](docs/validation.md)

面向设备所有者的小米智能存储 SSH 工具：验证真实命令执行、修复厂商菜单拦截，并提供实验性的密钥 SSH 引导流程。支持命令行和 Python 调用。

**验证密钥认证、命令输出、标准输入、退出码、PTY 和无密钥拒绝。** 只出现登录菜单或认证成功，不能算命令执行验证通过。

## 支持与验证范围

| 项目 | 状态 |
|---|---|
| 设备/固件 | RP05，`1.0.9.462.F24C26D24-REL` 的原始手动流程已实机验证 |
| `verify` | 本项目命令已对已有密钥 SSH 的实机只读验收 |
| `inspect` | mTLS 身份验证和固件/账户布局只读检查 |
| `patch-copy` | 对所有者提供的程序副本生成补丁；原文件不覆盖 |
| `bootstrap --apply --experimental` | 重构实现；**尚未在一台未解锁设备上完整重跑**，需理解实现与恢复步骤 |
| 主机环境 | Python 3.11+、现代 OpenSSL、OpenSSH；macOS/Linux，其他系统未验证 |
| 重启/固件更新 | 配置了 systemd 启动；重启与升级后的保留情况未实测 |

这个仓库没有附带任何真实设备的 IP、UID、账号、口令、证书、密钥、运行日志、照片、体检结果或固件二进制。厂商程序只在操作者自己的设备上生成独立副本。

## 安装

可在 [Releases](https://github.com/kentye747/xiaomi-nas-ssh/releases) 下载源码 ZIP、Python wheel 和 SHA-256 校验和。也可直接在自己的虚拟环境安装固定版本：

```sh
python -m pip install "git+https://github.com/kentye747/xiaomi-nas-ssh.git@v0.1.1"
```

从 GitHub 下载源码后，在项目目录运行：

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
xiaomi-nas-ssh --help
```

需要可解析 Ed25519 客户端证书的现代 OpenSSL。Mac 系统旧 Python/LibreSSL 握手失败时，请更换 Python 运行环境。不要关闭 TLS 校验来掩盖问题。

## 已经能 SSH：先做只读验证

如果本机已有配置好的 SSH 别名：

```sh
xiaomi-nas-ssh verify --ssh-alias owner-nas
```

输出为不含主机名、路径、密钥或原始远端输出的布尔结果，可用于自动化。成功退出码为 `0`，验证不通过为 `1`，输入/操作错误为 `2`。

使用地址时必须显式提供自己的私钥和已经可信固定的主机公钥文件：

```sh
# 请自行设置 NAS_HOST 为你自己的局域网 IPv4 地址。
xiaomi-nas-ssh verify --host "$NAS_HOST" \
  --identity "$HOME/.ssh/owner_nas_ed25519" \
  --known-hosts "$HOME/.ssh/owner_nas_hosts"
```

不会使用 `StrictHostKeyChecking=no` 或自动信任一次未经核对的 `ssh-keyscan` 结果。

## 第一次启用：实验性引导

只用于本人所有或已取得明确管理授权的设备。此流程修改系统设置，并可能让 SMB 共享短暂重连；请在没有备份/传输任务运行的维护窗口操作。它不处理、删除或迁移照片及其他已有用户文件。

前置条件：

1. 受支持的 RP05 固件，NAS 当前没有 SSH 监听。
2. 所有者已在小米智能存储桌面客户端登录；本机持有该客户端生成的证书、私钥和 CA 链。
3. 证书目录中有且仅有一套 `*_cert.pem`、对应的 `*_private_key.pem` 与 `ca_chain.pem`。**不要把这些文件上传给任何人。**
4. SMB 管理接口中只有一个原有账户、其 ID 为 `1`；多账户布局会拒绝自动修改。无需更改原账户名称或口令。
5. 已有 Ed25519 SSH 密钥与 `.pub` 文件；私钥带口令时，先在本机使用 `ssh-add` 加载。

```sh
# 若需要新密钥，请在本机终端交互生成，口令由你自己输入。
ssh-keygen -t ed25519 -f "$HOME/.ssh/owner_nas_ed25519"

# 请自行设置 NAS_HOST、CERT_DIR；证书目录不得提交到 Git。
xiaomi-nas-ssh inspect --host "$NAS_HOST" --cert-dir "$CERT_DIR"

# 默认只读计划，不修改设备。
xiaomi-nas-ssh bootstrap --host "$NAS_HOST" --cert-dir "$CERT_DIR" \
  --identity "$HOME/.ssh/owner_nas_ed25519"

# 理解实验性限制后才显式执行。
xiaomi-nas-ssh bootstrap --host "$NAS_HOST" --cert-dir "$CERT_DIR" \
  --identity "$HOME/.ssh/owner_nas_ed25519" \
  --state-dir "$HOME/.local/state/xiaomi-nas-ssh" \
  --apply --experimental
```

流程只接受一个私有局域网 IPv4 地址，不扫描网段。使用客户端 mTLS 证书认证、单独随机口令的临时管理共享、先解除加载钩子再执行的一次性引导，以及只接受 SSH 公钥的独立服务。**不建立无密码的网络 shell，不设置公网映射。**

成功后，本机 `state-dir` 中的 `known-hosts-*` 保存经已认证管理通道读取的主机公钥；恢复日志是 `session-*.json`，权限为 `0600`。查看自己的文件后即可按 OpenSSH 常规方式配置连接。默认输出不打印这些私人路径。

```sh
# 把 SESSION 替换为自己 state-dir 中的会话编号。
ssh -i "$HOME/.ssh/owner_nas_ed25519" \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$HOME/.local/state/xiaomi-nas-ssh/known-hosts-$SESSION" \
  "root@$NAS_HOST"
```

## 失败与恢复

失败后不要反复重跑 `bootstrap`。保留本机私有恢复日志，先检查清理状态：

```sh
xiaomi-nas-ssh cleanup --host "$NAS_HOST" --cert-dir "$CERT_DIR" \
  --state "$HOME/.local/state/xiaomi-nas-ssh/session-$SESSION.json"
```

激活阶段安排了约 240 秒后的尽力清理：未验证成功时请求回退本次 SSH 设置，再移除本次临时共享账户；成功时保留 SSH，清理临时入口。**断电、重启、网络中断或根执行未触发时，不保证自动清理完成。** 必须以管理接口回读和本机恢复状态为准。管理共享仍存在而自动清理失败时，应由所有者在 小米客户端管理界面或本地 root 通道检查并移除本次临时账户；不要删除原有账户或用户目录。

临时状态和原设置备份保留在设备的 root 专用目录，便于人工审查；现有用户文件不会被批量删除。已安装服务的回退原理及边界见 [架构文档](docs/architecture.md)。

## Python 调用

```python
from xiaomi_nas_ssh.ssh import SSHConfig, verify_ssh

result = verify_ssh(SSHConfig(alias="owner-nas"))
if not result["passed"]:
    raise RuntimeError("SSH verification failed")
```

```python
from xiaomi_nas_ssh.api import AdminAPI
from xiaomi_nas_ssh.bootstrap import bootstrap

# 使用自己的 host、cert_dir、identity、state_dir；不要打印 API 账户原始响应。
api = AdminAPI.from_directory(host, cert_dir)
plan = bootstrap(api, identity, state_dir)  # 只读；不传 apply 不会修改设备
```

## 开发与发布审查

```sh
python -m pip install .
python -m unittest discover -s tests -v
python tools/audit_release.py
```

测试使用合成数据和本地临时目录，不连接真实设备。发布前还会检查 Git 历史、构建包、提交作者及文件清单。不要把运行目录、诊断日志、证书、密钥或 NAS 配置提交到仓库。任何新的型号、固件或全新设备端到端验证都应单独记录，不能据一次成功外推兼容性。

## 来源与许可

项目代码为独立实现，MIT 许可。[NOTICE](NOTICE.md) 记录公开方法的来源和 Dropbear 相关说明。没有复制未声明许可的社区脚本，也不分发厂商固件或其程序副本。
