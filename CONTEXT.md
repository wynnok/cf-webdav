# cf-webdav Context

Cloudflare Workers + R2 上的 WebDAV 服务,用途是**备份专用**的加密存储端点:备份客户端(rclone / Duplicati 等)通过 WebDAV 写入密文对象,用于灾后恢复。威胁模型为:即使 R2 与 KV 全部可读,数据也不可还原(MASTER_KEY 机密不泄露)。

## Language

**备份 (Backup)**:
备份客户端经本服务写入、用于灾后恢复的数据集合。
_Avoid_: 快照、版本、备份集

**备份客户端 (Backup client)**:
通过 WebDAV 读写备份数据的第三方软件(rclone、Duplicati 等)。
_Avoid_: 用户、客户端(歧义时用全称)

**账号 (Account)**:
一组 WebDAV 凭据及其独立数据密钥、独立 R2 前缀。
_Avoid_: 用户(user)、用户记录

**账号记录 (Account record)**:
KV 中存储的单个账号的持久状态:PBKDF2 盐与哈希、被主密钥包装的数据密钥、disabled 标志。
_Avoid_: 用户表、凭据

**加密对象 (Encrypted object)**:
R2 中存储的单一对象,内容是 WDV2 分块加密 blob(密文 + 认证标签 + 经认证的总明文大小)。
_Avoid_: 文件、blob、密文文件

**数据密钥 (Data key)**:
每账号独立随机生成的 32 字节 AES-256 密钥,加密该账号全部加密对象;以被主密钥包装的形式存放于 KV。
_Avoid_: 会话密钥、文件密钥

**主密钥 (Master key / MASTER_KEY)**:
仅存在于 Worker 机密(不落任何存储)的 32 字节 AES-256 密钥,用于包装全部数据密钥。
_Avoid_: 根密钥(除非明确层级)

**目录 (Directory)**:
WebDAV 的虚拟容器。实目录以尾部 `/` 的加密空对象标记;虚目录仅由子对象前缀推导。
_Avoid_: 文件夹、collection

**完整性 (Integrity)**:
加密对象的认证标签 + 路径/块索引绑定。任何篡改在解密时被拒绝,对象即不可信。
_Avoid_: 校验和、校验(泛指)

**恢复 (Restore)**:
备份客户端从本服务下载加密对象并还原数据的过程;完整性由 GCM 认证与明文 MD5 ETag 保证,验证责任在客户端。

**恢复演练 (Restore drill)**:
定期实际执行的恢复验证流程,证明备份可用;与客户端侧自动校验不同,演练是人工定期动作。
_Avoid_: 校验(指自动验证时)、恢复测试(演练是规定动作)

**离线恢复包 (Offline recovery package)**:
由主密钥副本与导出的账号记录组成的离线凭证包;缺少它,主密钥或账号记录任一丢失都导致数据不可恢复。

**账号停用 (Disabled account)**:
账号记录带 disabled 标志后拒绝一切认证;重新启用需清除标志。
_Avoid_: 冻结、封号

**重新包装 (Rewrap)**:
用新主密钥重新加密全部数据密钥的动作,不触碰任何加密对象数据;用于主密钥轮换。
_Avoid_: 密钥轮换(单指数据密钥时)、重加密
