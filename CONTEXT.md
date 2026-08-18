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

**管理面 (Management surface)**:
由 Worker 提供的正式管理员界面,用于查看备份元数据和管理账号;不提供备份内容下载、解密、编辑或删除。
_Avoid_: 文件管理器、云盘

**管理员凭据 (Administrator credentials)**:
通过 Worker Secret 配置的一组管理员用户名和密码,只用于管理面登录,不与任何 WebDAV 账号共享。
_Avoid_: WebDAV 凭据、账号凭据

**管理员会话 (Administrator session)**:
管理面表单登录成功后签发的短期、签名 Cookie 会话。
_Avoid_: WebDAV 会话、Basic Auth 缓存

**备份元数据 (Backup metadata)**:
管理面可显示但不修改的备份对象信息:账号、路径、明文大小、时间和 ETag;不包含备份内容。
_Avoid_: 备份内容、文件预览

**账号移除 (Account removal)**:
危险且不可逆的管理动作:删除账号记录及该账号 R2 前缀下的全部备份对象。
_Avoid_: 账号停用、密码重置

**管理路由 (Management route)**:
管理面固定使用 `/admin` 前缀;WebDAV 保持根路径 `/`,以避免改变既有备份客户端 URL。
_Avoid_: 管理子域名、WebDAV 子路径

**跨站请求伪造令牌 (CSRF token)**:
管理面每个写操作表单携带的一次性随机令牌;服务端同时校验令牌和 Origin(同源、缺失或隐私模式下的 `null`,跨站 Origin 被拒绝),以阻止第三方站点伪造管理请求。
_Avoid_: 会话 Cookie、管理员凭据

**密码重置 (Password reset)**:
管理员为既有账号设置新密码的动作;只更新密码哈希与盐,保留账号数据密钥和全部备份对象。
_Avoid_: 账号移除、重新包装

**账号移除任务 (Account removal job)**:
可恢复的异步批处理任务:先停用目标账号,分批删除其 R2 前缀下的加密对象,全部完成后删除账号记录。
_Avoid_: 账号停用、同步删除

**管理会话上限 (Administrator session limit)**:
管理员会话 Cookie 在浏览器关闭时失效,且签名载荷强制最多存活四小时。
_Avoid_: 永久登录、WebDAV 认证缓存

**账号移除暂停 (Account removal pause)**:
停止账号移除任务的后续批处理,保留已删除的数据和当前游标;不是取消或回滚。
_Avoid_: 取消、恢复

**管理状态存储 (Management state store / ADMIN_KV)**:
与账号记录 KV 隔离的 KV 命名空间,保存管理员会话、一次性 CSRF 令牌及账号移除任务状态。
_Avoid_: ACCOUNTS_KV、通用缓存

**管理 CSRF 协调器 (Management CSRF coordinator / ADMIN_CSRF)**:
专用 Durable Object,原子消费管理员会话关联的一次性 CSRF 令牌,并在账号移除期间阻止新的 WebDAV 写操作、等待既有写操作结束;同时原子领取每分钟唯一的账号移除批次。令牌数据仍由 ADMIN_KV 设置过期。
_Avoid_: WebDAV 锁、尽力而为的 KV 删除、并发移除批次

**账号移除失败 (Account removal failure)**:
账号移除任务中单个对象删除连续失败三次后停止的状态;保留失败对象和错误摘要,等待管理员处理。
_Avoid_: 自动忽略、无限重试

**账号移除记录保留期 (Account removal record retention)**:
完成或失败的账号移除任务仅保留摘要、计数和错误信息 30 天,之后由定时任务清理。
_Avoid_: 永久审计日志、备份保留期

**移除中账号限制 (Account-removal account restriction)**:
账号移除任务运行或暂停时,禁止对该账号执行启用、停用或密码重置,以避免与不可逆删除过程冲突。
_Avoid_: 并行账号管理
