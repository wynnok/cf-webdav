# ADR-0001: 服务端分块 AES-256-GCM 加密

- 状态:已接受
- 日期:2026-08-12

## 背景

cf-webdav 是一个运行在 Cloudflare Workers 上的 WebDAV 服务,R2 为存储后端,用途是 WebDAV 备份。备份数据(数据库、虚拟机镜像等)高度敏感,**R2 一旦被访问即泄露全部备份**,因此仅依赖 R2 的 SSE 静态加密不够——密钥与数据同在一个账号体系内。

需求:即使 R2 被直接读取(读权限泄露、误配置、Cloudflare 侧事故),存储对象也不可还原。

## 决策

- **每个用户**持有独立的 32 字节随机数据密钥,用户数据全部用该密钥加密。
- 数据密钥被**主密钥包装**后存放在 Workers KV 用户记录中。主密钥通过 Wrangler secret(`MASTER_KEY`,64 位 hex)注入,**不落任何存储**。
- 对象加密使用 **AES-256-GCM 分块模式**:
  - 明文按固定大小(默认 4 MiB)切块,每块独立加密,便于流式读写且内存有界(单块缓冲)。
  - 每块 IV 由对象级随机 baseNonce 派生(末尾 4 字节覆盖为块索引)。
  - **AAD 绑定 `对象路径 + 块索引`**,使密文与路径/位置强绑定。
  - 认证标签 128 bit,任何篡改都会被 `SubtleCrypto.decrypt` 拒绝。
- 存储 blob 结构(自描述,头部含块大小和总明文大小):

  ```
  WDV2 | chunkSize(4B) | plaintextSize(8B) | baseNonce(12B) | [ plainLen(4B) | ciphertext+tag ] * n
  ```

  `plaintextSize` 作为每块的 AAD 一部分,使整块边界截断和伪造长度在解密时被拒绝。

- R2 custom metadata 保存明文元数据:`wdv_size`、`wdv_created`、`wdv_mtime`、`wdv_type`(file/dir)。(注意:R2 `list()` 不返回 customMetadata,PROPFIND 列表需对每个文件 `head()` 补齐元数据。)
- 目录用尾部 `/` 的加密空对象作标记;纯虚目录(从未 MKCOL 但有子文件)按前缀推导。
- 认证:Basic Auth;密码以 PBKDF2-SHA256 哈希(默认 210k 迭代)存 KV;成功认证结果按 `AUTH_CACHE_TTL_SECONDS`(默认 60s)缓存。

## 安全属性

- **R2 泄露不可读**:对象只有密文 + 无 key,数据与 key 不在同一存储。
- **完整性**:GCM 标签 + AAD 绑定路径,防篡改、防跨路径换包。
- **用户隔离**:各用户数据密钥独立,前缀 `u/<uuid>/` 隔离;一份数据密钥泄露不影响其他用户。
- **证书失窃缓解**:即使拿到 KV(用户记录)也需 MASTER_KEY 才能解开数据密钥;Master key 只存在于 Worker 机密与你的本地脚本环境。

## 权衡 / 限制

- WebCrypto 无流式 GCM,故采用分块;单请求内存约 2×块大小,128 MiB 隔离区下块大小上限约 48 MiB,默认 4 MiB 安全。
- 分块 GCM 不支持对单个分块的随机读定位到密文偏移后免解密——区间读仍会按块解密;典型备份恢复为顺序读,影响可忽略。
- `PUT` 无 `Content-Length` 时需整体缓冲明文(备份工具几乎都发送 Content-Length,该路径极少触发)。
- PROPFIND 深度 1 列表对每个文件做一次 R2 `head()`(R2 list 不返回元数据),大目录列表为 O(N) 读。
- 认证缓存意味着密码/用户变更最长延迟一个 TTL(默认 60s)生效。

## 备选方案

- **客户端(E2EE)加密**:密钥永不离开客户端,最安全;但第三方备份软件(duplicati/rclone/veeam)走 WebDAV 时无法自定义加密,故排除。
- **仅 R2 SSE**:配置简单,但密钥与数据同属一个云账号,不满足「R2 泄露不可读」。
- **整对象 GCM**:实现简单,但大文件必须整体缓冲,备份场景不可行。
