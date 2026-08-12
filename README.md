# cf-webdav

一款运行在 Cloudflare Workers 上的 WebDAV 服务,以 R2 为存储后端,提供**服务端加密**,用于安全备份。无服务器架构、全球边缘分发、零出站流量费。

- 多用户 + Basic Auth,用户数据按 `u/<uuid>/` 前缀隔离
- **服务端加密**:分块 AES-256-GCM,R2 里只有密文,泄露也不可读(见 [ADR-0001](docs/adr/0001-server-side-encryption.md))
- 文件 ETag 为明文 MD5,可供客户端和脚本进行确定性变更检测(见 [ADR-0002](docs/adr/0002-backup-verifiability.md))
- 完整 WebDAV 方法:OPTIONS / PROPFIND / PROPPATCH / GET / HEAD(含 Range 断点续传)/ PUT / MKCOL / DELETE / COPY / MOVE / LOCK / UNLOCK
- 为 rclone、Duplicati 和通用 WebDAV 客户端实现必要的深度、锁、multistatus 与 Range 语义

## 架构

```
WebDAV 客户端 ──Basic Auth──▶ Worker ──加密流──▶ R2(密文)
                                 │
                                 ├─ ACCOUNTS_KV  用户:PBKDF2 哈希 + 被主密钥包装的数据密钥
                                 └─ LOCKS_KV     WebDAV 锁(自动过期)
```

- 每个用户 32 字节随机**数据密钥**,用 `MASTER_KEY`(Wrangler secret)包装后存 KV
- 明文按 4 MiB 分块,每块 AES-256-GCM,IV 按块索引派生,**AAD 绑定「路径+块索引」**,防篡改、防跨路径换包
- 目录 = 尾部 `/` 的加密空对象标记;列表用 R2 `delimiter` 分页

## 部署模型:Cloudflare Workers,非 Pages

这是一个 **Cloudflare Worker** 服务,不是 Cloudflare Pages 项目。

- Worker 入口为 `src/index.ts`,由 `wrangler.jsonc` 的 `main` 字段声明。
- R2 桶、账号 KV 和锁 KV 都是 **Worker bindings**;请求在 Worker 中完成 Basic Auth、加密/解密和 WebDAV 协议处理。
- 用 `npm run deploy` 或 `npx wrangler deploy` 部署,成功后 Wrangler 会输出 `*.workers.dev` Worker URL。
- 项目不包含静态站点构建目录、`pages_build_output_dir` 或 Pages Functions。不要使用 `wrangler pages deploy`。
- 生产环境推荐在 Cloudflare Dashboard 为该 Worker 绑定 Custom Domain,再将该 HTTPS 地址配置给备份客户端。WebDAV 是 API 服务,不提供网页管理界面。

部署前可检查 Worker 构建和 bindings,不会上传任何版本:

```bash
npx wrangler deploy --dry-run
```

## 快速开始

本项目的 PBKDF2 认证和 PROPFIND 元数据读取以 **Workers Paid** 的 CPU/subrequest 配额为前提。请先确认 Worker 使用 Paid 计划；Workers Free 的 10ms CPU 与 50 次 subrequest 限额不符合 ADR-0003 的运行模型。

```bash
npm install
```

### 1. 创建资源

```bash
# R2 桶
npx wrangler r2 bucket create cf-webdav-backup
# 两个 KV namespace
npx wrangler kv namespace create ACCOUNTS_KV
npx wrangler kv namespace create LOCKS_KV
# 把输出的 id 填进 wrangler.jsonc 的对应字段
```

### 2. 主密钥(机密)

```bash
# 生成 32 字节(64 hex)
openssl rand -hex 32
# 注入为 secret(本地开发用 .dev.vars 里的 MASTER_KEY)
npx wrangler secret put MASTER_KEY
```

> **保管好 MASTER_KEY**:丢失后所有用户数据无法解密;泄露则加密失效。

### 3. 创建用户

```bash
# 用与生产相同的 MASTER_KEY 生成用户记录,并按提示写入 KV
MASTER_KEY=<64hex> npm run user:create -- alice 'your-strong-password'

# 预创建但停用账号(清除 KV 记录中的 disabled 后才可认证)
MASTER_KEY=<64hex> npm run user:create -- --disabled alice 'your-strong-password'
```

### 4. 部署

```bash
# 部署 Cloudflare Worker
npm run deploy
```

部署后做最小验收:

```bash
# Worker URL 以实际 wrangler 输出为准
curl -i -X OPTIONS https://YOUR_WORKER.workers.dev/
# 预期:401 和 WWW-Authenticate: Basic;说明请求已到达 Worker
```

配置账号后,用 WebDAV 客户端或下列请求验证认证和 DAV 能力:

```bash
curl -i -X OPTIONS \
  -u 'ACCOUNT:PASSWORD' \
  https://YOUR_WORKER.workers.dev/
# 预期:200、DAV: 1, 2 和 Allow 响应头
```

不要将真实密码、`MASTER_KEY` 或导出的账号记录放进 shell 历史、脚本或版本库。对生产验收,优先使用 rclone/duplicati 的安全凭据存储机制。

### 5. 客户端配置

**rclone**:

```ini
[cfwebdav]
type = webdav
vendor = other
url = https://cf-webdav.your-domain.workers.dev/
user = alice
pass = <rclone 加密后的密码>
```

**Duplicati**:目标选择 WebDAV,服务器填 Worker URL,路径留空或 `/backup`,提供用户名密码,加密选项选「AES-256」(Duplicati 自带)或「无」(本服务已加密)。

## 备份客户端与单文件上限

Cloudflare 会在 Worker 前拒绝超过账号 plan 请求体上限的请求:Free/Pro 为 100 MB、Business 为 200 MB、Enterprise 默认 500 MB。本服务会对带 `Content-Length` 的 PUT 提前返回 413,上限来自 `MAX_PUT_BYTES`，**必须配置为不大于你的 Cloudflare 账号实际上限**。

- Duplicati 使用远程块上传时,将其远程块大小配置在上限以下;不要把块大小调到 Cloudflare 请求体上限以上。
- rclone 的 `webdav` + `vendor = other` 会整文件 PUT;大于上限的单文件需要在源端分割、换用支持块级上传的备份工具,或提高 Cloudflare 账号 plan。
- rclone 的纯 WebDAV `vendor = other` 不支持服务端哈希校验;明文 MD5 ETag 仍可供自定义脚本或支持 ETag 的客户端进行变更检测。Duplicati 应使用自身的 verify 流程。

## 安全说明

- **R2 泄露不可读**:对象只有密文;数据密钥只以被 `MASTER_KEY` 包装的形式存于 KV。
- **认证**:密码 PBKDF2-SHA256 哈希存 KV(默认 210k 迭代),认证结果缓存 `AUTH_CACHE_TTL_SECONDS`(默认 60s)。
- **账号停用**:账号记录里的 `disabled: true` 会在下一次请求时拒绝认证;认证前总会读取当前账号记录。
- **传输安全**:所有响应带 `Cache-Control: no-store`,防止边缘缓存解密数据;请务必在 Worker 上启用 HTTPS(默认)。
- **完整性**:GCM 标签 + AAD 路径绑定,解密时校验,篡改即报错;文件 ETag 是明文 MD5,用于内容级变更检测。
- **限流与审计**:在 Cloudflare 面板为入口配置 Rate Limiting(至少限制失败 Basic Auth);通过 Workers Logs 记录方法、账号、路径与状态。不要记录 Authorization、密码、MASTER_KEY 或完整备份内容。

## 配置项(wrangler.jsonc `vars` / secrets)

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `MASTER_KEY`(secret) | — | 32 字节 hex,主密钥 |
| `CHUNK_SIZE_MB` | 4 | 加密分块大小(1–48 的整数;默认值是 128 MiB Worker 内存限制下的安全折中) |
| `PBKDF2_ITERATIONS` | 210000 | 密码哈希迭代 |
| `AUTH_CACHE_TTL_SECONDS` | 60 | 认证结果缓存 TTL |
| `PROPFIND_MAX_ENTRIES` | 5000 | 单次 PROPFIND 条目上限 |
| `LOCK_TIMEOUT_SECONDS` | 3600 | 锁默认超时 |
| `MAX_PUT_BYTES` | 524288000 | 单次 PUT 上限(须不大于 Cloudflare 账号 plan 上限) |

## 离线恢复包与密钥轮换

离线恢复包由两部分组成:**MASTER_KEY 的离线副本**与**账号记录导出文件**。二者任何一个丢失,都可能使数据无法恢复。账号记录虽然不含明文数据密钥,但包含被主密钥包装的数据密钥,必须加密保存且不得提交到版本库。

```bash
# 从生产 KV 导出全部 users/* 账号记录;文件会以 0600 权限创建
npm run accounts:export -- accounts-export.json

# 轮换主密钥:离线重新包装账号记录,不重加密 R2 数据
OLD_MASTER_KEY=<old-64hex> NEW_MASTER_KEY=<new-64hex> \
  npm run accounts:rewrap -- accounts-export.json accounts-rewrapped.json

# 在维护窗口暂停备份，审查并执行生成的 accounts-rewrapped.json.apply.sh，然后切换 Worker 的 MASTER_KEY
# 当前版本不支持双主密钥过渡，两个步骤之间账号会暂时不可用
```

保存旧主密钥和原导出文件,直到使用新密钥完成一次恢复演练。账号记录导出脚本通过 Wrangler 读取 KV,因此应只在受信任的本机运行。

## 运维与恢复演练

- 本服务使用**单区域 R2**,且不启用桶版本化:WebDAV 的 DELETE/覆盖写是真删,让 Duplicati 等客户端的保留策略保持真实语义。它是异地副本,**不能是唯一副本**。
- 不设服务端账号配额。通过 R2 面板监控存储量、Class A/B 操作数及账单,并按 [R2 定价](https://developers.cloudflare.com/r2/pricing/) 预估成本。
- KV 锁是最终一致的,部署假设是**同一账号的备份任务由客户端调度错开,不并发写同一目标路径**。
- 至少每月进行一次恢复演练:使用 Duplicati `verify` 或下载一个代表性备份集,在隔离位置实际还原并打开数据;同时确认离线恢复包可读取、主密钥副本可用。

## 开发与测试

```bash
npm run dev        # wrangler dev 本地预览
npm run typecheck  # tsc --noEmit
npm test           # vitest + miniflare 全量测试
npx wrangler deploy --dry-run  # 校验 Worker 打包与 bindings,不上传
```

测试覆盖:加密往返/篡改检测/路径绑定/密钥包装/区间读、认证、全部 WebDAV 方法、R2 密文落盘校验。

## 限制

- 单 Worker 内存上限(128 MiB)约束分块大小;默认 4 MiB 是安全折中。受 Cloudflare 请求体上限约束的单文件 PUT 见上文。
- `PUT` 无 `Content-Length` 时会缓冲明文(备份工具几乎总是带 Content-Length)。
- 密码哈希或被包装数据密钥变更会使认证缓存键失效;账号停用在下一次请求时生效。
- `LOCK` 为独占语义,`shared` 按独占处理。
- 已部署的 WDV1 加密对象与当前 WDV2 格式不兼容。当前项目尚未生产部署;若未来需要格式迁移,必须在部署前设计读取兼容或离线迁移流程。
