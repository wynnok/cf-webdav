# cf-webdav

`cf-webdav` 是一个运行在 **Cloudflare Workers** 上的加密 WebDAV 服务。它以 Cloudflare R2 为存储后端，供 rclone、Duplicati 等备份客户端写入和恢复数据。

> 这是 Cloudflare **Workers** 项目，不是 Cloudflare Pages 项目。WebDAV 位于根路径 `/`，管理员界面位于 `/admin`；不要使用 `wrangler pages deploy`。

## 特性

- 多账号 Basic Auth 认证，账号数据按 `u/<uuid>/` 前缀隔离。
- 每个账号使用独立数据密钥，R2 中只保存密文。
- WDV2 分块 AES-256-GCM 加密格式，总明文大小、对象路径和分块索引均受认证保护。
- 文件 ETag 使用明文 MD5，可用于确定性变更检测。
- 支持 `OPTIONS`、`PROPFIND`、`GET`、`HEAD`、`PUT`、`MKCOL`、`DELETE`、`COPY`、`MOVE`、`PROPPATCH`、`LOCK` 和 `UNLOCK`。
- 支持 Range 读取；响应前会认证完整加密对象，检测篡改与整块边界截断。
- `/admin` 提供账号生命周期管理及只读备份元数据浏览，不提供备份内容下载、解密、预览或对象删除。
- 提供账号记录导出和主密钥重新包装脚本。

## 架构

```text
WebDAV 备份客户端
        │ Basic Auth／HTTPS
        ▼
Cloudflare Worker
        ├── ACCOUNTS_KV：账号记录、密码哈希、被包装的数据密钥
        ├── LOCKS_KV：临时 WebDAV 锁
        ├── ADMIN_KV：管理员会话、CSRF 令牌、账号移除任务
        ├── ADMIN_CSRF Durable Object：原子消费 CSRF 令牌、协调移除与写入
        └── R2 Bucket：WDV2 加密对象
```

- `MASTER_KEY` 是仅存在于 Worker Secret 中的 32 字节主密钥。
- 每个账号有独立的 32 字节数据密钥。数据密钥经 `MASTER_KEY` 包装后保存在 `ACCOUNTS_KV`。
- 文件按默认 4 MiB 分块进行 AES-256-GCM 加密；目录使用尾部 `/` 的加密空对象标记。
- 本服务设计为备份专用端点。R2 是异地副本，不应成为唯一备份副本。

更多安全与运维决策见：

- [ADR-0001：服务端分块 AES-256-GCM 加密](docs/adr/0001-server-side-encryption.md)
- [ADR-0002：备份可验证性与明文 MD5 ETag](docs/adr/0002-backup-verifiability.md)
- [ADR-0003：运维与韧性模型](docs/adr/0003-operations-model.md)

## 部署方式

推荐完全通过 **Cloudflare Dashboard＋GitHub 集成** 部署。你不需要安装 Cloudflare 桌面应用，也不需要在本机登录 Wrangler。

部署会由 Cloudflare Workers Builds 自动完成：每次推送到 GitHub `main` 分支后，Cloudflare 从仓库读取 `wrangler.jsonc`，构建并部署 Worker。

部署前提：

- Cloudflare 账户已启用 **Workers Paid**。
- 可访问 GitHub 仓库 `wynnok/cf-webdav`。
- 有一个可用于 Worker 的名称，例如 `cf-webdav`。

Workers Free 的 10 ms CPU 和 50 次 subrequest 限额不符合本项目的 PBKDF2 认证与目录 PROPFIND 模型。

## 网页控制台部署教程

### 1．创建 R2 Bucket

在 Cloudflare Dashboard 中进入 **R2 Object Storage**，创建一个私有 Bucket：

| 用途 | Bucket 名称 |
| --- | --- |
| 生产数据 | `cf-webdav-r2` |

可按主要访问地区选择 Location Hint，例如亚太选择 `APAC`。不要开启公开访问，也不要开启对象版本化。

### 2．创建 KV Namespace

在 **Workers & Pages → KV** 中创建以下三个 Namespace：

| 用途 | Namespace 名称 |
| --- | --- |
| 账号记录 | `cf-webdav-accounts-kv` |
| WebDAV 锁 | `cf-webdav-locks-kv` |
| 管理状态 | `cf-webdav-admin-kv` |

打开每个 Namespace 的详情页，复制其 Namespace ID。

### 3．在 GitHub 中填写资源 ID

本项目使用 `wrangler.jsonc` 声明 Worker bindings。打开 GitHub 仓库中的 [`wrangler.jsonc`](wrangler.jsonc)，通过网页编辑器替换以下占位符：

| 配置字段 | 填写内容 |
| --- | --- |
| `ACCOUNTS_KV.id` | `cf-webdav-accounts-kv` 的 ID：`b46bf22fe2b042cd899593052e0da7b0` |
| `LOCKS_KV.id` | `cf-webdav-locks-kv` 的 ID：`565759437af24a679af98a656e98a799` |
| `ADMIN_KV.id` | `cf-webdav-admin-kv` 的 ID：`074a6dee1be849b994fcd3d150105d7c` |

当前仓库已配置生产 Bucket `cf-webdav-r2`：

```jsonc
"bucket_name": "cf-webdav-r2"
```

通过 GitHub 提交该配置修改到 `main`。不要将主密钥、账号密码或账号导出文件提交到 GitHub。

`wrangler.jsonc` 同时声明了 `ADMIN_CSRF` SQLite Durable Object 及其首次 migration。Workers Builds 执行 `npx wrangler deploy` 时会自动应用该 migration；Free 计划必须使用 `new_sqlite_classes`，不要删除或手动修改已有 migration tag。

### 4．导入 GitHub 仓库并创建 Worker

在 Cloudflare Dashboard：

1. 进入 **Workers & Pages**。
2. 点击 **Create application**。
3. 选择 **Import a repository**，不要选择 Pages。
4. 连接 GitHub，并授权 Cloudflare Workers Builds 访问 `wynnok/cf-webdav`。
5. 选择仓库 `wynnok/cf-webdav`。
6. Worker 名称填写 `cf-webdav`。该名称必须与 `wrangler.jsonc` 的 `name` 一致。
7. 生产分支选择 `main`。
8. 设置构建配置：

| 配置项 | 值 |
| --- | --- |
| Root directory | 留空，即仓库根目录 |
| Build command | `npm ci && npm run typecheck && npm test` |
| Deploy command | `npx wrangler deploy` |

9. 点击 **Save and Deploy**。

部署完成后，Cloudflare 会提供类似 `https://cf-webdav.<account>.workers.dev` 的 Worker URL。

### 5．配置 Worker Secret 和环境变量

进入：

```text
Workers & Pages → cf-webdav → Settings → Variables and Secrets
```

添加以下普通环境变量：

| 名称 | 默认值 | 说明 |
| --- | ---: | --- |
| `CHUNK_SIZE_MB` | `4` | 加密分块大小，只能是 1 到 48 的整数 |
| `PBKDF2_ITERATIONS` | `210000` | PBKDF2-SHA256 迭代次数 |
| `AUTH_CACHE_TTL_SECONDS` | `60` | 认证缓存 TTL |
| `PROPFIND_MAX_ENTRIES` | `5000` | 单次 PROPFIND 最大条目数 |
| `LOCK_TIMEOUT_SECONDS` | `3600` | WebDAV 锁默认超时秒数 |
| `MAX_PUT_BYTES` | 见下表 | 单次 PUT 应用层上限 |

`MAX_PUT_BYTES` 必须不大于 Cloudflare 账号请求体上限：

| Cloudflare 账户计划 | 建议 `MAX_PUT_BYTES` |
| --- | ---: |
| Free／Pro | `104857600`（100 MiB） |
| Business | `209715200`（200 MiB） |
| Enterprise | `524288000`（500 MiB） |

然后新增以下 **Secret**：

| 名称 | 值 |
| --- | --- |
| `MASTER_KEY` | 32 字节、64 位 hex 随机密钥 |
| `ADMIN_USERNAME` | 管理员登录用户名 |
| `ADMIN_PASSWORD` | 管理员登录密码 |
| `ADMIN_SESSION_SECRET` | 用于签名管理员 Cookie 的高强度随机值 |

在可信设备的本地终端生成密钥：

```bash
openssl rand -hex 32
```

复制输出并保存到密码管理器和离线恢复介质，然后在 Dashboard 中粘贴为 `MASTER_KEY` Secret。

可在可信设备生成 `ADMIN_SESSION_SECRET`：

```bash
openssl rand -base64 48
```

> 丢失 `MASTER_KEY` 会导致所有备份永久无法解密。不要将它发送到聊天、保存到 GitHub、写入脚本或公开终端历史。

保存变量后，点击 **Deploy** 或触发一次新的 GitHub 部署。

`/admin` 缺少任一管理员 Secret 时会返回 `503`。管理员会话在浏览器关闭后失效，且最长四小时；Cookie 使用 `HttpOnly`、`Secure` 与 `SameSite=Strict`。所有管理写操作均要求同源请求和由 `ADMIN_CSRF` Durable Object 原子消费的一次性 CSRF 令牌。

`wrangler.jsonc` 已配置每分钟 Cron。每次最多处理一个、最多删除 500 个对象的账号移除批次；已完成或失败任务的摘要在 30 天后清理。`ADMIN_CSRF` 同时会在账号移除开始后拒绝新的 WebDAV 写请求，并等待已开始的写请求结束，避免遗留无账号记录可恢复的加密对象。

### 6．使用管理员界面创建和管理账号

打开 `https://YOUR_WORKER.workers.dev/admin`，使用 `ADMIN_USERNAME` 与 `ADMIN_PASSWORD` 登录。首次登录后创建第一个 WebDAV 账号；账号名仅允许小写字母、数字、`.`、`_` 和 `-`，密码至少 8 个字符，创建的账号默认启用。

管理面可以：

- 查看账号状态及账号移除任务状态。
- 启用或停用账号。
- 重设密码。此操作仅替换密码盐和哈希，不改变数据密钥、账号 ID 或既有备份对象。
- 只读浏览某个账号的备份元数据：目录层级、路径前缀筛选、每页最多 100 项，以及路径、类型、明文大小、创建时间、修改时间和 ETag。
- 发起、暂停或继续账号移除任务。

管理面不会显示、写入日志或在提交后重新展示 WebDAV 密码；也不能下载、解密、预览、编辑或删除单个备份对象。

账号移除是危险且不可逆的操作。必须准确输入账号名确认；Worker 会立即停用该账号，再由 Cron 分批删除其 R2 前缀下的对象。任务可以暂停和继续，但不能取消或回滚；运行或暂停期间不能对该账号启用、停用或重设密码。单个对象删除连续失败三次会停止任务并保留失败对象路径与错误摘要，供管理员排查。不要在该账号仍有需要保留的备份时执行移除。

### 7．可选：手动创建账号记录

账号记录需要由项目脚本使用与你设置到 Worker 中相同的 `MASTER_KEY` 生成。此步骤只需要本机安装 Node.js，不需要本机安装或登录 Cloudflare Wrangler。

```bash
git clone https://github.com/wynnok/cf-webdav.git
cd cf-webdav
npm install

MASTER_KEY='你的64位主密钥' \
npm run user:create -- alice '高强度WebDAV密码'
```

脚本会输出一份 JSON 账号记录。

回到 Cloudflare Dashboard：

1. 进入 **Workers & Pages → KV**。
2. 打开生产 `ACCOUNTS_KV`。
3. 点击 **Add entry**。
4. Key 填写：

   ```text
   users/alice
   ```

5. Value 粘贴脚本输出的完整 JSON。
6. 保存。

可以创建停用账号：

```bash
MASTER_KEY='你的64位主密钥' \
npm run user:create -- --disabled alice '高强度WebDAV密码'
```

账号记录中的 `disabled: true` 会拒绝下一次认证请求。

### 8．部署后验收

管理员界面应返回登录页：

```bash
curl -i https://YOUR_WORKER.workers.dev/admin
```

设置全部管理员 Secret 后，响应应为 `200`，且正文包含登录表单。登录并创建账号后，确认账号显示为“已启用”；上传一个测试对象后，确认管理面只显示对象元数据而不显示其内容。

未认证请求应返回 `401`：

```bash
curl -i -X OPTIONS \
  https://YOUR_WORKER.workers.dev/
```

认证后应返回 `200`，并包含 `DAV: 1, 2`：

```bash
curl -i -X OPTIONS \
  -u 'alice:你的WebDAV密码' \
  https://YOUR_WORKER.workers.dev/
```

小文件读写验收：

```bash
printf 'webdav deployment check' > /tmp/cf-webdav-check.txt

curl -i -X PUT \
  -u 'alice:你的WebDAV密码' \
  --upload-file /tmp/cf-webdav-check.txt \
  https://YOUR_WORKER.workers.dev/deployment-check.txt

curl -i \
  -u 'alice:你的WebDAV密码' \
  https://YOUR_WORKER.workers.dev/deployment-check.txt

curl -i -X DELETE \
  -u 'alice:你的WebDAV密码' \
  https://YOUR_WORKER.workers.dev/deployment-check.txt
```

### 9．绑定自定义域名

建议使用独立子域名，例如 `dav.example.com`：

1. 进入 **Workers & Pages → cf-webdav → Settings → Domains & Routes**。
2. 点击 **Add Custom Domain**。
3. 填写 `dav.example.com`。
4. 等待 Cloudflare 配置 HTTPS 证书。

之后将 `https://dav.example.com/` 配置给备份客户端，并通过 `https://dav.example.com/admin` 访问管理面。即使绑定了自定义域名，它仍然是 Worker，不是 Pages。

## 备份客户端配置

### rclone

```ini
[cfwebdav]
type = webdav
vendor = other
url = https://dav.example.com/
user = alice
pass = <rclone obscure 生成的值>
```

建议通过 `rclone config` 交互式配置，以避免在配置文件中保存明文密码。

基础测试：

```bash
rclone lsd cfwebdav:
rclone mkdir cfwebdav:backup-test
rclone copy ./small-test-folder cfwebdav:backup-test
rclone ls cfwebdav:backup-test
rclone purge cfwebdav:backup-test
```

纯 WebDAV 的 `vendor = other` 不会将 ETag 用作 rclone 哈希校验。请通过实际下载、恢复或自定义校验脚本验证备份。

### Duplicati

在 Duplicati 中选择 WebDAV：

- 服务器地址填写 Worker URL 或自定义域名。
- 路径可使用 `/backup`。
- 使用独立 WebDAV 账号和强密码。
- 将远程块大小配置在 `MAX_PUT_BYTES` 与 Cloudflare 请求体上限以下。
- 定期运行 Duplicati 的 `verify`，并进行真实恢复演练。

## 安全与运维

### 访问保护

- 所有 WebDAV 请求必须通过 HTTPS。
- 在 Cloudflare Dashboard 的 **Security → WAF → Rate limiting rules** 中，为 `dav.example.com/*` 配置限流规则。
- 至少限制异常高频请求和 Basic Auth 暴力尝试。
- Workers Logs 会记录方法、账号、路径与状态；不要记录 Authorization、密码、`MASTER_KEY` 或完整备份内容。
- 管理动作会记录动作、目标账号、结果和时间；不会记录管理员密码、WebDAV 密码、会话 Cookie 或 CSRF 令牌。
- 管理面与 WebDAV 共用同一个 Worker 域名。为该域名配置 WAF 限流时，保留管理员登录和已认证备份客户端的正常访问能力。

### 文件大小与性能边界

- rclone 的 WebDAV `vendor = other` 通常整文件 PUT。超过 Cloudflare 请求体限制的单个文件需要在源端分割、提高账户计划，或改用按块上传的备份工具。
- 无 `Content-Length` 的 PUT 会在 Worker 中按 `MAX_PUT_BYTES` 计数并拒绝超限请求。
- Worker 内存上限为 128 MiB；默认 `CHUNK_SIZE_MB = 4` 是安全折中。
- `LOCK` 是独占语义；`shared` 按独占处理。
- KV 锁是最终一致的，因此同一账号的备份任务应由客户端错开，不要并发写同一路径。

### 离线恢复包与主密钥轮换

离线恢复包由两部分组成：

1. `MASTER_KEY` 的离线副本。
2. 导出的账号记录文件。

二者任何一个丢失，都可能使备份无法恢复。账号记录包含被包装的数据密钥，必须加密保存，且不得提交到版本库。

导出生产账号记录：

```bash
npm run accounts:export -- accounts-export.json
```

主密钥重新包装：

```bash
OLD_MASTER_KEY='旧64位主密钥' \
NEW_MASTER_KEY='新64位主密钥' \
npm run accounts:rewrap -- accounts-export.json accounts-rewrapped.json
```

当前版本不支持双主密钥过渡。必须在维护窗口暂停备份，应用生成的 `accounts-rewrapped.json.apply.sh`，切换 Worker Secret 中的 `MASTER_KEY`，然后进行账号认证和恢复演练。

### 恢复演练

至少每月进行一次：

1. 使用 Duplicati `verify`，或下载代表性备份集。
2. 在隔离位置实际还原并打开数据。
3. 确认 `MASTER_KEY` 离线副本与账号记录导出文件可读取。
4. 检查 Workers Logs、R2 用量和异常认证请求。

本项目使用单区域 R2，且不启用对象版本化。WebDAV 的覆盖写和 `DELETE` 是真删除，因此它不能成为唯一备份副本。

## 本地开发与验证

```bash
npm install
npm run typecheck
npm test
npx wrangler deploy --dry-run
```

其中 `npx wrangler deploy --dry-run` 只校验 Worker 打包与 bindings，不上传部署版本。

## 格式兼容性

当前加密格式为 WDV2。历史 WDV1 对象与当前格式不兼容。

当前项目尚未生产部署；如果未来需要格式迁移，必须先设计读取兼容层或离线迁移流程，再升级生产 Worker。
