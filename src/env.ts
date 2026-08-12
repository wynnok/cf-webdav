export interface Env {
  BACKUP_BUCKET: R2Bucket;
  ACCOUNTS_KV: KVNamespace;
  LOCKS_KV: KVNamespace;
  /** 64 位十六进制的 AES-256 主密钥,经 Wrangler secret 注入。 */
  MASTER_KEY: string;
  CHUNK_SIZE_MB?: number;
  PBKDF2_ITERATIONS?: number;
  AUTH_CACHE_TTL_SECONDS?: number;
  PROPFIND_MAX_ENTRIES?: number;
  LOCK_TIMEOUT_SECONDS?: number;
  /** 部署所在 Cloudflare 账号允许的最大 HTTP 请求体字节数。 */
  MAX_PUT_BYTES?: number;
}
