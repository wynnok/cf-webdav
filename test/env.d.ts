declare module "cloudflare:test" {
  interface ProvidedEnv {
    BACKUP_BUCKET: R2Bucket;
    ACCOUNTS_KV: KVNamespace;
    LOCKS_KV: KVNamespace;
    ADMIN_KV: KVNamespace;
    ADMIN_CSRF: DurableObjectNamespace;
    MASTER_KEY: string;
    ADMIN_USERNAME: string;
    ADMIN_PASSWORD: string;
    ADMIN_SESSION_SECRET: string;
    CHUNK_SIZE_MB: number;
    PBKDF2_ITERATIONS: number;
    AUTH_CACHE_TTL_SECONDS: number;
    PROPFIND_MAX_ENTRIES: number;
    MAX_PUT_BYTES: number;
  }
}
