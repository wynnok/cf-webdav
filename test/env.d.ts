declare module "cloudflare:test" {
  interface ProvidedEnv {
    BACKUP_BUCKET: R2Bucket;
    ACCOUNTS_KV: KVNamespace;
    LOCKS_KV: KVNamespace;
    MASTER_KEY: string;
    CHUNK_SIZE_MB: number;
    PBKDF2_ITERATIONS: number;
    AUTH_CACHE_TTL_SECONDS: number;
    PROPFIND_MAX_ENTRIES: number;
    MAX_PUT_BYTES: number;
  }
}
