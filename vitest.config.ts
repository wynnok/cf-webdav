import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        main: "./src/index.ts",
        // Miniflare cannot isolate a Durable Object's SQLite storage per test.
        isolatedStorage: false,
        singleWorker: true,
        miniflare: {
          compatibilityDate: "2025-07-15",
          compatibilityFlags: ["nodejs_compat"],
          kvNamespaces: ["ACCOUNTS_KV", "LOCKS_KV", "ADMIN_KV"],
          durableObjects: { ADMIN_CSRF: "AdminCsrf" },
          r2Buckets: ["BACKUP_BUCKET"],
          bindings: {
            MASTER_KEY: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            ADMIN_USERNAME: "admin",
            ADMIN_PASSWORD: "correct-horse-battery-staple",
            ADMIN_SESSION_SECRET: "test-admin-session-secret",
            CHUNK_SIZE_MB: 1,
            PBKDF2_ITERATIONS: 1000,
            AUTH_CACHE_TTL_SECONDS: 60,
            PROPFIND_MAX_ENTRIES: 100,
            MAX_PUT_BYTES: 64 * 1024,
            INLINE_MD5_MAX_BYTES: 16,
          },
        },
      },
    },
  },
});
