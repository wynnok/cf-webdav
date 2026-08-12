import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        main: "./src/index.ts",
        isolatedStorage: true,
        singleWorker: true,
        miniflare: {
          compatibilityDate: "2025-07-15",
          compatibilityFlags: ["nodejs_compat"],
          kvNamespaces: ["ACCOUNTS_KV", "LOCKS_KV"],
          r2Buckets: ["BACKUP_BUCKET"],
          bindings: {
            MASTER_KEY: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            CHUNK_SIZE_MB: 1,
            PBKDF2_ITERATIONS: 1000,
            AUTH_CACHE_TTL_SECONDS: 60,
            PROPFIND_MAX_ENTRIES: 100,
            MAX_PUT_BYTES: 64 * 1024,
          },
        },
      },
    },
  },
});
