import { Auth, PBKDF2_MAX_ITERATIONS, validPbkdf2Iterations } from "./auth";
import { acquireAccountMutation, Admin, releaseAccountMutation } from "./admin";
import { importKeyFromBytes } from "./crypto";
import { hexToBytes } from "./util";
import { DavRouter } from "./dav";
import { LockManager } from "./lock";
import { Storage, WebDavError } from "./storage";
import type { Env } from "./env";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    let account: string | undefined;
    try {
      const pbkdf2Iterations = env.PBKDF2_ITERATIONS ?? 100000;
      if (!validPbkdf2Iterations(pbkdf2Iterations)) {
        return new Response(`PBKDF2_ITERATIONS must be an integer between 1 and ${PBKDF2_MAX_ITERATIONS}`, { status: 500, headers: { "Cache-Control": "no-store" } });
      }
      const masterKeyBytes = hexToBytes(env.MASTER_KEY);
      if (masterKeyBytes.length !== 32) throw new Error("MASTER_KEY 必须是 32 字节");
      const masterKey = await importKeyFromBytes(masterKeyBytes);
      const path = new URL(request.url).pathname;
      if (path === "/admin" || path.startsWith("/admin/")) {
        return await new Admin(env, masterKey).dispatch(request);
      }

      const auth = new Auth(
        env.ACCOUNTS_KV,
        masterKey,
        pbkdf2Iterations,
        (env.AUTH_CACHE_TTL_SECONDS ?? 60) * 1000,
      );
      const user = await auth.authenticate(request);
      if (!user) {
        const response = new Response("Unauthorized", {
          status: 401,
          headers: {
            "WWW-Authenticate": 'Basic realm="cf-webdav", charset="UTF-8"',
            "Cache-Control": "no-store",
          },
        });
        audit(request, response.status);
        return response;
      }
      account = user.username;

      const chunkSizeMb = env.CHUNK_SIZE_MB ?? 4;
      if (!Number.isInteger(chunkSizeMb) || chunkSizeMb < 1 || chunkSizeMb > 48) {
        throw new Error("CHUNK_SIZE_MB 必须是 1 到 48 的整数");
      }
      const chunkSize = chunkSizeMb * 1024 * 1024;
      const maxPutBytes = env.MAX_PUT_BYTES ?? 500 * 1024 * 1024;
      const storage = new Storage(env.BACKUP_BUCKET, user.prefix, user.dataKey, chunkSize, maxPutBytes);
      const locks = new LockManager(
        env.LOCKS_KV,
        user.userId,
        env.LOCK_TIMEOUT_SECONDS ?? 3600,
      );
      const router = new DavRouter(storage, locks, {
        propfindMaxEntries: env.PROPFIND_MAX_ENTRIES ?? 5000,
        lockTimeoutSeconds: env.LOCK_TIMEOUT_SECONDS ?? 3600,
        maxPutBytes,
      });

      const mutating = new Set(["PUT", "MKCOL", "DELETE", "COPY", "MOVE", "PROPPATCH", "LOCK", "UNLOCK"]);
      const guarded = mutating.has(request.method);
      const lease = guarded ? await acquireAccountMutation(env, user.userId) : null;
      if (guarded && !lease) {
        const response = new Response("Locked", { status: 423, headers: { "Cache-Control": "no-store" } });
        audit(request, response.status, account);
        return response;
      }
      let response: Response;
      try {
        response = await router.dispatch(request);
      } finally {
        if (lease) await releaseAccountMutation(env, user.userId, lease);
      }
      audit(request, response.status, account);
      return response;
    } catch (e) {
      if (e instanceof WebDavError) {
        const response = davError(e);
        audit(request, response.status, account);
        return response;
      }
      console.error("Unhandled error:", e);
      const response = new Response("Internal Server Error", { status: 500, headers: { "Cache-Control": "no-store" } });
      audit(request, response.status, account);
      return response;
    }
  },
  async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
    const masterKeyBytes = hexToBytes(env.MASTER_KEY);
    if (masterKeyBytes.length !== 32) throw new Error("MASTER_KEY 必须是 32 字节");
    await new Admin(env, await importKeyFromBytes(masterKeyBytes)).runScheduled();
  },
};

export { AdminCsrf } from "./admin";

function audit(request: Request, status: number, account?: string): void {
  console.log(JSON.stringify({
    event: "webdav.request",
    method: request.method,
    account,
    path: new URL(request.url).pathname,
    status,
  }));
}

function davError(e: WebDavError): Response {
  const body = e.davCode
    ? `<?xml version="1.0" encoding="utf-8"?><D:error xmlns:D="DAV:"><D:${e.davCode}/></D:error>`
    : e.message;
  return new Response(body, {
    status: e.status,
    headers: { "Content-Type": "application/xml; charset=utf-8", "Cache-Control": "no-store" },
  });
}
