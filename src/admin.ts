import { makeUserRecord, normalizeUsername, pbkdf2Hash, type UserRecord, validateUserRecord } from "./auth";
import { generateDataKey, randomBytes, wrapKey } from "./crypto";
import type { Env } from "./env";
import { bytesToBase64, constantTimeEqual } from "./util";

const COOKIE = "cf_webdav_admin";
const SESSION_TTL = 4 * 60 * 60;
const CSRF_TTL = 15 * 60;
const BATCH_SIZE = 500;
const RETENTION = 30 * 24 * 60 * 60;

interface Session { id: string; expiresAt: number }
interface RemovalJob {
  account: string;
  userId: string;
  storagePrefix: string;
  status: "running" | "paused" | "failed" | "completed";
  cursor?: string;
  deleted: number;
  retries: number;
  failedKey?: string;
  error?: string;
  updatedAt: string;
  finishedAt?: string;
}

export class AdminCsrf implements DurableObject {
  constructor(private state: DurableObjectState) {}
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/mutation") return this.mutation(request);
    if (url.pathname === "/removal") return this.removal(request);
    const token = url.searchParams.get("token");
    if (!token) return new Response("Bad Request", { status: 400 });
    if (request.method === "PUT") { const expiresAt = Number(new URL(request.url).searchParams.get("expiresAt")); if (!Number.isFinite(expiresAt)) return new Response("Bad Request", { status: 400 }); await this.state.storage.put(token, expiresAt); await this.state.storage.setAlarm(expiresAt); return new Response(null, { status: 204 }); }
    if (request.method === "DELETE") {
      const expiresAt = await this.state.storage.get<number>(token);
      if (!expiresAt || expiresAt <= Date.now()) { await this.state.storage.delete(token); return new Response("Not Found", { status: 404 }); }
      await this.state.storage.delete(token);
      return new Response(null, { status: 204 });
    }
    return new Response("Method Not Allowed", { status: 405 });
  }
  async alarm(): Promise<void> {
    const now = Date.now();
    const tokens = await this.state.storage.list<number>();
    const expiries = [...tokens.entries()].filter(([, expiresAt]) => expiresAt <= now);
    await Promise.all(expiries.map(([token]) => this.state.storage.delete(token)));
    const next = [...tokens.values()].filter((expiresAt) => expiresAt > now).sort((a, b) => a - b)[0];
    if (next) await this.state.storage.setAlarm(next);
  }

  private async mutation(request: Request): Promise<Response> {
    if (request.method === "POST") {
      if (await this.state.storage.get<boolean>("removing")) return new Response("Locked", { status: 423 });
      const lease = crypto.randomUUID();
      await this.state.storage.put(`mutation/${lease}`, Date.now() + 6 * 60_000);
      return new Response(lease);
    }
    if (request.method === "DELETE") {
      const lease = new URL(request.url).searchParams.get("lease");
      if (lease) await this.state.storage.delete(`mutation/${lease}`);
      return new Response(null, { status: 204 });
    }
    return new Response("Method Not Allowed", { status: 405 });
  }

  private async removal(request: Request): Promise<Response> {
    if (request.method === "POST") {
      await this.state.storage.put("removing", true);
      return new Response(null, { status: 204 });
    }
    if (request.method === "GET") {
      const now = Date.now();
      const leases = await this.state.storage.list<number>({ prefix: "mutation/" });
      await Promise.all([...leases.entries()].filter(([, expiry]) => expiry <= now).map(([key]) => this.state.storage.delete(key)));
      return new Response(JSON.stringify({ active: [...leases.values()].filter((expiry) => expiry > now).length }), { headers: { "Content-Type": "application/json" } });
    }
    if (request.method === "PUT") {
      const now = Date.now();
      const minute = Math.floor(now / 60_000);
      const claimedMinute = await this.state.storage.get<number>("removal-minute");
      const runningUntil = await this.state.storage.get<number>("removal-running");
      if (claimedMinute === minute || (runningUntil && runningUntil > now)) return new Response("Already claimed", { status: 409 });
      await this.state.storage.put("removal-minute", minute);
      await this.state.storage.put("removal-running", now + 6 * 60_000);
      return new Response(null, { status: 204 });
    }
    if (request.method === "DELETE") { await this.state.storage.delete("removal-running"); return new Response(null, { status: 204 }); }
    return new Response("Method Not Allowed", { status: 405 });
  }
}

export async function acquireAccountMutation(env: Env, accountId: string): Promise<string | null> {
  const stub = env.ADMIN_CSRF.get(env.ADMIN_CSRF.idFromName(`account/${accountId}`));
  const response = await stub.fetch("https://admin/mutation", { method: "POST" });
  return response.status === 200 ? response.text() : null;
}

export async function releaseAccountMutation(env: Env, accountId: string, lease: string): Promise<void> {
  const stub = env.ADMIN_CSRF.get(env.ADMIN_CSRF.idFromName(`account/${accountId}`));
  await stub.fetch(`https://admin/mutation?lease=${encodeURIComponent(lease)}`, { method: "DELETE" });
}

export class Admin {
  constructor(private env: Env, private masterKey: CryptoKey) {}

  async dispatch(request: Request): Promise<Response> {
    if (!this.configured()) return response("Management surface is not configured", 503);
    const url = new URL(request.url);
    if (url.pathname === "/admin/login") return request.method === "POST" ? this.login(request) : page(loginPage());
    if (url.pathname === "/admin/logout" && request.method === "POST") return this.form(request, async () => {
      const out = redirect("/admin/login");
      out.headers.set("Set-Cookie", `${COOKIE}=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
      return out;
    });
    const session = await this.session(request);
    if (!session) return redirect("/admin/login");
    if (url.pathname === "/admin" && request.method === "GET") return this.dashboard(url, session);
    if (url.pathname === "/admin/accounts" && request.method === "POST") return this.form(request, () => this.create(request));
    const match = url.pathname.match(/^\/admin\/accounts\/([^/]+)\/(enable|disable|password|remove|pause|resume)$/);
    if (match && request.method === "POST") return this.form(request, () => this.action(request, decodeURIComponent(match[1]!), match[2]!));
    return response("Not Found", 404);
  }

  async runScheduled(): Promise<void> {
    if (!this.configured()) return;
    const scheduler = this.env.ADMIN_CSRF.get(this.env.ADMIN_CSRF.idFromName("removal-scheduler"));
    if ((await scheduler.fetch("https://admin/removal", { method: "PUT" })).status !== 204) return;
    try {
      let cursor: string | undefined;
      let ranBatch = false;
      do {
      const entries = await this.env.ADMIN_KV.list({ prefix: "removals/", cursor });
      for (const entry of entries.keys) {
        const job = await this.job(entry.name.slice(9));
      if (!job) continue;
        if (job.status === "running" && !ranBatch) { await this.removeBatch(job); ranBatch = true; }
      if ((job.status === "completed" || job.status === "failed") && job.finishedAt && Date.now() - Date.parse(job.finishedAt) > RETENTION * 1000) await this.env.ADMIN_KV.delete(entry.name);
      }
      cursor = entries.list_complete ? undefined : entries.cursor;
      } while (cursor);
    } finally {
      await scheduler.fetch("https://admin/removal", { method: "DELETE" });
    }
  }

  private configured(): boolean { return Boolean(this.env.ADMIN_USERNAME && this.env.ADMIN_PASSWORD && this.env.ADMIN_SESSION_SECRET); }

  private async login(request: Request): Promise<Response> {
    if (!sameOrigin(request)) return response("Forbidden", 403);
    const form = await request.formData();
    if (!constantTimeEqual(String(form.get("username") ?? ""), this.env.ADMIN_USERNAME!) || !constantTimeEqual(String(form.get("password") ?? ""), this.env.ADMIN_PASSWORD!)) return page(loginPage("用户名或密码错误"), 401);
    const id = crypto.randomUUID();
    const expiresAt = Date.now() + SESSION_TTL * 1000;
    await this.env.ADMIN_KV.put(`sessions/${id}`, "1", { expirationTtl: SESSION_TTL });
    const out = redirect("/admin");
    out.headers.set("Set-Cookie", `${COOKIE}=${await this.sign(`${id}.${expiresAt}`)}; Path=/admin; HttpOnly; Secure; SameSite=Strict`);
    audit("login", "admin", "success");
    return out;
  }

  private async dashboard(url: URL, session: Session): Promise<Response> {
    const account = url.searchParams.get("account") ?? "";
    const prefix = url.searchParams.get("prefix") ?? "";
    const cursor = url.searchParams.get("cursor") ?? undefined;
    const [accounts, objects, job, csrf] = await Promise.all([this.accounts(), account ? this.metadata(account, prefix, cursor) : Promise.resolve({ objects: [], cursor: undefined }), account ? this.job(account) : Promise.resolve(null), this.csrf(session)]);
    return page(dashboardPage(accounts, account, prefix, objects.objects, objects.cursor, job, csrf, url.searchParams.get("created") ?? "", url.searchParams.get("error") ?? "", session));
  }

  private async create(request: Request): Promise<Response> {
    const form = await request.formData();
    const account = normalizeUsername(String(form.get("account") ?? ""));
    const password = String(form.get("password") ?? "");
    if (!validAccount(account) || password.length < 8 || password !== String(form.get("passwordConfirmation") ?? "") || await this.record(account)) return redirect("/admin?error=invalid-account");
    const salt = randomBytes(16);
    const iterations = this.env.PBKDF2_ITERATIONS ?? 100000;
    const hash = await pbkdf2Hash(password, bytesToBase64(salt), iterations);
    const record = makeUserRecord(crypto.randomUUID(), account, salt, iterations, hash, await wrapKey(this.masterKey, generateDataKey()));
    await this.env.ACCOUNTS_KV.put(`users/${account}`, JSON.stringify(record));
    audit("account.create", account, "success");
    return redirect(`/admin?created=${encodeURIComponent(account)}`);
  }

  private async action(request: Request, rawAccount: string, action: string): Promise<Response> {
    const account = normalizeUsername(rawAccount);
    const record = await this.record(account);
    if (!record) return response("Not Found", 404);
    const job = await this.job(account);
    if (action === "pause" || action === "resume") {
      if (!job || !["running", "paused"].includes(job.status)) return redirect(`/admin?account=${encodeURIComponent(account)}`);
      job.status = action === "pause" ? "paused" : "running";
      job.updatedAt = new Date().toISOString();
      await this.saveJob(job);
    } else if (job && ["running", "paused"].includes(job.status)) return redirect(`/admin?account=${encodeURIComponent(account)}&error=removal-active`);
    else if (action === "enable" || action === "disable") await this.env.ACCOUNTS_KV.put(`users/${account}`, JSON.stringify({ ...record, disabled: action === "disable" }));
    else if (action === "password") {
      const form = await request.formData(); const password = String(form.get("password") ?? "");
      if (password.length < 8 || password !== String(form.get("passwordConfirmation") ?? "")) return redirect(`/admin?account=${encodeURIComponent(account)}&error=invalid-password`);
      const salt = randomBytes(16);
      const iterations = this.env.PBKDF2_ITERATIONS ?? 100000;
      await this.env.ACCOUNTS_KV.put(`users/${account}`, JSON.stringify({ ...record, iter: iterations, salt: bytesToBase64(salt), hash: await pbkdf2Hash(password, bytesToBase64(salt), iterations) }));
    } else if (action === "remove") {
      const form = await request.formData();
      if (String(form.get("confirmation") ?? "") !== account) return redirect(`/admin?account=${encodeURIComponent(account)}&error=confirmation`);
      const now = new Date().toISOString();
      const gate = this.env.ADMIN_CSRF.get(this.env.ADMIN_CSRF.idFromName(`account/${record.id}`));
      await gate.fetch("https://admin/removal", { method: "POST" });
      await this.env.ACCOUNTS_KV.put(`users/${account}`, JSON.stringify({ ...record, disabled: true }));
      await this.saveJob({ account, userId: record.id, storagePrefix: storagePrefix(record), status: "running", deleted: 0, retries: 0, updatedAt: now });
    } else return response("Not Found", 404);
    audit(`account.${action}`, account, "success");
    return redirect(`/admin?account=${encodeURIComponent(account)}`);
  }

  private async removeBatch(job: RemovalJob): Promise<void> {
    try {
      const gate = this.env.ADMIN_CSRF.get(this.env.ADMIN_CSRF.idFromName(`account/${job.userId}`));
      const activity = await (await gate.fetch("https://admin/removal")).json<{ active: number }>();
      if (activity.active > 0) return;
      const listed = await this.env.BACKUP_BUCKET.list({ prefix: job.storagePrefix, limit: BATCH_SIZE });
      for (const object of listed.objects) {
        try { await this.env.BACKUP_BUCKET.delete(object.key); job.deleted += 1; }
        catch (error) {
          job.retries = job.failedKey === object.key ? job.retries + 1 : 1;
          job.failedKey = object.key; job.error = error instanceof Error ? error.message : "Unknown deletion error";
          if (job.retries >= 3) { job.status = "failed"; job.finishedAt = new Date().toISOString(); }
          job.updatedAt = new Date().toISOString(); await this.saveJob(job); audit("account.removal.batch", job.account, job.status); return;
        }
      }
      job.retries = 0; job.failedKey = undefined; job.error = undefined; job.updatedAt = new Date().toISOString();
      if (!listed.truncated) { await this.env.ACCOUNTS_KV.delete(`users/${job.account}`); job.status = "completed"; job.finishedAt = job.updatedAt; }
    } catch (error) {
      job.retries += 1; job.error = error instanceof Error ? error.message : "Unknown deletion error"; job.updatedAt = new Date().toISOString();
      if (job.retries >= 3) { job.status = "failed"; job.finishedAt = job.updatedAt; }
    }
    await this.saveJob(job); audit("account.removal.batch", job.account, job.status);
  }

  private async accounts(): Promise<Array<{ account: string; record: UserRecord; job: RemovalJob | null }>> {
    const rows: Array<{ account: string; record: UserRecord; job: RemovalJob | null }> = [];
    let cursor: string | undefined;
    do {
      const listed = await this.env.ACCOUNTS_KV.list({ prefix: "users/", cursor });
      const page = await Promise.all(listed.keys.map(async ({ name }) => { const account = name.slice(6); const record = await this.record(account); return record ? { account, record, job: await this.job(account) } : null; }));
      rows.push(...page.filter((row): row is NonNullable<typeof row> => row !== null));
      cursor = listed.list_complete ? undefined : listed.cursor;
    } while (cursor);
    return rows.sort((a, b) => a.account.localeCompare(b.account));
  }

  private async metadata(account: string, prefix: string, cursor?: string): Promise<{ objects: Metadata[]; cursor?: string }> {
    const record = await this.record(account); if (!record) return { objects: [] };
    const base = `${storagePrefix(record)}${prefix}`;
    const listed = await this.env.BACKUP_BUCKET.list({ prefix: base, delimiter: "/", cursor, limit: 100, include: ["customMetadata"] });
    const directories = (listed.delimitedPrefixes ?? []).map((key) => ({ path: key.slice(storagePrefix(record).length), type: "directory", size: "-", created: "-", mtime: "-", etag: "-" }));
    return { objects: [...directories, ...listed.objects.map((object) => objectMetadata(object, storagePrefix(record)))], cursor: listed.truncated ? listed.cursor : undefined };
  }

  private async form(request: Request, action: () => Promise<Response>): Promise<Response> {
    const session = await this.session(request); if (!session) return redirect("/admin/login");
    if (!sameOrigin(request)) return response("Forbidden", 403);
    const token = String((await request.clone().formData()).get("csrf") ?? "");
    const stub = this.env.ADMIN_CSRF.get(this.env.ADMIN_CSRF.idFromName(session.id));
    if ((await stub.fetch(`https://csrf/token?token=${encodeURIComponent(token)}`, { method: "DELETE" })).status !== 204) return response("Forbidden", 403);
    if (!await this.env.ADMIN_KV.get(`csrf/${session.id}/${token}`)) return response("Forbidden", 403);
    await this.env.ADMIN_KV.delete(`csrf/${session.id}/${token}`); return action();
  }
  private async csrf(session: Session): Promise<string> { const token = bytesToBase64(randomBytes(32)).replace(/[+/=]/g, ""); await this.env.ADMIN_KV.put(`csrf/${session.id}/${token}`, "1", { expirationTtl: CSRF_TTL }); const stub = this.env.ADMIN_CSRF.get(this.env.ADMIN_CSRF.idFromName(session.id)); await stub.fetch(`https://csrf/token?token=${encodeURIComponent(token)}&expiresAt=${Date.now() + CSRF_TTL * 1000}`, { method: "PUT" }); return token; }
  private async session(request: Request): Promise<Session | null> { const raw = cookie(request.headers.get("Cookie"), COOKIE); if (!raw) return null; const dot = raw.lastIndexOf("."); const payload = raw.slice(0, dot); if (dot < 1 || !constantTimeEqual(await this.sign(payload), raw)) return null; const [id, expiry] = payload.split("."); const expiresAt = Number(expiry); return id && expiresAt > Date.now() && await this.env.ADMIN_KV.get(`sessions/${id}`) ? { id, expiresAt } : null; }
  private async sign(payload: string): Promise<string> { const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(this.env.ADMIN_SESSION_SECRET!), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); return `${payload}.${bytesToBase64(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)))).replace(/[+/=]/g, "")}`; }
  private async record(account: string): Promise<UserRecord | null> { const raw = await this.env.ACCOUNTS_KV.get(`users/${account}`); if (!raw) return null; try { const record = JSON.parse(raw) as UserRecord; validateUserRecord(record); return record; } catch { return null; } }
  private async job(account: string): Promise<RemovalJob | null> { const raw = await this.env.ADMIN_KV.get(`removals/${account}`); return raw ? JSON.parse(raw) as RemovalJob : null; }
  private saveJob(job: RemovalJob): Promise<void> { return this.env.ADMIN_KV.put(`removals/${job.account}`, JSON.stringify(job)); }
}

interface Metadata { path: string; type: string; size: string; created: string; mtime: string; etag: string }
function storagePrefix(record: UserRecord): string { return record.storagePrefix; }
function objectMetadata(object: R2Object, prefix: string): Metadata { const m = object.customMetadata ?? {}; return { path: object.key.slice(prefix.length), type: m.wdv_type ?? "file", size: m.wdv_size ?? "unknown", created: m.wdv_created ?? object.uploaded.toISOString(), mtime: m.wdv_mtime ?? object.uploaded.toISOString(), etag: m.wdv_md5 ?? object.etag }; }
function validAccount(value: string): boolean { return /^[a-z0-9][a-z0-9._-]{0,62}$/.test(value); }
function formatSize(raw: string): string { const size = Number(raw); if (!Number.isFinite(size) || size < 0) return raw; if (size === 0) return "0 B"; const units = ["B", "KiB", "MiB", "GiB", "TiB"]; const exponent = Math.min(Math.floor(Math.log(size) / Math.log(1024)), units.length - 1); if (exponent === 0) return `${size} B`; return `${(size / 1024 ** exponent).toFixed(1)} ${units[exponent]}`; }
function sameOrigin(request: Request): boolean { return request.headers.get("Origin") === new URL(request.url).origin; }
function cookie(header: string | null, name: string): string | null { return header?.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`))?.slice(name.length + 1) ?? null; }
function response(body: string, status: number): Response { return new Response(body, { status, headers: { "Cache-Control": "no-store" } }); }
function page(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Resource-Policy": "same-origin",
      "Permissions-Policy": "camera=(), geolocation=(), microphone=(), payment=()",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
    },
  });
}
function redirect(path: string): Response { return new Response(null, { status: 303, headers: { Location: path, "Cache-Control": "no-store" } }); }
function escape(value: string): string { return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
function audit(action: string, account: string, result: string): void { console.log(JSON.stringify({ event: "admin.action", action, account, result, time: new Date().toISOString() })); }
function layout(title: string, body: string): string {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escape(title)}</title><style>
    :root { color-scheme: light; font-family: "Fira Sans", "Noto Sans SC", system-ui, sans-serif; color: #171717; background: #f7f7f5; }
    * { box-sizing: border-box; } body { margin: 0; background: #f7f7f5; } button, input { font: inherit; } button { cursor: pointer; }
    a { color: #7c4a03; text-underline-offset: 3px; } a:hover { color: #171717; } :focus-visible { outline: 3px solid #a16207; outline-offset: 2px; }
    .shell { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 32px 0 56px; } .topbar { display: flex; align-items: center; justify-content: space-between; gap: 20px; padding-bottom: 28px; border-bottom: 1px solid #deded9; }
    .brand { display: flex; align-items: center; gap: 12px; color: #171717; text-decoration: none; font-weight: 700; letter-spacing: -.02em; } .brand-mark { display: grid; width: 32px; height: 32px; place-items: center; border-radius: 8px; background: #171717; color: #fff; font-family: monospace; font-size: 13px; }
    .eyebrow { margin: 0 0 5px; color: #706f6a; font-size: 12px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; } h1 { margin: 0; font-size: clamp(28px, 4vw, 40px); letter-spacing: -.045em; line-height: 1.05; } h2 { margin: 0; font-size: 18px; letter-spacing: -.02em; } h3 { margin: 0; font-size: 15px; }
    .button { min-height: 40px; border: 1px solid #171717; border-radius: 6px; padding: 8px 14px; background: #171717; color: #fff; font-weight: 650; transition: background .18s ease, border-color .18s ease; } .button:hover { background: #404040; border-color: #404040; } .button-secondary { background: #fff; color: #171717; border-color: #c8c8c3; } .button-secondary:hover { background: #efefeb; border-color: #a9a9a2; } .button-danger { background: #b42318; border-color: #b42318; } .button-danger:hover { background: #8d1b12; border-color: #8d1b12; }
    .intro { display: flex; justify-content: space-between; align-items: end; gap: 24px; margin: 36px 0 24px; } .intro p { max-width: 640px; margin: 10px 0 0; color: #5e5d58; line-height: 1.6; }
    .metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 28px; } .metric, .panel { border: 1px solid #deded9; border-radius: 10px; background: #fff; box-shadow: 0 1px 2px rgb(23 23 23 / 4%); } .metric { padding: 18px; } .metric-label { display: block; color: #706f6a; font-size: 13px; font-weight: 600; } .metric-value { display: block; margin-top: 8px; font-family: "Fira Code", ui-monospace, monospace; font-size: 28px; font-weight: 600; letter-spacing: -.06em; } .metric-accent { color: #8a5508; }
    .workspace { display: grid; grid-template-columns: minmax(0, 1fr) 360px; gap: 20px; align-items: start; } .panel { overflow: hidden; } .panel-heading { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 20px 20px 16px; border-bottom: 1px solid #ededea; } .panel-heading p { margin: 4px 0 0; color: #706f6a; font-size: 13px; } .panel-body { padding: 20px; }
    .field-grid { display: grid; gap: 14px; } .field-grid.compact { grid-template-columns: 1fr 1fr; } label { display: grid; gap: 7px; color: #3f3f3b; font-size: 13px; font-weight: 650; } input { width: 100%; min-height: 42px; border: 1px solid #c8c8c3; border-radius: 6px; padding: 9px 10px; background: #fff; color: #171717; } input:hover { border-color: #999991; } input:focus { border-color: #171717; outline: 0; box-shadow: 0 0 0 3px rgb(161 98 7 / 18%); } .form-actions { display: flex; justify-content: end; margin-top: 18px; }
    .table-scroll { overflow-x: auto; } table { width: 100%; min-width: 620px; border-collapse: collapse; text-align: left; } th { padding: 11px 20px; background: #fafaf8; color: #706f6a; font-size: 11px; font-weight: 750; letter-spacing: .07em; text-transform: uppercase; white-space: nowrap; } td { padding: 14px 20px; border-top: 1px solid #ededea; color: #3f3f3b; font-size: 14px; } td:first-child { color: #171717; font-weight: 600; } .path-cell { min-width: 180px; overflow-wrap: anywhere; } .table-action { display: flex; justify-content: end; } .empty { padding: 32px 20px; color: #706f6a; text-align: center; }
    .badge { display: inline-flex; align-items: center; min-height: 24px; border-radius: 999px; padding: 3px 9px; font-size: 12px; font-weight: 700; white-space: nowrap; } .badge-active, .badge-completed { background: #e8f3ea; color: #246333; } .badge-disabled, .badge-failed { background: #fdeceb; color: #9a241c; } .badge-running { background: #fdf3dd; color: #895807; } .badge-paused { background: #ececf5; color: #4f4a88; } .badge-neutral { background: #efefeb; color: #625f58; }
    .notice { margin: 0 0 20px; border: 1px solid #efc7c2; border-radius: 8px; padding: 12px 14px; background: #fff6f5; color: #8d1b12; font-size: 14px; } .notice-success { border-color: #bfe3c6; background: #f0f9f2; color: #246333; } .breadcrumb { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin-bottom: 14px; font-size: 13px; } .breadcrumb span { color: #a9a9a2; } code { font-family: "Fira Code", ui-monospace, monospace; font-size: 12px; } .detail { display: grid; gap: 20px; margin-top: 20px; } .path-form { display: grid; grid-template-columns: 1fr auto; gap: 10px; align-items: end; } .destructive { border-color: #efc7c2; } .destructive .panel-heading { background: #fffafa; } .muted { color: #706f6a; font-size: 13px; line-height: 1.55; } .job { border-left: 3px solid #a16207; padding: 12px 14px; background: #faf7ef; } .job p { margin: 7px 0 0; color: #5e5d58; font-size: 13px; line-height: 1.5; }
    .login-shell { display: grid; min-height: 100vh; place-items: center; padding: 24px; background: linear-gradient(135deg, #f7f7f5, #eeece5); } .login-card { width: min(100%, 420px); padding: 32px; border: 1px solid #deded9; border-radius: 12px; background: #fff; box-shadow: 0 18px 45px rgb(23 23 23 / 9%); } .login-card .intro { display: block; margin: 0 0 28px; } .login-card .button { width: 100%; margin-top: 20px; }
    @media (max-width: 800px) { .shell { width: min(100% - 24px, 680px); padding-top: 20px; } .topbar { padding-bottom: 20px; } .intro { display: block; margin: 28px 0 18px; } .metrics, .workspace { grid-template-columns: 1fr; } .metrics { gap: 10px; } .metric { padding: 14px; } .workspace { gap: 14px; } .panel-heading, .panel-body { padding: 16px; } th, td { padding-left: 16px; padding-right: 16px; } } @media (max-width: 480px) { .topbar { align-items: start; } .field-grid.compact, .path-form { grid-template-columns: 1fr; } .path-form .button { width: 100%; } .login-card { padding: 24px; } }
    @media (prefers-reduced-motion: reduce) { *, *::before, *::after { transition-duration: .01ms !important; } }
  </style></head><body>${body}</body></html>`;
}

function loginPage(error = ""): string {
  return layout("cf-webdav 管理登录", `<main class="login-shell"><section class="login-card" aria-labelledby="login-title"><a class="brand" href="/admin/login"><span class="brand-mark">wd</span><span>cf-webdav</span></a><div class="intro"><p class="eyebrow">Management surface</p><h1 id="login-title">管理面登录</h1><p>使用管理员凭据管理账号，并只查看备份元数据。</p></div>${error ? `<p class="notice" role="alert">${escape(error)}</p>` : ""}<form method="post" action="/admin/login"><div class="field-grid"><label>管理员用户名<input name="username" required autocomplete="username"></label><label>管理员密码<input name="password" type="password" required autocomplete="current-password"></label></div><button class="button" type="submit">登录管理面</button></form></section></main>`);
}

function statusBadge(status: string | undefined, type: "account" | "job" = "job"): string {
  if (!status) return `<span class="badge badge-neutral">无任务</span>`;
  const labels: Record<string, string> = { active: "已启用", disabled: "已停用", running: "进行中", paused: "已暂停", failed: "失败", completed: "已完成" };
  const variant = type === "account" ? (status === "disabled" ? "disabled" : "active") : status;
  return `<span class="badge badge-${variant}">${labels[status] ?? escape(status)}</span>`;
}

function dashboardPage(accounts: Array<{ account: string; record: UserRecord; job: RemovalJob | null }>, account: string, prefix: string, objects: Metadata[], cursor: string | undefined, job: RemovalJob | null, csrf: string, created: string, error: string, session: Session): string {
  const enabled = accounts.filter(({ record }) => !record.disabled).length;
  const activeRemovals = accounts.filter(({ job }) => job && ["running", "paused"].includes(job.status)).length;
  const errorMessages: Record<string, string> = { "invalid-account": "账号名或密码不符合要求，或账号已存在。", "invalid-password": "新密码不符合要求，或两次输入不一致。", "confirmation": "确认输入的账号名与目标账号不一致。", "removal-active": "移除任务运行或暂停期间，不能启用、停用或重置该账号密码。" };
  const errorNotice = error ? `<p class="notice" role="alert">${escape(errorMessages[error] ?? "操作失败，请重试。")}</p>` : "";
  const sessionHours = Math.max(0, Math.floor((session.expiresAt - Date.now()) / 3_600_000));
  const sessionNotice = sessionHours >= 1 ? `会话剩余约 ${sessionHours} 小时，到期后需重新登录。` : "会话剩余不足 1 小时，到期后需重新登录。";
  const rows = accounts.map(({ account: name, record, job: accountJob }) => `<tr><td><a href="/admin?account=${encodeURIComponent(name)}">${escape(name)}</a></td><td>${statusBadge(record.disabled ? "disabled" : "active", "account")}</td><td>${statusBadge(accountJob?.status)}</td><td><form class="table-action" method="post" action="/admin/accounts/${encodeURIComponent(name)}/${record.disabled ? "enable" : "disable"}"><input type="hidden" name="csrf" value="${csrf}"><button class="button button-secondary" type="submit">${record.disabled ? "启用" : "停用"}</button></form></td></tr>`).join("");
  const objectRows = objects.map((o) => {
    const path = o.type === "directory"
      ? `<a href="/admin?account=${encodeURIComponent(account)}&prefix=${encodeURIComponent(o.path)}">${escape(o.path)}</a>`
      : escape(o.path);
    return `<tr><td class="path-cell">${path}</td><td>${escape(o.type)}</td><td>${escape(formatSize(o.size))}</td><td>${escape(o.created)}</td><td>${escape(o.mtime)}</td><td>${escape(o.etag)}</td></tr>`;
  }).join("");
  const breadcrumb = (() => { const root = `/admin?account=${encodeURIComponent(account)}`; const segments = prefix.split("/").filter(Boolean); let accumulated = ""; const crumbs = segments.map((segment) => { accumulated += `${segment}/`; return `<a href="${root}&prefix=${encodeURIComponent(accumulated)}">${escape(segment)}</a>`; }); return `<nav class="breadcrumb" aria-label="面包屑"><a href="${root}">根目录</a>${crumbs.map((crumb) => `<span aria-hidden="true">/</span>${crumb}`).join("")}</nav>`; })();
  const selected = account ? `<section class="detail" aria-labelledby="account-title"><div class="panel"><div class="panel-heading"><div><p class="eyebrow">Backup metadata</p><h2 id="account-title">账号：${escape(account)}</h2></div>${job ? statusBadge(job.status) : ""}</div><div class="panel-body">${breadcrumb}<form method="get" class="path-form"><input type="hidden" name="account" value="${escape(account)}"><label>路径前缀<input name="prefix" value="${escape(prefix)}" placeholder="例如：archives/"></label><button class="button button-secondary" type="submit">筛选元数据</button></form></div><div class="table-scroll"><table><thead><tr><th>路径</th><th>类型</th><th>明文大小</th><th>创建时间</th><th>修改时间</th><th>ETag</th></tr></thead><tbody>${objectRows || `<tr><td colspan="6" class="empty">此路径下没有可显示的备份元数据。</td></tr>`}</tbody></table></div>${cursor ? `<div class="panel-body"><a href="/admin?account=${encodeURIComponent(account)}&prefix=${encodeURIComponent(prefix)}&cursor=${encodeURIComponent(cursor)}">加载下一页元数据</a></div>` : ""}</div>${job ? `<div class="panel-body job">${statusBadge(job.status)}<p>已删除 ${job.deleted} 个对象。${job.error ? `错误摘要：${escape(job.error)}` : ""}${job.status === "failed" && job.failedKey ? `失败对象：<code>${escape(job.failedKey.replace(job.storagePrefix, ""))}</code>。排查后可重新发起移除任务。` : ""}</p>${["running", "paused"].includes(job.status) ? `<form class="form-actions" method="post" action="/admin/accounts/${encodeURIComponent(account)}/${job.status === "running" ? "pause" : "resume"}"><input type="hidden" name="csrf" value="${csrf}"><button class="button button-secondary" type="submit">${job.status === "running" ? "暂停移除任务" : "继续移除任务"}</button></form>` : ""}</div>` : ""}</section><section class="workspace"><div class="panel"><div class="panel-heading"><div><p class="eyebrow">Credentials</p><h2>重设密码</h2></div></div><div class="panel-body"><form method="post" action="/admin/accounts/${encodeURIComponent(account)}/password"><input type="hidden" name="csrf" value="${csrf}"><div class="field-grid compact"><label>新密码<input name="password" type="password" minlength="8" required autocomplete="new-password"></label><label>确认新密码<input name="passwordConfirmation" type="password" minlength="8" required autocomplete="new-password"></label></div><div class="form-actions"><button class="button" type="submit">更新账号密码</button></div></form></div></div><aside class="panel destructive"><div class="panel-heading"><div><p class="eyebrow">Irreversible action</p><h2>移除账号</h2></div></div><div class="panel-body"><p class="muted">这会停用账号并异步移除其全部备份对象。操作无法撤销。</p><form method="post" action="/admin/accounts/${encodeURIComponent(account)}/remove"><input type="hidden" name="csrf" value="${csrf}"><label>输入账号名确认<input name="confirmation" required autocomplete="off"></label><div class="form-actions"><button class="button button-danger" type="submit">移除账号及备份</button></div></form></div></aside></section>` : "";
  return layout("cf-webdav 管理", `<main class="shell"><header class="topbar"><a class="brand" href="/admin"><span class="brand-mark">wd</span><span>cf-webdav</span></a><form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="${csrf}"><button class="button button-secondary" type="submit">退出登录</button></form></header><div class="intro"><div><p class="eyebrow">Management surface</p><h1>管理概览</h1><p>集中管理 WebDAV 账号，并以只读方式检查备份元数据。${sessionNotice}</p></div></div>${errorNotice}${created ? `<p class="notice notice-success" role="status">账号 ${escape(created)} 已创建。点击账号名可查看其备份元数据。</p>` : ""}<section class="metrics" aria-label="账号状态摘要"><article class="metric"><span class="metric-label">账号总数</span><strong class="metric-value">${accounts.length}</strong></article><article class="metric"><span class="metric-label">已启用账号</span><strong class="metric-value metric-accent">${enabled}</strong></article><article class="metric"><span class="metric-label">未完成的移除任务</span><strong class="metric-value">${activeRemovals}</strong></article></section><section class="workspace"><div class="panel"><div class="panel-heading"><div><p class="eyebrow">Accounts</p><h2>账号</h2></div><span class="muted">选择账号查看元数据</span></div><div class="table-scroll"><table><thead><tr><th>账号</th><th>状态</th><th>移除任务</th><th aria-label="操作"></th></tr></thead><tbody>${rows || `<tr><td colspan="4" class="empty">暂无账号。请先在右侧创建一个账号。</td></tr>`}</tbody></table></div></div><aside class="panel"><div class="panel-heading"><div><p class="eyebrow">New account</p><h2>创建账号</h2></div></div><div class="panel-body"><form method="post" action="/admin/accounts"><input type="hidden" name="csrf" value="${csrf}"><div class="field-grid"><label>账号名<input name="account" required pattern="[a-z0-9][a-z0-9._-]{0,62}" placeholder="backup-prod" autocomplete="username"></label><label>初始密码<input name="password" type="password" minlength="8" required autocomplete="new-password"></label><label>确认初始密码<input name="passwordConfirmation" type="password" minlength="8" required autocomplete="new-password"></label></div><div class="form-actions"><button class="button" type="submit">创建账号</button></div></form></div></aside></section>${selected}</main>`);
}
