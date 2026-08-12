import { makeUserRecord, normalizeUsername, pbkdf2Hash, type UserRecord } from "./auth";
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
    return page(dashboardPage(accounts, account, prefix, objects.objects, objects.cursor, job, csrf));
  }

  private async create(request: Request): Promise<Response> {
    const form = await request.formData();
    const account = normalizeUsername(String(form.get("account") ?? ""));
    const password = String(form.get("password") ?? "");
    if (!validAccount(account) || password.length < 8 || password !== String(form.get("passwordConfirmation") ?? "") || await this.record(account)) return redirect("/admin?error=invalid-account");
    const salt = randomBytes(16);
    const hash = await pbkdf2Hash(password, bytesToBase64(salt), this.env.PBKDF2_ITERATIONS ?? 210000);
    const record = makeUserRecord(crypto.randomUUID(), account, salt, this.env.PBKDF2_ITERATIONS ?? 210000, hash, await wrapKey(this.masterKey, generateDataKey()));
    await this.env.ACCOUNTS_KV.put(`users/${account}`, JSON.stringify(record));
    audit("account.create", account, "success");
    return redirect(`/admin?account=${encodeURIComponent(account)}`);
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
      await this.env.ACCOUNTS_KV.put(`users/${account}`, JSON.stringify({ ...record, salt: bytesToBase64(salt), hash: await pbkdf2Hash(password, bytesToBase64(salt), record.iter) }));
    } else if (action === "remove") {
      const form = await request.formData();
      if (String(form.get("confirmation") ?? "") !== account) return redirect(`/admin?account=${encodeURIComponent(account)}&error=confirmation`);
      const now = new Date().toISOString();
      const gate = this.env.ADMIN_CSRF.get(this.env.ADMIN_CSRF.idFromName(`account/${record.id}`));
      await gate.fetch("https://admin/removal", { method: "POST" });
      await this.env.ACCOUNTS_KV.put(`users/${account}`, JSON.stringify({ ...record, disabled: true }));
      await this.saveJob({ account, userId: record.id, status: "running", deleted: 0, retries: 0, updatedAt: now });
    } else return response("Not Found", 404);
    audit(`account.${action}`, account, "success");
    return redirect(`/admin?account=${encodeURIComponent(account)}`);
  }

  private async removeBatch(job: RemovalJob): Promise<void> {
    try {
      const gate = this.env.ADMIN_CSRF.get(this.env.ADMIN_CSRF.idFromName(`account/${job.userId}`));
      const activity = await (await gate.fetch("https://admin/removal")).json<{ active: number }>();
      if (activity.active > 0) return;
      const listed = await this.env.BACKUP_BUCKET.list({ prefix: `u/${job.userId}/`, limit: BATCH_SIZE });
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
    const base = `u/${record.id}/${prefix}`;
    const listed = await this.env.BACKUP_BUCKET.list({ prefix: base, delimiter: "/", cursor, limit: 100 });
    // R2 list() omits custom metadata; only head the current read-only page.
    const heads = await Promise.all(listed.objects.map((object) => this.env.BACKUP_BUCKET.head(object.key)));
    const directories = (listed.delimitedPrefixes ?? []).map((key) => ({ path: key.slice(`u/${record.id}/`.length), type: "directory", size: "-", created: "-", mtime: "-", etag: "-" }));
    return { objects: [...directories, ...heads.filter((object): object is R2Object => object !== null).map((object) => objectMetadata(object, record.id))], cursor: listed.truncated ? listed.cursor : undefined };
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
  private async record(account: string): Promise<UserRecord | null> { const raw = await this.env.ACCOUNTS_KV.get(`users/${account}`); return raw ? JSON.parse(raw) as UserRecord : null; }
  private async job(account: string): Promise<RemovalJob | null> { const raw = await this.env.ADMIN_KV.get(`removals/${account}`); return raw ? JSON.parse(raw) as RemovalJob : null; }
  private saveJob(job: RemovalJob): Promise<void> { return this.env.ADMIN_KV.put(`removals/${job.account}`, JSON.stringify(job)); }
}

interface Metadata { path: string; type: string; size: string; created: string; mtime: string; etag: string }
function objectMetadata(object: R2Object, userId: string): Metadata { const m = object.customMetadata ?? {}; return { path: object.key.slice(`u/${userId}/`.length), type: m.wdv_type ?? "file", size: m.wdv_size ?? "unknown", created: m.wdv_created ?? object.uploaded.toISOString(), mtime: m.wdv_mtime ?? object.uploaded.toISOString(), etag: m.wdv_md5 ?? object.etag }; }
function validAccount(value: string): boolean { return /^[a-z0-9][a-z0-9._-]{0,62}$/.test(value); }
function sameOrigin(request: Request): boolean { return request.headers.get("Origin") === new URL(request.url).origin; }
function cookie(header: string | null, name: string): string | null { return header?.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`))?.slice(name.length + 1) ?? null; }
function response(body: string, status: number): Response { return new Response(body, { status, headers: { "Cache-Control": "no-store" } }); }
function page(body: string, status = 200): Response { return new Response(body, { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } }); }
function redirect(path: string): Response { return new Response(null, { status: 303, headers: { Location: path, "Cache-Control": "no-store" } }); }
function escape(value: string): string { return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
function audit(action: string, account: string, result: string): void { console.log(JSON.stringify({ event: "admin.action", action, account, result, time: new Date().toISOString() })); }
function loginPage(error = ""): string { return `<!doctype html><title>cf-webdav 管理</title><main><h1>cf-webdav 管理</h1>${error ? `<p>${escape(error)}</p>` : ""}<form method="post" action="/admin/login"><label>用户名 <input name="username" required autocomplete="username"></label><label>密码 <input name="password" type="password" required autocomplete="current-password"></label><button>登录</button></form></main>`; }
function dashboardPage(accounts: Array<{ account: string; record: UserRecord; job: RemovalJob | null }>, account: string, prefix: string, objects: Metadata[], cursor: string | undefined, job: RemovalJob | null, csrf: string): string {
  const rows = accounts.map(({ account: name, record, job }) => `<tr><td><a href="/admin?account=${encodeURIComponent(name)}">${escape(name)}</a></td><td>${record.disabled ? "已停用" : "已启用"}</td><td>${job?.status ?? "-"}</td><td><form method="post" action="/admin/accounts/${encodeURIComponent(name)}/${record.disabled ? "enable" : "disable"}"><input type="hidden" name="csrf" value="${csrf}"><button>${record.disabled ? "启用" : "停用"}</button></form></td></tr>`).join("");
  const objectRows = objects.map((o) => {
    const path = o.type === "directory"
      ? `<a href="/admin?account=${encodeURIComponent(account)}&prefix=${encodeURIComponent(o.path)}">${escape(o.path)}</a>`
      : escape(o.path);
    return `<tr><td>${path}</td><td>${escape(o.type)}</td><td>${escape(o.size)}</td><td>${escape(o.created)}</td><td>${escape(o.mtime)}</td><td>${escape(o.etag)}</td></tr>`;
  }).join("");
  const selected = account ? `<section><h2>账号：${escape(account)}</h2><form method="get"><input type="hidden" name="account" value="${escape(account)}"><label>路径前缀 <input name="prefix" value="${escape(prefix)}"></label><button>筛选</button></form><table><tr><th>路径</th><th>类型</th><th>明文大小</th><th>创建时间</th><th>修改时间</th><th>ETag</th></tr>${objectRows}</table>${cursor ? `<a href="/admin?account=${encodeURIComponent(account)}&prefix=${encodeURIComponent(prefix)}&cursor=${encodeURIComponent(cursor)}">下一页</a>` : ""}<h3>重设密码</h3><form method="post" action="/admin/accounts/${encodeURIComponent(account)}/password"><input type="hidden" name="csrf" value="${csrf}"><input name="password" type="password" minlength="8" required><input name="passwordConfirmation" type="password" minlength="8" required><button>重设密码</button></form><h3>移除账号</h3><form method="post" action="/admin/accounts/${encodeURIComponent(account)}/remove"><input type="hidden" name="csrf" value="${csrf}"><label>输入账号名确认 <input name="confirmation" required></label><button>移除账号</button></form>${job ? `<p>移除任务：${job.status}，已删除 ${job.deleted} 个对象。${job.error ? `错误：${escape(job.error)}` : ""}</p>${["running", "paused"].includes(job.status) ? `<form method="post" action="/admin/accounts/${encodeURIComponent(account)}/${job.status === "running" ? "pause" : "resume"}"><input type="hidden" name="csrf" value="${csrf}"><button>${job.status === "running" ? "暂停" : "继续"}</button></form>` : ""}` : ""}</section>` : "";
  return `<!doctype html><title>cf-webdav 管理</title><main><form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="${csrf}"><button>退出</button></form><h1>cf-webdav 管理</h1><h2>创建账号</h2><form method="post" action="/admin/accounts"><input type="hidden" name="csrf" value="${csrf}"><input name="account" required pattern="[a-z0-9][a-z0-9._-]{0,62}" placeholder="账号"><input name="password" type="password" minlength="8" required placeholder="密码"><input name="passwordConfirmation" type="password" minlength="8" required placeholder="确认密码"><button>创建</button></form><h2>账号</h2><table><tr><th>账号</th><th>状态</th><th>移除任务</th><th>操作</th></tr>${rows}</table>${selected}</main>`;
}
