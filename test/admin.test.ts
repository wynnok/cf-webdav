import { describe, expect, it } from "vitest";
import { env, SELF } from "cloudflare:test";
import { Admin } from "../src/admin";
import { importKeyFromBytes } from "../src/crypto";
import { seedUser } from "./helpers";

async function login(): Promise<{ cookie: string; csrf: string }> {
  const res = await SELF.fetch("https://dav.example.com/admin/login", { method: "POST", redirect: "manual", headers: { Origin: "https://dav.example.com", "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ username: env.ADMIN_USERNAME, password: env.ADMIN_PASSWORD }) });
  expect(res.status).toBe(303);
  const cookie = res.headers.get("Set-Cookie")!.split(";")[0]!;
  const dashboard = await SELF.fetch("https://dav.example.com/admin", { headers: { Cookie: cookie } });
  const csrf = (await dashboard.text()).match(/name="csrf" value="([^"]+)"/)?.[1];
  expect(csrf).toBeTruthy();
  return { cookie, csrf: csrf! };
}

function form(cookie: string, csrf: string, values: Record<string, string>): RequestInit { return { method: "POST", redirect: "manual", headers: { Cookie: cookie, Origin: "https://dav.example.com", "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf, ...values }) }; }

describe("管理面", () => {
  it("缺少会话时跳转到登录页，错误管理员凭据被拒绝", async () => {
    expect((await SELF.fetch("https://dav.example.com/admin", { redirect: "manual" })).status).toBe(303);
    const bad = await SELF.fetch("https://dav.example.com/admin/login", { method: "POST", redirect: "manual", headers: { Origin: "https://dav.example.com", "Content-Type": "application/x-www-form-urlencoded" }, body: "username=admin&password=wrong" });
    expect(bad.status).toBe(401);
  });

  it("创建账号需要同源一次性 CSRF token，且新账号默认启用", async () => {
    const { cookie, csrf } = await login();
    const created = await SELF.fetch("https://dav.example.com/admin/accounts", form(cookie, csrf, { account: "managed", password: "new-password", passwordConfirmation: "new-password" }));
    expect(created.status).toBe(303);
    expect(JSON.parse((await env.ACCOUNTS_KV.get("users/managed"))!).disabled).not.toBe(true);
    const reused = await SELF.fetch("https://dav.example.com/admin/accounts", form(cookie, csrf, { account: "second", password: "new-password", passwordConfirmation: "new-password" }));
    expect(reused.status).toBe(403);
  });

  it("浏览只显示元数据，不返回备份内容", async () => {
    const user = await seedUser("metadata", "correct-horse-battery-staple");
    await env.BACKUP_BUCKET.put(`${user.prefix}secret.txt`, "encrypted-value", { customMetadata: { wdv_type: "file", wdv_size: "42", wdv_created: "2026-01-01T00:00:00.000Z", wdv_mtime: "2026-01-02T00:00:00.000Z", wdv_md5: "abc" } });
    const { cookie } = await login();
    const html = await (await SELF.fetch("https://dav.example.com/admin?account=metadata", { headers: { Cookie: cookie } })).text();
    expect(html).toContain("secret.txt"); expect(html).toContain("42"); expect(html).not.toContain("encrypted-value");
  });

  it("移除任务立即停用账号，Cron 删除前缀后才删除账号记录", async () => {
    const user = await seedUser("remove-me", "correct-horse-battery-staple");
    await env.BACKUP_BUCKET.put(`${user.prefix}one`, "ciphertext");
    const { cookie, csrf } = await login();
    expect((await SELF.fetch("https://dav.example.com/admin/accounts/remove-me/remove", form(cookie, csrf, { confirmation: "remove-me" }))).status).toBe(303);
    expect(JSON.parse((await env.ACCOUNTS_KV.get("users/remove-me"))!).disabled).toBe(true);
    await new Admin(env, await importKeyFromBytes(hex(env.MASTER_KEY))).runScheduled();
    expect(await env.ACCOUNTS_KV.get("users/remove-me")).toBeNull();
    expect((await env.BACKUP_BUCKET.list({ prefix: user.prefix })).objects).toHaveLength(0);
  });
});

function hex(value: string): Uint8Array { const out = new Uint8Array(value.length / 2); for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16); return out; }
