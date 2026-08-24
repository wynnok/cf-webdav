import { describe, expect, it, vi } from "vitest";
import { env, SELF } from "cloudflare:test";
import { Admin } from "../src/admin";
import { validPbkdf2Iterations } from "../src/auth";
import { importKeyFromBytes } from "../src/crypto";
import { basicAuth, seedUser } from "./helpers";

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

  it("浏览器省略或屏蔽 Origin 头时登录不被拒绝，跨站 Origin 仍被拒绝", async () => {
    const noOrigin = await SELF.fetch("https://dav.example.com/admin/login", { method: "POST", redirect: "manual", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ username: env.ADMIN_USERNAME, password: env.ADMIN_PASSWORD }) });
    expect(noOrigin.status).toBe(303);
    const nulled = await SELF.fetch("https://dav.example.com/admin/login", { method: "POST", redirect: "manual", headers: { Origin: "null", "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ username: env.ADMIN_USERNAME, password: env.ADMIN_PASSWORD }) });
    expect(nulled.status).toBe(303);
    const cookie = nulled.headers.get("Set-Cookie")!.split(";")[0]!;
    const dashboard = await (await SELF.fetch("https://dav.example.com/admin", { headers: { Cookie: cookie } })).text();
    const csrf = dashboard.match(/name="csrf" value="([^"]+)"/)?.[1]!;
    const create = await SELF.fetch("https://dav.example.com/admin/accounts", { method: "POST", redirect: "manual", headers: { Cookie: cookie, Origin: "null", "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf, account: "no-origin", password: "new-password", passwordConfirmation: "new-password" }) });
    expect(create.status).toBe(303);
    const crossSite = await SELF.fetch("https://dav.example.com/admin/login", { method: "POST", redirect: "manual", headers: { Origin: "https://evil.example.net", "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ username: env.ADMIN_USERNAME, password: env.ADMIN_PASSWORD }) });
    expect(crossSite.status).toBe(403);
  });

  it("管理首页提供带视口设置、状态摘要和语义化账号列表的响应式界面", async () => {
    const { cookie } = await login();
    const response = await SELF.fetch("https://dav.example.com/admin", { headers: { Cookie: cookie } });
    const html = await response.text();
    expect(html).toContain('name="viewport"');
    expect(html).toContain("管理概览");
    expect(html).toContain("账号总数");
    expect(html).toContain('class="table-scroll"');
    expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });

  it("创建账号需要同源一次性 CSRF token，且新账号默认启用", async () => {
    const { cookie, csrf } = await login();
    const created = await SELF.fetch("https://dav.example.com/admin/accounts", form(cookie, csrf, { account: "managed", password: "new-password", passwordConfirmation: "new-password" }));
    expect(created.status).toBe(303);
    expect(created.headers.get("Location")).toBe("/admin?created=managed");
    const record = JSON.parse((await env.ACCOUNTS_KV.get("users/managed"))!);
    expect(record.disabled).not.toBe(true);
    expect(record.storagePrefix).toMatch(/^accounts\/[0-9a-f-]+\/$/);
    expect((await SELF.fetch("https://dav.example.com/new.txt", { method: "PUT", headers: { Authorization: basicAuth("managed", "new-password"), "Content-Length": "5" }, body: "hello" })).status).toBe(201);
    expect((await env.BACKUP_BUCKET.list({ prefix: record.storagePrefix })).objects).toHaveLength(1);
    const reused = await SELF.fetch("https://dav.example.com/admin/accounts", form(cookie, csrf, { account: "second", password: "new-password", passwordConfirmation: "new-password" }));
    expect(reused.status).toBe(403);
  });

  it("概览页不读取账号元数据，只有选择账号时才显示", async () => {
    const user = await seedUser("on-demand", "correct-horse-battery-staple");
    await env.BACKUP_BUCKET.put(`${user.prefix}private.txt`, "encrypted-value", { customMetadata: { wdv_type: "file", wdv_size: "42" } });
    const { cookie } = await login();
    const overview = await (await SELF.fetch("https://dav.example.com/admin", { headers: { Cookie: cookie } })).text();
    expect(overview).not.toContain("private.txt");
    const detail = await (await SELF.fetch("https://dav.example.com/admin?account=on-demand", { headers: { Cookie: cookie } })).text();
    expect(detail).toContain("private.txt");
  });

  it("操作失败时概览页渲染对应的错误提示", async () => {
    const { cookie } = await login();
    const html = await (await SELF.fetch("https://dav.example.com/admin?error=invalid-account", { headers: { Cookie: cookie } })).text();
    expect(html).toContain("账号名或密码不符合要求");
  });

  it("创建账号成功提示使用成功样式而非错误样式", async () => {
    const { cookie } = await login();
    const html = await (await SELF.fetch("https://dav.example.com/admin?created=managed", { headers: { Cookie: cookie } })).text();
    expect(html).toMatch(/class="notice notice-success"/);
    expect(html).not.toMatch(/class="notice"[^>]*>账号 managed/);
  });

  it("元数据浏览显示逐级返回的面包屑导航", async () => {
    const user = await seedUser("breadcrumb", "correct-horse-battery-staple");
    await env.BACKUP_BUCKET.put(`${user.prefix}photos/2026/`, "dir", { customMetadata: { wdv_type: "dir" } });
    const { cookie } = await login();
    const html = await (await SELF.fetch("https://dav.example.com/admin?account=breadcrumb&prefix=photos/2026/", { headers: { Cookie: cookie } })).text();
    expect(html).toContain("面包屑");
    expect(html).toContain(`&prefix=${encodeURIComponent("photos/")}`);
    expect(html).toContain(`&prefix=${encodeURIComponent("photos/2026/")}`);
  });

  it("明文大小以易读格式显示", async () => {
    const user = await seedUser("readable", "correct-horse-battery-staple");
    await env.BACKUP_BUCKET.put(`${user.prefix}big.bin`, "ciphertext", { customMetadata: { wdv_type: "file", wdv_size: "1572864" } });
    const { cookie } = await login();
    const html = await (await SELF.fetch("https://dav.example.com/admin?account=readable", { headers: { Cookie: cookie } })).text();
    expect(html).toContain("1.5 MiB");
  });

  it("概览页显示管理员会话剩余时长", async () => {
    const { cookie } = await login();
    const html = await (await SELF.fetch("https://dav.example.com/admin", { headers: { Cookie: cookie } })).text();
    expect(html).toMatch(/会话剩余(约 [0-9]+ 小时|不足 1 小时)/);
  });

  it("失败的移除任务显示失败对象路径和重试指引", async () => {
    const user = await seedUser("failed-job", "correct-horse-battery-staple");
    await env.ADMIN_KV.put("removals/failed-job", JSON.stringify({ account: "failed-job", userId: user.id, storagePrefix: user.prefix, status: "failed", deleted: 3, retries: 3, failedKey: `${user.prefix}stuck.bin`, error: "R2 delete failed", updatedAt: new Date().toISOString(), finishedAt: new Date().toISOString() }));
    const { cookie } = await login();
    const html = await (await SELF.fetch("https://dav.example.com/admin?account=failed-job", { headers: { Cookie: cookie } })).text();
    expect(html).toContain("stuck.bin");
    expect(html).not.toContain(user.prefix);
    expect(html).toContain("重新发起移除");
  });

  it("拒绝超过 Workers 支持上限的 PBKDF2 配置", () => {
    expect(validPbkdf2Iterations(100000)).toBe(true);
    expect(validPbkdf2Iterations(100001)).toBe(false);
  });

  it("不再接受缺少 accounts 存储前缀的旧账号记录", async () => {
    const user = await seedUser("old-layout", "correct-horse-battery-staple");
    const record = JSON.parse((await env.ACCOUNTS_KV.get("users/old-layout"))!);
    delete record.storagePrefix;
    await env.ACCOUNTS_KV.put("users/old-layout", JSON.stringify(record));
    expect((await SELF.fetch("https://dav.example.com/", { headers: { Authorization: basicAuth(user.username, "correct-horse-battery-staple") } })).status).toBe(401);
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
    expect(await env.ADMIN_KV.get("scheduler/removals-pending")).toBe("1");
    await new Admin(env, await importKeyFromBytes(hex(env.MASTER_KEY))).runScheduled();
    expect(await env.ACCOUNTS_KV.get("users/remove-me")).toBeNull();
    expect((await env.BACKUP_BUCKET.list({ prefix: user.prefix })).objects).toHaveLength(0);
    expect(await env.ADMIN_KV.get("scheduler/removals-pending")).toBeNull();
  });

  it("没有待处理移除任务时，定时任务不扫描管理 KV", async () => {
    await env.ADMIN_KV.delete("scheduler/removals-pending");
    await env.ADMIN_KV.put("scheduler/removals-index-v1", "1");
    const list = vi.spyOn(env.ADMIN_KV, "list");

    await new Admin(env, await importKeyFromBytes(hex(env.MASTER_KEY))).runScheduled();

    expect(list).not.toHaveBeenCalled();
    list.mockRestore();
  });

  it("暂停任务继续后重新进入定时任务索引", async () => {
    const user = await seedUser("pause-resume", "correct-horse-battery-staple");
    await env.BACKUP_BUCKET.put(`${user.prefix}one`, "ciphertext");
    const { cookie, csrf } = await login();
    await SELF.fetch("https://dav.example.com/admin/accounts/pause-resume/remove", form(cookie, csrf, { confirmation: "pause-resume" }));

    const afterRemove = await SELF.fetch("https://dav.example.com/admin?account=pause-resume", { headers: { Cookie: cookie } });
    const pauseCsrf = (await afterRemove.text()).match(/name="csrf" value="([^"]+)"/)?.[1];
    expect(pauseCsrf).toBeTruthy();
    const paused = await SELF.fetch("https://dav.example.com/admin/accounts/pause-resume/pause", form(cookie, pauseCsrf!, {}));
    expect(paused.status).toBe(303);
    await env.ADMIN_KV.delete("scheduler/removals-pending");
    expect(await env.ADMIN_KV.get("scheduler/removals-pending")).toBeNull();

    const dashboard = await SELF.fetch("https://dav.example.com/admin?account=pause-resume", { headers: { Cookie: cookie } });
    const resumeCsrf = (await dashboard.text()).match(/name="csrf" value="([^"]+)"/)?.[1];
    expect(resumeCsrf).toBeTruthy();
    const resumed = await SELF.fetch("https://dav.example.com/admin/accounts/pause-resume/resume", form(cookie, resumeCsrf!, {}));
    expect(resumed.status).toBe(303);
    expect(await env.ADMIN_KV.get("scheduler/removals-pending")).toBe("1");
  });

});

function hex(value: string): Uint8Array { const out = new Uint8Array(value.length / 2); for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16); return out; }
