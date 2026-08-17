import { beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { env, SELF } from "cloudflare:test";
import { basicAuth, seedUser } from "./helpers";
import type { SeededUser } from "./helpers";

function md5Hex(data: Uint8Array): string {
  const h = createHash("md5");
  h.update(data);
  return h.digest("hex");
}

let user: SeededUser;
let auth: string;

beforeEach(async () => {
  user = await seedUser("alice", "correct-horse-battery-staple");
  auth = basicAuth("alice", "correct-horse-battery-staple");
});

function req(url: string, init: RequestInit = {}): Request {
  const headers = new Headers(init.headers ?? {});
  if (!headers.has("Authorization")) headers.set("Authorization", auth);
  return new Request(url, { ...init, headers });
}

describe("认证", () => {
  it("无凭据返回 401", async () => {
    const res = await SELF.fetch("https://dav.example.com/");
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toContain("Basic");
  });

  it("错误密码返回 401", async () => {
    const res = await SELF.fetch("https://dav.example.com/", {
      headers: { Authorization: basicAuth("alice", "wrong") },
    });
    expect(res.status).toBe(401);
  });

  it("成功认证的缓存不接受同账号的错误密码", async () => {
    expect((await SELF.fetch(req("https://dav.example.com/", { method: "OPTIONS" }))).status).toBe(200);
    const res = await SELF.fetch("https://dav.example.com/", {
      method: "PROPFIND",
      headers: { Authorization: basicAuth("alice", "wrong") },
    });
    expect(res.status).toBe(401);
  });

  it("不存在的用户返回 401", async () => {
    const res = await SELF.fetch("https://dav.example.com/", {
      headers: { Authorization: basicAuth("nobody", "x") },
    });
    expect(res.status).toBe(401);
  });

  it("账号停用后拒绝有效凭据", async () => {
    await seedUser("disabled-account", "correct-horse-battery-staple", { disabled: true });
    const res = await SELF.fetch("https://dav.example.com/", {
      headers: { Authorization: basicAuth("disabled-account", "correct-horse-battery-staple") },
    });
    expect(res.status).toBe(401);
  });

  it("已缓存账号被停用后下一请求被拒绝", async () => {
    expect((await SELF.fetch(req("https://dav.example.com/", { method: "OPTIONS" }))).status).toBe(200);
    const raw = JSON.parse((await env.ACCOUNTS_KV.get("users/alice"))!) as Record<string, unknown>;
    await env.ACCOUNTS_KV.put("users/alice", JSON.stringify({ ...raw, disabled: true }));
    const res = await SELF.fetch(req("https://dav.example.com/", { method: "OPTIONS" }));
    expect(res.status).toBe(401);
  });
});

describe("文件读写", () => {
  it("PUT 后 GET 往返一致", async () => {
    const body = "the quick brown fox jumps over the lazy dog 0123456789";
    let res = await SELF.fetch(req("https://dav.example.com/notes.txt", { method: "PUT", body }));
    expect(res.status).toBe(201);

    res = await SELF.fetch(req("https://dav.example.com/notes.txt"));
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(body);
  });

  it("覆盖写返回 204 并保留 created", async () => {
    await SELF.fetch(req("https://dav.example.com/f.txt", { method: "PUT", body: "first" }));
    const created1 = await propfind(await resOf("/f.txt"), "creationdate");
    const res = await SELF.fetch(req("https://dav.example.com/f.txt", { method: "PUT", body: "second" }));
    expect(res.status).toBe(204);
    const created2 = await propfind(await resOf("/f.txt"), "creationdate");
    expect(created1).toBe(created2);
  });

  it("If-None-Match:* 对已存在文件返回 412", async () => {
    await SELF.fetch(req("https://dav.example.com/f.txt", { method: "PUT", body: "x" }));
    const res = await SELF.fetch(
      req("https://dav.example.com/f.txt", { method: "PUT", body: "y", headers: { "If-None-Match": "*" } }),
    );
    expect(res.status).toBe(412);
  });

  it("已知长度超过部署上限时 PUT 返回 413 且不写入 R2", async () => {
    const body = new Uint8Array(env.MAX_PUT_BYTES + 1);
    const res = await SELF.fetch(req("https://dav.example.com/too-large.bin", { method: "PUT", body }));
    expect(res.status).toBe(413);
    expect(await env.BACKUP_BUCKET.head(`${user.prefix}too-large.bin`)).toBeNull();
  });

  it("GET 区间读返回 206 与 Content-Range", async () => {
    const body = "0123456789abcdefghijklmnopqrstuvwxyz";
    await SELF.fetch(req("https://dav.example.com/range.bin", { method: "PUT", body }));
    const res = await SELF.fetch(
      req("https://dav.example.com/range.bin", { headers: { Range: "bytes=10-19" } }),
    );
    expect(res.status).toBe(206);
    expect(res.headers.get("Content-Range")).toBe(`bytes 10-19/${body.length}`);
    expect(await res.text()).toBe("abcdefghij");
  });

  it("GET 尾部区间", async () => {
    const body = "0123456789abcdefghijklmnopqrstuvwxyz";
    await SELF.fetch(req("https://dav.example.com/range.bin", { method: "PUT", body }));
    const res = await SELF.fetch(
      req("https://dav.example.com/range.bin", { headers: { Range: "bytes=-5" } }),
    );
    expect(res.status).toBe(206);
    expect(await res.text()).toBe("vwxyz");
  });

  it("HEAD 返回长度且无正文", async () => {
    await SELF.fetch(req("https://dav.example.com/h.txt", { method: "PUT", body: "hello" }));
    const res = await SELF.fetch(req("https://dav.example.com/h.txt", { method: "HEAD" }));
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Length")).toBe("5");
    expect(await res.text()).toBe("");
  });

  it("R2 存储的是密文而非明文", async () => {
    const body = "this is a secret that must never appear in storage";
    await SELF.fetch(req("https://dav.example.com/sec.txt", { method: "PUT", body }));
    const obj = await env.BACKUP_BUCKET.get(`${user.prefix}sec.txt`);
    expect(obj).not.toBeNull();
    const stored = await obj!.arrayBuffer();
    const storedBytes = new Uint8Array(stored);
    expect(Buffer.from(stored).toString()).not.toContain("secret");
    expect(new TextDecoder().decode(storedBytes.slice(0, 4))).toBe("WDV2");
  });

  it("GET 的 ETag 是明文 MD5", async () => {
    const body = "etag-me-please";
    await SELF.fetch(req("https://dav.example.com/e.txt", { method: "PUT", body }));
    const res = await SELF.fetch(req("https://dav.example.com/e.txt"));
    expect(res.headers.get("ETag")).toBe(`"${md5Hex(new TextEncoder().encode(body))}"`);
  });

  it("流式 PUT(带 Content-Length)后 ETag 同样可用", async () => {
    const body = "streamed-etag-content";
    await SELF.fetch(req("https://dav.example.com/s.txt", {
      method: "PUT",
      body,
      headers: { "Content-Length": String(body.length) },
    }));
    const res = await SELF.fetch(req("https://dav.example.com/s.txt"));
    expect(res.headers.get("ETag")).toBe(`"${md5Hex(new TextEncoder().encode(body))}"`);
  });

  it("GET 期间对象被篡改时流以错误终止", async () => {
    const body = "integrity-check-content";
    await SELF.fetch(req("https://dav.example.com/tamper.bin", { method: "PUT", body }));
    const obj = await env.BACKUP_BUCKET.get(`${user.prefix}tamper.bin`);
    const stored = new Uint8Array(await obj!.arrayBuffer());
    stored[stored.length - 1]! ^= 0xff;
    await env.BACKUP_BUCKET.put(`${user.prefix}tamper.bin`, stored, { customMetadata: obj!.customMetadata });

    const res = await SELF.fetch(req("https://dav.example.com/tamper.bin"));
    expect(res.status).toBe(200);
    await expect(res.arrayBuffer()).rejects.toThrow();
  });

  it("PROPFIND 的 getetag 是明文 MD5", async () => {
    const body = "propfind-etag";
    await SELF.fetch(req("https://dav.example.com/p.txt", { method: "PUT", body }));
    const xml = await propfind(await resOf("/p.txt"), "getetag");
    expect(xml).toBe(`"${md5Hex(new TextEncoder().encode(body))}"`);
  });

  it("COPY 保留明文 MD5 作为 ETag", async () => {
    const body = "copied-etag-content";
    await SELF.fetch(req("https://dav.example.com/c.txt", { method: "PUT", body }));
    await SELF.fetch(req("https://dav.example.com/c.txt", {
      method: "COPY",
      headers: { Destination: "https://dav.example.com/c2.txt" },
    }));
    const res = await SELF.fetch(req("https://dav.example.com/c2.txt"));
    expect(res.headers.get("ETag")).toBe(`"${md5Hex(new TextEncoder().encode(body))}"`);
  });

  it("PROPFIND 列出文件与属性", async () => {
    await SELF.fetch(req("https://dav.example.com/doc.txt", { method: "PUT", body: "12345" }));
    const res = await SELF.fetch(
      req("https://dav.example.com/", {
        method: "PROPFIND",
        headers: { Depth: "1" },
        body: `<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:getcontentlength/><D:getetag/><D:getlastmodified/><D:resourcetype/></D:prop></D:propfind>`,
      }),
    );
    expect(res.status).toBe(207);
    const xml = await res.text();
    expect(xml).toContain("<D:href>/doc.txt</D:href>");
    expect(xml).toContain("<D:getcontentlength>5</D:getcontentlength>");
    expect(xml).toContain("<D:resourcetype></D:resourcetype>");
  });
});

describe("目录操作", () => {
  it("MKCOL 创建目录并在 PROPFIND 中可见", async () => {
    let res = await SELF.fetch(req("https://dav.example.com/backup/", { method: "MKCOL" }));
    expect(res.status).toBe(201);

    const marker = await env.BACKUP_BUCKET.head(`${user.prefix}backup/`);
    expect(marker).not.toBeNull();
    expect(marker!.customMetadata?.["wdv_type"]).toBe("dir");

    res = await SELF.fetch(
      req("https://dav.example.com/", { method: "PROPFIND", headers: { Depth: "1" } }),
    );
    expect(res.status).toBe(207);
    const xml = await res.text();
    expect(xml).toContain("<D:href>/backup/</D:href>");
    expect(xml).toContain("<D:collection/>");
  });

  it("父目录不存在时 MKCOL 返回 409", async () => {
    const res = await SELF.fetch(req("https://dav.example.com/a/b/", { method: "MKCOL" }));
    expect(res.status).toBe(409);
  });

  it("目录内 PUT 文件后可嵌套 PROPFIND", async () => {
    await SELF.fetch(req("https://dav.example.com/backup/", { method: "MKCOL" }));
    await SELF.fetch(req("https://dav.example.com/backup/x.db", { method: "PUT", body: "data" }));

    const res = await SELF.fetch(
      req("https://dav.example.com/backup/", { method: "PROPFIND", headers: { Depth: "1" } }),
    );
    expect(res.status).toBe(207);
    const xml = await res.text();
    expect(xml).toContain("<D:href>/backup/x.db</D:href>");
    expect(xml).toContain("<D:getcontentlength>4</D:getcontentlength>");
  });

  it("虚目录(未显式 MKCOL)也能被 PROPFIND 列出", async () => {
    await SELF.fetch(req("https://dav.example.com/auto/created.txt", { method: "PUT", body: "x" }));
    const res = await SELF.fetch(
      req("https://dav.example.com/auto/", { method: "PROPFIND", headers: { Depth: "1" } }),
    );
    expect(res.status).toBe(207);
    expect(await res.text()).toContain("<D:href>/auto/created.txt</D:href>");
  });
});

describe("删除 / 复制 / 移动", () => {
  it("DELETE 文件", async () => {
    await SELF.fetch(req("https://dav.example.com/gone.txt", { method: "PUT", body: "x" }));
    const res = await SELF.fetch(req("https://dav.example.com/gone.txt", { method: "DELETE" }));
    expect(res.status).toBe(204);
    const get = await SELF.fetch(req("https://dav.example.com/gone.txt"));
    expect(get.status).toBe(404);
  });

  it("DELETE 目录递归删除", async () => {
    await SELF.fetch(req("https://dav.example.com/d/", { method: "MKCOL" }));
    await SELF.fetch(req("https://dav.example.com/d/a.txt", { method: "PUT", body: "a" }));
    await SELF.fetch(req("https://dav.example.com/d/sub/", { method: "MKCOL" }));
    await SELF.fetch(req("https://dav.example.com/d/sub/b.txt", { method: "PUT", body: "b" }));

    const res = await SELF.fetch(req("https://dav.example.com/d/", { method: "DELETE" }));
    expect(res.status).toBe(204);

    const obj = await env.BACKUP_BUCKET.list({ prefix: user.prefix });
    expect(obj.objects.length).toBe(0);
  });

  it("COPY 文件内容与属性一致", async () => {
    await SELF.fetch(req("https://dav.example.com/src.txt", { method: "PUT", body: "copy-me" }));
    const res = await SELF.fetch(req("https://dav.example.com/src.txt", {
      method: "COPY",
      headers: { Destination: "https://dav.example.com/dst.txt" },
    }));
    expect(res.status).toBe(201);
    const got = await SELF.fetch(req("https://dav.example.com/dst.txt"));
    expect(await got.text()).toBe("copy-me");
  });

  it("MOVE 后源消失目标存在", async () => {
    await SELF.fetch(req("https://dav.example.com/m.txt", { method: "PUT", body: "mv" }));
    const res = await SELF.fetch(req("https://dav.example.com/m.txt", {
      method: "MOVE",
      headers: { Destination: "https://dav.example.com/m2.txt" },
    }));
    expect(res.status).toBe(201);
    expect((await SELF.fetch(req("https://dav.example.com/m.txt"))).status).toBe(404);
    expect(await (await SELF.fetch(req("https://dav.example.com/m2.txt"))).text()).toBe("mv");
  });
});

describe("锁", () => {
  it("LOCK → 未持锁 PUT 423 → 持锁成功 → UNLOCK", async () => {
    await SELF.fetch(req("https://dav.example.com/locky.txt", { method: "PUT", body: "v0" }));

    const lockRes = await SELF.fetch(
      req("https://dav.example.com/locky.txt", {
        method: "LOCK",
        headers: { Depth: "0", Timeout: "Second-600" },
        body: `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner>test</D:owner></D:lockinfo>`,
      }),
    );
    expect(lockRes.status).toBe(200);
    const lockXml = await lockRes.text();
    const tokenMatch = lockXml.match(/opaquelocktoken:[0-9a-f]+/);
    expect(tokenMatch).not.toBeNull();
    const token = tokenMatch![0];

    const blocked = await SELF.fetch(req("https://dav.example.com/locky.txt", { method: "PUT", body: "v1" }));
    expect(blocked.status).toBe(423);

    const held = await SELF.fetch(
      req("https://dav.example.com/locky.txt", {
        method: "PUT",
        body: "v2",
        headers: { If: `(<${token}>)` },
      }),
    );
    expect(held.status).toBe(204);

    const unlock = await SELF.fetch(
      req("https://dav.example.com/locky.txt", { method: "UNLOCK", headers: { "Lock-Token": `<${token}>` } }),
    );
    expect(unlock.status).toBe(204);

    const again = await SELF.fetch(req("https://dav.example.com/locky.txt", { method: "PUT", body: "v3" }));
    expect(again.status).toBe(204);
  });

  it("目录锁定阻止目录内写入", async () => {
    await SELF.fetch(req("https://dav.example.com/lockdir/", { method: "MKCOL" }));
    const lockRes = await SELF.fetch(
      req("https://dav.example.com/lockdir/", {
        method: "LOCK",
        headers: { Depth: "infinity", Timeout: "Second-300" },
        body: `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>`,
      }),
    );
    expect(lockRes.status).toBe(200);
    const token = (await lockRes.text()).match(/opaquelocktoken:[0-9a-f]+/)![0];

    const blocked = await SELF.fetch(req("https://dav.example.com/lockdir/inner.txt", { method: "PUT", body: "x" }));
    expect(blocked.status).toBe(423);

    const ok = await SELF.fetch(
      req("https://dav.example.com/lockdir/inner.txt", {
        method: "PUT",
        body: "x",
        headers: { If: `(<${token}>)` },
      }),
    );
    expect(ok.status).toBe(201);
  });
});

async function resOf(path: string): Promise<string> {
  const res = await SELF.fetch(req(`https://dav.example.com${path}`, { method: "PROPFIND", headers: { Depth: "0" } }));
  return res.text();
}

async function propfind(xml: string, prop: string): Promise<string | null> {
  const re = new RegExp(`<D:${prop}>([^<]*)</D:${prop}>`);
  return xml.match(re)?.[1] ?? null;
}
