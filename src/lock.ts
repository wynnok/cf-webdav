import { WebDavError } from "./storage";

export interface ActiveLock {
  token: string;
  owner: string;
  depth: "0" | "infinity";
  timeoutSeconds: number;
  expiresAt: number;
  created: string;
}

export function newLockToken(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `opaquelocktoken:${hex}`;
}

export class LockManager {
  constructor(
    private kv: KVNamespace,
    private userId: string,
    private defaultTimeoutSeconds: number,
  ) {}

  private key(path: string): string {
    return `locks/${this.userId}/${path}`;
  }

  private parse(raw: string | null): ActiveLock | null {
    if (!raw) return null;
    try {
      const lock = JSON.parse(raw) as ActiveLock;
      if (lock.expiresAt <= Date.now()) return null;
      return lock;
    } catch {
      return null;
    }
  }

  async get(path: string): Promise<ActiveLock | null> {
    return this.parse(await this.kv.get(this.key(path)));
  }

  async create(path: string, owner: string, depth: "0" | "infinity", timeoutSeconds: number): Promise<ActiveLock> {
    const existing = await this.get(path);
    if (existing) throw new WebDavError(423, "资源已被锁定", "lock-token-submitted");
    const now = Date.now();
    const lock: ActiveLock = {
      token: newLockToken(),
      owner,
      depth,
      timeoutSeconds,
      expiresAt: now + timeoutSeconds * 1000,
      created: new Date(now).toISOString(),
    };
    await this.kv.put(this.key(path), JSON.stringify(lock), { expirationTtl: timeoutSeconds });
    return lock;
  }

  async refresh(path: string, token: string, timeoutSeconds: number): Promise<ActiveLock> {
    const lock = await this.get(path);
    if (!lock) throw new WebDavError(412, "锁已过期");
    if (lock.token !== token) throw new WebDavError(423, "资源已被其他锁持有", "lock-token-submitted");
    lock.expiresAt = Date.now() + timeoutSeconds * 1000;
    await this.kv.put(this.key(path), JSON.stringify(lock), { expirationTtl: timeoutSeconds });
    return lock;
  }

  async remove(path: string, token: string): Promise<boolean> {
    const lock = await this.get(path);
    if (!lock) return false;
    if (lock.token !== token) throw new WebDavError(409, "Lock-Token 不匹配");
    await this.kv.delete(this.key(path));
    return true;
  }

  /** 检查 path 自身及所有祖先的锁,若被其他 token 持有则抛 423。 */
  async assertWritable(path: string, heldTokens: Set<string>): Promise<void> {
    const parts = path ? path.split("/") : [];
    const candidates: string[] = [];
    for (let i = 0; i <= parts.length; i++) {
      candidates.push(parts.slice(0, i).join("/"));
    }
    const locks = await Promise.all(candidates.map((p) => this.get(p)));
    for (const lock of locks) {
      if (lock && !heldTokens.has(lock.token)) {
        throw new WebDavError(423, `资源被锁:${lock.token}`, "lock-token-submitted");
      }
    }
  }

  /** 列出 path 下(含自身)所有锁,用于目录删除/移动。 */
  async listUnder(path: string): Promise<ActiveLock[]> {
    const out: ActiveLock[] = [];
    const base = `locks/${this.userId}/`;
    const prefix = path ? `${base}${path}` : base;
    let cursor: string | undefined;
    do {
      const res = await this.kv.list({ prefix, cursor });
      for (const k of res.keys) {
        const lock = this.parse(await this.kv.get(k.name));
        if (lock) out.push(lock);
      }
      cursor = res.list_complete ? undefined : res.cursor;
    } while (cursor);
    return out;
  }
}

export function parseIfHeader(header: string | null): Set<string> {
  const tokens = new Set<string>();
  if (!header) return tokens;
  const re = /opaquelocktoken:[0-9a-fA-F]+/g;
  for (const m of header.matchAll(re)) tokens.add(m[0]);
  return tokens;
}

export function parseLockInfo(body: string): { scope: "exclusive" | "shared"; owner: string; depth: "0" | "infinity" } {
  const scope = body.includes("shared") ? "shared" : "exclusive";
  const depthRaw = (body.match(/<D?:depth[^>]*>\s*(infinity|0)\s*<\/D?:depth>/i) ?? [])[1] ?? "infinity";
  const depth = depthRaw === "0" ? "0" : "infinity";
  const ownerMatch = body.match(/<D?:owner[^>]*>([\s\S]*?)<\/D?:owner>/i);
  let owner = ownerMatch ? ownerMatch[1]!.trim() : "";
  if (/^<[^>]+>.*<\/[^>]+>$/.test(owner)) {
    const inner = owner.match(/<[^>]+>([\s\S]*?)<\/[^>]+>/);
    owner = inner ? inner[1]!.trim() : "";
  }
  return { scope, owner, depth };
}
