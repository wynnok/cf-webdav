import { base64ToBytes, bytesToBase64, constantTimeEqual, decodeBase64Utf8 } from "./util";
import { DATA_KEY_LENGTH, IntegrityError, unwrapKey } from "./crypto";
import type { Env } from "./env";

export interface UserRecord {
  v: 1;
  id: string;
  salt: string;
  iter: number;
  hash: string;
  keyWrapped: string;
  created: string;
  disabled?: boolean;
}

export interface AuthenticatedUser {
  userId: string;
  username: string;
  prefix: string;
  dataKey: CryptoKey;
}

export async function pbkdf2Hash(password: string, saltB64: string, iterations: number): Promise<string> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: base64ToBytes(saltB64) as BufferSource, iterations },
    keyMaterial,
    256,
  );
  return bytesToBase64(new Uint8Array(bits));
}

export function normalizeUsername(username: string): string {
  return username.trim().toLowerCase();
}

function parseBasicAuth(authHeader: string): { username: string; password: string } | null {
  if (!authHeader.startsWith("Basic ")) return null;
  const b64 = authHeader.slice(6).trim();
  let decoded: string;
  try {
    decoded = decodeBase64Utf8(b64);
  } catch {
    return null;
  }
  const idx = decoded.indexOf(":");
  if (idx < 0) return null;
  return { username: decoded.slice(0, idx), password: decoded.slice(idx + 1) };
}

interface CacheEntry {
  dataKey: CryptoKey;
  expires: number;
}

const authenticationCache = new Map<string, CacheEntry>();

export class Auth {
  constructor(
    private kv: KVNamespace,
    private masterKey: CryptoKey,
    private pbkdf2Iterations: number,
    private cacheTtlMs: number,
  ) {}

  async authenticate(request: Request): Promise<AuthenticatedUser | null> {
    const header = request.headers.get("Authorization");
    if (!header) return null;
    const creds = parseBasicAuth(header);
    if (!creds) return null;

    const username = normalizeUsername(creds.username);
    const record = await this.loadRecord(username);
    if (!record || record.disabled) return null;

    const cacheKey = await authenticationCacheKey(header, record);
    const now = Date.now();
    const cached = authenticationCache.get(cacheKey);
    if (cached && cached.expires > now) {
      return this.toUser(record, cached.dataKey, username);
    }

    const hash = await pbkdf2Hash(creds.password, record.salt, record.iter);
    if (!constantTimeEqual(hash, record.hash)) {
      return null;
    }

    let dataKey: CryptoKey;
    try {
      dataKey = await unwrapKey(this.masterKey, record.keyWrapped);
    } catch {
      return null;
    }

    authenticationCache.set(cacheKey, { dataKey, expires: now + this.cacheTtlMs });
    if (authenticationCache.size > 1000) {
      const nowMs = Date.now();
      for (const [k, v] of authenticationCache) {
        if (v.expires <= nowMs) authenticationCache.delete(k);
      }
    }
    return this.toUser(record, dataKey, username);
  }

  async loadRecord(username: string): Promise<UserRecord | null> {
    const raw = await this.kv.get(`users/${username}`);
    if (!raw) return null;
    try {
      return JSON.parse(raw) as UserRecord;
    } catch {
      return null;
    }
  }

  private toUser(record: UserRecord, dataKey: CryptoKey, username: string): AuthenticatedUser {
    return {
      userId: record.id,
      username,
      prefix: `u/${record.id}/`,
      dataKey,
    };
  }
}

async function authenticationCacheKey(authorization: string, record: UserRecord): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`${authorization}\n${record.hash}\n${record.keyWrapped}`),
  );
  return bytesToBase64(new Uint8Array(digest));
}

export function makeUserRecord(
  id: string,
  username: string,
  salt: Uint8Array,
  iterations: number,
  hash: string,
  keyWrapped: string,
): UserRecord {
  return {
    v: 1,
    id,
    salt: bytesToBase64(salt),
    iter: iterations,
    hash,
    keyWrapped,
    created: new Date().toISOString(),
  };
}

export function validateUserRecord(record: UserRecord): void {
  if (record.v !== 1) throw new Error("不支持的 user record 版本");
  if (!record.id || !record.salt || !record.iter || !record.hash || !record.keyWrapped) {
    throw new Error("user record 字段缺失");
  }
}

export function unwrapDataKeyFromRecord(masterKey: CryptoKey, record: UserRecord): Promise<CryptoKey> {
  if (record.keyWrapped.length < 2 * (DATA_KEY_LENGTH + 16)) {
    throw new IntegrityError("密钥数据过短");
  }
  return unwrapKey(masterKey, record.keyWrapped);
}
