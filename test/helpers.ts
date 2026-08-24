import { env } from "cloudflare:test";
import { invalidateAuthCache, pbkdf2Hash } from "../src/auth";
import { generateDataKey, importKeyFromBytes, wrapKey, randomBytes } from "../src/crypto";
import { bytesToBase64 } from "../src/util";

export interface SeededUser {
  id: string;
  username: string;
  prefix: string;
}

export async function seedUser(
  username: string,
  password: string,
  opts: { disabled?: boolean } = {},
): Promise<SeededUser> {
  invalidateAuthCache(username);
  const master = await importKeyFromBytes(hex(env.MASTER_KEY));
  const salt = randomBytes(16);
  const hash = await pbkdf2Hash(password, bytesToBase64(salt), env.PBKDF2_ITERATIONS);
  const dataKey = generateDataKey();
  const keyWrapped = await wrapKey(master, dataKey);
  const id = crypto.randomUUID();
  const record = {
    v: 1,
    id,
    salt: bytesToBase64(salt),
    iter: env.PBKDF2_ITERATIONS,
    hash,
    keyWrapped,
    created: new Date().toISOString(),
    storagePrefix: `accounts/${id}/`,
    disabled: opts.disabled,
  };
  await env.ACCOUNTS_KV.put(`users/${username.toLowerCase()}`, JSON.stringify(record));
  return { id, username, prefix: `accounts/${id}/` };
}

function hex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function basicAuth(username: string, password: string): string {
  return `Basic ${btoa(`${username}:${password}`)}`;
}
