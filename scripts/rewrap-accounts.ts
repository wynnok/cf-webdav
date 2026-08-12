import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

interface AccountRecord {
  keyWrapped: string;
  [field: string]: unknown;
}

interface AccountExport {
  version: 1;
  accounts: Array<{ key: string; record: AccountRecord }>;
  [field: string]: unknown;
}

function b64(bytes: Uint8Array): string {
  let binary = "";
  const step = 0x8000;
  for (let i = 0; i < bytes.length; i += step) {
    binary += String.fromCharCode(...bytes.subarray(i, i + step));
  }
  return btoa(binary);
}

function masterKey(name: "OLD_MASTER_KEY" | "NEW_MASTER_KEY"): Buffer {
  const hex = process.env[name];
  if (!hex || !/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`${name} 必须是 32 字节(64 个 hex 字符)`);
  }
  return Buffer.from(hex, "hex");
}

function unwrapKey(wrappedB64: string, master: Buffer): Buffer {
  const blob = Buffer.from(wrappedB64, "base64");
  if (blob.length !== 12 + 32 + 16) throw new Error("keyWrapped 格式无效");
  const iv = blob.subarray(0, 12);
  const ciphertext = blob.subarray(12, -16);
  const tag = blob.subarray(-16);
  const decipher = createDecipheriv("aes-256-gcm", master, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function wrapKey(dataKey: Buffer, master: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", master, iv);
  const ciphertext = Buffer.concat([cipher.update(dataKey), cipher.final()]);
  return b64(Buffer.concat([iv, ciphertext, cipher.getAuthTag()]));
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function usage(): never {
  console.error("用法: OLD_MASTER_KEY=<64hex> NEW_MASTER_KEY=<64hex> npm run accounts:rewrap -- <input.json> <output.json>");
  process.exit(1);
}

function main(): void {
  const [input, output] = process.argv.slice(2);
  if (!input || !output || process.argv.length !== 4) usage();
  const oldMaster = masterKey("OLD_MASTER_KEY");
  const newMaster = masterKey("NEW_MASTER_KEY");
  const parsed = JSON.parse(readFileSync(input, "utf8")) as AccountExport;
  if (parsed.version !== 1 || !Array.isArray(parsed.accounts)) throw new Error("账号导出文件格式无效");

  const accounts = parsed.accounts.map(({ key, record }) => {
    if (!key.startsWith("users/") || !record?.keyWrapped) throw new Error(`账号记录无效:${key}`);
    return { key, record: { ...record, keyWrapped: wrapKey(unwrapKey(record.keyWrapped, oldMaster), newMaster) } };
  });
  const rewrapped: AccountExport = { ...parsed, accounts, rewrappedAt: new Date().toISOString() };
  const outputPath = resolve(output);
  writeFileSync(outputPath, `${JSON.stringify(rewrapped, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });

  const applyPath = `${outputPath}.apply.sh`;
  const commands = ["#!/usr/bin/env sh", "set -eu", ...accounts.map(({ key, record }) =>
    `npx wrangler kv key put --binding=ACCOUNTS_KV ${shellQuote(key)} ${shellQuote(JSON.stringify(record))}`,
  )];
  writeFileSync(applyPath, `${commands.join("\n")}\n`, { encoding: "utf8", mode: 0o600 });
  chmodSync(applyPath, 0o700);

  console.log(`已重新包装 ${accounts.length} 个账号记录至 ${outputPath}`);
  console.log(`在维护窗口内暂停备份,执行 ${applyPath} 更新全部账号记录并切换 Worker 的 MASTER_KEY。`);
  console.log("当前 Worker 只接受一个主密钥,两步切换期间账号会暂时不可用;恢复服务后先完成认证和恢复演练。");
}

main();
