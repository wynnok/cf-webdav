import { execFileSync } from "node:child_process";
import { chmodSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

interface KvKey {
  name: string;
}

interface AccountExport {
  version: 1;
  exportedAt: string;
  accounts: Array<{ key: string; record: unknown }>;
}

function usage(): never {
  console.error("用法: npm run accounts:export -- <output.json> [--preview]");
  process.exit(1);
}

function runWrangler(args: string[]): string {
  return execFileSync("npx", ["wrangler", ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
}

function main(): void {
  const args = process.argv.slice(2);
  const preview = args.includes("--preview");
  const positional = args.filter((arg) => arg !== "--preview");
  const output = positional[0];
  if (!output || positional.length !== 1) usage();

  const scope = preview ? ["--preview"] : [];
  const rawKeys = runWrangler(["kv", "key", "list", "--binding=ACCOUNTS_KV", "--prefix=users/", ...scope]);
  const keys = JSON.parse(rawKeys) as KvKey[];
  const accounts = keys.map((entry) => {
    const rawRecord = runWrangler(["kv", "key", "get", entry.name, "--binding=ACCOUNTS_KV", ...scope]);
    return { key: entry.name, record: JSON.parse(rawRecord) as unknown };
  });
  const exported: AccountExport = { version: 1, exportedAt: new Date().toISOString(), accounts };
  const outputPath = resolve(output);
  writeFileSync(outputPath, `${JSON.stringify(exported, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  chmodSync(outputPath, 0o600);

  console.log(`已导出 ${accounts.length} 个账号记录至 ${outputPath}`);
  console.log("该文件与 MASTER_KEY 共同构成离线恢复包;请加密保存,不要提交到版本库。");
}

main();
