import { randomBytes, pbkdf2Sync, createCipheriv } from "node:crypto";
import { randomUUID } from "node:crypto";

const ITERATIONS = Number(process.env.PBKDF2_ITERATIONS ?? 100000);
const MASTER_KEY_HEX = process.env.MASTER_KEY;

function b64(b: Uint8Array): string {
  let s = "";
  const step = 0x8000;
  for (let i = 0; i < b.length; i += step) s += String.fromCharCode(...b.subarray(i, i + step));
  return btoa(s);
}

function usage(): never {
  console.error(
    "用法: MASTER_KEY=<64位hex> node scripts/create-user.ts [--disabled] <username> <password>",
  );
  console.error("     username 只能包含字母/数字/._- ,将自动转小写");
  process.exit(1);
}

function validateUsername(u: string): string {
  const norm = u.trim().toLowerCase();
  if (!/^[a-z0-9._-]{1,64}$/.test(norm)) {
    console.error("用户名不合法(仅允许小写字母/数字/._- ,1-64 字符):", norm);
    process.exit(1);
  }
  return norm;
}

function main(): void {
  if (!MASTER_KEY_HEX) {
    console.error("缺少 MASTER_KEY 环境变量(64 位 hex,即 wrangler secret 的值)");
    usage();
  }
  if (MASTER_KEY_HEX.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(MASTER_KEY_HEX)) {
    console.error("MASTER_KEY 必须是 32 字节(64 个 hex 字符)");
    usage();
  }
  const args = process.argv.slice(2);
  const disabled = args.includes("--disabled");
  const positional = args.filter((arg) => arg !== "--disabled");
  const [usernameArg, passwordArg] = positional;
  if (!usernameArg || !passwordArg) usage();
  if (passwordArg.length < 8) {
    console.error("密码长度至少 8 位");
    process.exit(1);
  }
  const username = validateUsername(usernameArg);

  const salt = randomBytes(16);
  const hash = pbkdf2Sync(passwordArg, salt, ITERATIONS, 32, "sha256");
  const dataKey = randomBytes(32);

  const master = Buffer.from(MASTER_KEY_HEX!, "hex");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", master, iv);
  const ct = Buffer.concat([cipher.update(dataKey), cipher.final()]);
  const tag = cipher.getAuthTag();
  const keyWrapped = b64(Buffer.concat([iv, ct, tag]));

  const record = {
    v: 1,
    id: randomUUID(),
    salt: b64(salt),
    iter: ITERATIONS,
    hash: b64(hash),
    keyWrapped,
    created: new Date().toISOString(),
    ...(disabled ? { disabled: true } : {}),
  };

  console.log("用户记录(写入 KV):");
  console.log(JSON.stringify(record, null, 2));
  console.log("\n执行以下命令写入 KV:");
  console.log(`  wrangler kv key put --binding=ACCOUNTS_KV "users/${username}" '${JSON.stringify(record)}'`);
  console.log("\n(本地预览用 --binding=ACCOUNTS_KV --preview,或按 namespace id 指定)");
}

main();
