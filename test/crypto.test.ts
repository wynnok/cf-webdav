import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import {
  createDecryptStream,
  createEncryptStream,
  decryptBlob,
  encryptBlob,
  HEADER_LEN,
  generateDataKey,
  importKeyFromBytes,
  IntegrityError,
  unwrapKey,
  wrapKey,
  randomBytes,
} from "../src/crypto";

function md5Hex(data: Uint8Array): string {
  const h = createHash("md5");
  h.update(data);
  return h.digest("hex");
}

async function makeKey(): Promise<CryptoKey> {
  return importKeyFromBytes(generateDataKey());
}

function expectBytes(a: Uint8Array, b: Uint8Array): void {
  expect(a.length).toBe(b.length);
  expect(a.every((v, i) => v === b[i])).toBe(true);
}

async function collect(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    parts.push(value);
  }
  return parts.reduce((a, b) => {
    const out = new Uint8Array(a.length + b.length);
    out.set(a);
    out.set(b, a.length);
    return out;
  }, new Uint8Array(0));
}

function oneShot(data: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(c) {
      c.enqueue(data);
      c.close();
    },
  });
}

describe("加密:对象往返", () => {
  const keyP = makeKey();

  it("小对象往返", async () => {
    const key = await keyP;
    const plain = new TextEncoder().encode("hello webdav");
    const blob = await encryptBlob(key, "obj1", 4 * 1024 * 1024, plain);
    const out = await decryptBlob(key, "obj1", blob);
    expect(new TextDecoder().decode(out)).toBe("hello webdav");
  });

  it("空对象往返", async () => {
    const key = await keyP;
    const blob = await encryptBlob(key, "empty", 4 * 1024 * 1024, new Uint8Array(0));
    const out = await decryptBlob(key, "empty", blob);
    expect(out.length).toBe(0);
  });

  it("跨多个分块往返", async () => {
    const key = await keyP;
    const chunkSize = 1024 * 1024;
    const plain = new Uint8Array(chunkSize * 3 + 12345);
    for (let i = 0; i < plain.length; i++) plain[i] = i % 251;
    const blob = await encryptBlob(key, "big", chunkSize, plain);
    const out = await decryptBlob(key, "big", blob);
    expectBytes(out, plain);
  });

  it("正好在分块边界往返", async () => {
    const key = await keyP;
    const chunkSize = 65536;
    const plain = randomBytes(chunkSize);
    const blob = await encryptBlob(key, "edge", chunkSize, plain);
    const out = await decryptBlob(key, "edge", blob);
    expectBytes(out, plain);
  });
});

describe("加密:完整性", () => {
  it("篡改密文被检测", async () => {
    const key = await makeKey();
    const plain = new TextEncoder().encode("secret data");
    const blob = await encryptBlob(key, "obj", 4 * 1024 * 1024, plain);
    blob[blob.length - 1]! ^= 0xff;
    await expect(decryptBlob(key, "obj", blob)).rejects.toThrow(IntegrityError);
  });

  it("篡改非最后一块被检测", async () => {
    const key = await makeKey();
    const chunkSize = 65536;
    const plain = new Uint8Array(chunkSize * 2);
    for (let i = 0; i < plain.length; i++) plain[i] = i % 251;
    const blob = await encryptBlob(key, "obj", chunkSize, plain);
    blob[20000]! ^= 0x01;
    await expect(decryptBlob(key, "obj", blob)).rejects.toThrow(IntegrityError);
  });

  it("在完整分块边界截断对象被检测", async () => {
    const key = await makeKey();
    const chunkSize = 65536;
    const plain = new Uint8Array(chunkSize * 2);
    const blob = await encryptBlob(key, "truncated", chunkSize, plain);
    const firstRecordLength = 4 + chunkSize + 16;
    const truncated = blob.slice(0, HEADER_LEN + firstRecordLength);
    await expect(decryptBlob(key, "truncated", truncated)).rejects.toThrow(IntegrityError);
  });

  it("换路径(AAD 绑定)被检测", async () => {
    const key = await makeKey();
    const plain = new TextEncoder().encode("data");
    const blob = await encryptBlob(key, "path-a", 4 * 1024 * 1024, plain);
    await expect(decryptBlob(key, "path-b", blob)).rejects.toThrow(IntegrityError);
  });
});

describe("加密:密钥包装", () => {
  it("包装/解包往返", async () => {
    const master = await makeKey();
    const dataKey = generateDataKey();
    const wrapped = await wrapKey(master, dataKey);
    const unwrapped = await unwrapKey(master, wrapped);
    const plain = new TextEncoder().encode("x");
    const blob = await encryptBlob(unwrapped, "k", 4 * 1024 * 1024, plain);
    expect((await decryptBlob(unwrapped, "k", blob)).length).toBe(1);
  });

  it("错误主密钥无法解包", async () => {
    const master = await makeKey();
    const wrong = await makeKey();
    const wrapped = await wrapKey(master, generateDataKey());
    await expect(unwrapKey(wrong, wrapped)).rejects.toThrow(IntegrityError);
  });
});

describe("加密:区间读", () => {
  it("中间区间与整读一致", async () => {
    const key = await makeKey();
    const chunkSize = 65536;
    const plain = new Uint8Array(chunkSize * 3 + 777);
    for (let i = 0; i < plain.length; i++) plain[i] = i % 251;
    const blob = await encryptBlob(key, "r", chunkSize, plain);
    const source = oneShot(blob);
    const { stream } = createDecryptStream(key, "r", source, { start: 100000, end: 200000 });
    const got = await collect(stream);
    expectBytes(got, plain.slice(100000, 200000));
  });

  it("跨分块区间", async () => {
    const key = await makeKey();
    const chunkSize = 65536;
    const plain = new Uint8Array(chunkSize * 3 + 777);
    for (let i = 0; i < plain.length; i++) plain[i] = i % 251;
    const blob = await encryptBlob(key, "r2", chunkSize, plain);
    const { stream } = createDecryptStream(key, "r2", oneShot(blob), { start: 65530, end: 65540 });
    const got = await collect(stream);
    expectBytes(got, plain.slice(65530, 65540));
  });

  it("区间之前被篡改的分块也会被认证", async () => {
    const key = await makeKey();
    const chunkSize = 65536;
    const plain = new Uint8Array(chunkSize * 3);
    for (let i = 0; i < plain.length; i++) plain[i] = i % 251;
    const blob = await encryptBlob(key, "r-tamper", chunkSize, plain);
    blob[100]! ^= 0x01;
    const { stream } = createDecryptStream(key, "r-tamper", oneShot(blob), {
      start: chunkSize * 2,
      end: plain.length,
    });
    await expect(collect(stream)).rejects.toThrow(IntegrityError);
  });

  it("前缀到末尾", async () => {
    const key = await makeKey();
    const chunkSize = 65536;
    const plain = new Uint8Array(chunkSize + 10);
    for (let i = 0; i < plain.length; i++) plain[i] = i % 251;
    const blob = await encryptBlob(key, "r3", chunkSize, plain);
    const { stream } = createDecryptStream(key, "r3", oneShot(blob), { start: 500, end: plain.length });
    const got = await collect(stream);
    expectBytes(got, plain.slice(500));
  });
});

describe("加密:流式接口", () => {
  it("createEncryptStream 正确产出可解密流", async () => {
    const key = await makeKey();
    const chunkSize = 65536;
    const plain = randomBytes(chunkSize + 1000);
    const enc = createEncryptStream(key, "s", chunkSize, plain.length, oneShot(plain));
    const blob = await collect(enc.stream);
    const size = await enc.plaintextSize;
    expect(size).toBe(plain.length);
    const out = await decryptBlob(key, "s", blob);
    expectBytes(out, plain);
  });

  it("createEncryptStream 计算明文 md5(跨分块)", async () => {
    const key = await makeKey();
    const chunkSize = 65536;
    const plain = new Uint8Array(chunkSize * 2 + 123);
    for (let i = 0; i < plain.length; i++) plain[i] = i % 251;
    const enc = createEncryptStream(key, "m", chunkSize, plain.length, oneShot(plain));
    await collect(enc.stream);
    expect(await enc.md5).toBe(md5Hex(plain));
  });

  it("createEncryptStream 空输入的 md5", async () => {
    const key = await makeKey();
    const enc = createEncryptStream(key, "e", 65536, 0, oneShot(new Uint8Array(0)));
    await collect(enc.stream);
    expect(await enc.md5).toBe("d41d8cd98f00b204e9800998ecf8427e");
  });
});
