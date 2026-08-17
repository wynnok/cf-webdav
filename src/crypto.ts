import { createHash } from "node:crypto";
import { concatBytes, base64ToBytes, bytesToBase64, bytesEqual } from "./util";

export const TAG_LENGTH = 16;
export const NONCE_LENGTH = 12;
export const DATA_KEY_LENGTH = 32;

const MAGIC = new TextEncoder().encode("WDV2");
export const HEADER_LEN = 4 + 4 + 8 + NONCE_LENGTH; // magic + chunkSize + plaintextSize + baseNonce

export class IntegrityError extends Error {}

function chunkIv(baseNonce: Uint8Array, index: number): Uint8Array {
  const iv = new Uint8Array(baseNonce);
  const dv = new DataView(iv.buffer, iv.byteOffset, iv.byteLength);
  dv.setUint32(iv.byteLength - 4, index >>> 0, false);
  return iv;
}

function aad(objectKey: string, index: number, plaintextSize: number): Uint8Array {
  return new TextEncoder().encode(`${objectKey}\n${index}\n${plaintextSize}`);
}

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  const step = 65536;
  for (let i = 0; i < n; i += step) {
    crypto.getRandomValues(out.subarray(i, Math.min(i + step, n)));
  }
  return out;
}

/** 给定明文总长与分块大小,计算加密后 blob 的精确字节数(用于 R2 put 的固定长度流)。 */
export function ciphertextLength(plaintextSize: number, chunkSize: number): number {
  const chunks = plaintextSize === 0 ? 0 : Math.ceil(plaintextSize / chunkSize);
  return HEADER_LEN + plaintextSize + chunks * (4 + TAG_LENGTH);
}

export async function importKeyFromBytes(bytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", bytes as BufferSource, { name: "AES-GCM" }, true, [
    "encrypt",
    "decrypt",
  ]);
}

export function generateDataKey(): Uint8Array {
  return randomBytes(DATA_KEY_LENGTH);
}

export async function wrapKey(masterKey: CryptoKey, raw: Uint8Array): Promise<string> {
  const iv = randomBytes(NONCE_LENGTH);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, masterKey, raw as BufferSource);
  return bytesToBase64(concatBytes(iv, new Uint8Array(ct)));
}

export async function unwrapKey(masterKey: CryptoKey, wrapped: string): Promise<CryptoKey> {
  const blob = base64ToBytes(wrapped);
  if (blob.length <= NONCE_LENGTH) throw new IntegrityError("密钥数据损坏");
  const iv = blob.slice(0, NONCE_LENGTH);
  const ct = blob.slice(NONCE_LENGTH);
  try {
    const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128 }, masterKey, ct as BufferSource);
    return importKeyFromBytes(new Uint8Array(raw));
  } catch {
    throw new IntegrityError("无法解开用户数据密钥:MASTER_KEY 不匹配或数据被篡改");
  }
}

async function encryptChunk(
  key: CryptoKey,
  iv: Uint8Array,
  aadBytes: Uint8Array,
  plain: Uint8Array,
): Promise<Uint8Array> {
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aadBytes, tagLength: 128 },
    key,
    plain as BufferSource,
  );
  const out = new Uint8Array(4 + ct.byteLength);
  new DataView(out.buffer).setUint32(0, plain.length, false);
  out.set(new Uint8Array(ct), 4);
  return out;
}

async function decryptChunk(
  key: CryptoKey,
  iv: Uint8Array,
  aadBytes: Uint8Array,
  ct: Uint8Array,
  expectedPlainLen: number,
): Promise<Uint8Array> {
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: aadBytes, tagLength: 128 },
      key,
      ct as BufferSource,
    );
    const out = new Uint8Array(pt);
    if (out.length !== expectedPlainLen) throw new IntegrityError("解密长度不符");
    return out;
  } catch (e) {
    if (e instanceof IntegrityError) throw e;
    throw new IntegrityError("对象校验失败:数据可能被篡改或密钥不匹配");
  }
}

/** 明文区间,start/end 均含 start、不含 end。 */
export interface PlainRange {
  start: number;
  end: number;
}

export interface EncryptStreamResult {
  stream: ReadableStream<Uint8Array>;
  plaintextSize: Promise<number>;
  /** 明文的 MD5(hex),流消费完成后可用。 */
  md5: Promise<string>;
}

export interface DecryptStreamResult {
  stream: ReadableStream<Uint8Array>;
  /** 已读取到的明文总字节数。整读时等于对象明文大小;区间读时为已消费部分。 */
  plaintextSize: Promise<number>;
}

/** 以追加方式累积字节片段,避免反复整段复制。 */
class ByteAccumulator {
  private parts: Uint8Array[] = [];
  private total = 0;

  get length(): number {
    return this.total;
  }

  push(part: Uint8Array): void {
    if (part.length === 0) return;
    this.parts.push(part);
    this.total += part.length;
  }

  /** 取出前 n 字节(不足时取全部);剩余部分保留。 */
  take(n: number): Uint8Array {
    const m = Math.min(n, this.total);
    if (m === 0) return new Uint8Array(0);
    if (this.parts.length === 1 && this.parts[0]!.length === m) {
      const out = this.parts[0]!;
      this.parts = [];
      this.total = 0;
      return out;
    }
    const out = new Uint8Array(m);
    let off = 0;
    while (off < m && this.parts.length > 0) {
      const head = this.parts[0]!;
      const used = Math.min(head.length, m - off);
      out.set(used === head.length ? head : head.subarray(0, used), off);
      off += used;
      if (used === head.length) this.parts.shift();
      else this.parts[0] = head.subarray(used);
    }
    this.total -= m;
    return out;
  }
}

export function md5Hex(data: Uint8Array): string {
  return createHash("md5").update(data).digest("hex");
}

export function createEncryptStream(
  key: CryptoKey,
  objectKey: string,
  chunkSize: number,
  expectedPlaintextSize: number,
  source: ReadableStream<Uint8Array>,
): EncryptStreamResult {
  if (!Number.isSafeInteger(expectedPlaintextSize) || expectedPlaintextSize < 0) {
    throw new Error("明文大小必须是非负安全整数");
  }
  const reader = source.getReader();
  const baseNonce = randomBytes(NONCE_LENGTH);
  const header = new Uint8Array(HEADER_LEN);
  header.set(MAGIC, 0);
  new DataView(header.buffer).setUint32(4, chunkSize, false);
  new DataView(header.buffer).setBigUint64(8, BigInt(expectedPlaintextSize), false);
  header.set(baseNonce, 16);

  const hash = createHash("md5");
  const acc = new ByteAccumulator();
  let chunkIndex = 0;
  let inputDone = false;
  let sentHeader = false;
  let closed = false;
  let plaintextSize = 0;

  let resolveSize: (n: number) => void;
  const sizePromise = new Promise<number>((res) => (resolveSize = res));
  let resolveMd5: (h: string) => void;
  const md5Promise = new Promise<string>((res) => (resolveMd5 = res));

  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (closed) return;
      try {
        if (!sentHeader) {
          sentHeader = true;
          controller.enqueue(header);
        }
        while (true) {
          while (acc.length < chunkSize && !inputDone) {
            const { value, done } = await reader.read();
            if (done) {
              inputDone = true;
              break;
            }
            acc.push(value);
            plaintextSize += value.length;
          }
          if (acc.length === 0) {
            if (closed) return;
            if (plaintextSize !== expectedPlaintextSize) throw new IntegrityError("明文大小与 Content-Length 不符");
            closed = true;
            resolveMd5(hash.digest("hex"));
            resolveSize(plaintextSize);
            controller.close();
            return;
          }
          const plain = acc.take(chunkSize);
          hash.update(plain);
          const record = await encryptChunk(
            key,
            chunkIv(baseNonce, chunkIndex),
            aad(objectKey, chunkIndex, expectedPlaintextSize),
            plain,
          );
          chunkIndex++;
          controller.enqueue(record);
          if (inputDone && acc.length === 0) {
            if (closed) return;
            if (plaintextSize !== expectedPlaintextSize) throw new IntegrityError("明文大小与 Content-Length 不符");
            closed = true;
            resolveMd5(hash.digest("hex"));
            resolveSize(plaintextSize);
            controller.close();
            return;
          }
        }
      } catch (e) {
        closed = true;
        controller.error(e);
      }
    },
    cancel(reason) {
      closed = true;
      return reader.cancel(reason).catch(() => {});
    },
  });

  return { stream, plaintextSize: sizePromise, md5: md5Promise };
}

class BufferedReader {
  private reader: ReadableStreamDefaultReader<Uint8Array>;
  private buf = new ByteAccumulator();
  private eof = false;

  constructor(source: ReadableStream<Uint8Array>) {
    this.reader = source.getReader();
  }

  private async fill(): Promise<boolean> {
    if (this.eof) return false;
    const { value, done } = await this.reader.read();
    if (done) {
      this.eof = true;
      return false;
    }
    this.buf.push(value);
    return true;
  }

  /** 读取至多 n 字节;EOF 时返回不足部分或 null。 */
  async read(n: number): Promise<Uint8Array | null> {
    while (this.buf.length < n && !this.eof) {
      if (!(await this.fill())) break;
    }
    const out = this.buf.take(n);
    return out.length > 0 ? out : null;
  }
}

export function createDecryptStream(
  key: CryptoKey,
  objectKey: string,
  source: ReadableStream<Uint8Array>,
  range?: PlainRange,
): DecryptStreamResult {
  const reader = new BufferedReader(source);
  let chunkSize = 0;
  let baseNonce = new Uint8Array(0);
  let expectedPlaintextSize = 0;
  let plainOffset = 0;
  let total = 0;
  let finished = false;

  let resolveTotal: (n: number) => void;
  const totalPromise = new Promise<number>((res) => (resolveTotal = res));

  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        if (chunkSize === 0) {
          const head = await reader.read(HEADER_LEN);
          if (!head || head.length < HEADER_LEN) throw new IntegrityError("对象损坏:缺少加密头");
          if (!bytesEqual(head.slice(0, 4), MAGIC)) throw new IntegrityError("对象损坏:不是有效的加密对象");
          chunkSize = new DataView(head.buffer, head.byteOffset, head.byteLength).getUint32(4, false);
          const expected = new DataView(head.buffer, head.byteOffset, head.byteLength).getBigUint64(8, false);
          if (expected > BigInt(Number.MAX_SAFE_INTEGER)) throw new IntegrityError("对象大小超出支持范围");
          expectedPlaintextSize = Number(expected);
          if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) throw new IntegrityError("对象损坏:无效分块大小");
          baseNonce = head.slice(16);
        }
        while (true) {
          if (finished) {
            resolveTotal(total);
            controller.close();
            return;
          }
          const lenBuf = await reader.read(4);
          if (!lenBuf || lenBuf.length < 4) {
            if (lenBuf && lenBuf.length > 0) throw new IntegrityError("对象损坏:截断的记录头");
            if (total !== expectedPlaintextSize) throw new IntegrityError("对象损坏:明文长度不符");
            finished = true;
            resolveTotal(total);
            controller.close();
            return;
          }
          const plainLen = new DataView(lenBuf.buffer, lenBuf.byteOffset, lenBuf.byteLength).getUint32(0, false);
          if (plainLen === 0 || plainLen > chunkSize || total + plainLen > expectedPlaintextSize) {
            throw new IntegrityError("对象损坏:无效分块长度");
          }
          const chunkIndex = Math.floor(plainOffset / chunkSize);
          const ct = await reader.read(plainLen + TAG_LENGTH);
          if (!ct || ct.length < plainLen + TAG_LENGTH) throw new IntegrityError("对象损坏:截断的密文");

          const start = plainOffset;
          const end = start + plainLen;
          plainOffset = end;
          total += plainLen;

          const iv = chunkIv(baseNonce, chunkIndex);
          const plain = await decryptChunk(key, iv, aad(objectKey, chunkIndex, expectedPlaintextSize), ct, plainLen);
          const wantStart = range ? Math.max(range.start, start) : start;
          const wantEnd = range ? Math.min(range.end, end) : end;

          if (wantEnd > wantStart) {
            const slice = plain.slice(wantStart - start, wantEnd - start);
            controller.enqueue(slice);
          }
        }
      } catch (e) {
        finished = true;
        controller.error(e);
      }
    },
  });

  return { stream, plaintextSize: totalPromise };
}

/** 便捷函数:整体解密(用于测试/小对象)。 */
export async function encryptBlob(
  key: CryptoKey,
  objectKey: string,
  chunkSize: number,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const src = new ReadableStream<Uint8Array>({
    start(c) {
      c.enqueue(plaintext);
      c.close();
    },
  });
  const { stream, plaintextSize } = createEncryptStream(key, objectKey, chunkSize, plaintext.length, src);
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    parts.push(value);
  }
  await plaintextSize;
  return concatBytes(...parts);
}

export async function decryptBlob(
  key: CryptoKey,
  objectKey: string,
  blob: Uint8Array,
): Promise<Uint8Array> {
  const src = new ReadableStream<Uint8Array>({
    start(c) {
      c.enqueue(blob);
      c.close();
    },
  });
  const { stream, plaintextSize } = createDecryptStream(key, objectKey, src);
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    parts.push(value);
  }
  await plaintextSize;
  return concatBytes(...parts);
}
