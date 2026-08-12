import { ciphertextLength, createDecryptStream, createEncryptStream } from "./crypto";
import type { PlainRange } from "./crypto";
import { collectBytes, concatBytes, nowIso, oneShotStream } from "./util";

export const META_TYPE = "wdv_type";
export const META_SIZE = "wdv_size";
export const META_CREATED = "wdv_created";
export const META_MTIME = "wdv_mtime";
export const META_MD5 = "wdv_md5";

export interface StoredNode {
  key: string;
  /** WebDAV 路径(无首尾斜杠,空串为根) */
  path: string;
  isDir: boolean;
  /** 明文大小;文件未知时为 -1 */
  size: number;
  /** R2 对象 etag(密文) */
  etag: string;
  /** 明文 MD5(hex),文件且已写入元数据时存在 */
  md5?: string;
  created: string;
  mtime: string;
  contentType?: string;
}

export interface ListEntry {
  name: string;
  isDir: boolean;
  node?: StoredNode;
}

function emptyStream(): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(c) {
      c.close();
    },
  });
}

async function drain(stream: ReadableStream<Uint8Array>): Promise<void> {
  const reader = stream.getReader();
  for (;;) {
    const { done } = await reader.read();
    if (done) break;
  }
}

function fixed(stream: ReadableStream<Uint8Array>, length: number): ReadableStream<Uint8Array> {
  return stream.pipeThrough(new FixedLengthStream(length));
}

export class Storage {
  constructor(
    private bucket: R2Bucket,
    private prefix: string,
    private dataKey: CryptoKey,
    private chunkSize: number,
    private maxPutBytes: number,
  ) {}

  private fileKey(path: string): string {
    return path ? `${this.prefix}${path}` : this.prefix;
  }

  private dirKey(path: string): string {
    return path ? `${this.prefix}${path}/` : this.prefix;
  }

  private dirPrefix(path: string): string {
    return path ? `${this.prefix}${path}/` : this.prefix;
  }

  private toNode(obj: R2Object, path: string, forceDir = false): StoredNode {
    const cm = obj.customMetadata ?? {};
    const isDir = forceDir || cm[META_TYPE] === "dir";
    const rawSize = cm[META_SIZE];
    const size = rawSize !== undefined && rawSize !== null && rawSize !== "" ? Number(rawSize) : -1;
    const uploaded = obj.uploaded;
    return {
      key: obj.key,
      path,
      isDir,
      size: isDir ? 0 : size,
      etag: obj.etag,
      md5: isDir ? undefined : cm[META_MD5] || undefined,
      created: cm[META_CREATED] ?? uploaded.toISOString(),
      mtime: cm[META_MTIME] ?? uploaded.toISOString(),
      contentType: obj.httpMetadata?.contentType,
    };
  }

  private virtualDir(path: string): StoredNode {
    return {
      key: this.dirKey(path),
      path,
      isDir: true,
      size: 0,
      etag: `d:${path ? path : "root"}`,
      created: nowIso(),
      mtime: nowIso(),
    };
  }

  async stat(path: string): Promise<StoredNode | null> {
    if (path === "") return this.virtualDir("");
    const fobj = await this.bucket.head(this.fileKey(path));
    if (fobj) return this.toNode(fobj, path);
    const dobj = await this.bucket.head(this.dirKey(path));
    if (dobj) return this.toNode(dobj, path, true);
    const probe = await this.bucket.list({ prefix: this.dirPrefix(path), limit: 1 });
    if (probe.objects.length > 0 || probe.delimitedPrefixes.length > 0) {
      return this.virtualDir(path);
    }
    return null;
  }

  async resolvePlaintextSize(key: string): Promise<number> {
    const obj = await this.bucket.get(key);
    if (!obj) return 0;
    const dec = createDecryptStream(this.dataKey, key, obj.body);
    await drain(dec.stream);
    return dec.plaintextSize;
  }

  async listChildren(path: string): Promise<ListEntry[]> {
    const prefix = this.dirPrefix(path);
    const fileObjs: R2Object[] = [];
    const dirNames = new Set<string>();
    let cursor: string | undefined;
    do {
      const res = await this.bucket.list({ prefix, delimiter: "/", cursor, limit: 1000 });
      for (const d of res.delimitedPrefixes ?? []) {
        const name = d.slice(prefix.length).replace(/\/$/, "");
        if (name !== "" && !name.includes("/")) dirNames.add(name);
      }
      for (const obj of res.objects ?? []) {
        if (obj.key.endsWith("/")) continue;
        fileObjs.push(obj);
      }
      cursor = res.truncated ? res.cursor : undefined;
    } while (cursor);

    const nodes = await this.headForNodes(fileObjs);
    const entries: ListEntry[] = [];
    for (const name of dirNames) entries.push({ name, isDir: true });
    for (const node of nodes) entries.push({ name: lastSegment(node.path), isDir: false, node });
    entries.sort((a, b) => {
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
      return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
    });
    return entries;
  }

  /** 递归列出 path 下所有对象(不含 path 自身)。 */
  async listAll(path: string): Promise<StoredNode[]> {
    const prefix = this.dirPrefix(path);
    const objs: R2Object[] = [];
    let cursor: string | undefined;
    do {
      const res = await this.bucket.list({ prefix, cursor, limit: 1000 });
      for (const obj of res.objects ?? []) {
        const rel = obj.key.slice(this.prefix.length);
        if (rel === "") continue;
        objs.push(obj);
      }
      cursor = res.truncated ? res.cursor : undefined;
    } while (cursor);
    return this.headForNodes(objs);
  }

  /** list() 不含 customMetadata,需逐个 head 补齐元数据。 */
  private async headForNodes(objs: R2Object[]): Promise<StoredNode[]> {
    const out: StoredNode[] = [];
    const BATCH = 50;
    for (let i = 0; i < objs.length; i += BATCH) {
      const slice = objs.slice(i, i + BATCH);
      const heads = await Promise.all(slice.map((o) => this.bucket.head(o.key)));
      for (const h of heads) {
        if (!h) continue;
        const path = h.key.slice(this.prefix.length);
        out.push(this.toNode(h, path));
      }
    }
    return out;
  }

  async putFile(
    path: string,
    body: ReadableStream<Uint8Array>,
    opts: { size?: number; contentType?: string; created?: string; mtime?: string; expectAbsent?: boolean } = {},
  ): Promise<StoredNode> {
    const key = this.fileKey(path);
    let created = opts.created;
    if (opts.expectAbsent) {
      if (await this.bucket.head(key)) throw new WebDavError(412, "对象已存在");
    } else if (created === undefined) {
      const prev = await this.bucket.head(key);
      if (prev) {
        const prevCm = prev.customMetadata ?? {};
        if (prevCm[META_TYPE] !== "dir") created = prevCm[META_CREATED];
      }
    }
    const mtime = opts.mtime ?? created ?? nowIso();
    created = created ?? nowIso();
    const sizeKnown = opts.size !== undefined;
    const cm: Record<string, string> = {
      [META_TYPE]: "file",
      [META_SIZE]: "0",
      [META_CREATED]: created,
      [META_MTIME]: mtime,
    };

    let plainLen: number;
    let source: ReadableStream<Uint8Array>;
    if (sizeKnown) {
      plainLen = opts.size!;
      source = body;
    } else {
      const buf = await collectBytesWithinLimit(body, this.maxPutBytes);
      plainLen = buf.length;
      source = oneShotStream(buf);
    }
    cm[META_SIZE] = String(plainLen);

    const enc = createEncryptStream(this.dataKey, key, this.chunkSize, plainLen, source);
    const out = fixed(enc.stream, ciphertextLength(plainLen, this.chunkSize));
    await this.bucket.put(key, out, {
      customMetadata: cm,
      httpMetadata: opts.contentType ? { contentType: opts.contentType } : undefined,
    });
    // R2 metadata is fixed when a streaming put starts; MD5 exists only after encryption consumes all plaintext.
    await this.backfillMd5(key, await enc.md5);
    const obj = (await this.bucket.head(key))!;
    return this.toNode(obj, path);
  }

  async putDir(path: string, opts: { created?: string; mtime?: string } = {}): Promise<StoredNode> {
    if (!path) return this.virtualDir("");
    const key = this.dirKey(path);
    if (await this.bucket.head(key)) throw new WebDavError(405, "目标已存在");
    const created = opts.created ?? nowIso();
    const mtime = opts.mtime ?? created;
    const cm = {
      [META_TYPE]: "dir",
      [META_SIZE]: "0",
      [META_CREATED]: created,
      [META_MTIME]: mtime,
    };
    const enc = createEncryptStream(this.dataKey, key, this.chunkSize, 0, emptyStream());
    const obj = await this.bucket.put(key, fixed(enc.stream, ciphertextLength(0, this.chunkSize)), {
      customMetadata: cm,
    });
    return this.toNode(obj, path, true);
  }

  async putEmptyDirObject(key: string, created: string, mtime: string): Promise<void> {
    const cm = {
      [META_TYPE]: "dir",
      [META_SIZE]: "0",
      [META_CREATED]: created,
      [META_MTIME]: mtime,
    };
    const enc = createEncryptStream(this.dataKey, key, this.chunkSize, 0, emptyStream());
    await this.bucket.put(key, fixed(enc.stream, ciphertextLength(0, this.chunkSize)), { customMetadata: cm });
  }

  async getFile(
    path: string,
    range?: PlainRange,
  ): Promise<{ stream: ReadableStream<Uint8Array>; size: number; node: StoredNode } | null> {
    const key = this.fileKey(path);
    const obj = await this.bucket.get(key);
    if (!obj) return null;
    let node = this.toNode(obj, path);
    if (node.size < 0) {
      node = { ...node, size: await this.resolvePlaintextSize(key) };
    }
    await this.verifyObject(key, obj);
    const verified = await this.bucket.get(key);
    if (!verified || verified.version !== obj.version || verified.etag !== obj.etag) {
      throw new WebDavError(409, "对象在读取期间发生变化");
    }
    const dec = createDecryptStream(this.dataKey, key, verified.body, range);
    return { stream: dec.stream, size: node.size, node };
  }

  async delete(path: string, isDir: boolean): Promise<void> {
    if (isDir) {
      const keys: string[] = [];
      if (path) keys.push(this.dirKey(path));
      let cursor: string | undefined;
      do {
        const res = await this.bucket.list({ prefix: this.dirPrefix(path), cursor, limit: 1000 });
        keys.push(...res.objects.map((o) => o.key));
        cursor = res.truncated ? res.cursor : undefined;
      } while (cursor);
      for (let i = 0; i < keys.length; i += 1000) {
        await this.bucket.delete(keys.slice(i, i + 1000));
      }
    } else {
      await this.bucket.delete(this.fileKey(path));
    }
  }

  async copy(srcPath: string, dstPath: string): Promise<void> {
    const src = await this.stat(srcPath);
    if (!src) throw new WebDavError(404, "源不存在");
    if (src.isDir) {
      await this.putDir(dstPath, { created: src.created, mtime: src.mtime });
      await this.copyDirRaw(this.dirPrefix(srcPath), this.dirKey(dstPath));
    } else {
      await this.copyObjectRaw(this.fileKey(srcPath), this.fileKey(dstPath), src);
    }
  }

  async move(srcPath: string, dstPath: string): Promise<void> {
    const src = await this.stat(srcPath);
    if (!src) throw new WebDavError(404, "源不存在");
    await this.copy(srcPath, dstPath);
    await this.delete(srcPath, src.isDir);
  }

  async patchMetadata(
    path: string,
    patch: { created?: string; mtime?: string },
    isDir = false,
  ): Promise<StoredNode> {
    const key = isDir ? this.dirKey(path) : this.fileKey(path);
    const obj = await this.bucket.get(key);
    if (!obj) throw new WebDavError(404, "资源不存在");
    const cm = { ...(obj.customMetadata ?? {}) };
    if (patch.created) cm[META_CREATED] = patch.created;
    if (patch.mtime) cm[META_MTIME] = patch.mtime;
    await this.bucket.put(key, fixed(obj.body, obj.size), {
      customMetadata: cm,
      httpMetadata: obj.httpMetadata ?? undefined,
    });
    const head = await this.bucket.head(key);
    return this.toNode(head!, path, isDir);
  }

  private async copyDirRaw(srcPrefix: string, dstPrefix: string): Promise<void> {
    const objs: R2Object[] = [];
    let cursor: string | undefined;
    do {
      const res = await this.bucket.list({ prefix: srcPrefix, cursor, limit: 1000 });
      objs.push(...(res.objects ?? []));
      cursor = res.truncated ? res.cursor : undefined;
    } while (cursor);

    const nodes = await this.headForNodes(objs);
    for (const node of nodes) {
      const rel = node.key.slice(srcPrefix.length);
      const dstKey = `${dstPrefix}${rel}`;
      if (node.isDir) {
        await this.putEmptyDirObject(dstKey, node.created, node.mtime);
      } else {
        await this.copyObjectRaw(node.key, dstKey, node);
      }
    }
  }

  private async copyObjectRaw(srcKey: string, dstKey: string, src: StoredNode): Promise<void> {
    const obj = await this.bucket.get(srcKey);
    if (!obj) throw new WebDavError(404, "源不存在");
    const dec = createDecryptStream(this.dataKey, srcKey, obj.body);
    if (src.size >= 0) {
      const enc = createEncryptStream(this.dataKey, dstKey, this.chunkSize, src.size, dec.stream);
      await this.bucket.put(dstKey, fixed(enc.stream, ciphertextLength(src.size, this.chunkSize)), {
        customMetadata: {
          [META_TYPE]: "file",
          [META_SIZE]: String(src.size),
          [META_CREATED]: src.created,
          [META_MTIME]: src.mtime,
        },
        httpMetadata: src.contentType ? { contentType: src.contentType } : undefined,
      });
      await this.backfillMd5(dstKey, src.md5 ?? await enc.md5);
    } else {
      const buf = await collectBytes(dec.stream);
      const enc = createEncryptStream(this.dataKey, dstKey, this.chunkSize, buf.length, oneShotStream(buf));
      await this.bucket.put(dstKey, fixed(enc.stream, ciphertextLength(buf.length, this.chunkSize)), {
        customMetadata: {
          [META_TYPE]: "file",
          [META_SIZE]: String(buf.length),
          [META_CREATED]: src.created,
          [META_MTIME]: src.mtime,
        },
        httpMetadata: src.contentType ? { contentType: src.contentType } : undefined,
      });
      await this.backfillMd5(dstKey, src.md5 ?? await enc.md5);
    }
  }

  private async backfillMd5(key: string, md5: string): Promise<void> {
    const obj = await this.bucket.get(key);
    if (!obj) throw new WebDavError(500, "加密对象写入后丢失");
    await this.bucket.put(key, fixed(obj.body, obj.size), {
      customMetadata: { ...(obj.customMetadata ?? {}), [META_MD5]: md5 },
      httpMetadata: obj.httpMetadata ?? undefined,
    });
  }

  private async verifyObject(key: string, obj: R2ObjectBody): Promise<void> {
    const dec = createDecryptStream(this.dataKey, key, obj.body);
    await drain(dec.stream);
  }
}

async function collectBytesWithinLimit(stream: ReadableStream<Uint8Array>, limit: number): Promise<Uint8Array> {
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > limit) {
      await reader.cancel();
      throw new WebDavError(413, `上传对象超过部署上限(${limit} bytes)`);
    }
    parts.push(value);
  }
  return concatBytes(...parts);
}

export class WebDavError extends Error {
  constructor(
    public status: number,
    message: string,
    public davCode?: string,
  ) {
    super(message);
  }
}

function lastSegment(path: string): string {
  if (!path) return "";
  const parts = path.split("/");
  return parts[parts.length - 1] ?? "";
}
