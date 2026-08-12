import { LockManager, parseIfHeader, parseLockInfo } from "./lock";
import type { ActiveLock } from "./lock";
import { Storage, WebDavError } from "./storage";
import type { StoredNode } from "./storage";
import type { PlainRange } from "./crypto";
import { escapeXml, toHttpDate, parseHttpDate } from "./util";

type PropfindType = "allprop" | "propname" | "prop";

const SUPPORTED_PROPS = [
  "resourcetype",
  "getcontentlength",
  "getlastmodified",
  "creationdate",
  "getetag",
  "getcontenttype",
  "displayname",
  "supportedlock",
  "lockdiscovery",
] as const;

const ALLOW_METHODS = "OPTIONS, PROPFIND, PROPPATCH, GET, HEAD, PUT, MKCOL, DELETE, COPY, MOVE, LOCK, UNLOCK";

export interface DavNode extends StoredNode {
  href: string;
  lock: ActiveLock | null;
}

function decodePath(pathname: string): string {
  const segs = pathname.split("/").filter((s) => s.length > 0);
  const out: string[] = [];
  for (const s of segs) {
    let dec: string;
    try {
      dec = decodeURIComponent(s);
    } catch {
      throw new WebDavError(400, "无效的 URL 编码");
    }
    if (dec.includes("\0")) throw new WebDavError(400, "路径含非法字符");
    out.push(dec);
  }
  return out.join("/");
}

function buildHref(path: string, isDir: boolean): string {
  const segs = path ? path.split("/") : [];
  const enc = segs.map((s) => encodeURIComponent(s)).join("/");
  return `/${enc}${isDir && path ? "/" : ""}`;
}

function lastSegment(path: string): string {
  if (!path) return "";
  const parts = path.split("/");
  return parts[parts.length - 1] ?? "";
}

function toDavNode(node: StoredNode, lock: ActiveLock | null): DavNode {
  return { ...node, href: buildHref(node.path, node.isDir), lock };
}

function entityTag(node: Pick<StoredNode, "etag" | "md5">): string {
  return node.md5 ?? node.etag;
}

function parsePropfindBody(xml: string): { type: PropfindType; props: string[] } {
  if (!xml.trim()) return { type: "allprop", props: [] };
  if (/allprop/i.test(xml)) return { type: "allprop", props: [] };
  if (/propname/i.test(xml)) return { type: "propname", props: [] };
  const props: string[] = [];
  const block = xml.match(/<prop[^>]*>([\s\S]*?)<\/prop>/i)?.[1] ?? xml;
  const re = /<(?:[\w-]+:)?([\w-]+)(?:\s[^>]*)?\/?>/g;
  for (const m of block.matchAll(re)) props.push(m[1]!);
  return { type: "prop", props };
}

interface ProppatchOp {
  action: "set" | "remove";
  name: string;
  value: string | null;
}

function parseProppatchBody(xml: string): ProppatchOp[] {
  const ops: ProppatchOp[] = [];
  for (const action of ["set", "remove"] as const) {
    const re = new RegExp(`<D?:${action}[^>]*>([\\s\\S]*?)<\\/D?:${action}>`, "gi");
    let m: RegExpExecArray | null;
    while ((m = re.exec(xml))) {
      const block = m[1]!;
      const inner = block.match(/<prop[^>]*>([\s\S]*?)<\/prop>/i)?.[1] ?? block;
      const pairRe = /<(?:[\w-]+:)?([\w-]+)(?:\s[^>]*)?>([\s\S]*?)<\/(?:[\w-]+:)?\1>/g;
      let pm: RegExpExecArray | null;
      while ((pm = pairRe.exec(inner))) ops.push({ action, name: pm[1]!, value: pm[2]!.trim() });
      const selfRe = /<(?:[\w-]+:)?([\w-]+)\/>/g;
      let sm: RegExpExecArray | null;
      while ((sm = selfRe.exec(inner))) ops.push({ action, name: sm[1]!, value: null });
    }
  }
  return ops;
}

function activeLockXml(lock: ActiveLock, href: string): string {
  const scope = lock.depth === "0" ? "exclusive" : "exclusive";
  return `<D:activelock>` +
    `<D:locktype><D:write/></D:locktype>` +
    `<D:lockscope><D:${scope}/></D:lockscope>` +
    `<D:depth>${lock.depth}</D:depth>` +
    (lock.owner ? `<D:owner>${escapeXml(lock.owner)}</D:owner>` : `<D:owner/>`) +
    `<D:timeout>Second-${lock.timeoutSeconds}</D:timeout>` +
    `<D:locktoken><D:href>${escapeXml(lock.token)}</D:href></D:locktoken>` +
    `<D:lockroot><D:href>${escapeXml(href)}</D:href></D:lockroot>` +
    `</D:activelock>`;
}

function propValue(name: string, node: DavNode): string | null {
  switch (name) {
    case "resourcetype":
      return node.isDir ? "<D:collection/>" : "";
    case "getcontentlength":
      return node.isDir ? null : String(node.size);
    case "getlastmodified":
      return toHttpDate(new Date(node.mtime));
    case "creationdate":
      return node.created;
    case "getetag":
      return `"${escapeXml(entityTag(node))}"`;
    case "getcontenttype":
      return node.contentType ?? "application/octet-stream";
    case "displayname":
      return escapeXml(lastSegment(node.path));
    case "supportedlock":
      return `<D:lockentry><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>`;
    case "lockdiscovery":
      return node.lock ? activeLockXml(node.lock, node.href) : "";
    default:
      return null;
  }
}

function nodeResponse(node: DavNode, type: PropfindType, props: string[]): string {
  const ok: string[] = [];
  const missing: string[] = [];
  if (type === "propname") {
    for (const p of SUPPORTED_PROPS) ok.push(`<D:${p}/>`);
  } else {
    const list = type === "allprop" ? SUPPORTED_PROPS : props;
    for (const p of list) {
      const v = propValue(p, node);
      if (v !== null) ok.push(`<D:${p}>${v}</D:${p}>`);
      else if (type === "prop") missing.push(p);
    }
  }
  let xml = `<D:response><D:href>${escapeXml(node.href)}</D:href>`;
  xml += `<D:propstat><D:prop>${ok.join("")}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>`;
  if (missing.length > 0) {
    xml += `<D:propstat><D:prop>${missing.map((p) => `<D:${p}/>`).join("")}</D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>`;
  }
  xml += `</D:response>`;
  return xml;
}

function multistatus(responses: string[]): string {
  return `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">${responses.join("")}</D:multistatus>`;
}

function depthOf(request: Request): "0" | "1" | "infinity" {
  const d = (request.headers.get("Depth") ?? "1").toLowerCase();
  if (d === "0" || d === "1" || d === "infinity") return d;
  return "1";
}

function parseRange(header: string | null, size: number): PlainRange | null {
  if (!header || size < 0) return null;
  const m = header.match(/^bytes=(\d*)-(\d*)$/);
  if (!m) return null;
  const s = m[1]!;
  const e = m[2]!;
  if (s === "" && e === "") return null;
  if (s === "") {
    const len = Number(e);
    if (!Number.isFinite(len) || len <= 0) return null;
    return { start: Math.max(0, size - len), end: size };
  }
  const start = Number(s);
  const end = e === "" ? size : Math.min(Number(e) + 1, size);
  if (!Number.isFinite(start) || start >= size || start >= end) return null;
  return { start, end };
}

function davHeaders(init?: HeadersInit): Headers {
  const h = new Headers(init);
  if (!h.has("DAV")) h.set("DAV", "1, 2");
  if (!h.has("MS-Author-Via")) h.set("MS-Author-Via", "DAV");
  if (!h.has("Cache-Control")) h.set("Cache-Control", "no-store");
  return h;
}

export interface DavRouterOptions {
  propfindMaxEntries: number;
  lockTimeoutSeconds: number;
  maxPutBytes: number;
}

export class DavRouter {
  constructor(
    private storage: Storage,
    private locks: LockManager,
    private opts: DavRouterOptions,
  ) {}

  async dispatch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = decodePath(url.pathname);
    const isDir = url.pathname.endsWith("/");

    switch (request.method) {
      case "OPTIONS":
        return this.options();
      case "PROPFIND":
        return this.propfind(request, path, isDir);
      case "PROPPATCH":
        return this.proppatch(request, path);
      case "GET":
      case "HEAD":
        return this.read(request, path, request.method === "HEAD");
      case "PUT":
        return this.put(request, path);
      case "MKCOL":
        return this.mkcol(request, path);
      case "DELETE":
        return this.delete(request, path);
      case "COPY":
        return this.copyOrMove(request, path, false);
      case "MOVE":
        return this.copyOrMove(request, path, true);
      case "LOCK":
        return this.lock(request, path);
      case "UNLOCK":
        return this.unlock(request, path);
      default:
        return new Response("Method Not Allowed", { status: 405, headers: davHeaders({ Allow: ALLOW_METHODS }) });
    }
  }

  private options(): Response {
    return new Response(null, { status: 200, headers: davHeaders({ Allow: ALLOW_METHODS, "Content-Length": "0" }) });
  }

  private async propfind(request: Request, path: string, isDir: boolean): Promise<Response> {
    const depth = depthOf(request);
    const body = await request.text();
    const req = parsePropfindBody(body);

    const target = await this.storage.stat(path);
    if (!target) throw new WebDavError(404, "资源不存在");
    const targetLock = await this.locks.get(path);

    const nodes: DavNode[] = [toDavNode(target, targetLock)];
    if (depth === "1") {
      const children = await this.storage.listChildren(path);
      for (const child of children) {
        const childPath = path ? `${path}/${child.name}` : child.name;
        const childNode: StoredNode = child.node ?? {
          key: "",
          path: childPath,
          isDir: child.isDir,
          size: 0,
          etag: "",
          created: "",
          mtime: "",
        };
        nodes.push(toDavNode(childNode, null));
      }
    } else if (depth === "infinity") {
      const all = await this.storage.listAll(path);
      for (const n of all) nodes.push(toDavNode(n, null));
    }

    if (nodes.length > this.opts.propfindMaxEntries) {
      throw new WebDavError(507, "目录列表过大");
    }
    const responses = nodes.map((n) => nodeResponse(n, req.type, req.props));
    return new Response(multistatus(responses), {
      status: 207,
      headers: davHeaders({ "Content-Type": "application/xml; charset=utf-8" }),
    });
  }

  private async read(request: Request, path: string, isHead: boolean): Promise<Response> {
    const target = await this.storage.stat(path);
    if (!target) throw new WebDavError(404, "资源不存在");
    if (target.isDir) throw new WebDavError(404, "目录不支持 GET");

    const range = parseRange(request.headers.get("Range"), target.size);
    const got = await this.storage.getFile(path, range ?? undefined);
    if (!got) throw new WebDavError(404, "资源不存在");

    const headers = davHeaders({
      "Content-Type": got.node.contentType ?? "application/octet-stream",
      ETag: `"${entityTag(got.node)}"`,
      "Last-Modified": toHttpDate(new Date(got.node.mtime)),
      "Accept-Ranges": "bytes",
    });

    if (range) {
      const length = range.end - range.start;
      headers.set("Content-Length", String(length));
      headers.set("Content-Range", `bytes ${range.start}-${range.end - 1}/${got.size}`);
      return new Response(isHead ? null : got.stream, { status: 206, headers });
    }
    headers.set("Content-Length", String(got.size));
    return new Response(isHead ? null : got.stream, { status: 200, headers });
  }

  private async put(request: Request, path: string): Promise<Response> {
    if (path === "") throw new WebDavError(403, "不能写入根目录");
    const heldTokens = parseIfHeader(request.headers.get("If"));
    await this.locks.assertWritable(path, heldTokens);

    const target = await this.storage.stat(path);
    if (target?.isDir) throw new WebDavError(409, "目标是一个目录");
    if (target && !target.isDir) {
      const inm = request.headers.get("If-None-Match");
      if (inm && inm.trim() === "*") throw new WebDavError(412, "Precondition Failed");
      const im = request.headers.get("If-Match");
      if (im && !im.includes(entityTag(target))) throw new WebDavError(412, "Precondition Failed");
    }

    const cl = request.headers.get("Content-Length");
    const size = cl !== null && /^\d+$/.test(cl) ? Number(cl) : undefined;
    if (size !== undefined && size > this.opts.maxPutBytes) {
      throw new WebDavError(413, `上传对象超过部署上限(${this.opts.maxPutBytes} bytes)`);
    }
    const contentType = request.headers.get("Content-Type") ?? undefined;
    const mtime = parseHttpDate(request.headers.get("Last-Modified"))?.toISOString();
    const body = request.body ?? new ReadableStream<Uint8Array>({ start(c) { c.close(); } });

    const expectAbsent = request.headers.get("If-None-Match")?.trim() === "*";
    const created = await this.storage.putFile(path, body, { size, contentType, mtime, expectAbsent });
    return new Response(null, {
      status: target ? 204 : 201,
      headers: davHeaders({ ETag: `"${entityTag(created)}"`, "Content-Length": "0" }),
    });
  }

  private async mkcol(request: Request, path: string): Promise<Response> {
    if (path === "") throw new WebDavError(405, "根目录已存在");
    const parent = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
    const parentStat = await this.storage.stat(parent);
    if (!parentStat || !parentStat.isDir) throw new WebDavError(409, "父目录不存在或不是目录");
    const heldTokens = parseIfHeader(request.headers.get("If"));
    await this.locks.assertWritable(path, heldTokens);
    await this.storage.putDir(path);
    return new Response(null, { status: 201, headers: davHeaders({ "Content-Length": "0" }) });
  }

  private async delete(request: Request, path: string): Promise<Response> {
    const target = await this.storage.stat(path);
    if (!target) throw new WebDavError(404, "资源不存在");
    const heldTokens = parseIfHeader(request.headers.get("If"));
    await this.locks.assertWritable(path, heldTokens);
    if (target.isDir) {
      const under = await this.locks.listUnder(path);
      for (const l of under) {
        if (!heldTokens.has(l.token)) throw new WebDavError(423, "目录下有资源被锁定", "lock-token-submitted");
      }
    }
    await this.storage.delete(path, target.isDir);
    return new Response(null, { status: 204, headers: davHeaders({ "Content-Length": "0" }) });
  }

  private async copyOrMove(request: Request, path: string, isMove: boolean): Promise<Response> {
    const destHeader = request.headers.get("Destination");
    if (!destHeader) throw new WebDavError(400, "缺少 Destination 头");
    let destUrl: URL;
    try {
      destUrl = new URL(destHeader);
    } catch {
      throw new WebDavError(400, "Destination 无效");
    }
    if (destUrl.host !== new URL(request.url).host) {
      throw new WebDavError(403, "不支持跨主机操作");
    }
    const destPath = decodePath(destUrl.pathname);
    if (destPath === path) throw new WebDavError(403, "源与目标相同");
    if (destPath === "") throw new WebDavError(403, "不能操作根目录");

    const src = await this.storage.stat(path);
    if (!src) throw new WebDavError(404, "源不存在");
    const dest = await this.storage.stat(destPath);
    const overwrite = (request.headers.get("Overwrite") ?? "T").toUpperCase() !== "F";
    if (dest && !overwrite) throw new WebDavError(412, "目标已存在");

    const heldTokens = parseIfHeader(request.headers.get("If"));
    await this.locks.assertWritable(path, heldTokens);
    await this.locks.assertWritable(destPath, heldTokens);

    const depth = depthOf(request);
    if (depth === "0" && src.isDir) {
      await this.storage.putDir(destPath, { created: src.created, mtime: src.mtime });
    } else {
      await this.storage.copy(path, destPath);
    }
    if (isMove) {
      await this.storage.delete(path, src.isDir);
    }
    return new Response(null, { status: dest ? 204 : 201, headers: davHeaders({ "Content-Length": "0" }) });
  }

  private async lock(request: Request, path: string): Promise<Response> {
    const depth = (request.headers.get("Depth") ?? "infinity").toLowerCase() === "0" ? "0" : "infinity";
    const timeout = parseTimeout(request.headers.get("Timeout"), this.opts.lockTimeoutSeconds);
    const ifTokens = parseIfHeader(request.headers.get("If"));

    const existing = await this.locks.get(path);
    if (existing) {
      if (ifTokens.has(existing.token)) {
        const refreshed = await this.locks.refresh(path, existing.token, timeout);
        return this.lockResponse(path, refreshed);
      }
      throw new WebDavError(423, "资源已被锁定", "lock-token-submitted");
    }

    const body = await request.text();
    const info = parseLockInfo(body);
    const lock = await this.locks.create(path, info.owner, depth, timeout);
    return this.lockResponse(path, lock);
  }

  private async unlock(request: Request, path: string): Promise<Response> {
    const tokenHeader = request.headers.get("Lock-Token");
    if (!tokenHeader) throw new WebDavError(400, "缺少 Lock-Token 头");
    const token = tokenHeader.replace(/[<>]/g, "").trim();
    const removed = await this.locks.remove(path, token);
    if (!removed) throw new WebDavError(409, "无匹配锁");
    return new Response(null, { status: 204, headers: davHeaders({ "Content-Length": "0" }) });
  }

  private lockResponse(path: string, lock: ActiveLock): Response {
    const href = buildHref(path, false);
    const xml = multistatus([
      `<D:response><D:href>${escapeXml(href)}</D:href>` +
        `<D:propstat><D:prop><D:lockdiscovery>${activeLockXml(lock, href)}</D:lockdiscovery></D:prop>` +
        `<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`,
    ]);
    return new Response(xml, {
      status: 200,
      headers: davHeaders({ "Content-Type": "application/xml; charset=utf-8", "Lock-Token": `<${lock.token}>` }),
    });
  }

  private async proppatch(request: Request, path: string): Promise<Response> {
    const target = await this.storage.stat(path);
    if (!target) throw new WebDavError(404, "资源不存在");
    if (target.isDir) throw new WebDavError(403, "目录不支持 PROPPATCH");
    const body = await request.text();
    const ops = parseProppatchBody(body);
    const applied: string[] = [];
    const denied: string[] = [];
    const patch: { created?: string; mtime?: string } = {};
    for (const op of ops) {
      const name = op.name.toLowerCase();
      if (op.action === "remove") {
        denied.push(op.name);
        continue;
      }
      if (name === "getlastmodified" || name === "win32lastmodified" || name === "creationdate") {
        const d = parseHttpDate(op.value) ?? parseIso(op.value ?? "");
        if (d) {
          if (name === "creationdate") patch.created = d.toISOString();
          else patch.mtime = d.toISOString();
          applied.push(op.name);
          continue;
        }
        denied.push(op.name);
      } else {
        denied.push(op.name);
      }
    }
    if (Object.keys(patch).length > 0) {
      await this.storage.patchMetadata(path, patch);
    }
    const xml = multistatus([
      `<D:response><D:href>${escapeXml(toDavNode(target, null).href)}</D:href>` +
        (applied.length > 0
          ? `<D:propstat><D:prop>${applied.map((p) => `<D:${escapeXml(p)}/>`).join("")}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>`
          : "") +
        (denied.length > 0
          ? `<D:propstat><D:prop>${denied.map((p) => `<D:${escapeXml(p)}/>`).join("")}</D:prop><D:status>HTTP/1.1 403 Forbidden</D:status></D:propstat>`
          : "") +
        `</D:response>`,
    ]);
    return new Response(xml, { status: 207, headers: davHeaders({ "Content-Type": "application/xml; charset=utf-8" }) });
  }
}

function parseIso(s: string): Date | null {
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : new Date(t);
}

function parseTimeout(header: string | null, fallback: number): number {
  if (header) {
    const m = header.match(/Second-(\d+)/i);
    if (m) {
      const n = Number(m[1]);
      if (n > 0 && n <= 86400) return n;
    }
    if (/Infinite/i.test(header)) return fallback;
  }
  return fallback;
}
