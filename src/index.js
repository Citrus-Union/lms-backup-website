function escapeHtml(input) {
  return input
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function normalizePrefix(rawPrefix) {
  if (!rawPrefix) return "";
  const trimmed = rawPrefix.replace(/^\/+/, "").replace(/\/+$/, "");
  return trimmed ? `${trimmed}/` : "";
}

function parentPrefix(prefix) {
  if (!prefix) return "";
  const withoutSlash = prefix.slice(0, -1);
  const idx = withoutSlash.lastIndexOf("/");
  if (idx === -1) return "";
  return withoutSlash.slice(0, idx + 1);
}

function nameFromKey(key, prefix) {
  return key.startsWith(prefix) ? key.slice(prefix.length) : key;
}

function encodeRfc3986(value) {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function formatAmzDate(date) {
  const yyyy = date.getUTCFullYear();
  const mm = String(date.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(date.getUTCDate()).padStart(2, "0");
  const hh = String(date.getUTCHours()).padStart(2, "0");
  const mi = String(date.getUTCMinutes()).padStart(2, "0");
  const ss = String(date.getUTCSeconds()).padStart(2, "0");
  return `${yyyy}${mm}${dd}T${hh}${mi}${ss}Z`;
}

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function canonicalQuery(entries) {
  return entries
    .map(([key, value]) => [encodeRfc3986(key), encodeRfc3986(value)])
    .sort((a, b) => {
      if (a[0] < b[0]) return -1;
      if (a[0] > b[0]) return 1;
      if (a[1] < b[1]) return -1;
      if (a[1] > b[1]) return 1;
      return 0;
    })
    .map(([key, value]) => `${key}=${value}`)
    .join("&");
}

function parsePresignExpiry(rawValue) {
  const parsed = Number.parseInt(rawValue ?? "", 10);
  if (!Number.isFinite(parsed)) return 300;
  return Math.max(1, Math.min(604800, parsed));
}

async function hmacSha256(key, data) {
  const keyData =
    typeof key === "string" ? new TextEncoder().encode(key) : key.buffer;
  const dataBytes =
    typeof data === "string" ? new TextEncoder().encode(data) : data.buffer;
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, dataBytes);
  return new Uint8Array(signature);
}

async function sha256Hex(data) {
  const dataBytes =
    typeof data === "string" ? new TextEncoder().encode(data) : data.buffer;
  return toHex(await crypto.subtle.digest("SHA-256", dataBytes));
}

async function buildPresignedDownloadUrl({
  accountId,
  bucketName,
  key,
  accessKeyId,
  secretAccessKey,
  expiresIn,
}) {
  const host = `${bucketName}.${accountId}.r2.cloudflarestorage.com`;
  const encodedKey = key.split("/").map(encodeRfc3986).join("/");
  const amzDate = formatAmzDate(new Date());
  const dateStamp = amzDate.slice(0, 8);
  const scope = `${dateStamp}/auto/s3/aws4_request`;
  const filename = key.split("/").pop() || "file";
  const disposition = `attachment; filename="${filename.replaceAll('"', "")}"`;

  const presignParams = [
    ["X-Amz-Algorithm", "AWS4-HMAC-SHA256"],
    ["X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD"],
    ["X-Amz-Credential", `${accessKeyId}/${scope}`],
    ["X-Amz-Date", amzDate],
    ["X-Amz-Expires", String(expiresIn)],
    ["X-Amz-SignedHeaders", "host"],
    ["response-content-disposition", disposition],
    ["x-id", "GetObject"],
  ];

  const canonicalQueryString = canonicalQuery(presignParams);
  const canonicalRequest = [
    "GET",
    `/${encodedKey}`,
    canonicalQueryString,
    `host:${host}\n`,
    "host",
    "UNSIGNED-PAYLOAD",
  ].join("\n");

  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    scope,
    await sha256Hex(canonicalRequest),
  ].join("\n");

  const kDate = await hmacSha256(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = await hmacSha256(kDate, "auto");
  const kService = await hmacSha256(kRegion, "s3");
  const kSigning = await hmacSha256(kService, "aws4_request");
  const signature = toHex(await hmacSha256(kSigning, stringToSign));

  return `https://${host}/${encodedKey}?${canonicalQueryString}&X-Amz-Signature=${signature}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/download") {
      const key = url.searchParams.get("key");
      if (!key) return new Response("missing key", { status: 400 });

      const r2AccountId = String(env.R2_ACCOUNT_ID || "").trim();
      const r2BucketName = String(env.R2_BUCKET_NAME || "").trim();
      const r2AccessKeyId = String(env.R2_ACCESS_KEY_ID || "").trim();
      const r2SecretAccessKey = String(env.R2_SECRET_ACCESS_KEY || "").trim();

      const canPresign =
        r2AccountId && r2BucketName && r2AccessKeyId && r2SecretAccessKey;
      if (canPresign) {
        try {
          const presignedUrl = await buildPresignedDownloadUrl({
            accountId: r2AccountId,
            bucketName: r2BucketName,
            key,
            accessKeyId: r2AccessKeyId,
            secretAccessKey: r2SecretAccessKey,
            expiresIn: parsePresignExpiry(env.R2_PRESIGN_EXPIRES),
          });
          return Response.redirect(presignedUrl, 302);
        } catch (error) {
          console.error("failed to create presigned URL", error);
        }
      }

      const object = await env.R2_BUCKET.get(key);
      if (!object) return new Response("not found", { status: 404 });

      const headers = new Headers();
      object.writeHttpMetadata(headers);
      headers.set("etag", object.httpEtag);
      headers.set(
        "content-disposition",
        `attachment; filename="${key.split("/").pop() || "file"}"`,
      );
      return new Response(object.body, { headers });
    }

    if (url.pathname !== "/") {
      return new Response("not found", { status: 404 });
    }

    const prefix = normalizePrefix(url.searchParams.get("path") || "");
    let cursor;
    const folders = new Set();
    const files = [];

    do {
      const page = await env.R2_BUCKET.list({
        prefix,
        delimiter: "/",
        cursor,
      });

      for (const folderPrefix of page.delimitedPrefixes || []) {
        folders.add(folderPrefix);
      }

      for (const obj of page.objects) {
        if (obj.key !== prefix) files.push(obj.key);
      }

      cursor = page.truncated ? page.cursor : undefined;
    } while (cursor);

    const folderItems = Array.from(folders).sort((a, b) => a.localeCompare(b));
    const fileItems = files.sort((a, b) => a.localeCompare(b));
    const parent = parentPrefix(prefix);
    const lines = [];

    lines.push("<!doctype html>");
    lines.push('<meta charset="utf-8">');
    lines.push(`<h3>Index of /${escapeHtml(prefix)}</h3>`);

    if (prefix) {
      lines.push(
        `<div><a href="/?path=${encodeURIComponent(parent)}">..</a></div>`,
      );
    }

    for (const folderPrefix of folderItems) {
      const folderName = `${nameFromKey(folderPrefix, prefix).replace(/\/$/, "")}/`;
      lines.push(
        `<div><a href="/?path=${encodeURIComponent(folderPrefix)}">${escapeHtml(
          folderName,
        )}</a></div>`,
      );
    }

    for (const key of fileItems) {
      const fileName = nameFromKey(key, prefix);
      lines.push(
        `<div><a href="/download?key=${encodeURIComponent(key)}">${escapeHtml(
          fileName,
        )}</a></div>`,
      );
    }

    if (!folderItems.length && !fileItems.length) {
      lines.push("<div>(empty)</div>");
    }

    return new Response(lines.join("\n"), {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  },
};
