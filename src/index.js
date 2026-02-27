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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/download") {
      const key = url.searchParams.get("key");
      if (!key) return new Response("missing key", { status: 400 });

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
    lines.push("<meta charset=\"utf-8\">");
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
