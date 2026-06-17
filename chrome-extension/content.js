// Content script: runs inside the OneDrive / SharePoint web app.
// On request from the popup it computes the current folder's human-readable
// path and a short ?id=<resid>&cid=<cid> URL, using the page's own
// same-origin authenticated session (no OAuth, no extra permissions).
//
// The resid is the SharePoint UniqueId of the folder, fetched from the
// _api/web/GetFolderByServerRelativePath endpoint. Verified that
//   https://onedrive.live.com/?id=<UniqueId>&cid=<CID>
// resolves to the folder for consumer (SharePoint-backed) OneDrive.

"use strict";

// Extract the decoded server-relative id from the current URL.
// Mirrors convert_onedrive_url_to_path() in acl-manager.tcl: pull the `id`
// query param and URL-decode it. Returns null if absent.
function getDecodedId() {
  const m = location.href.match(/[?&]id=([^&]*)/);
  if (!m) return null;
  try {
    return decodeURIComponent(m[1]);
  } catch (e) {
    return m[1];
  }
}

// Derive the consumer CID (the /personal/{CID}/ segment), or null.
function getCid() {
  const dec = getDecodedId();
  if (dec) {
    const m = dec.match(/^\/personal\/([^/]+)\//);
    if (m) return m[1];
  }
  // Fall back to an explicit cid query param if present.
  const q = location.href.match(/[?&]cid=([^&]*)/);
  return q ? decodeURIComponent(q[1]) : null;
}

// The _api web root for the current site. For consumer OneDrive and
// *-my.sharepoint.com personal sites this is /personal/{id}; for team sites
// it is /sites/{name} or /teams/{name}; otherwise the origin root web.
function getWebPrefix(serverRelative) {
  const m = serverRelative.match(/^(\/(?:personal|sites|teams)\/[^/]+)/);
  return m ? m[1] : "";
}

// Human-readable path: strip the /personal/{id}/Documents/ (or
// /.../Shared Documents/) prefix so what remains is what the user sees.
// Mirrors the prefix-stripping in convert_onedrive_url_to_path().
function toDisplayPath(serverRelative) {
  let p = serverRelative.replace(/^\/personal\/[^/]+\/Documents\/?/, "");
  p = p.replace(/^\/(?:sites|teams)\/[^/]+\/(?:Shared )?Documents\/?/i, "");
  return p === "" ? "/" : p;
}

async function fetchUniqueId(serverRelative) {
  const webPrefix = getWebPrefix(serverRelative);
  // Inline the decodedurl argument (verified shape). Single quotes in the
  // path are doubled per OData string-literal escaping.
  const arg = encodeURIComponent(serverRelative).replace(/'/g, "%27%27");
  const url = `${location.origin}${webPrefix}/_api/web/GetFolderByServerRelativePath(decodedurl='${arg}')?$select=UniqueId,Name,ServerRelativeUrl`;
  const resp = await fetch(url, {
    headers: { accept: "application/json;odata=nometadata" },
    credentials: "include",
  });
  if (!resp.ok) throw new Error("API " + resp.status);
  const data = await resp.json();
  return data; // { UniqueId, Name, ServerRelativeUrl }
}

async function computeInfo() {
  const serverRelative = getDecodedId();
  if (!serverRelative || serverRelative[0] !== "/") {
    return {
      ok: false,
      reason: "No folder id in the URL — open a folder in OneDrive.",
      url: location.href,
    };
  }
  const cid = getCid();
  const displayPath = toDisplayPath(serverRelative);
  const out = {
    ok: true,
    host: location.host,
    serverRelative,
    path: displayPath,
    cid,
    shortUrl: null,
    uniqueId: null,
    name: null,
  };
  try {
    const data = await fetchUniqueId(serverRelative);
    out.uniqueId = data.UniqueId;
    out.name = data.Name;
    if (cid && data.UniqueId) {
      out.shortUrl = `https://onedrive.live.com/?id=${data.UniqueId}&cid=${cid}`;
    } else if (data.UniqueId) {
      // Business sites: best-effort; resid-style links are not guaranteed.
      out.shortUrl = `${location.origin}/?id=${data.UniqueId}`;
      out.shortUrlNote = "Business site: short link is best-effort.";
    }
  } catch (e) {
    out.shortUrlError = String(e);
  }
  return out;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === "GET_INFO") {
    computeInfo().then(sendResponse);
    return true; // async response
  }
});
