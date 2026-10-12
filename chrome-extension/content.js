// Content script for the OneDrive / SharePoint web app.
// Answers the toolbar popup with the current folder's human-readable path
// and a short ?id=<resid>&cid=<cid> URL that addresses the folder by id
// instead of the full path.
//
// The resid is the SharePoint UniqueId of the folder, fetched from the
// page's own same-origin authenticated _api endpoint (no OAuth). Verified
// that https://onedrive.live.com/?id=<UniqueId>&cid=<CID> resolves to the
// folder for consumer (SharePoint-backed) OneDrive.
//
// OneDrive is a single-page app whose URL changes without a page load, so
// the info is computed from location.href each time the popup asks.

"use strict";

// --- URL / id parsing (shares the rules of convert_onedrive_url_to_path in
//     warden.tcl) -------------------------------------------------------

function getDecodedId() {
  const m = location.href.match(/[?&]id=([^&]*)/);
  if (!m) return null;
  try {
    return decodeURIComponent(m[1]);
  } catch (e) {
    return m[1];
  }
}

function getCid() {
  const dec = getDecodedId();
  if (dec) {
    const m = dec.match(/^\/personal\/([^/]+)\//);
    if (m) return m[1];
  }
  const q = location.href.match(/[?&]cid=([^&]*)/);
  return q ? decodeURIComponent(q[1]) : null;
}

// The _api web root: /personal/{id}, /sites/{name}, /teams/{name}, else origin.
function getWebPrefix(serverRelative) {
  const m = serverRelative.match(/^(\/(?:personal|sites|teams)\/[^/]+)/);
  return m ? m[1] : "";
}

// Strip the document-library prefix so what remains is what the user sees.
function toDisplayPath(serverRelative) {
  let p = serverRelative.replace(/^\/personal\/[^/]+\/Documents\/?/, "");
  p = p.replace(/^\/(?:sites|teams)\/[^/]+\/(?:Shared )?Documents\/?/i, "");
  return p === "" ? "/" : p;
}

async function fetchUniqueId(serverRelative) {
  const webPrefix = getWebPrefix(serverRelative);
  // Single quotes in the path are doubled per OData string-literal escaping.
  const arg = encodeURIComponent(serverRelative).replace(/'/g, "%27%27");
  const url = `${location.origin}${webPrefix}/_api/web/GetFolderByServerRelativePath(decodedurl='${arg}')?$select=UniqueId,Name,ServerRelativeUrl`;
  const resp = await fetch(url, {
    headers: { accept: "application/json;odata=nometadata" },
    credentials: "include",
  });
  if (!resp.ok) throw new Error("API " + resp.status);
  return resp.json(); // { UniqueId, Name, ServerRelativeUrl }
}

async function computeInfo() {
  const serverRelative = getDecodedId();
  if (!serverRelative || serverRelative[0] !== "/") {
    return { ok: false };
  }
  const cid = getCid();
  const out = {
    ok: true,
    path: toDisplayPath(serverRelative),
    cid,
    shortUrl: null,
    uniqueId: null,
  };
  try {
    const data = await fetchUniqueId(serverRelative);
    out.uniqueId = data.UniqueId;
    if (cid && data.UniqueId) {
      out.shortUrl = `https://onedrive.live.com/?id=${data.UniqueId}&cid=${cid}`;
    } else if (data.UniqueId) {
      out.shortUrl = `${location.origin}/?id=${data.UniqueId}`;
      out.shortUrlBestEffort = true;
    }
  } catch (e) {
    out.shortUrlError = String(e);
  }
  return out;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg === "getInfo") {
    computeInfo().then(sendResponse);
    return true; // response is sent asynchronously
  }
});
