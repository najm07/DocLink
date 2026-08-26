const state = { selected: "mine", path: "", view: "pcs", contacts: [], nodeName: "", selfFp: "" };

function native(cmd) {
  try {
    if (window.ipc && window.ipc.postMessage) {
      window.ipc.postMessage(cmd);
      return true;
    }
  } catch (_) {}
  return false;
}

async function api(url, opts) {
  const r = await fetch(url, opts);
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).error || msg; } catch (_) {}
    throw new Error(msg);
  }
  const ct = r.headers.get("content-type") || "";
  return ct.includes("json") ? r.json() : r.text();
}

function fmtSize(n) {
  if (n < 1024) return n + " B";
  const units = ["KB", "MB", "GB", "TB"];
  let v = n, i = -1;
  do { v /= 1024; i++; } while (v >= 1024 && i < units.length - 1);
  return v.toFixed(1) + " " + units[i];
}

function fmtTime(unix) {
  if (!unix) return "";
  return new Date(unix * 1000).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function fmtExpiry(g) {
  if (!g.expires_unix) return "until revoked";
  const d = g.expires_unix * 1000 - Date.now();
  if (d <= 0) return "expired";
  const days = Math.floor(d / 86400000);
  return days >= 1 ? days + "d left" : Math.floor(d / 3600000) + "h left";
}

function groupId(id) {
  return (id || "").replace(/(.{4})(?=.)/g, "$1-");
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function within(path, ancestor) {
  return ancestor !== "" && path.length > ancestor.length && path.startsWith(ancestor + "/");
}

function topMost(paths) {
  return paths.filter((p) => !paths.some((q) => q !== p && within(p, q)));
}

function setView(name) {
  state.view = name;
  document.querySelectorAll(".act").forEach((b) => {
    b.classList.toggle("active", b.dataset.view === name);
  });
  document.querySelectorAll(".side-view").forEach((el) => {
    el.hidden = el.dataset.view !== name;
  });
}

function updateChrome() {
  const mine = state.selected === "mine";
  const c = state.contacts.find((x) => x.node_id === state.selected);
  document.getElementById("title-context").textContent = mine
    ? "— This PC"
    : c ? "— " + c.alias : "";
  document.getElementById("tab").textContent = mine
    ? "This PC — shared"
    : c ? c.alias : "Shared files";
  const online = state.contacts.filter((x) => x.online).length;
  document.getElementById("sb-left").textContent = mine
    ? "Your shared folder"
    : c ? (c.online ? "Connected" : "Offline") + "  " + c.alias : "Ready";
  document.getElementById("sb-right").textContent =
    state.contacts.length
      ? online + "/" + state.contacts.length + " online"
      : "";
}

async function loadInfo() {
  const info = await api("/v1/admin/info");
  state.nodeName = info.name || "";
  state.selfFp = info.fingerprint || "";
  const btn = document.getElementById("this-node");
  const val = document.getElementById("this-node-id");
  val.textContent = groupId(info.node_id);
  btn.title = "Click to copy · " + info.fingerprint;
  btn.onclick = async () => {
    await navigator.clipboard.writeText(info.node_id);
    const prev = val.textContent;
    val.textContent = "Copied";
    setTimeout(() => { val.textContent = prev; }, 1100);
  };
}

async function loadContacts() {
  state.contacts = await api("/v1/admin/contacts");
  const ul = document.getElementById("peers");
  ul.innerHTML = "";

  const me = document.createElement("li");
  me.className = "row" + (state.selected === "mine" ? " active" : "");
  me.innerHTML =
    '<svg class="fico" viewBox="0 0 16 16"><path d="M2 3h12v8H2z" fill="none" stroke="currentColor"/><path d="M6 13h4" stroke="currentColor"/></svg>' +
    '<span class="grow"><span class="name">This PC</span>' +
    '<span class="sub">shared/</span></span>';
  me.onclick = () => {
    state.selected = "mine";
    state.path = "";
    loadContacts();
    loadListing();
  };
  ul.appendChild(me);

  for (const c of state.contacts) {
    const li = document.createElement("li");
    li.className = "row" + (state.selected === c.node_id ? " active" : "");
    li.innerHTML =
      '<span class="dot ' + (c.online ? "on" : "") + '"></span>' +
      '<span class="grow">' +
        '<span class="name">' + escapeHtml(c.alias) + '</span>' +
        '<span class="sub">' + groupId(c.node_id) + '</span>' +
      '</span>' +
      '<span class="tag">' + escapeHtml(c.status) + '</span>';
    li.onclick = () => {
      state.selected = c.node_id;
      state.path = "";
      loadContacts();
      loadListing();
    };
    ul.appendChild(li);
  }
  updateChrome();
}

async function loadRequests() {
  const reqs = await api("/v1/admin/requests");
  const badge = document.getElementById("act-inbox-badge");
  badge.hidden = reqs.length === 0;
  badge.textContent = reqs.length;
  const ul = document.getElementById("requests");
  ul.innerHTML = "";
  if (!reqs.length) {
    ul.innerHTML = '<li class="hint-row">No pending requests.</li>';
    return;
  }
  for (const r of reqs) {
    const li = document.createElement("li");
    li.className = "block";
    const days = Math.round(r.requested_duration_secs / 86400);
    const want = r.requested_duration_secs === 0 ? "until revoked" : days + "d";
    li.innerHTML =
      '<div class="name">' + escapeHtml(r.name) + '</div>' +
      '<div class="sub">' + groupId(r.node_id) + ' · wants ' + want + '</div>' +
      '<div class="actions"></div>';
    const row = li.querySelector(".actions");
    for (const d of [1, 7, 30]) {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = d + "d";
      b.onclick = () => decide(r.node_id, "approve", d * 86400);
      row.appendChild(b);
    }
    const always = document.createElement("button");
    always.type = "button";
    always.textContent = "Always";
    always.onclick = () => decide(r.node_id, "approve", 0);
    row.appendChild(always);
    const deny = document.createElement("button");
    deny.type = "button";
    deny.className = "danger";
    deny.textContent = "Deny";
    deny.onclick = () => decide(r.node_id, "deny", 0);
    row.appendChild(deny);
    ul.appendChild(li);
  }
}

async function decide(nodeId, decision, secs) {
  await api("/v1/admin/requests/" + nodeId + "/decision", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ decision, duration_secs: secs }),
  });
  await Promise.all([loadRequests(), loadGrants()]);
}

async function loadGrants() {
  const grants = await api("/v1/admin/grants");
  const ul = document.getElementById("grants");
  ul.innerHTML = "";
  if (!grants.length) {
    ul.innerHTML = '<li class="hint-row">Nobody has access to this PC.</li>';
    return;
  }
  for (const g of grants) {
    const li = document.createElement("li");
    li.className = "row";
    const scope = g.paths && g.paths.length ? g.paths.length + " item(s)" : "Everything";
    li.innerHTML =
      '<span class="grow"><span class="name">' + escapeHtml(g.name) + '</span>' +
      '<span class="sub">' + fmtExpiry(g) + ' · ' + scope + '</span></span>';
    const edit = document.createElement("button");
    edit.type = "button";
    edit.className = "text";
    edit.textContent = "Access";
    edit.onclick = () => openAccessEditor(g);
    const revoke = document.createElement("button");
    revoke.type = "button";
    revoke.className = "danger text";
    revoke.textContent = "Revoke";
    revoke.onclick = async () => {
      await api("/v1/admin/grants/" + g.fingerprint, { method: "DELETE" });
      loadGrants();
    };
    li.append(edit, revoke);
    ul.appendChild(li);
  }
}

// ---- side panel (share item / access editor) ----

function closePanel() {
  const p = document.getElementById("side-panel");
  if (p) p.remove();
}

function panelOverlay(titleText) {
  closePanel();
  const el = document.createElement("div");
  el.className = "share-panel";
  el.id = "side-panel";
  el.innerHTML =
    '<div class="sp-head"><b></b><button type="button" class="tool" id="sp-close">✕</button></div>' +
    '<div class="sp-body"></div>';
  el.querySelector("b").textContent = titleText;
  el.querySelector("#sp-close").onclick = closePanel;
  document.body.appendChild(el);
  return el.querySelector(".sp-body");
}

async function openSharePanel(path) {
  const grants = await api("/v1/admin/grants");
  const body = panelOverlay('Share "' + path.split("/").pop() + '"');
  if (!grants.length) {
    body.innerHTML = '<p class="hint-row">No approved PCs yet. Approve a request first.</p>';
    return;
  }
  const checked = new Set();
  const list = document.createElement("div");
  for (const g of grants) {
    const full = !g.paths || g.paths.length === 0;
    const has = full || (g.paths || []).some((p) => path === p || within(path, p));
    if (has) checked.add(g.fingerprint);
    const row = document.createElement("label");
    row.className = "sp-row";
    row.innerHTML = '<input type="checkbox"> <span class="name"></span> <span class="dim"></span>';
    row.querySelector(".name").textContent = g.name;
    row.querySelector(".dim").textContent = full ? "full access" : (g.paths || []).length + " item(s)";
    const cb = row.querySelector("input");
    cb.checked = has;
    cb.onchange = () => {
      if (cb.checked) checked.add(g.fingerprint);
      else checked.delete(g.fingerprint);
    };
    list.appendChild(row);
  }
  body.appendChild(list);
  const note = document.createElement("p");
  note.className = "dim";
  note.textContent =
    "Unchecking a PC hides this item from them — PCs that had full access switch to selected-items mode covering the rest of your share.";
  body.appendChild(note);
  const actions = document.createElement("div");
  actions.className = "sp-actions";
  const save = document.createElement("button");
  save.type = "button";
  save.className = "primary";
  save.textContent = "Save";
  save.onclick = async () => {
    await api("/v1/admin/share-item", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ path, fingerprints: [...checked] }),
    });
    closePanel();
    loadGrants();
  };
  actions.appendChild(save);
  body.appendChild(actions);
}

async function buildTree(container, base, checked, depth) {
  const data = await api("/v1/admin/myshare/list?path=" + encodeURIComponent(base));
  for (const e of data.entries) {
    const row = document.createElement("div");
    row.className = "gnode";
    row.style.paddingLeft = depth * 14 + "px";
    const inherited = [...checked].some((p) => within(e.path, p));
    row.innerHTML =
      (e.kind === "dir" ? '<button type="button" class="tw">▸</button>' : '<span class="tw"></span>') +
      '<input type="checkbox">' +
      '<span class="gname"></span>';
    row.querySelector(".gname").textContent = e.name;
    const cb = row.querySelector("input");
    cb.checked = inherited || checked.has(e.path);
    cb.disabled = inherited;
    if (inherited) row.title = "Covered by a checked parent folder";
    cb.onchange = () => {
      if (cb.checked) {
        for (const p of [...checked]) {
          if (within(p, e.path)) checked.delete(p);
        }
        checked.add(e.path);
      } else {
        checked.delete(e.path);
      }
    };
    container.appendChild(row);
    if (e.kind === "dir") {
      const kids = document.createElement("div");
      kids.style.display = "none";
      container.appendChild(kids);
      let loaded = false;
      row.querySelector(".tw").onclick = () => {
        const open = kids.style.display !== "none";
        kids.style.display = open ? "none" : "";
        row.querySelector(".tw").textContent = open ? "▸" : "▾";
        if (!open && !loaded) {
          loaded = true;
          buildTree(kids, e.path, checked, depth + 1);
        }
      };
    }
  }
}

async function openAccessEditor(g) {
  const body = panelOverlay("Access — " + g.name);
  const mode = document.createElement("div");
  mode.className = "sp-mode";
  mode.innerHTML =
    '<label><input type="radio" name="sp-mode" value="all"> Everything</label>' +
    '<label><input type="radio" name="sp-mode" value="custom"> Only selected items</label>';
  body.appendChild(mode);
  const treeBox = document.createElement("div");
  treeBox.className = "gtree";
  body.appendChild(treeBox);
  const actions = document.createElement("div");
  actions.className = "sp-actions";
  const save = document.createElement("button");
  save.type = "button";
  save.className = "primary";
  save.textContent = "Save";
  actions.appendChild(save);
  body.appendChild(actions);

  const checked = new Set(g.paths || []);
  const [rAll, rCustom] = mode.querySelectorAll("input");
  rAll.checked = !g.paths || g.paths.length === 0;
  rCustom.checked = !rAll.checked;
  const refreshTree = () => {
    treeBox.style.display = rCustom.checked ? "" : "none";
  };
  rAll.onchange = refreshTree;
  rCustom.onchange = refreshTree;
  refreshTree();
  buildTree(treeBox, "", checked, 0);

  save.onclick = async () => {
    const paths = rAll.checked ? [] : topMost([...checked]);
    await api("/v1/admin/grants/" + g.fingerprint, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ paths }),
    });
    closePanel();
    loadGrants();
  };
}

// ---- add contact (two-stage: resolve+verify fingerprint, then pair) ----

let pendingAdd = null;

function resetAddStage() {
  pendingAdd = null;
  document.getElementById("add-fields").hidden = false;
  document.getElementById("add-verify").hidden = true;
}

async function addContact(ev) {
  ev.preventDefault();
  const status = document.getElementById("add-status");

  // Stage 1 — resolve the ID and show the remote fingerprint for
  // out-of-band verification. No pair request leaves this machine yet.
  if (!pendingAdd) {
    const id = document.getElementById("add-id").value.trim().toLowerCase().replace(/[^0-9a-f]/g, "");
    const alias = document.getElementById("add-alias").value.trim();
    const host = document.getElementById("add-host").value.trim();
    const dur = parseInt(document.getElementById("add-duration").value, 10);
    if (id.length !== 16) {
      status.textContent = "ID is 16 hex characters.";
      return;
    }
    status.textContent = "Looking on the LAN…";
    try {
      const q = "/v1/admin/contact-fingerprint?node_id=" + encodeURIComponent(id) +
        (host ? "&host=" + encodeURIComponent(host) : "");
      const info = await api(q);
      pendingAdd = { id, alias, host, dur };
      document.getElementById("add-remote-fp").textContent = groupId(info.fingerprint);
      document.getElementById("add-self-fp").textContent = groupId(state.selfFp);
      document.getElementById("add-fields").hidden = true;
      document.getElementById("add-verify").hidden = false;
      const cb = document.getElementById("add-fp-ok");
      cb.checked = false;
      document.getElementById("add-confirm").disabled = true;
      status.textContent = "";
    } catch (e) {
      status.textContent = e.message;
    }
    return;
  }

  // Stage 2 — the user confirmed the fingerprint; send the pair request.
  status.textContent = "Sending pair request…";
  try {
    const r = await api("/v1/admin/contacts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        node_id: pendingAdd.id,
        alias: pendingAdd.alias,
        host: pendingAdd.host || null,
        duration_secs: pendingAdd.dur,
      }),
    });
    status.textContent =
      r.status === "approved" ? "Approved. You can browse it now."
      : r.status === "pending" ? "Request sent. Waiting for approval."
      : "Denied.";
    if (r.status === "approved" || r.status === "pending") {
      resetAddStage();
      document.getElementById("add-id").value = "";
      document.getElementById("add-alias").value = "";
      document.getElementById("add-host").value = "";
      loadContacts();
    }
  } catch (e) {
    status.textContent = e.message;
  }
}

let discovered = [];

async function loadPeers() {
  try {
    discovered = await api("/v1/admin/peers");
  } catch (_) {
    discovered = [];
  }
  const box = document.getElementById("add-discovered");
  if (!box) return;
  box.innerHTML = "";
  if (!discovered.length) {
    const hint = document.createElement("p");
    hint.className = "hint-row";
    hint.textContent =
      "Nothing discovered on the LAN. Both PCs must run DocLink and allow it through Windows Firewall (mDNS UDP 5353).";
    box.appendChild(hint);
    return;
  }
  box.appendChild(Object.assign(document.createElement("p"), {
    className: "dim",
    textContent: "Discovered on the LAN — click to fill:",
  }));
  for (const p of discovered) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "disc-row";
    row.textContent = groupId(p.node_id) + "  ·  " + p.addr + ":" + p.http_port;
    row.onclick = () => {
      document.getElementById("add-id").value = p.node_id;
      document.getElementById("add-status").textContent =
        "ID filled — click Next to verify this PC.";
    };
    box.appendChild(row);
  }
}

// ---- editor (file grid) ----

function renderBreadcrumb() {
  const nav = document.getElementById("breadcrumb");
  nav.innerHTML = "";
  if (!state.selected) return;
  const mine = state.selected === "mine";
  const parts = state.path ? state.path.split("/") : [];
  const root = document.createElement("a");
  root.textContent = "shared";
  root.href = "#";
  root.onclick = (e) => { e.preventDefault(); state.path = ""; loadListing(); };
  nav.appendChild(root);
  parts.forEach((part, i) => {
    nav.appendChild(document.createTextNode(" / "));
    const a = document.createElement("a");
    a.textContent = part;
    a.href = "#";
    a.onclick = (e) => {
      e.preventDefault();
      state.path = parts.slice(0, i + 1).join("/");
      loadListing();
    };
    nav.appendChild(a);
  });
  if (mine) {
    const open = document.createElement("a");
    open.textContent = "  ·  open folder";
    open.href = "#";
    open.className = "dim";
    open.onclick = (e) => {
      e.preventDefault();
      api("/v1/admin/myshare/reveal", { method: "POST" });
    };
    nav.appendChild(open);
  }
}

function fileIcon(kind) {
  if (kind === "dir") {
    return '<svg class="fico" viewBox="0 0 16 16"><path d="M1 3h5l1 2h8v8H1z"/></svg>';
  }
  return '<svg class="fico file" viewBox="0 0 16 16"><path d="M4 1h6l4 4v10H4z" fill="none" stroke="currentColor"/><path d="M10 1v4h4" fill="none" stroke="currentColor"/></svg>';
}

// Type-aware glyph for icon views: same visual language as fileIcon
// (amber filled folder, stroked gray documents), but per file category.
const S = 'fill="none" stroke="currentColor" stroke-width="1.2"';
const Glyph = {
  folder: '<svg class="fico" viewBox="0 0 16 16"><path d="M1 3h5l1 2h8v8H1z"/></svg>',
  file: '<svg class="fico file" viewBox="0 0 16 16"><path d="M4 1h6l4 4v10H4z" fill="none" stroke="currentColor"/><path d="M10 1v4h4" fill="none" stroke="currentColor"/></svg>',
  image: `<svg class="fico file" viewBox="0 0 16 16"><rect x="2" y="3" width="12" height="10" rx="1" ${S}/><circle cx="5.5" cy="6.2" r="1.1" ${S}/><path d="M4 11.5l3-3 2.2 2.2L11.5 8.5l2.5 2.5" ${S}/></svg>`,
  audio: `<svg class="fico file" viewBox="0 0 16 16"><path d="M9.5 3v6.8a2.3 2.3 0 1 1-1.4-2.1" ${S}/><path d="M9.5 3l3.8-.9v3l-3.8.9" ${S}/></svg>`,
  video: `<svg class="fico file" viewBox="0 0 16 16"><rect x="2" y="4" width="12" height="9" rx="1" ${S}/><path d="M7 7l3.5 1.8L7 10.6z" fill="currentColor" stroke="none"/></svg>`,
  pdf: `<svg class="fico file" viewBox="0 0 16 16"><path d="M4 1h6l4 4v10H4z" ${S}/><path d="M10 1v4h4" ${S}/><path d="M6.2 9h4.6M6.2 11.5h4.6" ${S}/><text x="6" y="14.4" font-size="3.4" fill="currentColor" stroke="none" font-family="Segoe UI">A</text></svg>`,
  sheet: `<svg class="fico file" viewBox="0 0 16 16"><rect x="2" y="2.5" width="12" height="11.5" ${S}/><path d="M2 6h12M2 9.5h12M6 2.5V14M10 2.5V14" ${S}/></svg>`,
  slides: `<svg class="fico file" viewBox="0 0 16 16"><rect x="2" y="3" width="12" height="8" rx="1" ${S}/><path d="M8 11v2.5M5.5 13.5h5" ${S}/></svg>`,
  archive: `<svg class="fico file" viewBox="0 0 16 16"><rect x="3" y="2" width="10" height="12" ${S}/><path d="M8 2v4.5M6.4 4.4h3.2" ${S}/></svg>`,
  code: `<svg class="fico file" viewBox="0 0 16 16"><path d="M5.5 4.5L2 8l3.5 3.5M10.5 4.5L14 8l-3.5 3.5" ${S}/></svg>`,
  doc: `<svg class="fico file" viewBox="0 0 16 16"><path d="M4 1h6l4 4v10H4z" ${S}/><path d="M10 1v4h4" ${S}/><path d="M6 8h5M6 10.5h5M6 13h3.5" ${S}/></svg>`,
};

const EXT_GLYPH = {
  png: "image", jpg: "image", jpeg: "image", gif: "image", webp: "image",
  bmp: "image", ico: "image", svg: "image",
  mp4: "video", m4v: "video", webm: "video", mov: "video", mkv: "video",
  mp3: "audio", wav: "audio", ogg: "audio", oga: "audio", m4a: "audio",
  flac: "audio",
  pdf: "pdf",
  xlsx: "sheet", xlsm: "sheet", xls: "sheet", csv: "sheet",
  pptx: "slides", ppt: "slides",
  zip: "archive", rar: "archive", "7z": "archive",
  js: "code", mjs: "code", ts: "code", rs: "code", py: "code", rb: "code",
  sh: "code", bat: "code", ps1: "code", c: "code", h: "code", cpp: "code",
  hpp: "code", cs: "code", java: "code",
  exe: "doc", msi: "doc",
};

function fileGlyph(name, kind) {
  if (kind === "dir") return Glyph.folder;
  const e = extOf(name);
  if (EXT_GLYPH[e]) return Glyph[EXT_GLYPH[e]];
  if (VIEWABLE_TEXT.includes(e)) return Glyph.doc;
  if (e === "") return Glyph.doc;
  return Glyph.file;
}

async function loadListing() {
  renderBreadcrumb();
  const grid = document.getElementById("listing");
  const status = document.getElementById("status");
  grid.innerHTML = "";
  status.textContent = "";
  document.getElementById("sb-mid").textContent = "";
  if (!state.selected) {
    status.textContent = "Select a PC in the sidebar, or press + to add one by ID.";
    return;
  }
  const mine = state.selected === "mine";
  const url = mine
    ? "/v1/admin/myshare/list?path=" + encodeURIComponent(state.path)
    : "/v1/admin/browse/" + state.selected + "/list?path=" + encodeURIComponent(state.path);
  try {
    const data = await api(url);
    for (const e of data.entries) {
      const row = document.createElement("div");
      row.className = "item" + (e.kind === "dir" ? " dir" : "");
      row.innerHTML =
        '<span class="iname">' + fileGlyph(e.name, e.kind) + '<span></span></span>' +
        '<span class="isize">' + (e.kind === "file" ? fmtSize(e.size) : "") + '</span>' +
        '<span class="itime">' + fmtTime(e.modified_unix) + '</span>' +
        '<span class="iacts"></span>';
      row.querySelector(".iname span").textContent = e.name;
      if (e.kind === "dir") {
        row.onclick = (ev) => {
          if (ev.target.closest(".iacts")) return;
          state.path = e.path;
          loadListing();
        };
      }
      const acts = row.querySelector(".iacts");
      if (mine) {
        const sh = document.createElement("button");
        sh.type = "button";
        sh.textContent = "Share…";
        sh.onclick = () => openSharePanel(e.path);
        acts.appendChild(sh);
        const del = document.createElement("button");
        del.type = "button";
        del.className = "danger";
        del.textContent = "Delete";
        del.onclick = async () => {
          if (!confirm('Delete "' + e.name + '" from your share?')) return;
          await api("/v1/admin/myshare?path=" + encodeURIComponent(e.path), { method: "DELETE" });
          loadListing();
        };
        acts.appendChild(del);
      } else if (e.kind === "file") {
        const vw = document.createElement("button");
        vw.type = "button";
        vw.textContent = "View";
        vw.title = "Preview before downloading";
        vw.onclick = () => openViewer(state.selected, e.path, e.size);
        const dl = document.createElement("a");
        dl.textContent = "Download";
        dl.href = "/v1/admin/browse/" + state.selected + "/file?path=" + encodeURIComponent(e.path);
        const pr = document.createElement("button");
        pr.type = "button";
        pr.textContent = "Print";
        pr.title = "Download and hand to Windows' print verb";
        pr.onclick = async () => {
          const mid = document.getElementById("sb-mid");
          const prev = mid.textContent;
          pr.disabled = true;
          mid.textContent = "Printing " + e.name + "…";
          try {
            await api("/v1/admin/print/" + state.selected + "?path=" + encodeURIComponent(e.path), { method: "POST" });
            mid.textContent = "Sent to printer: " + e.name;
          } catch (err) {
            mid.textContent = "";
            status.textContent = err.message;
          }
          pr.disabled = false;
          setTimeout(() => { if (mid.textContent.startsWith("Sent to printer")) mid.textContent = prev; }, 4000);
        };
        acts.append(vw, dl, pr);
      }
      grid.appendChild(row);
    }
    document.getElementById("sb-mid").textContent =
      data.entries.length + (data.entries.length === 1 ? " item" : " items");
    if (!data.entries.length) {
      status.textContent = mine
        ? "Your shared folder is empty — drop files into shared/ to publish them."
        : "Folder is empty.";
    }
  } catch (err) {
    status.textContent = err.message;
  }
}

// ---- network view (M5): live LAN discovery + visibility toggle ----

let netTimer = null;

async function renderNet() {
  const ul = document.getElementById("netlist");
  if (!ul) return;
  let peers = [], contacts = [];
  try {
    [peers, contacts] = await Promise.all([
      api("/v1/admin/peers"),
      api("/v1/admin/contacts"),
    ]);
  } catch (_) { /* daemon restarting; keep last frame */ }

  const badge = document.getElementById("act-net-badge");
  if (badge) {
    badge.hidden = peers.length === 0;
    badge.textContent = peers.length;
  }

  ul.innerHTML = "";
  if (!peers.length) {
    const li = document.createElement("li");
    li.className = "hint-row";
    li.textContent =
      "No PCs discovered yet. They must run DocLink with 'Visible' enabled and allow mDNS (UDP 5353) through the firewall.";
    ul.appendChild(li);
  }
  for (const p of peers) {
    const known = contacts.find((c) => c.node_id === p.node_id);
    const li = document.createElement("li");
    li.className = "row" + (known && state.selected === p.node_id ? " active" : "");
    li.innerHTML =
      '<span class="dot on"></span>' +
      '<span class="grow"><span class="name"></span>' +
      '<span class="sub">' + escapeHtml(p.addr + ":" + p.http_port) + "</span></span>" +
      '<span class="tag"></span>';
    li.querySelector(".name").textContent = known ? known.alias : groupId(p.node_id);
    const tag = li.querySelector(".tag");
    if (known) {
      tag.textContent = known.status;
    } else {
      const add = document.createElement("button");
      add.type = "button";
      add.textContent = "Add";
      add.onclick = (ev) => {
        ev.stopPropagation();
        document.getElementById("add-id").value = p.node_id;
        setView("pcs");
        const form = document.getElementById("add-form");
        form.hidden = false;
        resetAddStage();
        document.getElementById("add-alias").focus();
        loadPeers();
      };
      tag.appendChild(add);
    }
    ul.appendChild(li);
  }
}

async function loadVisibility() {
  const cb = document.getElementById("adv-toggle");
  if (!cb) return;
  try {
    const s = await api("/v1/admin/settings");
    cb.checked = !!s.advertise;
  } catch (_) { /* keep last known */ }
}

async function saveVisibility() {
  const cb = document.getElementById("adv-toggle");
  try {
    const r = await api("/v1/admin/settings", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ advertise: cb.checked }),
    });
    cb.checked = !!r.advertise;
  } catch (e) {
    document.getElementById("add-status").textContent = e.message || String(e);
    // revert to server truth
    loadVisibility();
  }
}

// ---- file viewer (preview before download) ----

const VIEWABLE_TEXT = ["txt","md","log","csv","json","xml","toml","ini","cfg",
  "yaml","yml","js","mjs","ts","rs","py","rb","sh","bat","ps1","c","h","cpp",
  "hpp","cs","java","html","htm","css"];
const TEXT_PREVIEW_LIMIT = 512 * 1024;

function extOf(name) {
  const i = name.lastIndexOf(".");
  return i >= 0 ? name.slice(i + 1).toLowerCase() : "";
}

function viewerKind(name, size) {
  const e = extOf(name);
  if (e === "pdf") return "pdf";
  if (["png","jpg","jpeg","gif","webp","bmp","ico"].includes(e)) return "image";
  if (e === "svg") return "svg";
  if (["mp4","m4v","webm","mov","mkv"].includes(e)) return "video";
  if (["mp3","wav","ogg","oga","m4a","flac"].includes(e)) return "audio";
  if (VIEWABLE_TEXT.includes(e)) return size <= 8 * 1024 * 1024 ? "text" : "toolarge";
  if (e === "") return size <= 8 * 1024 * 1024 ? "text" : "toolarge"; // extensionless: try text
  if (e === "docx") return "docx";
  if (["xlsx","xlsm","xls"].includes(e)) return "sheet";
  if (["pptx","ppt","odt","ods","odp","rtf","doc"].includes(e)) return "office";
  return "unknown";
}

// Lazy, once-only loader for the vendored preview libraries.
const libCache = {};
function loadLib(src) {
  libCache[src] ??= new Promise((res, rej) => {
    const s = document.createElement("script");
    s.src = src;
    s.onload = res;
    s.onerror = () => { delete libCache[src]; rej(new Error("failed to load " + src)); };
    document.head.appendChild(s);
  });
  return libCache[src];
}

async function fetchBuffer(raw) {
  const r = await fetch(raw);
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.arrayBuffer();
}

function openViewer(peerId, path, size) {
  const name = path.split("/").pop();
  const raw = "/v1/admin/browse/" + peerId + "/raw?path=" + encodeURIComponent(path);
  const dl  = "/v1/admin/browse/" + peerId + "/file?path=" + encodeURIComponent(path);
  const kind = viewerKind(name, size);

  closeViewer();
  const el = document.createElement("div");
  el.className = "viewer-overlay";
  el.id = "file-viewer";
  el.innerHTML =
    '<div class="viewer">' +
      '<div class="v-head"><b class="v-name"></b>' +
        '<span class="dim v-size"></span>' +
        '<button type="button" class="text" id="v-download">Download</button>' +
        '<button type="button" class="tool" id="v-close">✕</button></div>' +
      '<div class="v-body" id="v-body"><p class="hint-row">Loading preview…</p></div>' +
    '</div>';
  document.body.appendChild(el);
  el.querySelector(".v-name").textContent = name;
  el.querySelector(".v-size").textContent = fmtSize(size);
  el.querySelector("#v-close").onclick = closeViewer;
  const dlb = el.querySelector("#v-download");
  dlb.onclick = () => { location.href = dl; };
  el.addEventListener("click", (ev) => { if (ev.target === el) closeViewer(); });

  const body = el.querySelector("#v-body");
  switch (kind) {
    case "pdf":
      body.innerHTML = '<iframe class="v-frame" title="PDF preview"></iframe>';
      body.querySelector("iframe").src = raw;
      break;
    case "image":
    case "svg":
      body.classList.add("centered");
      body.innerHTML = '<img class="v-img" alt="preview">';
      body.querySelector("img").src = raw;
      break;
    case "video":
      body.innerHTML = '<video class="v-media" controls autoplay></video>';
      body.querySelector("video").src = raw;
      break;
    case "audio":
      body.classList.add("centered");
      body.innerHTML =
        '<div class="v-audiocard"><audio controls autoplay style="width:min(560px,90%)"></audio></div>';
      body.querySelector("audio").src = raw;
      break;
    case "text": {
      fetch(raw)
        .then((r) => (r.ok ? r.text() : Promise.reject(new Error("HTTP " + r.status))))
        .then((t) => {
          if (!document.getElementById("file-viewer")) return; // closed meanwhile
          if (t.length > TEXT_PREVIEW_LIMIT) t = t.slice(0, TEXT_PREVIEW_LIMIT) + "\n… truncated …";
          body.innerHTML = '<pre class="v-text"></pre>';
          body.querySelector("pre").textContent = t;
        })
        .catch((err) => {
          body.innerHTML = '<p class="hint-row">Preview failed: ' + escapeHtml(String(err.message || err)) + "</p>";
        });
      break;
    }
    case "toolarge":
      body.innerHTML = '<p class="hint-row">File too large to preview as text — use Download.</p>';
      break;
    case "docx":
      body.innerHTML =
        '<div class="v-docx-wrap"><p class="hint-row">Rendering document…</p></div>';
      (async () => {
        try {
          await loadLib("vendor/jszip.min.js");
          await loadLib("vendor/docx-preview.min.js");
          const buf = await fetchBuffer(raw);
          if (!document.getElementById("file-viewer")) return;
          const wrap = body.querySelector(".v-docx-wrap");
          wrap.innerHTML = "";
          await window.docx.renderAsync(buf, wrap, null, {
            inWrapper: true,
            ignoreLastRenderedPageBreak: true,
          });
          wrap.classList.add("v-docx-page");
        } catch (err) {
          const wrap = body.querySelector(".v-docx-wrap");
          if (wrap) wrap.innerHTML = '<p class="hint-row">Preview failed: ' + escapeHtml(String(err.message || err)) + "</p>";
        }
      })();
      break;
    case "sheet": {
      body.innerHTML =
        '<div class="v-sheet-wrap"><p class="hint-row">Rendering spreadsheet…</p></div>';
      (async () => {
        try {
          await loadLib("vendor/xlsx.full.min.js");
          const buf = await fetchBuffer(raw);
          if (!document.getElementById("file-viewer")) return;
          const wb = window.XLSX.read(buf, { type: "array", sheetRows: 5000 });
          const wrap = body.querySelector(".v-sheet-wrap");
          wrap.innerHTML = "";
          for (const sheetName of wb.SheetNames) {
            const h = document.createElement("h4");
            h.className = "v-sheet-name";
            h.textContent = sheetName;
            wrap.appendChild(h);
            const holder = document.createElement("div");
            holder.className = "v-sheet";
            holder.innerHTML = window.XLSX.utils.sheet_to_html(wb.Sheets[sheetName]);
            wrap.appendChild(holder);
          }
        } catch (err) {
          const wrap = body.querySelector(".v-sheet-wrap");
          if (wrap) wrap.innerHTML = '<p class="hint-row">Preview failed: ' + escapeHtml(String(err.message || err)) + "</p>";
        }
      })();
      break;
    }
    case "office":
      body.innerHTML =
        '<p class="hint-row">No in-browser renderer for this format (.ppt/.pptx/.odp/.doc legacy) — use Download to open it locally.</p>';
      break;
    default:
      body.innerHTML = '<p class="hint-row">No preview available for this file type — use Download.</p>';
  }
}

function closeViewer() {
  const v = document.getElementById("file-viewer");
  if (v) {
    // Stop media playback before teardown.
    v.querySelectorAll("video,audio").forEach((m) => { try { m.pause(); } catch (_) {} });
    v.remove();
  }
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeViewer();
});

function initNetView() {
  const cb = document.getElementById("adv-toggle");
  if (!cb) return;
  cb.addEventListener("change", saveVisibility);
  document.querySelectorAll(".act").forEach((b) => {
    b.addEventListener("click", () => {
      if (b.dataset.view === "net") {
        renderNet();
        loadVisibility();
      }
    });
  });
}

document.querySelectorAll(".act").forEach((b) => {
  b.onclick = () => setView(b.dataset.view);
});

// ---- view mode switching (list / small icons / large icons) ----

const FILE_VIEWS = ["list", "icons-sm", "icons-lg"];

function applyFileView(v) {
  if (!FILE_VIEWS.includes(v)) v = "list";
  const grid = document.getElementById("listing");
  if (!grid) return;
  grid.className = "grid" + (v === "list" ? "" : " view-" + v);
  const head = document.querySelector(".grid-head");
  if (head) head.style.display = v === "list" ? "" : "none";
  document.querySelectorAll("#view-switch button").forEach((b) => {
    b.classList.toggle("active", b.dataset.v === v);
  });
}

function initFileView() {
  const bar = document.getElementById("view-switch");
  if (!bar) return;
  bar.querySelectorAll("button").forEach((b) => {
    b.onclick = () => {
      localStorage.setItem("doclink.fileView", b.dataset.v);
      applyFileView(b.dataset.v);
    };
  });
  applyFileView(localStorage.getItem("doclink.fileView") || "list");
}

document.getElementById("btn-add").onclick = () => {
  const form = document.getElementById("add-form");
  form.hidden = !form.hidden;
  if (!form.hidden) {
    resetAddStage();
    document.getElementById("add-id").focus();
    loadPeers();
  }
};
document.getElementById("add-form").onsubmit = addContact;
document.getElementById("add-fp-ok").onchange = (e) => {
  document.getElementById("add-confirm").disabled = !e.target.checked;
};
document.getElementById("add-back").onclick = () => {
  resetAddStage();
  document.getElementById("add-status").textContent = "";
};

const drag = document.getElementById("title-drag");
drag.addEventListener("mousedown", (e) => {
  if (e.button === 0) native("drag");
});
drag.addEventListener("dblclick", () => native("maximize"));

if (native("ping") || (window.ipc && window.ipc.postMessage)) {
  document.getElementById("win-controls").hidden = false;
  document.querySelectorAll("#win-controls [data-win]").forEach((b) => {
    b.addEventListener("click", () => native(b.dataset.win));
  });
}

loadInfo();
loadContacts();
loadRequests();
loadGrants();
initNetView();
initFileView();
setInterval(() => {
  loadContacts();
  loadRequests();
  loadGrants();
  if (!document.getElementById("add-form").hidden) loadPeers();
  if (state.view === "net") renderNet();
}, 5000);
loadListing();
