const state = { selected: null, path: "", view: "pcs", contacts: [], nodeName: "" };

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
  const c = state.contacts.find((x) => x.node_id === state.selected);
  document.getElementById("title-context").textContent = c
    ? "— " + c.alias
    : "";
  document.getElementById("tab").textContent = c ? c.alias : "Shared files";
  const online = state.contacts.filter((x) => x.online).length;
  document.getElementById("sb-left").textContent = c
    ? (c.online ? "Connected" : "Offline") + "  " + c.alias
    : "Ready";
  document.getElementById("sb-right").textContent =
    state.contacts.length
      ? online + "/" + state.contacts.length + " online"
      : "";
}

async function loadInfo() {
  const info = await api("/v1/admin/info");
  state.nodeName = info.name || "";
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
  if (!state.contacts.length) {
    ul.innerHTML = '<li class="hint-row">No PCs. Press + and paste an ID.</li>';
    updateChrome();
    return;
  }
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
    li.innerHTML =
      '<span class="grow"><span class="name">' + escapeHtml(g.name) + '</span>' +
      '<span class="sub">' + fmtExpiry(g) + '</span></span>';
    const b = document.createElement("button");
    b.type = "button";
    b.className = "danger text";
    b.textContent = "Revoke";
    b.onclick = async () => {
      await api("/v1/admin/grants/" + g.fingerprint, { method: "DELETE" });
      loadGrants();
    };
    li.appendChild(b);
    ul.appendChild(li);
  }
}

async function addContact(ev) {
  ev.preventDefault();
  const id = document.getElementById("add-id").value.trim().toLowerCase().replace(/[^0-9a-f]/g, "");
  const alias = document.getElementById("add-alias").value.trim();
  const host = document.getElementById("add-host").value.trim();
  const dur = parseInt(document.getElementById("add-duration").value, 10);
  const status = document.getElementById("add-status");
  if (id.length !== 16) {
    status.textContent = "ID is 16 hex characters.";
    return;
  }
  status.textContent = "Looking on the LAN…";
  try {
    const r = await api("/v1/admin/contacts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ node_id: id, alias, host: host || null, duration_secs: dur }),
    });
    status.textContent =
      r.status === "approved" ? "Approved. You can browse it now."
      : r.status === "pending" ? "Request sent. Waiting for approval."
      : "Denied.";
    if (r.status === "approved" || r.status === "pending") {
      document.getElementById("add-id").value = "";
      document.getElementById("add-alias").value = "";
      document.getElementById("add-host").value = "";
      loadContacts();
    }
  } catch (e) {
    status.textContent = e.message;
  }
}

function renderBreadcrumb() {
  const nav = document.getElementById("breadcrumb");
  nav.innerHTML = "";
  if (!state.selected) return;
  const parts = state.path ? state.path.split("/") : [];
  const root = document.createElement("a");
  root.textContent = "shared";
  root.href = "#";
  root.onclick = (e) => { e.preventDefault(); state.path = ""; loadListing(); };
  nav.appendChild(root);
  parts.forEach((part, i) => {
    nav.appendChild(document.createTextNode(" / "));
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
}

function fileIcon(kind) {
  if (kind === "dir") {
    return '<svg class="fico" viewBox="0 0 16 16"><path d="M1 3h5l1 2h8v8H1z"/></svg>';
  }
  return '<svg class="fico file" viewBox="0 0 16 16"><path d="M4 1h6l4 4v10H4z" fill="none" stroke="currentColor"/><path d="M10 1v4h4" fill="none" stroke="currentColor"/></svg>';
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
  try {
    const data = await api(
      "/v1/admin/browse/" + state.selected + "/list?path=" + encodeURIComponent(state.path)
    );
    for (const e of data.entries) {
      const row = document.createElement("div");
      row.className = "item" + (e.kind === "dir" ? " dir" : "");
      row.innerHTML =
        '<span class="iname">' + fileIcon(e.kind) + '<span></span></span>' +
        '<span class="isize">' + (e.kind === "file" ? fmtSize(e.size) : "") + '</span>' +
        '<span class="itime">' + fmtTime(e.modified_unix) + '</span>' +
        '<span class="iacts"></span>';
      row.querySelector(".iname span").textContent = e.name;
      if (e.kind === "dir") {
        row.onclick = () => { state.path = e.path; loadListing(); };
      } else {
        const acts = row.querySelector(".iacts");
        const dl = document.createElement("a");
        dl.textContent = "Download";
        dl.href = "/v1/admin/browse/" + state.selected + "/file?path=" + encodeURIComponent(e.path);
        const pr = document.createElement("button");
        pr.type = "button";
        pr.textContent = "Print";
        pr.disabled = true;
        pr.title = "Coming next";
        acts.append(dl, pr);
      }
      grid.appendChild(row);
    }
    document.getElementById("sb-mid").textContent =
      data.entries.length + (data.entries.length === 1 ? " item" : " items");
    if (!data.entries.length) status.textContent = "Folder is empty.";
  } catch (err) {
    status.textContent = err.message;
  }
}

document.querySelectorAll(".act").forEach((b) => {
  b.onclick = () => setView(b.dataset.view);
});

document.getElementById("btn-add").onclick = () => {
  const form = document.getElementById("add-form");
  form.hidden = !form.hidden;
  if (!form.hidden) document.getElementById("add-id").focus();
};
document.getElementById("add-form").onsubmit = addContact;

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
setInterval(() => {
  loadContacts();
  loadRequests();
  loadGrants();
}, 5000);
loadListing();
