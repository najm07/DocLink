// DocLink web UI — talks only to the local daemon's admin plane.
// PCs are added by DocLink ID and approved by the sharing PC;
// browsing goes through the daemon's signed proxy.

const state = { selected: null, path: "" };

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
  if (!unix) return "—";
  const d = new Date(unix * 1000);
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function fmtExpiry(g) {
  if (!g.expires_unix) return "until revoked";
  const d = g.expires_unix * 1000 - Date.now();
  if (d <= 0) return "expired";
  const days = Math.floor(d / 86400000);
  if (days >= 1) return days + "d left";
  return Math.floor(d / 3600000) + "h left";
}

function groupId(id) {
  return (id || "").replace(/(.{4})(?=.)/g, "$1-");
}

function icon(kind) {
  if (kind === "dir") {
    return '<svg class="ico" viewBox="0 0 24 24"><path d="M3 7h6l2 2h10v10H3z" fill="none" stroke="currentColor" stroke-width="1.8"/></svg>';
  }
  return '<svg class="ico" viewBox="0 0 24 24"><path d="M7 3h7l5 5v13H7z" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M14 3v5h5" fill="none" stroke="currentColor" stroke-width="1.8"/></svg>';
}

async function loadInfo() {
  const info = await api("/v1/admin/info");
  const btn = document.getElementById("this-node");
  const val = document.getElementById("this-node-id");
  val.textContent = groupId(info.node_id);
  btn.title = "Click to copy · fingerprint: " + info.fingerprint;
  btn.onclick = async () => {
    await navigator.clipboard.writeText(info.node_id);
    const prev = val.textContent;
    val.textContent = "Copied";
    setTimeout(() => { val.textContent = prev; }, 1200);
  };
}

async function loadContacts() {
  const contacts = await api("/v1/admin/contacts");
  const ul = document.getElementById("peers");
  ul.innerHTML = "";
  if (!contacts.length) {
    ul.innerHTML = '<li class="empty-row">No PCs yet. Click + to add one by ID.</li>';
    return;
  }
  for (const c of contacts) {
    const li = document.createElement("li");
    li.className = "peer" + (state.selected === c.node_id ? " active" : "");
    li.innerHTML =
      '<span class="dot ' + (c.online ? "on" : "off") + '"></span>' +
      '<span class="peer-meta">' +
        '<span class="peer-name">' + escapeHtml(c.alias) + '</span>' +
        '<span class="peer-sub">' + groupId(c.node_id) + ' · ' + escapeHtml(c.status) + '</span>' +
      '</span>';
    li.onclick = () => {
      state.selected = c.node_id;
      state.path = "";
      loadContacts();
      loadListing();
    };
    ul.appendChild(li);
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function loadRequests() {
  const reqs = await api("/v1/admin/requests");
  const section = document.getElementById("requests-section");
  section.hidden = reqs.length === 0;
  document.getElementById("req-count").textContent = reqs.length;
  const ul = document.getElementById("requests");
  ul.innerHTML = "";
  for (const r of reqs) {
    const li = document.createElement("li");
    li.className = "card";
    const days = Math.round(r.requested_duration_secs / 86400);
    const want = r.requested_duration_secs === 0 ? "until revoked" : days + " days";
    li.innerHTML =
      '<div class="card-title">' + escapeHtml(r.name) + '</div>' +
      '<div class="card-sub">' + groupId(r.node_id) + ' · wants ' + want + '</div>' +
      '<div class="chip-row"></div>';
    const row = li.querySelector(".chip-row");
    for (const d of [1, 7, 30]) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "chip";
      b.textContent = d + "d";
      b.onclick = () => decide(r.node_id, "approve", d * 86400);
      row.appendChild(b);
    }
    const inf = document.createElement("button");
    inf.type = "button";
    inf.className = "chip";
    inf.textContent = "Always";
    inf.title = "Until you revoke it";
    inf.onclick = () => decide(r.node_id, "approve", 0);
    row.appendChild(inf);
    const deny = document.createElement("button");
    deny.type = "button";
    deny.className = "chip danger";
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
  const section = document.getElementById("grants-section");
  section.hidden = grants.length === 0;
  const ul = document.getElementById("grants");
  ul.innerHTML = "";
  for (const g of grants) {
    const li = document.createElement("li");
    li.className = "grant";
    li.innerHTML =
      '<span><b>' + escapeHtml(g.name) + '</b><span class="dim"> ' + fmtExpiry(g) + '</span></span>';
    const b = document.createElement("button");
    b.type = "button";
    b.className = "link-btn danger";
    b.textContent = "Revoke";
    b.onclick = async () => {
      await api("/v1/admin/grants/" + g.fingerprint, { method: "DELETE" });
      loadGrants();
    };
    li.appendChild(b);
    ul.appendChild(li);
  }
}

function openModal() {
  document.getElementById("modal").hidden = false;
  document.getElementById("add-id").focus();
}
function closeModal() {
  document.getElementById("modal").hidden = true;
  document.getElementById("add-status").textContent = "";
}

async function addContact(ev) {
  ev.preventDefault();
  const id = document.getElementById("add-id").value.trim().toLowerCase().replace(/[^0-9a-f]/g, "");
  const alias = document.getElementById("add-alias").value.trim();
  const host = document.getElementById("add-host").value.trim();
  const dur = parseInt(document.getElementById("add-duration").value, 10);
  const status = document.getElementById("add-status");
  if (id.length !== 16) {
    status.textContent = "A DocLink ID is 16 hex characters (dashes are fine).";
    return;
  }
  status.textContent = "Looking for that PC on the network…";
  try {
    const r = await api("/v1/admin/contacts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ node_id: id, alias, host: host || null, duration_secs: dur }),
    });
    status.textContent =
      r.status === "approved" ? "Approved — you can browse " + alias + " now."
      : r.status === "pending" ? "Request sent. Wait for them to approve it."
      : "Denied by the remote PC.";
    if (r.status === "approved" || r.status === "pending") {
      document.getElementById("add-id").value = "";
      document.getElementById("add-alias").value = "";
      document.getElementById("add-host").value = "";
      loadContacts();
      if (r.status === "approved") setTimeout(closeModal, 900);
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
  root.textContent = "Shared";
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
}

async function loadListing() {
  renderBreadcrumb();
  const tbody = document.querySelector("#listing tbody");
  const status = document.getElementById("status");
  tbody.innerHTML = "";
  status.textContent = "";
  if (!state.selected) {
    status.innerHTML = "Select a PC on the left, or click <b>+</b> to add one by its DocLink ID.";
    return;
  }
  try {
    const data = await api(
      "/v1/admin/browse/" + state.selected + "/list?path=" + encodeURIComponent(state.path)
    );
    for (const e of data.entries) {
      const tr = document.createElement("tr");
      const tdName = document.createElement("td");
      tdName.className = "name-cell";
      tdName.innerHTML = icon(e.kind) + " <span></span>";
      tdName.querySelector("span").textContent = e.name;
      if (e.kind === "dir") {
        tdName.classList.add("is-dir");
        tdName.onclick = () => { state.path = e.path; loadListing(); };
      }
      const tdSize = document.createElement("td");
      tdSize.className = "num";
      tdSize.textContent = e.kind === "file" ? fmtSize(e.size) : "";
      const tdMod = document.createElement("td");
      tdMod.className = "muted";
      tdMod.textContent = fmtTime(e.modified_unix);
      const tdActions = document.createElement("td");
      tdActions.className = "actions";
      if (e.kind === "file") {
        const dl = document.createElement("a");
        dl.className = "btn-sm";
        dl.textContent = "Download";
        dl.href = "/v1/admin/browse/" + state.selected + "/file?path=" + encodeURIComponent(e.path);
        tdActions.appendChild(dl);
        const pr = document.createElement("button");
        pr.type = "button";
        pr.className = "btn-sm ghost";
        pr.textContent = "Print";
        pr.disabled = true;
        pr.title = "Coming next — downloads to temp, then the Windows print verb";
        tdActions.appendChild(pr);
      }
      tr.append(tdName, tdSize, tdMod, tdActions);
      tbody.appendChild(tr);
    }
    if (data.entries.length === 0) status.textContent = "This folder is empty.";
  } catch (err) {
    status.textContent = err.message;
  }
}

document.getElementById("btn-add").onclick = openModal;
document.getElementById("btn-cancel").onclick = closeModal;
document.getElementById("modal").addEventListener("click", (e) => {
  if (e.target.id === "modal") closeModal();
});
document.getElementById("add-form").onsubmit = addContact;

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
