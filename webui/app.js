// DocLink web UI — talks only to the local daemon's admin plane
// (127.0.0.1). PCs are added by DocLink ID and approved by the
// sharing PC; browsing goes through the daemon's signed proxy.

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
  return unix ? new Date(unix * 1000).toLocaleString() : "";
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
  return id.replace(/(.{4})(?=.)/g, "$1-");
}

async function loadInfo() {
  const info = await api("/v1/admin/info");
  const el = document.getElementById("this-node");
  el.textContent = info.name + " · " + groupId(info.node_id);
  el.title = "DocLink ID: " + groupId(info.node_id) + " (click to copy)\nfingerprint: " + info.fingerprint;
  el.onclick = () => navigator.clipboard.writeText(info.node_id);
}

async function loadContacts() {
  const contacts = await api("/v1/admin/contacts");
  const ul = document.getElementById("peers");
  ul.innerHTML = "";
  for (const c of contacts) {
    const li = document.createElement("li");
    const dot = c.online ? "🟢" : "⚪";
    li.textContent = dot + " " + c.alias;
    li.title = groupId(c.node_id) + (c.host ? " · " + c.host : "") + "\nstatus: " + c.status;
    if (state.selected === c.node_id) li.className = "active";
    li.onclick = () => {
      state.selected = c.node_id;
      state.path = "";
      loadContacts();
      loadListing();
    };
    ul.appendChild(li);
  }
  if (!contacts.length) {
    const li = document.createElement("li");
    li.className = "dim";
    li.textContent = "No PCs added yet";
    ul.appendChild(li);
  }
}

async function loadRequests() {
  const reqs = await api("/v1/admin/requests");
  document.getElementById("requests-section").style.display = reqs.length ? "" : "none";
  const ul = document.getElementById("requests");
  ul.innerHTML = "";
  for (const r of reqs) {
    const li = document.createElement("li");
    const label = document.createElement("div");
    const days = Math.round(r.requested_duration_secs / 86400);
    label.innerHTML =
      "<b>" + r.name + "</b> <span class=\"dim\">" + groupId(r.node_id) + "</span><br>" +
      "<span class=\"dim\">requests " + (r.requested_duration_secs === 0 ? "until revoked" : days + "d") + "</span>";
    const row = document.createElement("div");
    row.className = "req-actions";
    for (const d of [1, 7, 30]) {
      const b = document.createElement("button");
      b.textContent = d + "d";
      b.onclick = () => decide(r.node_id, "approve", d * 86400);
      row.appendChild(b);
    }
    const inf = document.createElement("button");
    inf.textContent = "∞";
    inf.title = "Until revoked";
    inf.onclick = () => decide(r.node_id, "approve", 0);
    row.appendChild(inf);
    const deny = document.createElement("button");
    deny.textContent = "✕";
    deny.className = "deny";
    deny.title = "Deny";
    deny.onclick = () => decide(r.node_id, "deny", 0);
    row.appendChild(deny);
    li.append(label, row);
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
  document.getElementById("grants-section").style.display = grants.length ? "" : "none";
  const ul = document.getElementById("grants");
  ul.innerHTML = "";
  for (const g of grants) {
    const li = document.createElement("li");
    const label = document.createElement("span");
    label.innerHTML = "<b>" + g.name + "</b> <span class=\"dim\">" + fmtExpiry(g) + "</span>";
    const b = document.createElement("button");
    b.textContent = "Revoke";
    b.className = "deny";
    b.onclick = async () => {
      await api("/v1/admin/grants/" + g.fingerprint, { method: "DELETE" });
      loadGrants();
    };
    li.append(label, b);
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
    status.textContent = "A DocLink ID is 16 hex characters (dashes are fine).";
    return;
  }
  try {
    const r = await api("/v1/admin/contacts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ node_id: id, alias, host: host || null, duration_secs: dur }),
    });
    status.textContent =
      r.status === "approved" ? "Approved — you can browse " + alias + " now."
      : r.status === "pending" ? "Request sent — waiting for " + alias + " to approve."
      : "Denied by the remote PC.";
    document.getElementById("add-id").value = "";
    document.getElementById("add-alias").value = "";
    document.getElementById("add-host").value = "";
    loadContacts();
  } catch (e) {
    status.textContent = "Error: " + e.message;
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
  root.onclick = () => { state.path = ""; loadListing(); };
  nav.appendChild(root);
  parts.forEach((part, i) => {
    nav.appendChild(document.createTextNode(" / "));
    const a = document.createElement("a");
    a.textContent = part;
    a.href = "#";
    a.onclick = () => { state.path = parts.slice(0, i + 1).join("/"); loadListing(); };
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
    status.textContent = "Add a PC by its DocLink ID above, then select it to browse its shared files.";
    return;
  }
  try {
    const data = await api(
      "/v1/admin/browse/" + state.selected + "/list?path=" + encodeURIComponent(state.path)
    );
    for (const e of data.entries) {
      const tr = document.createElement("tr");
      const tdName = document.createElement("td");
      if (e.kind === "dir") {
        const a = document.createElement("a");
        a.textContent = "📁 " + e.name;
        a.href = "#";
        a.onclick = () => { state.path = e.path; loadListing(); };
        tdName.appendChild(a);
      } else {
        tdName.textContent = "📄 " + e.name;
      }
      const tdSize = document.createElement("td");
      tdSize.textContent = e.kind === "file" ? fmtSize(e.size) : "";
      const tdMod = document.createElement("td");
      tdMod.textContent = fmtTime(e.modified_unix);
      const tdActions = document.createElement("td");
      if (e.kind === "file") {
        const dl = document.createElement("a");
        dl.textContent = "Download";
        dl.href = "/v1/admin/browse/" + state.selected + "/file?path=" + encodeURIComponent(e.path);
        tdActions.appendChild(dl);
        const pr = document.createElement("button");
        pr.textContent = "Print";
        pr.disabled = true;
        pr.title = "Lands in M3 — downloads to temp, then the Windows print verb";
        tdActions.appendChild(document.createTextNode(" "));
        tdActions.appendChild(pr);
      }
      tr.append(tdName, tdSize, tdMod, tdActions);
      tbody.appendChild(tr);
    }
    if (data.entries.length === 0) status.textContent = "Empty folder.";
  } catch (err) {
    status.textContent = "Error: " + err.message;
  }
}

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
