// DocLink web UI — talks only to the local daemon (same origin).
// M0/M1: browses THIS node's share. M2 adds peer browsing via the
// daemon-side proxy (/v1/peers/{id}/list|file), which is why the
// peer list is already fetched and rendered here.

const state = { path: "" };

async function api(url) {
  const r = await fetch(url);
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).error || msg; } catch (_) {}
    throw new Error(msg);
  }
  return r.json();
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

async function loadThisNode() {
  const info = await api("/v1/info");
  const el = document.getElementById("this-node");
  el.textContent = info.name + " · " + info.node_id;
  el.title = info.fingerprint;
}

async function loadPeers() {
  const peers = await api("/v1/peers");
  const ul = document.getElementById("peers");
  ul.innerHTML = "";
  const me = document.createElement("li");
  me.textContent = "This PC";
  me.className = "active";
  ul.appendChild(me);
  for (const p of peers) {
    const li = document.createElement("li");
    li.textContent = p.name;
    li.title = p.addr + " · " + p.fingerprint;
    // M2: clicking a peer will browse it via the local proxy.
    li.className = "peer-disabled";
    ul.appendChild(li);
  }
}

function renderBreadcrumb() {
  const nav = document.getElementById("breadcrumb");
  nav.innerHTML = "";
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
  try {
    const data = await api("/v1/list?path=" + encodeURIComponent(state.path));
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
        dl.href = "/v1/file?path=" + encodeURIComponent(e.path);
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

loadThisNode();
loadPeers();
setInterval(loadPeers, 5000);
loadListing();
