// app.js — WMS Dashboard frontend

const GEAR_NAMES  = ["SLEEP", "GEAR_2", "GEAR_1", "LOCKING"];
const ALERT_TYPES = new Set([
  "EVT_FIRE_ALARM", "EVT_ALARM_DOOR_FORCED",
  "EVT_ALARM_UNAUTHORIZED", "EVT_TAG_LOST"
]);

// ── Tab switching ─────────────────────────────────────────────────────

document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
  });
});

// ── Helpers ───────────────────────────────────────────────────────────

function formatTime(ms) {
  if (!ms) return "—";
  return new Date(ms).toLocaleTimeString();
}

function gearPill(gear) {
  const name = GEAR_NAMES[gear] ?? `GEAR${gear}`;
  return `<span class="pill gear${gear}">${name}</span>`;
}

function elapsed(ms) {
  if (!ms) return "—";
  const s = Math.floor((Date.now() - ms) / 1000);
  if (s < 60)  return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  return `${Math.floor(s/3600)}h ago`;
}

// ── State ─────────────────────────────────────────────────────────────

let tags         = {};   // uid → tag_state row
let anchors      = {};   // anchor_id → anchor row
let events       = [];   // recent events (capped at 200)
let alerts       = [];   // alert events
let firmwareList = [];   // [{id, version, filename, size_bytes, sha256, uploaded_ms}]

// ── Render throttling ─────────────────────────────────────────────────
// Coalesce rapid SSE bursts: at most one DOM rebuild per animation frame.

// Full render — all 6 panels (doors, alerts, events log, firmware, status, tags)
let _renderPending = false;
function scheduleRender() {
  if (_renderPending) return;
  _renderPending = true;
  requestAnimationFrame(() => { _renderPending = false; renderAll(); });
}

// Lightweight render — only tags table + status bar.
// Used for high-frequency RTLS position updates so the other panels
// (door cards, events log, firmware) are not rebuilt on every frame.
let _tagsRenderPending = false;
function scheduleTagsRender() {
  if (_tagsRenderPending || _renderPending) return;  // full render already covers this
  _tagsRenderPending = true;
  requestAnimationFrame(() => {
    _tagsRenderPending = false;
    renderTags();
    renderStatus();
  });
}

// RTLS event types — high-frequency position updates that only affect the tags panel
const RTLS_TYPES = new Set([
  "EVT_RTLS_UPDATE", "EVT_TAG_APPROACH", "EVT_TAG_AT_DOOR", "EVT_TAG_RETREAT"
]);

// ── Render functions ──────────────────────────────────────────────────

function renderTags() {
  const tbody = document.getElementById("tag-tbody");
  const rows  = Object.values(tags).sort((a, b) => b.last_seen_ms - a.last_seen_ms);
  tbody.innerHTML = rows.map(t => `
    <tr>
      <td>0x${t.uid.toString(16).toUpperCase().padStart(4,"0")}</td>
      <td>${t.nearest_anchor ?? "—"}</td>
      <td>${t.dist_cm ?? "—"}</td>
      <td>${gearPill(t.gear ?? 0)}</td>
      <td>${t.escort ? '<span class="pill escort">YES</span>' : "—"}</td>
      <td>${elapsed(t.last_seen_ms)}</td>
    </tr>
  `).join("") || '<tr><td colspan="6" style="color:#6b7280">No tags detected</td></tr>';
}

const CFG_STATUS_STYLE = {
  "APPLIED":  "color:#22c55e",
  "PENDING":  "color:#f59e0b",
  "FAILED":   "color:#ef4444",
  "DEFAULT":  "color:#6b7280",
};

function cfgStatusBadge(status) {
  const s = status || "DEFAULT";
  return `<span style="font-size:0.75rem;font-weight:600;${CFG_STATUS_STYLE[s] || ''}">${s}</span>`;
}

function renderDoors() {
  const container = document.getElementById("door-cards");
  const now = Date.now();
  const rows = Object.values(anchors);
  container.innerHTML = rows.map(a => {
    const isOnline = a.last_heartbeat_ms && (now - a.last_heartbeat_ms) < 120000;
    return `
    <div class="door-card${isOnline ? "" : " offline"}">
      <h3>Anchor ${a.anchor_id} — ${a.location_label || "Door"}
        <button class="btn-remove" data-anchor-id="${a.anchor_id}" title="Remove anchor">✕</button>
      </h3>
      <div class="indicator">
        <span class="dot ${a.locked ? "on" : "green"}"></span>
        <span class="pill ${a.locked ? "locked" : "unlocked"}">${a.locked ? "LOCKED" : "UNLOCKED"}</span>
      </div>
      <div class="indicator">
        <span class="dot ${a.fire ? "on" : ""}"></span>
        <span>Fire alarm: <b>${a.fire ? "ACTIVE" : "OK"}</b></span>
      </div>
      <div class="indicator">
        <span class="dot ${a.ajar ? "yellow" : ""}"></span>
        <span>Door ajar: <b>${a.ajar ? "YES" : "No"}</b></span>
      </div>
      <div style="margin-top:10px;border-top:1px solid #374151;padding-top:8px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
          <span style="font-size:0.78rem;color:#9ca3af">Config</span>
          ${cfgStatusBadge(a.config_status)}
        </div>
        <div style="font-size:0.75rem;color:#6b7280;line-height:1.7">
          REX: <b>${a.rex_duration_ms ?? 3000} ms</b> &nbsp;|&nbsp;
          Relay: <b>${a.relay_hold_ms ?? 500} ms</b> &nbsp;|&nbsp;
          Ajar: <b>${((a.door_ajar_timeout_ms ?? 30000)/1000).toFixed(0)} s</b><br>
          Signal-loss: <b>${((a.signal_loss_timeout_ms ?? 60000)/1000).toFixed(0)} s → ${a.signal_loss_mode ?? "LOCK"}</b> &nbsp;|&nbsp;
          Buzzer: <b>${a.buzzer_enable ? `ON ${a.buzzer_duration_ms ?? 1000}ms` : "OFF"}</b>
        </div>
        ${a.config_updated_ms ? `<div style="font-size:0.72rem;color:#4b5563;margin-top:2px">Updated: ${formatTime(a.config_updated_ms)}</div>` : ""}
      </div>
      <div class="indicator" style="margin-top:8px;color:#6b7280;font-size:0.78rem">
        Last heartbeat: ${elapsed(a.last_heartbeat_ms)}
      </div>
      <div class="ota-section">
        <div class="ota-header">
          <span>FW: <b>${a.fw_version || "unknown"}</b></span>
          <span class="ota-badge ota-${(a.ota_status || 'idle').toLowerCase()}">${a.ota_status || 'IDLE'}</span>
        </div>
        <div class="ota-controls">
          <select class="ota-fw-select" data-anchor-id="${a.anchor_id}">
            <option value="">— select version —</option>
            ${firmwareList.map(f => `<option value="${f.id}">${f.version}</option>`).join("")}
          </select>
          <button class="btn-ota" data-anchor-id="${a.anchor_id}"
                  ${a.ota_status === 'IN_PROGRESS' ? 'disabled' : ''}>
            ${a.ota_status === 'IN_PROGRESS' ? 'Updating…' : 'Push OTA'}
          </button>
        </div>
        ${a.ota_status === 'IN_PROGRESS' ? `
        <div class="ota-progress-bar">
          <div class="ota-progress-fill" style="width:${a.ota_percent || 0}%"></div>
        </div>` : ''}
      </div>
    </div>
  `;
  }).join("") || '<p style="color:#6b7280">No anchors registered</p>';
}

function renderFirmware() {
  const tbody = document.getElementById("fw-tbody");
  if (!tbody) return;
  tbody.innerHTML = firmwareList.map(f => `
    <tr>
      <td><b>${f.version}</b></td>
      <td style="font-size:0.8rem;color:#9ca3af">${f.filename}</td>
      <td>${(f.size_bytes / 1024).toFixed(1)} KB</td>
      <td style="font-size:0.72rem;color:#6b7280;font-family:monospace">${f.sha256.slice(0,16)}…</td>
      <td>${formatTime(f.uploaded_ms)}</td>
      <td><button class="btn-remove btn-fw-delete" data-fw-id="${f.id}" title="Delete firmware">✕</button></td>
    </tr>
  `).join("") || '<tr><td colspan="6" style="color:#6b7280">No firmware uploaded</td></tr>';
}

function renderAlerts() {
  const tbody = document.getElementById("alert-tbody");
  tbody.innerHTML = alerts.slice(0, 50).map(e => `
    <tr class="alert-row">
      <td>${formatTime(e.ts_ms)}</td>
      <td>${e.anchor_id}</td>
      <td><b>${e.type}</b></td>
      <td>${e.tag_uid ? `0x${e.tag_uid.toString(16).toUpperCase().padStart(4,"0")}` : "—"}</td>
      <td>${e.dist_cm ? e.dist_cm + " cm" : "—"}</td>
    </tr>
  `).join("") || '<tr><td colspan="5" style="color:#6b7280">No alerts</td></tr>';
}

function renderEvents() {
  const filter = document.getElementById("filter-input").value.toLowerCase();
  const tbody  = document.getElementById("event-tbody");
  const rows   = events.filter(e =>
    !filter ||
    e.type?.toLowerCase().includes(filter) ||
    String(e.anchor_id).includes(filter)
  ).slice(0, 100);

  tbody.innerHTML = rows.map(e => `
    <tr>
      <td>${formatTime(e.ts_ms)}</td>
      <td>${e.anchor_id}</td>
      <td>${e.type}</td>
      <td>${e.tag_uid ? `0x${e.tag_uid.toString(16).toUpperCase().padStart(4,"0")}` : "—"}</td>
      <td>${e.dist_cm ?? "—"}</td>
    </tr>
  `).join("") || '<tr><td colspan="5" style="color:#6b7280">No events</td></tr>';
}

function renderStatus() {
  const now    = Date.now();
  const online = Object.values(anchors).filter(
    a => a.last_heartbeat_ms && (now - a.last_heartbeat_ms) < 120000
  ).length;
  const active = Object.values(tags).filter(
    t => t.last_seen_ms && (now - t.last_seen_ms) < 60000
  ).length;
  document.getElementById("stat-anchors").textContent = `Anchors: ${online}/${Object.keys(anchors).length} online`;
  document.getElementById("stat-tags").textContent    = `Active Tags: ${active}`;
}

function renderAll() {
  renderTags();
  renderDoors();
  renderAlerts();
  renderEvents();
  renderFirmware();
  renderStatus();
}

document.getElementById("filter-input").addEventListener("input", renderEvents);

// Remove-anchor button delegation
document.getElementById("door-cards").addEventListener("click", e => {
  const removeBtn = e.target.closest(".btn-remove[data-anchor-id]");
  if (removeBtn) {
    const id = parseInt(removeBtn.dataset.anchorId);
    if (!confirm(`Remove Anchor ${id} from the server?\nThis cannot be undone unless the anchor reconnects.`)) return;
    fetch(`/api/anchor/${id}`, { method: "DELETE" })
      .then(() => { delete anchors[id]; renderDoors(); renderStatus(); });
    return;
  }

  const otaBtn = e.target.closest(".btn-ota");
  if (otaBtn) {
    const anchorId = otaBtn.dataset.anchorId;
    const sel = document.querySelector(`.ota-fw-select[data-anchor-id="${anchorId}"]`);
    if (!sel?.value) { alert("Select a firmware version first."); return; }
    fetch(`/api/anchor/${anchorId}/ota/start?fw_id=${sel.value}`, { method: "POST" });
    return;
  }
});

// Firmware tab — delete button delegation
document.addEventListener("click", e => {
  const btn = e.target.closest(".btn-fw-delete");
  if (!btn) return;
  const fwId = parseInt(btn.dataset.fwId);
  if (!confirm("Delete this firmware file?")) return;
  fetch(`/api/firmware/${fwId}`, { method: "DELETE" })
    .then(() => {
      firmwareList = firmwareList.filter(f => f.id !== fwId);
      renderFirmware();
      renderDoors();   // refresh dropdowns
    });
});

// Firmware upload
document.getElementById("fw-upload-btn").addEventListener("click", () => {
  const version = document.getElementById("fw-version-input").value.trim();
  const fileInput = document.getElementById("fw-file-input");
  const status = document.getElementById("fw-upload-status");
  if (!version) { alert("Enter a version label first."); return; }
  if (!fileInput.files.length) { alert("Choose a .bin file first."); return; }
  const fd = new FormData();
  fd.append("version", version);
  fd.append("file", fileInput.files[0]);
  status.textContent = "Uploading…";
  fetch("/api/firmware", { method: "POST", body: fd })
    .then(r => r.json())
    .then(fw => {
      firmwareList.unshift(fw);
      renderFirmware();
      renderDoors();
      status.textContent = `Uploaded ${fw.version}`;
      document.getElementById("fw-version-input").value = "";
      fileInput.value = "";
    })
    .catch(() => { status.textContent = "Upload failed."; });
});

// Load firmware list when Firmware tab is opened
document.querySelectorAll(".tab-btn").forEach(btn => {
  if (btn.dataset.tab === "firmware") {
    btn.addEventListener("click", () => {
      fetch("/api/firmware").then(r => r.json()).then(list => {
        firmwareList = list;
        renderFirmware();
        renderDoors();
      });
    });
  }
});

// ── SSE connection ────────────────────────────────────────────────────

function connect() {
  const badge = document.getElementById("conn-status");
  const es    = new EventSource("/api/events/stream");

  es.onopen = () => {
    badge.textContent = "Live";
    badge.className   = "badge online";
  };

  es.onerror = () => {
    badge.textContent = "Reconnecting…";
    badge.className   = "badge offline";
  };

  es.onmessage = (e) => {
    const msg = JSON.parse(e.data);

    if (msg.type === "_snapshot") {
      // Initial state dump from server
      msg.tags.forEach(t    => { tags[t.uid]           = t; });
      msg.anchors.forEach(a => { anchors[a.anchor_id]  = a; });
      renderAll();
      return;
    }

    if (msg.type === "_anchor_removed") {
      delete anchors[msg.anchor_id];
      scheduleRender();
      return;
    }

    if (msg.type === "_config_update") {
      const id = msg.anchor_id;
      if (anchors[id]) Object.assign(anchors[id], msg);
      scheduleRender();
      return;
    }

    if (msg.type === "OTA_PROGRESS") {
      const id = msg.anchor_id;
      if (anchors[id]) { anchors[id].ota_status = "IN_PROGRESS"; anchors[id].ota_percent = msg.percent; }
      scheduleRender();
      return;
    }

    if (msg.type === "OTA_COMPLETE") {
      const id = msg.anchor_id;
      if (anchors[id]) {
        anchors[id].ota_status  = "COMPLETE";
        anchors[id].ota_percent = 100;
        if (msg.fw_version) anchors[id].fw_version = msg.fw_version;
      }
      scheduleRender();
      return;
    }

    if (msg.type === "OTA_FAILED") {
      const id = msg.anchor_id;
      if (anchors[id]) { anchors[id].ota_status = "FAILED"; anchors[id].ota_percent = 0; }
      scheduleRender();
      return;
    }

    // Live event — update state
    const id    = msg.anchor_id;
    const etype = msg.type || "";

    if (id !== undefined && !anchors[id]) anchors[id] = { anchor_id: id };
    if (id !== undefined) anchors[id].last_heartbeat_ms = msg.ts_ms;

    if (etype === "EVT_DOOR_LOCKED")   { if (anchors[id]) anchors[id].locked = 1; }
    if (etype === "EVT_DOOR_UNLOCKED") { if (anchors[id]) anchors[id].locked = 0; }
    if (etype === "EVT_FIRE_ALARM")    { if (anchors[id]) anchors[id].fire   = 1; }
    if (etype === "EVT_FIRE_CLEARED")  { if (anchors[id]) anchors[id].fire   = 0; }

    if (msg.tag_uid !== undefined) {
      tags[msg.tag_uid] = {
        ...(tags[msg.tag_uid] || {}),
        uid:            msg.tag_uid,
        nearest_anchor: id,
        dist_cm:        msg.dist_cm,
        gear:           msg.gear,
        escort:         msg.escort,
        last_seen_ms:   msg.ts_ms,
      };
    }

    // RTLS position updates — only refresh tags panel, skip events log
    if (RTLS_TYPES.has(etype)) {
      scheduleTagsRender();
      return;
    }

    // All other events go to the events log
    events.unshift(msg);
    if (events.length > 200) events.length = 200;

    if (ALERT_TYPES.has(etype)) {
      alerts.unshift(msg);
      if (alerts.length > 100) alerts.length = 100;
    }

    scheduleRender();
  };
}

// ── Boot ──────────────────────────────────────────────────────────────

// Load initial data via REST, then open SSE.
// Each fetch has a 5-second timeout so a busy server can't stall the page forever.
async function fetchWithTimeout(url, ms = 5000) {
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), ms);
  try   { return await fetch(url, { signal: ctrl.signal }).then(r => r.json()); }
  finally { clearTimeout(tid); }
}

Promise.all([
  fetchWithTimeout("/api/tags"),
  fetchWithTimeout("/api/anchors"),
  fetchWithTimeout("/api/events?limit=100"),
  fetchWithTimeout("/api/alerts?limit=50"),
  fetchWithTimeout("/api/firmware"),
]).then(([t, a, ev, al, fw]) => {
  t.forEach(tag   => { tags[tag.uid]            = tag; });
  a.forEach(anch  => { anchors[anch.anchor_id]  = anch; });
  events = ev;
  alerts = al;
  firmwareList = fw;
  renderAll();
  connect();
}).catch(() => connect());  // Still open SSE even if REST fails or times out

// Re-render elapsed times every 10 s
setInterval(renderAll, 10000);
