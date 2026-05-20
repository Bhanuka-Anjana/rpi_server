// app.js — WMS Dashboard frontend

const GEAR_NAMES  = ["SLEEP", "GEAR_2", "GEAR_1", "LOCKING"];
const ALERT_TYPES = new Set([
  "EVT_FIRE_ALARM", "EVT_ALARM_DOOR_FORCED",
  "EVT_ALARM_UNAUTHORIZED", "EVT_TAG_LOST"
]);
const TWR_DEBUG_LIMIT = 300;

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

function anchorKey(row) {
  if (!row) return undefined;
  if (row.anchor_id_str !== undefined) return row.anchor_id_str;
  if (row.anchor_id !== undefined) return String(row.anchor_id);
  return undefined;
}

function anchorLabel(row) {
  return row?.eui || anchorKey(row) || "—";
}

function hex16(value) {
  if (value === undefined || value === null || value === "") return "-";
  const num = Number(value);
  if (!Number.isFinite(num)) return String(value);
  return `0x${num.toString(16).toUpperCase().padStart(4, "0")}`;
}

function hex8(value) {
  if (value === undefined || value === null || value === "") return "-";
  const num = Number(value);
  if (!Number.isFinite(num)) return String(value);
  return `0x${num.toString(16).toUpperCase().padStart(2, "0")}`;
}

function boolLabel(value) {
  if (value === undefined || value === null) return "-";
  return Number(value) ? "YES" : "NO";
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  }[ch]));
}

function storeAnchor(row) {
  const id = anchorKey(row);
  if (id !== undefined) anchors[id] = row;
  return id;
}

function anchorDisplayById(id) {
  const row = anchors[String(id)] || anchors[id];
  return row ? anchorLabel(row) : String(id ?? "-");
}

function numberOrBlank(value) {
  return value === undefined || value === null ? "" : String(value);
}

function roomAnchorFor(anchorId) {
  const key = String(anchorId);
  for (const room of rooms) {
    const match = (room.anchors || []).find(a => String(a.anchor_id_str || a.anchor_id) === key);
    if (match) return { room, anchor: match };
  }
  return null;
}

function selectedRoom() {
  if (!rooms.length) return null;
  if (!selectedRoomId || !rooms.some(r => String(r.id) === String(selectedRoomId))) {
    selectedRoomId = rooms[0].id;
  }
  return rooms.find(r => String(r.id) === String(selectedRoomId)) || rooms[0];
}

// ── State ─────────────────────────────────────────────────────────────

let tags         = {};   // uid → tag_state row
let anchors      = {};   // anchor_id → anchor row
let rooms        = [];    // configured rooms and room-anchor mappings
let events       = [];   // recent events (capped at 200)
let alerts       = [];   // alert events
let firmwareList = [];   // [{id, version, filename, size_bytes, sha256, uploaded_ms}]
let twrDebug     = [];   // recent raw TWR samples shown in the debug tab
let selectedRoomId = null;

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
    renderRooms();
    renderStatus();
  });
}

// RTLS event types — high-frequency position updates that only affect the tags panel
let _twrRenderPending = false;
function scheduleTwrDebugRender() {
  if (_twrRenderPending || _renderPending) return;
  _twrRenderPending = true;
  requestAnimationFrame(() => {
    _twrRenderPending = false;
    renderTags();
    renderTwrDebug();
    renderRooms();
    renderStatus();
  });
}

const RTLS_TYPES = new Set([
  "EVT_RTLS_UPDATE", "EVT_TWR_SAMPLE", "EVT_TAG_APPROACH", "EVT_TAG_AT_DOOR", "EVT_TAG_RETREAT"
]);

// ── Render functions ──────────────────────────────────────────────────

function renderTags() {
  const tbody = document.getElementById("tag-tbody");
  const rows  = Object.values(tags).sort((a, b) => b.last_seen_ms - a.last_seen_ms);
  tbody.innerHTML = rows.map(t => `
    <tr>
      <td>0x${t.uid.toString(16).toUpperCase().padStart(4,"0")}</td>
      <td>${t.nearest_anchor_eui || t.nearest_anchor || "—"}</td>
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
    const id = anchorKey(a);
    const isOnline = a.last_heartbeat_ms && (now - a.last_heartbeat_ms) < 120000;
    return `
    <div class="door-card${isOnline ? "" : " offline"}">
      <h3>Anchor ${anchorLabel(a)} — ${a.location_label || "Door"}
        <button class="btn-remove" data-anchor-id="${id}" title="Remove anchor">✕</button>
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
          <select class="ota-fw-select" data-anchor-id="${id}">
            <option value="">— select version —</option>
            ${firmwareList.map(f => `<option value="${f.id}">${f.version}</option>`).join("")}
          </select>
          <button class="btn-ota" data-anchor-id="${id}"
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
      <td>${anchorLabel(e)}</td>
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
    anchorLabel(e).toLowerCase().includes(filter)
  ).slice(0, 100);

  tbody.innerHTML = rows.map(e => `
    <tr>
      <td>${formatTime(e.ts_ms)}</td>
      <td>${anchorLabel(e)}</td>
      <td>${e.type}</td>
      <td>${e.tag_uid ? `0x${e.tag_uid.toString(16).toUpperCase().padStart(4,"0")}` : "—"}</td>
      <td>${e.dist_cm ?? "—"}</td>
    </tr>
  `).join("") || '<tr><td colspan="5" style="color:#6b7280">No events</td></tr>';
}

function renderTwrDebug() {
  const tbody = document.getElementById("twr-debug-tbody");
  const count = document.getElementById("twr-debug-count");
  if (!tbody) return;
  if (count) count.textContent = `${twrDebug.length} sample${twrDebug.length === 1 ? "" : "s"}`;

  tbody.innerHTML = twrDebug.map(e => {
    const decision = e.lock_decision || "-";
    const decisionClass = decision === "LOCK" ? "decision-lock" :
                          decision === "UNLOCK" ? "decision-unlock" : "";
    const sentText = e.lock_command_sent ? "YES" :
                     e.lock_expiry_owner === "anchor" && decision === "UNLOCK" ? "ANCHOR TIMER" :
                     e.lock_decision_changed === false ? "NO CHANGE" : "NO";
    const sentClass = e.lock_command_sent ? "decision-sent" : "decision-idle";
    return `
    <tr>
      <td>${formatTime(e.ts_ms)}</td>
      <td>${anchorLabel(e)}</td>
      <td>${hex16(e.anchor_short_id)}</td>
      <td>${hex16(e.tag_uid)}</td>
      <td>${e.dist_cm ?? "-"}${e.lock_threshold_cm !== undefined ? ` / ${e.lock_threshold_cm}` : ""}</td>
      <td>${e.x_cm ?? "-"}</td>
      <td>${e.y_cm ?? "-"}</td>
      <td>${e.range_num ?? "-"}</td>
      <td>${hex8(e.flags)}</td>
      <td>${boolLabel(e.escort)}</td>
      <td><span class="pill ${decisionClass}">${decision}</span></td>
      <td><span class="pill ${sentClass}">${sentText}</span></td>
      <td class="raw-cell">${e.raw_hex || "-"}</td>
    </tr>
  `;
  }).join("") || '<tr><td colspan="13" style="color:#6b7280">No TWR samples</td></tr>';
}

function renderRooms() {
  const container = document.getElementById("room-admin");
  if (!container) return;

  const room = selectedRoom();
  const roomOptions = rooms.map(r =>
    `<option value="${r.id}" ${room && r.id === room.id ? "selected" : ""}>${esc(r.name)}</option>`
  ).join("");
  const anchorOptions = Object.values(anchors).map(a => {
    const id = anchorKey(a);
    const mapped = roomAnchorFor(id);
    const suffix = mapped ? ` (${mapped.room.name})` : "";
    return `<option value="${id}">${esc(anchorLabel(a))}${esc(suffix)}</option>`;
  }).join("");

  const preview = room ? renderRoomPreview(room) : '<div class="room-empty">Create a room to preview anchors and tags.</div>';
  const mappings = room ? (room.anchors || []) : [];

  container.innerHTML = `
    <div class="room-grid">
      <div class="room-panel">
        <h3>Create Room</h3>
        <div class="room-form compact">
          <input id="room-new-name" placeholder="Room name" />
          <input id="room-new-width" type="number" min="100" placeholder="Width cm" />
          <input id="room-new-height" type="number" min="100" placeholder="Height cm" />
          <button id="room-create-btn">Create</button>
        </div>

        <h3>Selected Room</h3>
        ${rooms.length ? `
        <div class="room-form">
          <select id="room-select">${roomOptions}</select>
          <input id="room-edit-name" value="${esc(room.name)}" />
          <input id="room-edit-width" type="number" min="100" value="${room.width_cm}" />
          <input id="room-edit-height" type="number" min="100" value="${room.height_cm}" />
          <button id="room-save-btn">Save</button>
          <button id="room-delete-btn" class="danger">Delete</button>
        </div>

        <h3>Assign Anchor</h3>
        <div class="room-form anchor-form">
          <select id="room-anchor-select">${anchorOptions || '<option value="">No anchors</option>'}</select>
          <input id="room-anchor-uwb" type="number" min="0" max="65535" placeholder="UWB short ID" />
          <input id="room-anchor-x" type="number" placeholder="X cm" />
          <input id="room-anchor-y" type="number" placeholder="Y cm" />
          <input id="room-anchor-heading" type="number" step="0.1" placeholder="Heading deg" />
          <input id="room-anchor-radius" type="number" min="1" placeholder="Danger radius" />
          <label class="room-check"><input id="room-anchor-enabled" type="checkbox" checked /> Lock</label>
          <button id="room-anchor-save-btn">Assign</button>
        </div>

        <table class="room-anchor-table">
          <thead>
            <tr><th>Anchor</th><th>UWB</th><th>X</th><th>Y</th><th>Heading</th><th>Radius</th><th>Lock</th><th></th></tr>
          </thead>
          <tbody>
            ${mappings.map(a => `
              <tr data-room-anchor-id="${a.anchor_id_str || a.anchor_id}">
                <td>${esc(a.eui || anchorDisplayById(a.anchor_id_str || a.anchor_id))}</td>
                <td><input data-field="uwb_short_id" type="number" min="0" max="65535" value="${numberOrBlank(a.uwb_short_id)}" /></td>
                <td><input data-field="room_x_cm" type="number" value="${numberOrBlank(a.room_x_cm)}" /></td>
                <td><input data-field="room_y_cm" type="number" value="${numberOrBlank(a.room_y_cm)}" /></td>
                <td><input data-field="heading_deg" type="number" step="0.1" value="${numberOrBlank(a.heading_deg)}" /></td>
                <td><input data-field="danger_radius_cm" type="number" min="1" value="${numberOrBlank(a.danger_radius_cm)}" /></td>
                <td><input data-field="lock_enabled" type="checkbox" ${a.lock_enabled ? "checked" : ""} /></td>
                <td>
                  <button class="room-row-save">Save</button>
                  <button class="room-row-remove danger">Remove</button>
                </td>
              </tr>
            `).join("") || '<tr><td colspan="8" style="color:#6b7280">No anchors assigned</td></tr>'}
          </tbody>
        </table>` : '<p class="room-empty">No rooms configured.</p>'}
      </div>
      <div class="room-panel preview-panel">
        ${preview}
      </div>
    </div>
  `;
}

function renderRoomPreview(room) {
  const w = Math.max(1, Number(room.width_cm || 1));
  const h = Math.max(1, Number(room.height_cm || 1));
  const anchorsHtml = (room.anchors || []).map(a => {
    const x = Number(a.room_x_cm || 0);
    const y = Number(a.room_y_cm || 0);
    const r = Number(a.danger_radius_cm || 0);
    return `
      <div class="danger-zone" style="left:${((x - r) / w) * 100}%;bottom:${((y - r) / h) * 100}%;width:${(2 * r / w) * 100}%;height:${(2 * r / h) * 100}%"></div>
      <div class="room-anchor-dot" style="left:${(x / w) * 100}%;bottom:${(y / h) * 100}%" title="${esc(a.eui || anchorDisplayById(a.anchor_id_str || a.anchor_id))}">
        <span>${hex16(a.uwb_short_id)}</span>
      </div>
    `;
  }).join("");
  const tagsHtml = Object.values(tags).filter(t =>
    Number(t.room_id) === Number(room.id) &&
    t.global_x_cm !== undefined && t.global_x_cm !== null &&
    t.global_y_cm !== undefined && t.global_y_cm !== null
  ).map(t => `
    <div class="room-tag-dot" style="left:${(Number(t.global_x_cm) / w) * 100}%;bottom:${(Number(t.global_y_cm) / h) * 100}%"
         title="0x${Number(t.uid).toString(16).toUpperCase().padStart(4, "0")}">
      T
    </div>
  `).join("");

  return `
    <div class="room-preview-head">
      <b>${esc(room.name)}</b>
      <span>${room.width_cm} x ${room.height_cm} cm</span>
    </div>
    <div class="room-preview" style="aspect-ratio:${w}/${h}">
      ${anchorsHtml}
      ${tagsHtml}
    </div>
  `;
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
  renderRooms();
  renderAlerts();
  renderTwrDebug();
  renderEvents();
  renderFirmware();
  renderStatus();
}

document.getElementById("filter-input").addEventListener("input", renderEvents);
document.getElementById("twr-clear-btn").addEventListener("click", () => {
  twrDebug = [];
  renderTwrDebug();
});

document.getElementById("room-admin").addEventListener("change", e => {
  if (e.target.id === "room-select") {
    selectedRoomId = Number(e.target.value);
    renderRooms();
  }
});

document.getElementById("room-admin").addEventListener("click", e => {
  const room = selectedRoom();

  if (e.target.id === "room-create-btn") {
    const body = {
      name: document.getElementById("room-new-name").value.trim() || "Room",
      width_cm: Number(document.getElementById("room-new-width").value || 500),
      height_cm: Number(document.getElementById("room-new-height").value || 500),
    };
    fetch("/api/rooms", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body) })
      .then(r => r.json())
      .then(created => { selectedRoomId = created.id; return fetch("/api/rooms"); })
      .then(r => r.json())
      .then(list => { rooms = list; renderRooms(); });
    return;
  }

  if (!room) return;

  if (e.target.id === "room-save-btn") {
    const body = {
      name: document.getElementById("room-edit-name").value.trim() || room.name,
      width_cm: Number(document.getElementById("room-edit-width").value || room.width_cm),
      height_cm: Number(document.getElementById("room-edit-height").value || room.height_cm),
    };
    fetch(`/api/rooms/${room.id}`, { method: "PUT", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body) })
      .then(() => fetch("/api/rooms"))
      .then(r => r.json())
      .then(list => { rooms = list; renderRooms(); });
    return;
  }

  if (e.target.id === "room-delete-btn") {
    if (!confirm(`Delete room ${room.name}?`)) return;
    fetch(`/api/rooms/${room.id}`, { method: "DELETE" })
      .then(() => fetch("/api/rooms"))
      .then(r => r.json())
      .then(list => { rooms = list; selectedRoomId = rooms[0]?.id || null; renderRooms(); });
    return;
  }

  if (e.target.id === "room-anchor-save-btn") {
    const anchorId = document.getElementById("room-anchor-select").value;
    if (!anchorId) return;
    const body = {
      uwb_short_id: document.getElementById("room-anchor-uwb").value,
      room_x_cm: Number(document.getElementById("room-anchor-x").value || 0),
      room_y_cm: Number(document.getElementById("room-anchor-y").value || 0),
      heading_deg: Number(document.getElementById("room-anchor-heading").value || 0),
      danger_radius_cm: Number(document.getElementById("room-anchor-radius").value || 300),
      lock_enabled: document.getElementById("room-anchor-enabled").checked ? 1 : 0,
    };
    fetch(`/api/rooms/${room.id}/anchors/${anchorId}`, {
      method: "PUT", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)
    }).then(() => fetch("/api/rooms"))
      .then(r => r.json())
      .then(list => { rooms = list; renderRooms(); });
    return;
  }

  const row = e.target.closest("tr[data-room-anchor-id]");
  if (!row) return;
  const anchorId = row.dataset.roomAnchorId;

  if (e.target.classList.contains("room-row-save")) {
    const body = {};
    row.querySelectorAll("[data-field]").forEach(input => {
      body[input.dataset.field] = input.type === "checkbox" ? (input.checked ? 1 : 0) : input.value;
    });
    fetch(`/api/rooms/${room.id}/anchors/${anchorId}`, {
      method: "PUT", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)
    }).then(() => fetch("/api/rooms"))
      .then(r => r.json())
      .then(list => { rooms = list; renderRooms(); });
    return;
  }

  if (e.target.classList.contains("room-row-remove")) {
    fetch(`/api/rooms/anchors/${anchorId}`, { method: "DELETE" })
      .then(() => fetch("/api/rooms"))
      .then(r => r.json())
      .then(list => { rooms = list; renderRooms(); });
  }
});

// Remove-anchor button delegation
document.getElementById("door-cards").addEventListener("click", e => {
  const removeBtn = e.target.closest(".btn-remove[data-anchor-id]");
  if (removeBtn) {
    const id = removeBtn.dataset.anchorId;
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
      msg.anchors.forEach(a => { storeAnchor(a); });
      rooms = msg.rooms || [];
      selectedRoomId = rooms[0]?.id || selectedRoomId;
      renderAll();
      return;
    }

    if (msg.type === "_rooms_update") {
      rooms = msg.rooms || [];
      selectedRoomId = rooms[0]?.id || selectedRoomId;
      scheduleRender();
      return;
    }

    if (msg.type === "_anchor_removed") {
      delete anchors[anchorKey(msg)];
      scheduleRender();
      return;
    }

    if (msg.type === "_config_update") {
      const id = anchorKey(msg);
      if (anchors[id]) Object.assign(anchors[id], msg);
      scheduleRender();
      return;
    }

    if (msg.type === "OTA_PROGRESS") {
      const id = anchorKey(msg);
      if (anchors[id]) { anchors[id].ota_status = "IN_PROGRESS"; anchors[id].ota_percent = msg.percent; }
      scheduleRender();
      return;
    }

    if (msg.type === "OTA_COMPLETE") {
      const id = anchorKey(msg);
      if (anchors[id]) {
        anchors[id].ota_status  = "COMPLETE";
        anchors[id].ota_percent = 100;
        if (msg.fw_version) anchors[id].fw_version = msg.fw_version;
      }
      scheduleRender();
      return;
    }

    if (msg.type === "OTA_FAILED") {
      const id = anchorKey(msg);
      if (anchors[id]) { anchors[id].ota_status = "FAILED"; anchors[id].ota_percent = 0; }
      scheduleRender();
      return;
    }

    // Live event — update state
    const id    = anchorKey(msg);
    const etype = msg.type || "";

    if (id !== undefined && !anchors[id]) anchors[id] = { anchor_id: msg.anchor_id, anchor_id_str: id };
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
        x_cm:           msg.x_cm,
        y_cm:           msg.y_cm,
        room_id:        msg.room_id,
        room_name:      msg.room_name,
        global_x_cm:    msg.global_x_cm,
        global_y_cm:    msg.global_y_cm,
        source_anchor:  msg.source_anchor,
        gear:           msg.gear,
        escort:         msg.escort,
        last_seen_ms:   msg.ts_ms,
      };
    }

    // RTLS position updates — only refresh tags panel, skip events log
    if (etype === "EVT_TWR_SAMPLE") {
      twrDebug.unshift(msg);
      if (twrDebug.length > TWR_DEBUG_LIMIT) twrDebug.length = TWR_DEBUG_LIMIT;
      scheduleTwrDebugRender();
      return;
    }

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
  fetchWithTimeout("/api/rooms"),
]).then(([t, a, ev, al, fw, roomList]) => {
  t.forEach(tag   => { tags[tag.uid]            = tag; });
  a.forEach(anch  => { storeAnchor(anch); });
  events = ev;
  alerts = al;
  firmwareList = fw;
  rooms = roomList || [];
  selectedRoomId = rooms[0]?.id || null;
  renderAll();
  connect();
}).catch(() => connect());  // Still open SSE even if REST fails or times out

// Re-render elapsed times every 10 s
setInterval(renderAll, 10000);
