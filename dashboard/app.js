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

function roomAnchorById(room, anchorId) {
  if (!room || anchorId === null || anchorId === undefined) return null;
  return (room.anchors || []).find(a => String(a.anchor_id_str || a.anchor_id) === String(anchorId)) || null;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
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
let selectedRoomAnchorId = null;
let placingAnchorId = null;
let roomDrag = null;

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
    renderRoomMapOnly();
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
    renderRoomMapOnly();
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

function renderRoomMapOnly() {
  if (roomDrag) return;
  const container = document.getElementById("room-admin");
  if (!container) return;
  const mapPanel = container.querySelector(".room-map-panel");
  const room = selectedRoom();
  if (mapPanel && room) mapPanel.innerHTML = renderRoomMap(room);
}


function renderRoomInspector(room, anchor) {
  if (!anchor) {
    return `
      <h3>Inspector</h3>
      <p class="room-empty">Click an anchor on the map to select it.<br>Drag the circle to move. Drag the red □ to rotate the x-axis or the green □ to rotate the y-axis.</p>
    `;
  }

  return `
    <h3>Selected Anchor</h3>
    <div class="anchor-inspector-card">
      <b>${esc(anchor.eui || anchorDisplayById(anchor.anchor_id_str || anchor.anchor_id))}</b>
    </div>
    <div class="inspector-fields">
      <label>UWB Short ID</label>
      <input id="insp-uwb" type="number" min="0" max="65535" value="${numberOrBlank(anchor.uwb_short_id)}" placeholder="0" />
      <label>X position (cm)</label>
      <input id="insp-x" type="number" value="${numberOrBlank(anchor.room_x_cm)}" placeholder="0" />
      <label>Y position (cm)</label>
      <input id="insp-y" type="number" value="${numberOrBlank(anchor.room_y_cm)}" placeholder="0" />
      <label>X-axis angle (°)</label>
      <input id="insp-x-angle" type="number" step="1" value="${Number(anchor.heading_deg || 0).toFixed(0)}" />
      <label>Y-axis angle (°) <small style="color:#6b7280">= x + 90°</small></label>
      <input id="insp-y-angle" type="number" step="1" value="${(Number(anchor.heading_deg || 0) + 90).toFixed(0)}" />
      <label>Danger radius (cm)</label>
      <input id="insp-radius" type="number" min="1" value="${numberOrBlank(anchor.danger_radius_cm)}" placeholder="300" />
    </div>
    <div class="inspector-fields">
      <label class="room-check">
        <input id="insp-flip-x" type="checkbox" ${anchor.flip_x ? "checked" : ""} />
        Flip x-axis
      </label>
      <label class="room-check">
        <input id="insp-flip-y" type="checkbox" ${anchor.flip_y ? "checked" : ""} />
        Flip y-axis
      </label>
    </div>
    <div class="visual-control-grid">
      <button id="insp-save-btn">Save</button>
      <button data-anchor-action="lock">${anchor.lock_enabled ? "Disable Lock" : "Enable Lock"}</button>
      <button data-anchor-action="remove" class="danger">Remove</button>
    </div>
  `;
}

function renderRoomMap(room) {
  const w = Math.max(1, Number(room.width_cm || 1));
  const h = Math.max(1, Number(room.height_cm || 1));
  const axisLen  = Math.max(50, Math.min(w, h) * 0.13);
  const anchorR  = Math.max(10, Math.min(w, h) * 0.018);
  const labelSz  = Math.max(12, Math.min(w, h) * 0.025);

  const anchorSvg = (room.anchors || []).map(a => {
    const id = String(a.anchor_id_str || a.anchor_id);
    const x  = clamp(Number(a.room_x_cm || 0), 0, w);
    const y  = clamp(Number(a.room_y_cm || 0), 0, h);
    const sy = h - y;                             // SVG y (flipped)
    const radius = Number(a.danger_radius_cm || 0);
    const theta  = Number(a.heading_deg || 0) * Math.PI / 180;
    const selected = String(selectedRoomAnchorId) === id;

    // x-axis (red): heading_deg direction, optionally flipped
    const tX    = a.flip_x ? theta + Math.PI : theta;
    const xEx   = x  + Math.cos(tX) * axisLen;
    const xEy   = sy - Math.sin(tX) * axisLen;

    // y-axis (green): 90° CCW from x, optionally flipped
    const tY    = a.flip_y ? theta - Math.PI / 2 : theta + Math.PI / 2;
    const yEx   = x  + Math.cos(tY) * axisLen;
    const yEy   = sy - Math.sin(tY) * axisLen;

    // labels offset just past each arrowhead in its own axis direction
    const xLx = xEx + Math.cos(tX) * (labelSz + 2);
    const xLy = xEy - Math.sin(tX) * (labelSz + 2) + labelSz * 0.35;
    const yLx = yEx + Math.cos(tY) * (labelSz + 2);
    const yLy = yEy - Math.sin(tY) * (labelSz + 2) + labelSz * 0.35;

    return `
      <circle class="map-danger${a.lock_enabled ? "" : " disabled"}" cx="${x}" cy="${sy}" r="${radius}" />

      <line stroke="#ef4444" stroke-width="2.5" stroke-linecap="round" marker-end="url(#ax-x)"
            x1="${x}" y1="${sy}" x2="${xEx}" y2="${xEy}" />
      <text fill="#ef4444" font-size="${labelSz}" font-weight="bold" text-anchor="middle"
            x="${xLx}" y="${xLy}">x</text>

      <line stroke="#22c55e" stroke-width="2.5" stroke-linecap="round" marker-end="url(#ax-y)"
            x1="${x}" y1="${sy}" x2="${yEx}" y2="${yEy}" />
      <text fill="#22c55e" font-size="${labelSz}" font-weight="bold" text-anchor="middle"
            x="${yLx}" y="${yLy}">y</text>

      <rect class="map-axis-handle" x="${xEx - 6}" y="${xEy - 6}" width="12" height="12"
            data-anchor-id="${id}" data-drag="x-axis" title="Drag to rotate x-axis" />
      <rect class="map-axis-handle" x="${yEx - 6}" y="${yEy - 6}" width="12" height="12"
            data-anchor-id="${id}" data-drag="y-axis" title="Drag to rotate y-axis" />

      <circle class="map-anchor${selected ? " selected" : ""}" cx="${x}" cy="${sy}" r="${anchorR}"
              data-anchor-id="${id}" data-drag="anchor" />
      <text class="map-label" x="${x + anchorR + 4}" y="${sy - anchorR}">${esc(hex16(a.uwb_short_id))}</text>
    `;
  }).join("");

  const tagR    = Math.max(8,  Math.min(w, h) * 0.014);
  const distSz  = Math.max(10, Math.min(w, h) * 0.020);

  const tagSvg = Object.values(tags).filter(t =>
    Number(t.room_id) === Number(room.id) &&
    t.global_x_cm !== undefined && t.global_x_cm !== null &&
    t.global_y_cm !== undefined && t.global_y_cm !== null
  ).map(t => {
    const tx   = clamp(Number(t.global_x_cm), 0, w);
    const ty   = clamp(Number(t.global_y_cm), 0, h);
    const tsy  = h - ty;   // SVG y (flipped)

    // Find the anchor that produced this ranging.
    // source_anchor_id_str is the authoritative string key (avoids JS integer precision loss).
    // Fall back to nearest_anchor (also a string anchor_id_str).
    const srcId = t.source_anchor_id_str || t.nearest_anchor || String(t.source_anchor ?? "");
    const src   = srcId ? (room.anchors || []).find(
      a => (a.anchor_id_str && a.anchor_id_str === srcId) ||
           String(a.anchor_id) === srcId ||
           String(a.uwb_short_id) === srcId
    ) : null;

    let rangingLine = "";
    if (src) {
      const ax  = clamp(Number(src.room_x_cm || 0), 0, w);
      const asy = h - clamp(Number(src.room_y_cm || 0), 0, h);
      const mx  = (tx + ax) / 2;
      const my  = (tsy + asy) / 2;
      rangingLine = `
        <line stroke="#f59e0b" stroke-width="1.5" stroke-dasharray="6,4" stroke-opacity="0.85"
              x1="${tx}" y1="${tsy}" x2="${ax}" y2="${asy}" />
        ${t.dist_cm != null ? `
        <text fill="#f59e0b" font-size="${distSz}" font-weight="bold" text-anchor="middle"
              x="${mx}" y="${my - 4}">${t.dist_cm} cm</text>` : ""}
      `;
    }

    return `
      <g class="map-tag">
        ${rangingLine}
        <circle cx="${tx}" cy="${tsy}" r="${tagR}" />
        <text x="${tx + tagR + 4}" y="${tsy + 4}">0x${Number(t.uid).toString(16).toUpperCase().padStart(4, "0")}</text>
      </g>
    `;
  }).join("");

  return `
    <div class="room-map-head">
      <div>
        <b>${esc(room.name)}</b>
        <span>${room.width_cm} x ${room.height_cm} cm</span>
      </div>
      <span>${placingAnchorId ? "Click the map to place anchor" : "Drag ○ to move · drag red □ to set x-axis · drag green □ to set y-axis"}</span>
    </div>
    <svg id="room-map-svg" class="room-map-svg" viewBox="0 0 ${w} ${h}"
         data-room-id="${room.id}" preserveAspectRatio="xMidYMid meet">
      <defs>
        <marker id="ax-x" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
          <polygon points="0 0, 7 3.5, 0 7" fill="#ef4444" />
        </marker>
        <marker id="ax-y" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
          <polygon points="0 0, 7 3.5, 0 7" fill="#22c55e" />
        </marker>
      </defs>
      <rect class="map-floor" x="0" y="0" width="${w}" height="${h}" />
      ${anchorSvg}
      ${tagSvg}
    </svg>
  `;
}

function renderRooms() {
  const container = document.getElementById("room-admin");
  if (!container || roomDrag) return;

  // Don't clobber inspector inputs while user is editing — just refresh the map.
  if (container.contains(document.activeElement) &&
      document.activeElement.tagName === "INPUT") {
    renderRoomMapOnly();
    return;
  }

  const room = selectedRoom();
  const selectedAnchor = roomAnchorById(room, selectedRoomAnchorId);
  const unassignedAnchors = Object.values(anchors).filter(a => !roomAnchorFor(anchorKey(a)));

  container.innerHTML = `
    <div class="visual-room-layout">
      <aside class="visual-room-sidebar">
        <div class="room-sidebar-head">
          <h3>Rooms</h3>
          <button id="visual-room-create-btn">New</button>
        </div>
        <div class="room-list">
          ${rooms.map(r => `
            <button class="room-list-item${room && r.id === room.id ? " active" : ""}" data-room-id="${r.id}">
              <span>${esc(r.name)}</span>
              <small>${r.width_cm} x ${r.height_cm} cm</small>
            </button>
          `).join("") || '<p class="room-empty">No rooms configured</p>'}
        </div>
        ${room ? `
          <div class="room-actions">
            <button id="visual-room-edit-btn">Edit Size</button>
            <button id="visual-room-delete-btn" class="danger">Delete</button>
          </div>
        ` : ""}
        <h3>Place Anchors</h3>
        <div class="anchor-palette">
          ${unassignedAnchors.map(a => {
            const id = anchorKey(a);
            return `<button class="anchor-chip${String(placingAnchorId) === String(id) ? " active" : ""}" data-place-anchor="${id}">${esc(anchorLabel(a))}</button>`;
          }).join("") || '<p class="room-empty">All known anchors are placed</p>'}
        </div>
      </aside>

      <section class="room-map-panel">
        ${room ? renderRoomMap(room) : '<div class="room-map-empty">Create a room to start visual setup.</div>'}
      </section>

      <aside class="visual-room-sidebar inspector">
        ${room ? renderRoomInspector(room, selectedAnchor) : '<p class="room-empty">No room selected</p>'}
      </aside>
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

// Keep x-axis and y-axis angle inputs in sync (y = x + 90°)
document.getElementById("room-admin").addEventListener("input", e => {
  if (e.target.id === "insp-x-angle") {
    const ya = document.getElementById("insp-y-angle");
    if (ya) ya.value = (Number(e.target.value || 0) + 90).toFixed(0);
  } else if (e.target.id === "insp-y-angle") {
    const xa = document.getElementById("insp-x-angle");
    if (xa) xa.value = (Number(e.target.value || 0) - 90).toFixed(0);
  }
});
document.getElementById("twr-clear-btn").addEventListener("click", () => {
  twrDebug = [];
  renderTwrDebug();
});

function roomMapPoint(evt) {
  const svg = document.getElementById("room-map-svg");
  const room = selectedRoom();
  if (!svg || !room) return null;
  const pt = svg.createSVGPoint();
  pt.x = evt.clientX;
  pt.y = evt.clientY;
  const mapped = pt.matrixTransform(svg.getScreenCTM().inverse());
  const w = Number(room.width_cm || 1);
  const h = Number(room.height_cm || 1);
  return {
    x: Math.round(clamp(mapped.x, 0, w)),
    y: Math.round(clamp(h - mapped.y, 0, h)),
  };
}

function fetchRoomsAndRender() {
  return fetch("/api/rooms")
    .then(r => r.json())
    .then(list => {
      rooms = list || [];
      renderRooms();
    });
}

function saveVisualRoomAnchor(room, anchorId, updates) {
  const current = roomAnchorById(room, anchorId) || {};
  const body = {
    uwb_short_id: current.uwb_short_id ?? "",
    room_x_cm: current.room_x_cm ?? 0,
    room_y_cm: current.room_y_cm ?? 0,
    heading_deg: current.heading_deg ?? 0,
    danger_radius_cm: current.danger_radius_cm ?? 300,
    lock_enabled: current.lock_enabled ?? 1,
    ...updates,
  };
  return fetch(`/api/rooms/${room.id}/anchors/${anchorId}`, {
    method: "PUT",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body),
  }).then(fetchRoomsAndRender);
}

function updateVisualAnchorLocal(room, anchorId, updates) {
  const anchor = roomAnchorById(room, anchorId);
  if (!anchor) return null;
  Object.assign(anchor, updates);
  renderRoomMapOnly();
  return anchor;
}

document.getElementById("room-admin").addEventListener("pointerdown", e => {
  const target = e.target.closest("[data-drag]");
  if (!target) return;
  const room = selectedRoom();
  const anchorId = target.dataset.anchorId;
  if (!room || !anchorId) return;
  selectedRoomAnchorId = anchorId;
  placingAnchorId = null;
  const _a = roomAnchorById(room, anchorId);
  roomDrag = {
    anchorId, mode: target.dataset.drag, moved: false,
    startX: e.clientX, startY: e.clientY,
    flipX: !!_a?.flip_x, flipY: !!_a?.flip_y,
  };
  target.setPointerCapture(e.pointerId);
  e.preventDefault();
});

document.addEventListener("pointermove", e => {
  if (!roomDrag) return;
  const dx0 = e.clientX - roomDrag.startX;
  const dy0 = e.clientY - roomDrag.startY;
  if (!roomDrag.moved && dx0 * dx0 + dy0 * dy0 < 16) return;  // 4px threshold
  roomDrag.moved = true;

  const room = selectedRoom();
  const point = roomMapPoint(e);
  const anchor = roomAnchorById(room, roomDrag.anchorId);
  if (!room || !point || !anchor) return;

  if (roomDrag.mode === "anchor") {
    updateVisualAnchorLocal(room, roomDrag.anchorId, {
      room_x_cm: point.x,
      room_y_cm: point.y,
    });
    return;
  }

  // Both axis handles rotate the same heading_deg; offset and flip adjust for each axis
  const dx = point.x - Number(anchor.room_x_cm || 0);
  const dy = point.y - Number(anchor.room_y_cm || 0);
  let deg = Math.atan2(dy, dx) * 180 / Math.PI;
  if (roomDrag.mode === "y-axis") deg -= 90;          // y leads x by 90°
  if (roomDrag.mode === "x-axis" && roomDrag.flipX) deg += 180;  // handle is at flipped tip
  if (roomDrag.mode === "y-axis" && roomDrag.flipY) deg += 180;
  updateVisualAnchorLocal(room, roomDrag.anchorId, {
    heading_deg: Math.round(deg * 10) / 10,
  });
});

document.addEventListener("pointerup", () => {
  if (!roomDrag) return;
  const drag = roomDrag;
  roomDrag = null;
  if (!drag.moved) {
    // Pure click — just show the anchor in the inspector without saving
    renderRooms();
    return;
  }
  const room = selectedRoom();
  const anchor = roomAnchorById(room, drag.anchorId);
  if (!room || !anchor) return;
  if (drag.mode === "anchor") {
    saveVisualRoomAnchor(room, drag.anchorId, {
      room_x_cm: anchor.room_x_cm,
      room_y_cm: anchor.room_y_cm,
    });
  } else {
    saveVisualRoomAnchor(room, drag.anchorId, {
      heading_deg: anchor.heading_deg,
    });
  }
});

document.getElementById("room-admin").addEventListener("click", e => {
  const room = selectedRoom();

  const roomButton = e.target.closest(".room-list-item");
  if (roomButton) {
    selectedRoomId = Number(roomButton.dataset.roomId);
    selectedRoomAnchorId = null;
    placingAnchorId = null;
    renderRooms();
    return;
  }

  const placeButton = e.target.closest("[data-place-anchor]");
  if (placeButton) {
    placingAnchorId = placeButton.dataset.placeAnchor;
    selectedRoomAnchorId = null;
    renderRooms();
    return;
  }

  if (e.target.id === "visual-room-create-btn") {
    const name = prompt("Room name", "Room");
    if (name === null) return;
    const width = Number(prompt("Room width in cm", "500") || 500);
    const height = Number(prompt("Room height in cm", "500") || 500);
    fetch("/api/rooms", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ name: name.trim() || "Room", width_cm: width, height_cm: height }),
    }).then(r => r.json())
      .then(created => { selectedRoomId = created.id; return fetchRoomsAndRender(); });
    return;
  }

  if (!room) return;

  if (e.target.id === "visual-room-edit-btn") {
    const name = prompt("Room name", room.name);
    if (name === null) return;
    const width = Number(prompt("Room width in cm", String(room.width_cm)) || room.width_cm);
    const height = Number(prompt("Room height in cm", String(room.height_cm)) || room.height_cm);
    fetch(`/api/rooms/${room.id}`, {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ name: name.trim() || room.name, width_cm: width, height_cm: height }),
    }).then(fetchRoomsAndRender);
    return;
  }

  if (e.target.id === "visual-room-delete-btn") {
    if (!confirm(`Delete room ${room.name}?`)) return;
    fetch(`/api/rooms/${room.id}`, { method: "DELETE" })
      .then(() => {
        selectedRoomId = null;
        selectedRoomAnchorId = null;
        placingAnchorId = null;
        return fetchRoomsAndRender();
      });
    return;
  }

  const svg = e.target.closest("#room-map-svg");
  if (svg && placingAnchorId && !e.target.dataset.drag) {
    const point = roomMapPoint(e);
    if (!point) return;
    const placingId = placingAnchorId;
    placingAnchorId = null;
    selectedRoomAnchorId = placingId;
    saveVisualRoomAnchor(room, placingId, {
      uwb_short_id: "",
      room_x_cm: point.x,
      room_y_cm: point.y,
      heading_deg: 0,
      danger_radius_cm: 300,
      lock_enabled: 1,
    });
    return;
  }

  const mapAnchor = e.target.closest("[data-anchor-id]");
  if (mapAnchor && !e.target.dataset.drag) {
    selectedRoomAnchorId = mapAnchor.dataset.anchorId;
    placingAnchorId = null;
    renderRooms();
    return;
  }

  if (e.target.id === "insp-save-btn" && selectedRoomAnchorId) {
    saveVisualRoomAnchor(room, selectedRoomAnchorId, {
      uwb_short_id:     document.getElementById("insp-uwb")?.value ?? "",
      room_x_cm:        Number(document.getElementById("insp-x")?.value       || 0),
      room_y_cm:        Number(document.getElementById("insp-y")?.value       || 0),
      heading_deg:      Number(document.getElementById("insp-x-angle")?.value || 0),
      danger_radius_cm: Number(document.getElementById("insp-radius")?.value  || 300),
      flip_x:           document.getElementById("insp-flip-x")?.checked ? 1 : 0,
      flip_y:           document.getElementById("insp-flip-y")?.checked ? 1 : 0,
    });
    return;
  }

  const actionBtn = e.target.closest("[data-anchor-action]");
  if (!actionBtn || !selectedRoomAnchorId) return;
  const anchor = roomAnchorById(room, selectedRoomAnchorId);
  if (!anchor) return;

  const action = actionBtn.dataset.anchorAction;
  if (action === "remove") {
    fetch(`/api/rooms/anchors/${selectedRoomAnchorId}`, { method: "DELETE" })
      .then(() => {
        selectedRoomAnchorId = null;
        return fetchRoomsAndRender();
      });
    return;
  }

  if (action === "lock") {
    saveVisualRoomAnchor(room, selectedRoomAnchorId, { lock_enabled: anchor.lock_enabled ? 0 : 1 });
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
      const prev = tags[msg.tag_uid] || {};
      tags[msg.tag_uid] = {
        ...prev,
        uid:            msg.tag_uid,
        nearest_anchor: id,
        dist_cm:        msg.dist_cm,
        x_cm:           msg.x_cm,
        y_cm:           msg.y_cm,
        room_id:        msg.room_id,
        room_name:      msg.room_name,
        global_x_cm:    msg.global_x_cm,
        global_y_cm:    msg.global_y_cm,
        // keep previous source_anchor fields if this event doesn't carry them
        source_anchor:        msg.source_anchor        ?? prev.source_anchor,
        source_anchor_id_str: msg.source_anchor_id_str ?? prev.source_anchor_id_str,
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
      scheduleTagsRender();   // also refresh room map so dotted line updates
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
