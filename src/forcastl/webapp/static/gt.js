"use strict";
(function () {
  const FIELDS = ["event_ids", "processes", "accounts", "commands", "network", "registry"];
  const SUB_FIELDS = ["processes", "accounts", "commands", "network", "registry"]; // substring-matched
  let files = [];
  let cur = null;          // current file payload
  let saved = {};          // committed GT evidence {field:[values]}
  let pendAdd = {};        // {field: Set} staged additions
  let pendRem = {};        // {field: Set} staged removals of saved values
  let activeField = null;
  let unreviewedOnly = false;
  let pendLabel = null;    // null = no change, else {value:"YES"|"NO", reason}
  let artefactNorm = "";   // normalized artefact text (client-side add guard)
  let idSet = new Set();   // event ids present in the file

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  const norm = (s) => String(s).toLowerCase().split(/\s+/).join(" ").trim();
  // registry hive variants (GT stores HKEY_LOCAL_MACHINE; source uses HKLM, etc.)
  const HIVES = [["HKEY_LOCAL_MACHINE", "HKLM"], ["HKEY_CURRENT_USER", "HKCU"],
    ["HKEY_CLASSES_ROOT", "HKCR"], ["HKEY_CURRENT_CONFIG", "HKCC"], ["HKEY_USERS", "HKU"]];
  function regVariants(v) {
    const up = String(v).toUpperCase(); const out = [v];
    for (const [l, s] of HIVES) {
      if (up.startsWith(l)) out.push(s + v.slice(l.length));
      else if (up.startsWith(s + "\\") || up === s) out.push(l + v.slice(s.length));
    }
    return out;
  }

  function status(msg, kind) { const el = $("status"); if (el) { el.textContent = msg || ""; el.className = kind || ""; } }
  const effLabel = () => (pendLabel !== null ? pendLabel.value : (cur ? cur.malicious : "YES"));
  const dirty = () => pendLabel !== null || FIELDS.some((f) => (pendAdd[f] && pendAdd[f].size) || (pendRem[f] && pendRem[f].size));
  const pendCount = () => (pendLabel !== null ? 1 : 0) + FIELDS.reduce((n, f) => n + (pendAdd[f] ? pendAdd[f].size : 0) + (pendRem[f] ? pendRem[f].size : 0), 0);

  async function api(path, opts) {
    const r = await fetch(path, opts);
    if (!r.ok) { let d = r.statusText; try { d = (await r.json()).detail || d; } catch (e) {} const e = new Error(d); e.status = r.status; throw e; }
    return r.json();
  }

  // values to show for a field, with status: 'saved' | 'remove' | 'add'
  function activeValues(field) {
    const out = [];
    (saved[field] || []).forEach((v) => out.push({ value: String(v), status: (pendRem[field] && pendRem[field].has(String(v))) ? "remove" : "saved" }));
    (pendAdd[field] ? [...pendAdd[field]] : []).forEach((v) => out.push({ value: String(v), status: "add" }));
    return out;
  }

  // ---- file list ----
  async function loadFiles() {
    files = (await api("/api/gt/files")).files;
    renderReviewBar(); renderFiles($("search").value || "");
  }
  function renderReviewBar() {
    const host = $("reviewbar"); if (!host) return;
    const rc = files.filter((x) => x.reviewed).length;
    host.innerHTML = `<span><b style="color:#22c55e">${rc}</b> / ${files.length} reviewed</span>`;
    const lab = document.createElement("label");
    lab.innerHTML = `<input type="checkbox"${unreviewedOnly ? " checked" : ""}> unreviewed only`;
    lab.querySelector("input").onchange = (e) => { unreviewedOnly = e.target.checked; renderFiles($("search").value); };
    host.appendChild(lab);
  }
  function renderFiles(filter) {
    const f = (filter || "").toLowerCase(), host = $("files"); host.innerHTML = "";
    files.filter((x) => (!f || x.name.toLowerCase().includes(f)) && (!unreviewedOnly || !x.reviewed)).forEach((x) => {
      const n = Object.values(x.counts).reduce((a, b) => a + b, 0);
      const row = document.createElement("div");
      row.className = "frow" + (cur && cur.name === x.name ? " sel" : "") + (x.reviewed ? " reviewed" : "");
      row.innerHTML = `<span class="nm" title="${esc(x.name)}">${x.reviewed ? '<span class="rv">✓</span>' : ""}<span class="badge ${x.malicious}">${x.malicious}</span> ${esc(x.name)}</span>` +
        `<span class="meta">${esc(x.source || "")} · ${esc(x.difficulty || "")} · ${n} GT items</span>`;
      row.onclick = () => openFile(x.name);
      host.appendChild(row);
    });
  }

  // ---- open a file ----
  async function openFile(name) {
    if (dirty() && !confirm("Discard unsaved changes on the current file?")) return;
    status("loading…");
    try { cur = await api("/api/gt/file/" + encodeURIComponent(name)); }
    catch (e) { status("load failed: " + e.message, "err"); return; }
    saved = cur.evidence || {};
    pendAdd = {}; pendRem = {}; FIELDS.forEach((f) => { pendAdd[f] = new Set(); pendRem[f] = new Set(); });
    activeField = null; pendLabel = null;
    const parts = []; idSet = new Set();
    cur.events.forEach((ev) => { if (ev.event_id) idSet.add(ev.event_id); ev.fields.forEach((fl) => parts.push(fl.value)); });
    artefactNorm = norm(parts.join("  "));
    renderFiles($("search").value);
    renderHeader(); renderToolbar(); renderEvidence(); renderEvents();
    status("");
  }

  function renderHeader() {
    $("fileheader").innerHTML =
      `<div style="font-size:15px;font-weight:600"><span class="badge ${cur.malicious}">${cur.malicious}</span> ${esc(cur.name)}</div>` +
      `<div class="path">${esc(cur.csv_path)} · ${cur.event_count} events${cur.truncated ? ` (showing first ${cur.events.length})` : ""}</div>`;
  }

  function renderToolbar() {
    const tb = $("toolbar"); tb.hidden = false; tb.innerHTML = "";
    // verdict (malicious/benign) toggle — staged like evidence
    const eff = effLabel();
    const vb = document.createElement("button");
    vb.className = "verdict " + eff + (pendLabel !== null ? " pending" : "");
    vb.textContent = (eff === "YES" ? "MALICIOUS" : "BENIGN") + (pendLabel !== null ? " *" : "");
    vb.title = "flip the conviction (staged until Save)";
    vb.onclick = toggleLabel;
    tb.appendChild(vb);
    // evidence field buttons
    FIELDS.forEach((f) => {
      const b = document.createElement("button");
      b.className = "fld" + (activeField === f ? " active" : "");
      b.innerHTML = `<span class="dot" style="background:var(--c-${f})"></span>${f}`;
      b.onclick = () => { activeField = (activeField === f ? null : f); renderToolbar(); status(activeField ? `field: ${activeField} — select text in the source to stage it` : ""); };
      tb.appendChild(b);
    });
    // save bar
    const bar = document.createElement("span"); bar.id = "savebar";
    const dc = pendCount();
    bar.innerHTML = `<span class="dirty">${dc ? "● " + dc + " unsaved" : ""}</span>`;
    const save = document.createElement("button"); save.className = "save"; save.textContent = "Save"; save.disabled = !dc; save.onclick = saveAll;
    const rev = document.createElement("button"); rev.className = "revert"; rev.textContent = "Revert"; rev.disabled = !dc; rev.onclick = revertAll;
    bar.appendChild(save); bar.appendChild(rev); tb.appendChild(bar);
    const st = document.createElement("span"); st.id = "status"; tb.appendChild(st);
    // reviewed toggle — far right
    const revBtn = document.createElement("button");
    revBtn.className = "revtoggle" + (cur.reviewed ? " on" : "");
    revBtn.textContent = cur.reviewed ? "✓ Reviewed" : "Mark reviewed";
    revBtn.style.marginLeft = "auto";
    revBtn.onclick = toggleReview;
    tb.appendChild(revBtn);
  }

  function toggleLabel() {
    if (!cur) return;
    const next = effLabel() === "YES" ? "NO" : "YES";
    if (next === cur.malicious) { pendLabel = null; status("verdict change reverted"); }
    else {
      const reason = window.prompt(`Reason for marking this file ${next === "YES" ? "MALICIOUS" : "BENIGN"}? (optional)`, "");
      if (reason === null) return;  // cancelled
      pendLabel = { value: next, reason: reason.trim() };
      status(`verdict staged → ${next === "YES" ? "MALICIOUS" : "BENIGN"} (unsaved)`, "ok");
    }
    refresh();
  }

  function renderEvidence() {
    const host = $("evidence"); host.innerHTML = "";
    FIELDS.forEach((f) => activeValues(f).forEach((it) => {
      const c = document.createElement("span");
      c.className = "chip st-" + it.status; c.style.background = `var(--c-${f})`;
      const tag = it.status === "add" ? "+ " : it.status === "remove" ? "− " : "";
      c.innerHTML = `${tag}${esc(it.value)} <span class="x" title="toggle">${it.status === "remove" ? "↺" : "×"}</span>`;
      c.querySelector(".x").onclick = () => toggle(f, it.value, it.status);
      host.appendChild(c);
    }));
    if (!host.children.length) host.innerHTML = `<span class="path">No ground-truth evidence yet for this file.</span>`;
  }

  function highlight(text) {
    const trimmed = text.trim();
    // event_ids: whole-cell exact match only
    for (const it of activeValues("event_ids")) {
      if (it.value.toLowerCase() === trimmed.toLowerCase()) {
        return `<mark class="f-event_ids st-${it.status}" data-field="event_ids" data-value="${esc(it.value)}" data-status="${it.status}" title="event_ids">${esc(text)}</mark>`;
      }
    }
    const pairs = [];
    SUB_FIELDS.forEach((f) => activeValues(f).forEach((it) => {
      if (!it.value) return;
      const needles = f === "registry" ? regVariants(it.value) : [it.value];
      needles.forEach((n) => pairs.push({ field: f, needle: n, value: it.value, status: it.status }));
    }));
    pairs.sort((a, b) => b.needle.length - a.needle.length);
    const lc = text.toLowerCase(), cover = new Array(text.length).fill(null);
    for (const p of pairs) {
      const needle = p.needle.toLowerCase(); if (!needle) continue;
      let i = lc.indexOf(needle);
      while (i !== -1) {
        let free = true; for (let j = i; j < i + needle.length; j++) if (cover[j]) { free = false; break; }
        if (free) for (let j = i; j < i + needle.length; j++) cover[j] = p;
        i = lc.indexOf(needle, i + needle.length);
      }
    }
    let out = "", k = 0;
    while (k < text.length) {
      if (!cover[k]) { out += esc(text[k]); k++; continue; }
      const c = cover[k]; let j = k; while (j < text.length && cover[j] === c) j++;
      out += `<mark class="f-${c.field} st-${c.status}" data-field="${c.field}" data-value="${esc(c.value)}" data-status="${c.status}" title="${c.field}">${esc(text.slice(k, j))}</mark>`;
      k = j;
    }
    return out;
  }

  function renderEvents() {
    const host = $("events"); host.innerHTML = "";
    cur.events.forEach((ev) => {
      const box = document.createElement("div"); box.className = "ev";
      let kv = "";
      if (ev.fields.length) ev.fields.forEach((fl) => { kv += `<div class="k">${esc(fl.name)}</div><div class="v">${highlight(fl.value)}</div>`; });
      else kv = `<div class="k">—</div><div class="v">(no payload fields)</div>`;
      box.innerHTML = `<div class="eh"><b>Event ${esc(ev.event_id)}</b> · ${esc(ev.time)} · ${esc(ev.provider)} ${ev.map ? "· " + esc(ev.map) : ""}</div><div class="kv">${kv}</div>`;
      host.appendChild(box);
    });
    host.querySelectorAll("mark").forEach((m) => { m.onclick = () => toggle(m.dataset.field, m.dataset.value, m.dataset.status); });
  }

  // toggle a value's staged state based on its current status
  function toggle(field, value, st) {
    if (st === "add") pendAdd[field].delete(value);
    else if (st === "saved") pendRem[field].add(value);
    else if (st === "remove") pendRem[field].delete(value);
    refresh();
  }

  // stage an addition from the current text selection
  function stageSelection() {
    if (!cur || !activeField) return;
    const sel = (window.getSelection().toString() || "").trim();
    if (!sel) return;
    const present = activeField === "event_ids" ? idSet.has(sel) : artefactNorm.includes(norm(sel));
    if (!present) { status(`“${sel.slice(0, 30)}” not found in source — can't add`, "err"); return; }
    // already saved (and not staged-removed)? just unmark any pending removal
    const isSaved = (saved[activeField] || []).some((v) => String(v).toLowerCase() === sel.toLowerCase());
    if (isSaved) { pendRem[activeField].delete(sel); status("already in ground truth", "ok"); }
    else { pendAdd[activeField].add(sel); status(`staged → ${activeField}: “${sel.slice(0, 40)}” (unsaved)`, "ok"); }
    window.getSelection().removeAllRanges();
    refresh();
  }

  async function saveAll() {
    const adds = [], removes = [];
    FIELDS.forEach((f) => { (pendAdd[f] || []).forEach((v) => adds.push({ field: f, value: v })); (pendRem[f] || []).forEach((v) => removes.push({ field: f, value: v })); });
    if (!adds.length && !removes.length && pendLabel === null) return;
    const body = { adds, removes };
    if (pendLabel !== null) { body.label = pendLabel.value; body.label_reason = pendLabel.reason; }
    try {
      const res = await api("/api/gt/file/" + encodeURIComponent(cur.name) + "/evidence/batch", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      saved = res.evidence;
      if (res.malicious) { cur.malicious = res.malicious; const ff = files.find((x) => x.name === cur.name); if (ff) ff.malicious = res.malicious; }
      pendAdd = {}; pendRem = {}; FIELDS.forEach((f) => { pendAdd[f] = new Set(); pendRem[f] = new Set(); });
      pendLabel = null;
      const rej = res.rejected || [];
      const lbl = res.applied.label ? " · verdict updated" : "";
      status(`saved (+${res.applied.adds} / −${res.applied.removes})${lbl}` + (rej.length ? ` · ${rej.length} rejected (not in source)` : ""), rej.length ? "err" : "ok");
      renderHeader();
      loadFiles().catch(() => {});  // refresh counts in the file list
      refresh();
    } catch (e) { status("save failed: " + e.message, "err"); }
  }

  async function toggleReview() {
    if (!cur) return;
    const next = !cur.reviewed;
    try {
      await api("/api/gt/file/" + encodeURIComponent(cur.name) + "/review", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reviewed: next }),
      });
      cur.reviewed = next;
      const f = files.find((x) => x.name === cur.name); if (f) f.reviewed = next;
      renderToolbar(); renderReviewBar(); renderFiles($("search").value);
      status(next ? "marked reviewed" : "marked unreviewed", "ok");
    } catch (e) { status("review toggle failed: " + e.message, "err"); }
  }

  function revertAll() {
    pendAdd = {}; pendRem = {}; FIELDS.forEach((f) => { pendAdd[f] = new Set(); pendRem[f] = new Set(); });
    pendLabel = null;
    status("reverted unsaved changes");
    refresh();
  }

  function refresh() { renderHeader(); renderToolbar(); renderEvidence(); renderEvents(); }

  $("search").addEventListener("input", (e) => renderFiles(e.target.value));
  document.addEventListener("mouseup", (e) => { if ($("events").contains(e.target) && activeField) stageSelection(); });
  window.addEventListener("beforeunload", (e) => { if (dirty()) { e.preventDefault(); e.returnValue = ""; } });
  loadFiles().catch((e) => { $("files").innerHTML = `<div class="frow">load failed: ${esc(e.message)}</div>`; });
})();
