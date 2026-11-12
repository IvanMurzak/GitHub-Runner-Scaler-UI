// runner-manager coordinator dashboard. Plain ES2020, no dependencies.
// Served under a strict CSP: no inline styles, so dynamic sizes and colors go
// through CSS custom properties set with style.setProperty().
'use strict';

(() => {
  // ---------------------------------------------------------------- helpers
  const SVGNS = 'http://www.w3.org/2000/svg';
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  function apply(el, props) {
    if (!props) return;
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === 'class') el.setAttribute('class', v);
      else if (k === 'text') el.textContent = v;
      else if (k === 'vars') for (const [n, val] of Object.entries(v)) el.style.setProperty(n, val);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : String(v));
    }
  }
  function append(el, kids) {
    for (const k of kids.flat(Infinity)) {
      if (k == null || k === false) continue;
      el.append(k instanceof Node ? k : String(k));
    }
  }
  function h(tag, props, ...kids) { const el = document.createElement(tag); apply(el, props); append(el, kids); return el; }
  function s(tag, props, ...kids) { const el = document.createElementNS(SVGNS, tag); apply(el, props); append(el, kids); return el; }

  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  const pad2 = (n) => String(n).padStart(2, '0');
  const isNum = (v) => typeof v === 'number' && isFinite(v);
  const nowSec = () => Date.now() / 1000;

  // ------------------------------------------------------------------ state
  const RANGES = ['1h', '6h', '24h', '7d'];
  const RANGE_LABEL = { '1h': 'last hour', '6h': 'last 6 hours', '24h': 'last 24 hours', '7d': 'last 7 days' };
  const OVERVIEW_MS = 5000, METRICS_MIN_MS = 60000, STALE_SECS = 20;

  const state = {
    session: null, ov: null, metrics: null,
    range: loadRange(),
    skew: 0,            // server clock minus local clock, seconds
    lastOk: 0,          // local time of the last successful overview fetch
    failed: false,
    timers: {},
    showAllRecent: false,
    hostColors: new Map(),
    audit: null, auditErr: null, auditSig: '', showAllAudit: false,
    auditOpen: loadFlag('rm.audit.open', true),
    auditAll: loadFlag('rm.audit.all', false),
  };
  const serverNow = () => nowSec() + state.skew;

  function loadRange() {
    try { const r = localStorage.getItem('rm.range'); if (RANGES.includes(r)) return r; } catch (_) { /* storage unavailable */ }
    return '6h';
  }
  function saveRange(r) { try { localStorage.setItem('rm.range', r); } catch (_) { /* ignore */ } }
  function loadFlag(k, dflt) {
    try { const v = localStorage.getItem(k); if (v === '1' || v === '0') return v === '1'; } catch (_) { /* storage unavailable */ }
    return dflt;
  }
  function saveFlag(k, v) { try { localStorage.setItem(k, v ? '1' : '0'); } catch (_) { /* ignore */ } }

  // ------------------------------------------------------------- formatting
  function fmtDur(secs) {
    if (!isNum(secs)) return '—';
    let sec = Math.max(0, Math.round(secs));
    if (sec < 60) return `${sec}s`;
    const m = Math.floor(sec / 60); sec %= 60;
    if (m < 60) return `${m}m ${pad2(sec)}s`;
    const hr = Math.floor(m / 60);
    if (hr < 24) return `${hr}h ${pad2(m % 60)}m`;
    return `${Math.floor(hr / 24)}d ${hr % 24}h`;
  }
  function fmtAgo(t) {
    if (!isNum(t)) return '—';
    const d = serverNow() - t;
    if (d < 10) return 'just now';
    if (d < 60) return `${Math.floor(d)}s ago`;
    if (d < 3600) return `${Math.floor(d / 60)} min ago`;
    if (d < 86400) return `${Math.floor(d / 3600)} h ago`;
    return `${Math.floor(d / 86400)} d ago`;
  }
  function fmtBytes(b) {
    if (!isNum(b)) return '—';
    const g = b / 2 ** 30;
    if (g >= 1024) return `${(g / 1024).toFixed(g >= 10240 ? 0 : 1)} TiB`;
    if (g >= 100) return `${g.toFixed(0)} GiB`;
    if (g >= 1) return `${g.toFixed(1)} GiB`;
    return `${Math.round(b / 2 ** 20)} MiB`;
  }
  const fmtPct = (v) => (isNum(v) ? `${Math.round(v)}%` : '—');
  const fmtInt = (v) => (isNum(v) ? String(Math.round(v)) : '—');
  function fmtClock(t) {
    const d = new Date(t * 1000);
    return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  }
  function fmtDay(t) {
    return new Date(t * 1000).toLocaleDateString(undefined, { weekday: 'short', day: 'numeric' });
  }
  function fmtStamp(t) {
    return new Date(t * 1000).toLocaleString(undefined, { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
  }
  const repoShort = (r) => (r ? String(r).split('/').pop() : '—');
  const humanize = (v) => (v ? String(v).replace(/_/g, ' ') : '—');
  // GitHub's web address as the coordinator is configured (GitHub Enterprise Server too).
  const githubWeb = () => (state.ov && state.ov.github_web) || 'https://github.com';
  const jobUrl = (j) => `${githubWeb()}/${j.repository}/actions/runs/${j.run_id}/job/${j.id}`;
  const repoUrl = (r) => `${githubWeb()}/${r}`;
  const repoLink = (r, cls) => h('a', { class: cls, href: repoUrl(r), target: '_blank', rel: 'noopener', title: r, text: repoShort(r) });

  // Live-updating text: elements carry data-since (elapsed) or data-ago (relative).
  const since = (t, cls) => h('span', { class: cls || 'num', 'data-since': isNum(t) ? t : null, text: isNum(t) ? fmtDur(serverNow() - t) : '—' });
  const ago = (t, cls) => h('time', { class: cls, 'data-ago': isNum(t) ? t : null, datetime: isNum(t) ? new Date(t * 1000).toISOString() : null, title: isNum(t) ? fmtStamp(t) : null, text: fmtAgo(t) });

  function tick() {
    for (const el of $$('[data-since]')) el.textContent = fmtDur(serverNow() - Number(el.dataset.since));
    for (const el of $$('[data-ago]')) el.textContent = fmtAgo(Number(el.dataset.ago));
    renderLive();
  }

  // -------------------------------------------------------------------- api
  class AuthError extends Error {}
  async function api(path, opts = {}) {
    const res = await fetch(path, { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' }, ...opts });
    if (res.status === 401) throw new AuthError('unauthenticated');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.status === 204 ? null : res.json();
  }

  // ------------------------------------------------------------------ boot
  async function boot() {
    $('#signout').addEventListener('click', signOut);
    $('#recent-toggle').addEventListener('click', () => { state.showAllRecent = !state.showAllRecent; if (state.ov) renderRecent(state.ov); });
    buildRangeSwitch();
    buildAuditControls();
    setupDrawer();
    document.addEventListener('visibilitychange', onVisibility);
    document.addEventListener('pointerdown', (e) => { if (!e.target.closest('.plot')) hideAllTips(); });
    try {
      state.session = await api('/api/session');
    } catch (e) {
      if (e instanceof AuthError) return showLogin();
      showLogin('Cannot reach the coordinator right now. Retrying…');
      setTimeout(() => location.reload(), 8000);
      return;
    }
    showApp();
  }

  function showLogin(netMsg) {
    stopTimers();
    if (dw.id) closeDrawer(true);
    $('#boot').hidden = true; $('#app').hidden = true; $('#login').hidden = false;
    document.title = 'Sign in · Runner Manager';
    const params = new URLSearchParams(location.search);
    const msg = $('#login-msg');
    let text = null, kind = 'err';
    if (netMsg) { text = netMsg; kind = 'warn'; }
    else if (params.has('denied')) text = 'This GitHub account is not allowed to open this dashboard. Ask the owner to add it, or sign in with another account.';
    else if (params.has('error')) text = 'Sign-in did not complete. Please try again.';
    msg.hidden = !text;
    if (text) { msg.textContent = text; msg.className = `notice notice-${kind}`; }
  }

  function showApp() {
    $('#boot').hidden = true; $('#login').hidden = true; $('#app').hidden = false;
    if (location.search) history.replaceState(null, '', `/${location.hash}`);
    const u = state.session || {};
    const who = $('#who');
    who.replaceChildren();
    append(who, [
      u.avatar_url ? h('img', { class: 'avatar', src: u.avatar_url, alt: '', width: 28, height: 28, referrerpolicy: 'no-referrer' }) : null,
      h('span', { class: 'who-login', text: u.login || '' }),
    ]);
    who.title = u.login ? `Signed in as ${u.login}` : '';
    startTimers();
    const id = hashHost();
    if (id) openDrawer(id, false);
  }

  async function signOut() {
    const btn = $('#signout');
    btn.disabled = true;
    try { await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' }); } catch (_) { /* reload anyway */ }
    location.replace('/');
  }

  // --------------------------------------------------------------- refresh
  function startTimers() {
    stopTimers();
    loadOverview();
    loadMetrics();
    loadAudit();
    state.timers.tick = setInterval(tick, 1000);
  }
  function stopTimers() {
    clearTimeout(state.timers.ov); clearTimeout(state.timers.m); clearTimeout(state.timers.audit); clearInterval(state.timers.tick);
    state.timers = {};
  }
  const polling = () => !document.hidden && !$('#app').hidden;
  function onVisibility() {
    if ($('#app').hidden) return;
    if (document.hidden) stopTimers(); else startTimers();
  }

  async function loadOverview() {
    clearTimeout(state.timers.ov);
    try {
      const ov = await api('/api/overview');
      if (isNum(ov.generated_at)) state.skew = ov.generated_at - nowSec();
      state.ov = ov; state.lastOk = nowSec(); state.failed = false;
      renderOverview(ov);
    } catch (e) {
      if (e instanceof AuthError) return showLogin();
      state.failed = true;
      renderLive();
    }
    if (polling()) state.timers.ov = setTimeout(loadOverview, OVERVIEW_MS);
  }

  async function loadMetrics() {
    clearTimeout(state.timers.m);
    const range = state.range;
    $('#charts').classList.add('is-loading');
    try {
      const m = await api(`/api/metrics?range=${encodeURIComponent(range)}`);
      if (range === state.range) { state.metrics = m; renderCharts(); if (state.ov) renderHosts(state.ov); }
    } catch (e) {
      if (e instanceof AuthError) return showLogin();
    } finally {
      $('#charts').classList.remove('is-loading');
    }
    // No point refetching faster than the series gains a point: 7d steps are 30 min.
    const step = state.metrics && state.metrics.range === state.range ? state.metrics.step_secs : 0;
    if (polling()) state.timers.m = setTimeout(loadMetrics, Math.max(METRICS_MIN_MS, isNum(step) ? step * 1000 : 0));
  }

  // ---------------------------------------------------------------- header
  function renderLive() {
    const el = $('#live');
    if (!el || $('#app').hidden) return;
    const age = state.lastOk ? nowSec() - state.lastOk : Infinity;
    const stale = state.failed || age > STALE_SECS;
    el.classList.toggle('is-stale', stale);
    $('#live-text').textContent = stale ? (state.lastOk ? `Stale · ${fmtDur(age)}` : 'Connecting') : 'Live';
    el.title = state.lastOk ? `Last update ${new Date(state.lastOk * 1000).toLocaleTimeString()}${state.failed ? ' · last refresh failed' : ''}` : 'Waiting for first update';
  }

  function renderUpdate(ov) {
    const u = ov.update;
    const banner = $('#banner'), chip = $('#update-chip');
    banner.replaceChildren(); banner.hidden = true; chip.hidden = true;
    if (!u) return;
    if (u.state === 'rolled_back' || u.state === 'failed') {
      const title = u.state === 'rolled_back' ? 'Update rolled back' : 'Update failed';
      const meta = [
        u.current && `running v${u.current}`,
        u.latest && u.latest !== u.current && `target v${u.latest}`,
      ].filter(Boolean).join(' · ');
      banner.hidden = false;
      banner.append(h('div', { class: 'banner', role: 'alert' },
        h('span', { class: 'banner-icon', 'aria-hidden': 'true', text: '!' }),
        h('div', { class: 'banner-body' },
          h('strong', { text: title }),
          u.message ? h('p', { text: u.message }) : null,
          h('p', { class: 'banner-meta' }, meta, meta ? ' · ' : '', 'checked ', ago(u.checked_at))),
      ));
    } else if (u.state === 'updated' && isNum(u.changed_at) && serverNow() - u.changed_at < 86400) {
      chip.hidden = false;
      chip.textContent = `Updated to v${u.current || ov.version}`;
      chip.title = [u.message, `${fmtAgo(u.changed_at)}`].filter(Boolean).join(' · ');
    }
  }

  // -------------------------------------------------------------- overview
  function renderOverview(ov) {
    $('#version').textContent = ov.version ? `v${ov.version}` : '';
    $('#uptime').replaceChildren(isNum(ov.started_at) ? h('span', {}, 'Coordinator up ', since(ov.started_at)) : '');
    assignHostColors();
    renderUpdate(ov);
    renderKpis(ov);
    renderHosts(ov);
    renderQueue(ov);
    renderRunning(ov);
    renderRecent(ov);
    renderPools(ov);
    renderLive();
    syncDrawer();
  }

  function meterBar(pct, extra) {
    const p = isNum(pct) ? clamp(pct, 0, 100) : 0;
    const level = !isNum(pct) ? 'none' : p >= 90 ? 'err' : p >= 75 ? 'high' : p >= 50 ? 'warn' : 'ok';
    return h('span', { class: `bar bar-${level} ${extra || ''}`, role: 'presentation', vars: { '--pct': `${p}%` } });
  }

  function kpi(label, value, sub, extra) {
    return h('div', { class: 'kpi' },
      h('p', { class: 'kpi-label', text: label }),
      h('p', { class: 'kpi-value' }, value),
      sub ? h('p', { class: 'kpi-sub' }, sub) : null,
      extra || null);
  }

  function renderKpis(ov) {
    const sm = ov.summary || {};
    const pct = isNum(sm.slots_busy) && sm.slots_total > 0 ? (sm.slots_busy / sm.slots_total) * 100 : null;
    const oldest = (ov.queue || [])[0];
    const runHosts = new Set((ov.running || []).map((j) => j.host_id).filter(Boolean)).size;
    $('#kpis').replaceChildren(
      kpi('Machines online', h('span', { class: 'num' }, fmtInt(sm.hosts_online), h('small', { text: ` / ${fmtInt(sm.hosts_total)}` }))),
      kpi('Runner slots busy', h('span', { class: 'num' }, fmtInt(sm.slots_busy), h('small', { text: ` / ${fmtInt(sm.slots_total)}` })),
        isNum(pct) ? `${Math.round(pct)}% utilised` : null, meterBar(pct, 'kpi-bar')),
      kpi('Jobs running / queued', h('span', { class: 'num' }, fmtInt(sm.jobs_running), h('small', { text: ` / ${fmtInt(sm.jobs_queued)}` })),
        h('span', {},
          runHosts ? `on ${runHosts} machine${runHosts === 1 ? '' : 's'}` : sm.jobs_running ? null : 'all idle',
          oldest ? h('span', {}, ' · oldest waits ', since(oldest.queued_at)) : null)),
      kpi('Queue wait p50', h('span', { class: 'num', text: fmtDur(sm.p50_queue_wait_secs) }),
        h('span', {}, 'p90 ', h('b', { class: 'num', text: fmtDur(sm.p90_queue_wait_secs) }))),
    );
  }

  // ---------------------------------------------------------------- hosts
  // The one client-side sort: colours follow the name order of every known host in
  // either list, so they stay put when a host goes offline. The lists come sorted.
  function assignHostColors() {
    const names = new Map();
    for (const x of (state.ov && state.ov.hosts) || []) names.set(x.id, x.name || x.hostname || x.id);
    for (const x of (state.metrics && state.metrics.hosts) || []) if (!names.has(x.id)) names.set(x.id, x.name || x.id);
    const ids = [...names.keys()].sort((a, b) => String(names.get(a)).localeCompare(String(names.get(b))));
    state.hostColors = new Map(ids.map((id, i) => [id, `var(--s${(i % 8) + 1})`]));
  }
  const hostColor = (id) => state.hostColors.get(id) || 'var(--muted)';
  const hostDot = (id) => h('span', { class: 'host-dot', 'aria-hidden': 'true', vars: { '--c': hostColor(id) } });
  const machine = (id, name) => h('span', { class: 'machine' }, hostDot(id), name);

  function hostStatus(x) {
    if (!x.online) return { key: 'offline', label: 'Offline' };
    if (x.unfit) return { key: 'unfit', label: 'Unfit' };
    if (x.draining) return { key: 'draining', label: 'Draining' };
    return { key: 'online', label: 'Online' };
  }
  const OS_NAME = { linux: 'Linux', windows: 'Windows', macos: 'macOS' };

  function meterRow(label, pct, value) {
    return h('div', { class: 'meter' },
      h('span', { class: 'meter-label', text: label }),
      h('span', { class: 'meter-value num', text: value }),
      meterBar(pct));
  }

  // A machine's memory used, as a percent of its total, per sample.
  function ramPct(x) {
    return (x.ram_used || []).map((u, i) => {
      const total = (x.ram_total || [])[i];
      return isNum(u) && isNum(total) && total > 0 ? (u / total) * 100 : null;
    });
  }

  function sparkline(hostId) {
    const m = state.metrics;
    const mh = m && (m.hosts || []).find((x) => x.id === hostId);
    if (!mh || !Array.isArray(mh.cpu) || mh.cpu.filter(isNum).length < 2) return h('div', { class: 'spark spark-empty', text: 'No CPU history yet' });
    const g = regroup(m.t || [], m.step_secs || 60, groupOf(mh.cpu.length, SPARK_POINTS), [mh.cpu, ramPct(mh)]);
    const [cpu, mem] = g.series;
    const n = cpu.length, W = 120, H = 32;
    const toPts = (vals) => vals.map((v, i) => (isNum(v) ? [(i / Math.max(1, n - 1)) * W, H - (clamp(v, 0, 100) / 100) * (H - 2) - 1] : null));
    const peak = (vals) => { const v = vals.filter(isNum); return v.length ? Math.max(...v) : null; };
    const cpuPts = toPts(cpu);
    return h('div', { class: 'spark' },
      s('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', role: 'img', 'aria-label': `CPU and memory over the ${RANGE_LABEL[m.range] || m.range}: CPU peak ${fmtPct(peak(cpu))}, memory peak ${fmtPct(peak(mem))}` },
        s('path', { class: 'spark-area', d: areaPath(cpuPts, H, true) }),
        s('path', { class: 'spark-line spark-ram', d: linePath(toPts(mem), true), 'vector-effect': 'non-scaling-stroke' }),
        s('path', { class: 'spark-line', d: linePath(cpuPts, true), 'vector-effect': 'non-scaling-stroke' })),
      h('span', { class: 'spark-cap' },
        h('span', {}, h('i', { class: 'spark-key', 'aria-hidden': 'true' }), 'CPU', h('i', { class: 'spark-key spark-key-ram', 'aria-hidden': 'true' }), `RAM · ${m.range}`),
        h('span', { class: 'num', text: `peak ${fmtPct(peak(cpu))} · ${fmtPct(peak(mem))}` })));
  }

  function hostCard(x) {
    const st = hostStatus(x);
    const total = isNum(x.ram_bytes) ? x.ram_bytes : null;
    const used = total != null && isNum(x.free_ram_bytes) ? total - x.free_ram_bytes : null;
    const slots = (x.busy_slots || 0) + (x.free_slots || 0);
    const os = String(x.os || '').toLowerCase();
    return h('article', { class: `host is-${st.key}`, 'aria-label': `${x.name || x.hostname}, ${st.label}` },
      h('header', { class: 'host-head' },
        hostDot(x.id),
        h('div', { class: 'host-id' },
          h('h3', { class: 'host-name', title: x.hostname || null },
            h('a', { class: 'host-open', href: `#host=${encodeURIComponent(x.id)}`, 'data-host': x.id, text: x.name || x.hostname || x.id })),
          h('p', { class: 'host-sub' },
            h('span', { class: `os os-${os || 'unknown'}`, text: OS_NAME[os] || os || 'unknown' }),
            [x.arch, isNum(x.cores) ? `${x.cores} cores` : null].filter(Boolean).join(' · '))),
        h('div', { class: 'host-badges' },
          h('span', { class: `status status-${st.key}` }, h('i', { 'aria-hidden': 'true' }), st.label),
          accessChip(x, !!x.remote_changes))),
      h('div', { class: 'host-meters' },
        meterRow('CPU', x.cpu_load_percent, fmtPct(x.cpu_load_percent)),
        meterRow('Memory', used != null && total ? (used / total) * 100 : null, `${fmtBytes(used)} / ${fmtBytes(total)}`),
        meterRow('Slots', slots ? ((x.busy_slots || 0) / slots) * 100 : null, slots ? `${x.busy_slots || 0} / ${slots}` : '—')),
      sparkline(x.id),
      versionLine(x),
      h('footer', { class: 'host-foot' },
        diskLine(x),
        !x.online ? h('span', {}, 'Last seen ', ago(x.last_seen_at))
          : isNum(x.connected_since) ? h('span', {}, 'Up ', since(x.connected_since)) : null));
  }

  // `Disk 176 GiB / 1.5 TiB` with a meter, from 0.4.66; free space before.
  function diskLine(x) {
    const total = x.disk_total_bytes, free = x.disk_free_bytes;
    if (!isNum(total) || total <= 0 || !isNum(free)) return h('span', {}, 'Disk free ', h('b', { class: 'num', text: fmtBytes(free) }));
    const used = Math.max(0, total - free);
    return h('span', { class: 'disk', title: `${fmtBytes(free)} free` },
      h('span', {}, 'Disk ', h('b', { class: 'num', text: `${fmtBytes(used)} / ${fmtBytes(total)}` })),
      meterBar((used / total) * 100));
  }

  function renderHosts(ov) {
    const hosts = ov.hosts || [];  // online first, then by name
    const on = hosts.filter((x) => x.online).length;
    $('#machines-count').textContent = hosts.length ? `${on} of ${hosts.length} online` : '';
    // Cards are rebuilt on every poll: keep keyboard focus on the same card.
    const f = document.activeElement;
    const keep = f && f.classList && f.classList.contains('host-open') ? f.dataset.host : null;
    $('#hosts').replaceChildren(...(hosts.length ? hosts.map(hostCard)
      : [empty('No machines enrolled yet', 'Machines appear here once their runner-manager agent connects.')]));
    if (keep) { const el = $(`.host-open[data-host="${CSS.escape(keep)}"]`); if (el) el.focus({ preventScroll: true }); }
  }

  // ---------------------------------------------------------------- tables
  function empty(title, text) {
    return h('div', { class: 'empty' }, h('span', { class: 'empty-icon', 'aria-hidden': 'true' }), h('p', { class: 'empty-title', text: title }), text ? h('p', { text }) : null);
  }

  function jobCell(j) {
    return h('td', { class: 'c-job' },
      h('a', { class: 'job-link', href: jobUrl(j), target: '_blank', rel: 'noopener', text: j.name || `Job ${j.id}` }),
      repoLink(j.repository, 'repo-link'));
  }
  const td = (label, cls, ...kids) => h('td', { class: cls, 'data-label': label }, ...kids);
  const numCell = (label, text) => td(label, 'c-num', h('span', { class: 'num', text }));
  function chips(labels) {
    const list = Array.isArray(labels) ? labels : labels ? String(labels).split(',') : [];
    return h('span', { class: 'chips' }, list.map(chip));
  }
  // `not-wsl` is an exclusion: the job avoids machines carrying `wsl`.
  function chip(l) {
    const excludes = /^not-./i.test(l) ? l.slice(4) : null;
    return h('span', {
      class: `chip${l === 'self-hosted' ? ' chip-dim' : ''}${excludes ? ' chip-not' : ''}`,
      title: excludes ? `Excludes machines labelled ${excludes}` : null,
      text: l,
    });
  }
  function table(caption, heads, rows) {
    return h('table', { class: 'tbl' },
      h('caption', { class: 'sr-only', text: caption }),
      h('thead', {}, h('tr', {}, heads.map((x) => h('th', { scope: 'col', class: x[1] || null, text: x[0] })))),
      h('tbody', {}, rows));
  }
  function hostName(id, fallback) {
    const x = ((state.ov && state.ov.hosts) || []).find((y) => y.id === id);
    return (x && (x.name || x.hostname)) || fallback || '—';
  }
  function machineCell(j) {
    return td('Machine', 'c-machine',
      machine(j.host_id, j.host_name || hostName(j.host_id)),
      j.runner_name ? h('span', { class: 'runner mono', title: j.runner_name, text: j.runner_name }) : null);
  }

  function renderQueue(ov) {
    const q = ov.queue || [];
    $('#queue-count').textContent = q.length ? String(q.length) : '';
    $('#queue').replaceChildren(q.length
      ? table('Queued jobs', [['Job'], ['Labels', 'c-labels'], ['Waiting', 'c-num']], q.map((j) => h('tr', {},
        jobCell(j), td('Labels', 'c-labels', chips(j.labels)),
        td('Waiting', 'c-num', since(j.queued_at, 'num wait'))))
      ) : empty('Queue is clear', 'New jobs are placed as soon as a slot frees up.'));
  }

  function renderRunning(ov) {
    const r = ov.running || [];
    $('#running-count').textContent = r.length ? String(r.length) : '';
    $('#running').replaceChildren(r.length
      ? table('Running jobs', [['Job'], ['Machine'], ['Elapsed', 'c-num']], r.map((j) => h('tr', {},
        jobCell(j), machineCell(j), td('Elapsed', 'c-num', since(j.started_at)))))
      : empty('No jobs running', 'Every runner slot is idle.'));
  }

  const CONCLUSION = {
    success: ['ok', '✓'], failure: ['err', '✕'], timed_out: ['err', '⏱'], startup_failure: ['err', '✕'],
    cancelled: ['dim', '⊘'], skipped: ['dim', '↷'], neutral: ['dim', '–'], action_required: ['warn', '!'],
  };
  function conclusion(c) {
    const [kind, glyph] = CONCLUSION[c] || ['dim', '•'];
    return h('span', { class: `badge badge-${kind}` }, h('span', { 'aria-hidden': 'true', text: glyph }), humanize(c || 'unknown'));
  }

  function renderRecent(ov) {
    const all = ov.recent || [];
    const LIMIT = 12;
    const list = state.showAllRecent ? all : all.slice(0, LIMIT);
    const btn = $('#recent-toggle');
    btn.hidden = all.length <= LIMIT;
    btn.textContent = state.showAllRecent ? 'Show fewer' : `Show all ${all.length}`;
    btn.setAttribute('aria-expanded', String(state.showAllRecent));
    $('#recent').replaceChildren(list.length
      ? table('Recently completed jobs', [['Result'], ['Job'], ['Machine'], ['Duration', 'c-num'], ['Finished', 'c-num']], list.map((j) => h('tr', {},
        td('Result', 'c-result', conclusion(j.conclusion)), jobCell(j), machineCell(j),
        numCell('Duration', fmtDur(j.duration_secs)),
        td('Finished', 'c-num c-when', ago(j.completed_at, 'muted')))))
      : empty('No completed jobs yet', null));
  }

  function renderPools(ov) {
    const pools = ov.pools || [], leases = ov.leases || [];
    const sec = $('#pools-section');
    sec.hidden = !pools.length && !leases.length;
    if (sec.hidden) return;
    const parts = [];
    if (pools.length) parts.push(h('div', { class: 'card' }, h('h3', { class: 'card-title', text: 'Pools' }),
      table('Pools', [['Repository'], ['Labels'], ['Queued', 'c-num'], ['Leases', 'c-num'], ['Oldest', 'c-num'], ['Reason']], pools.map((p) => h('tr', {},
        h('td', { class: 'c-job' }, repoLink(p.repository, 'job-link')),
        td('Labels', '', chips(p.labels)),
        numCell('Queued', fmtInt(p.queued)),
        numCell('Leases', fmtInt(p.leases)),
        numCell('Oldest', fmtDur(p.oldest_wait_secs)),
        td('Reason', '', h('span', { class: p.refusal ? 'text-err' : 'muted', text: p.refusal || humanize(p.reason) })))))));
    if (leases.length) parts.push(h('div', { class: 'card' }, h('h3', { class: 'card-title', text: 'Leases' }),
      table('Leases', [['Machine'], ['Repository'], ['State'], ['Age', 'c-num']], leases.map((l) => h('tr', {},
        h('td', { class: 'c-job' }, machine(l.host_id, hostName(l.host_id))),
        td('Repository', '', l.repository ? repoLink(l.repository) : '—'),
        td('State', '', h('span', { class: 'badge badge-dim', text: humanize(l.state) })),
        numCell('Age', fmtDur(l.age_secs)))))));
    $('#pools').replaceChildren(...parts);
  }

  // ---------------------------------------------------------------- charts
  // A wide range has more points than a plot has room for. They are averaged
  // in groups first, to about LINE_POINTS points for a line and COLUMN_COUNT
  // columns, so a chart reads the same at 1h and at 7d. Groups are aligned to
  // whole multiples of their width, so a refresh does not reshape the past.
  const LINE_POINTS = 90, COLUMN_COUNT = 48, SPARK_POINTS = 60;

  // `series` (arrays over `t`, one point per `step` seconds) averaged into
  // groups of `k` steps; a group with no value stays empty.
  function regroup(t, step, k, series) {
    if (k <= 1 || !t.length) return { t, step, series };
    const width = step * k;
    const slot = new Map(), keys = [];
    const at = t.map((tt) => {
      const g = Math.floor(tt / width) * width;
      if (!slot.has(g)) { slot.set(g, keys.length); keys.push(g); }
      return slot.get(g);
    });
    return {
      t: keys, step: width,
      series: series.map((vals) => {
        const sum = new Array(keys.length).fill(0), cnt = new Array(keys.length).fill(0);
        vals.forEach((v, i) => { if (isNum(v)) { sum[at[i]] += v; cnt[at[i]]++; } });
        return sum.map((x, g) => (cnt[g] ? x / cnt[g] : null));
      }),
    };
  }
  const groupOf = (n, target) => Math.max(1, Math.ceil(n / target));

  const f1 = (v) => v.toFixed(1);
  // Fritsch–Carlson monotone cubic: smooth, and never overshoots a value.
  function curve(p, smooth) {
    if (p.length === 1) return `M${f1(p[0][0])} ${f1(p[0][1])}l0 0`;
    if (!smooth || p.length < 3) return 'M' + p.map((q) => `${f1(q[0])} ${f1(q[1])}`).join('L');
    const n = p.length, dx = [], m = [], tg = [];
    for (let i = 0; i < n - 1; i++) { dx[i] = p[i + 1][0] - p[i][0]; m[i] = (p[i + 1][1] - p[i][1]) / (dx[i] || 1); }
    tg[0] = m[0]; tg[n - 1] = m[n - 2];
    for (let i = 1; i < n - 1; i++) {
      tg[i] = m[i - 1] * m[i] <= 0 ? 0 : (3 * (dx[i - 1] + dx[i])) / ((2 * dx[i] + dx[i - 1]) / m[i - 1] + (dx[i] + 2 * dx[i - 1]) / m[i]);
    }
    let d = `M${f1(p[0][0])} ${f1(p[0][1])}`;
    for (let i = 0; i < n - 1; i++) {
      const third = dx[i] / 3;
      d += `C${f1(p[i][0] + third)} ${f1(p[i][1] + tg[i] * third)} ${f1(p[i + 1][0] - third)} ${f1(p[i + 1][1] - tg[i + 1] * third)} ${f1(p[i + 1][0])} ${f1(p[i + 1][1])}`;
    }
    return d;
  }
  // The unbroken runs of points, split where a point is missing.
  function runsOf(pts) {
    const out = []; let run = [];
    for (const p of pts) {
      if (p) run.push(p);
      else if (run.length) { out.push(run); run = []; }
    }
    if (run.length) out.push(run);
    return out;
  }
  const linePath = (pts, smooth) => runsOf(pts).map((r) => curve(r, smooth)).join('');
  // Area under a line down to a fixed baseline, one closed shape per run of values.
  const areaPath = (pts, base, smooth) => runsOf(pts).map((r) =>
    `${curve(r, smooth)}L${f1(r[r.length - 1][0])} ${f1(base)}L${f1(r[0][0])} ${f1(base)}Z`).join('');

  function yScale(maxV, fixed, integer) {
    const top0 = fixed || (maxV > 0 ? maxV : 1);
    const raw = top0 / 4;
    const p = 10 ** Math.floor(Math.log10(raw));
    let step = [1, 2, 2.5, 5, 10].map((m) => m * p).find((x) => x >= raw - 1e-9);
    if (integer) step = Math.max(1, Math.ceil(step));
    const top = fixed || step * Math.max(1, Math.ceil(maxV / step));
    const ticks = [];
    for (let v = 0; v <= top + 1e-9; v += step) ticks.push(v);
    return { top, ticks };
  }

  const TICK_STEPS = [300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800];
  function timeTicks(t0, t1, maxN) {
    const step = TICK_STEPS.find((x) => (t1 - t0) / x <= maxN) || 172800;
    const off = new Date(t0 * 1000).getTimezoneOffset() * 60;
    const out = [];
    for (let t = Math.ceil((t0 - off) / step) * step + off; t <= t1; t += step) out.push(t);
    return { step, ticks: out };
  }

  const charts = [];
  function setupChart(fig) {
    const plot = $('.plot', fig);
    const c = { fig, plot, cfg: null, idx: null, frame: 0 };
    plot.tabIndex = 0;
    plot.addEventListener('pointermove', (e) => hover(c, e));
    plot.addEventListener('pointerdown', (e) => hover(c, e));
    plot.addEventListener('pointerleave', (e) => { if (e.pointerType !== 'touch') hideTip(c); });
    plot.addEventListener('blur', () => hideTip(c));
    plot.addEventListener('keydown', (e) => {
      if (!c.cfg || !c.geo) return;
      const n = c.cfg.t.length;
      const step = { ArrowLeft: -1, ArrowRight: 1, Home: -n, End: n }[e.key];
      if (step == null) { if (e.key === 'Escape') hideTip(c); return; }
      e.preventDefault();
      showTip(c, clamp((c.idx == null ? n - 1 : c.idx) + step, 0, n - 1));
    });
    new ResizeObserver(() => { cancelAnimationFrame(c.frame); c.frame = requestAnimationFrame(() => drawChart(c)); }).observe(plot);
    charts.push(c);
    return c;
  }
  const hideAllTips = () => charts.forEach(hideTip);

  // cfg.kind: 'lines' (smooth, one per series), 'columns' (stacked) or
  // 'strips' (a row per series, each 0..yMax).
  function drawChart(c) {
    const { plot, cfg } = c;
    if (!cfg) return;
    const W = Math.round(plot.clientWidth), H = Math.round(plot.clientHeight);
    if (W < 40 || H < 40) return;
    const t = cfg.t || [];
    const n = t.length;
    c.idx = null;
    if (n < 2 || !cfg.series.length) {
      plot.replaceChildren(h('div', { class: 'plot-empty', text: 'No data for this range yet' }));
      c.geo = null;
      return;
    }
    const narrow = W < 420;
    const strips = cfg.kind === 'strips';
    const P = { l: strips ? (narrow ? 74 : 96) : narrow ? 30 : 38, r: 8, t: 8, b: 22 };
    const pw = W - P.l - P.r, ph = H - P.t - P.b;
    const step = cfg.step;
    const t0 = t[0], t1 = t[n - 1] + step;
    const X = (tv) => P.l + ((tv - t0) / (t1 - t0 || 1)) * pw;
    const xAt = (i) => X(t[i] + step / 2);

    // Columns stack: drawn from cumulative values; tooltips read raw ones.
    let tops = cfg.series.map((sr) => sr.values);
    let bases = null;
    if (cfg.kind === 'columns') {
      const acc = new Array(n).fill(0);
      bases = []; tops = [];
      for (const sr of cfg.series) {
        bases.push(acc.slice());
        for (let i = 0; i < n; i++) if (isNum(sr.values[i])) acc[i] += sr.values[i];
        tops.push(acc.slice());
      }
    }
    let maxV = 0;
    for (const vals of tops) for (const v of vals) if (isNum(v) && v > maxV) maxV = v;
    const ys = yScale(maxV, cfg.yMax, cfg.integer);
    const Y = (v) => P.t + (1 - v / ys.top) * ph;

    const svg = s('svg', { class: 'chart-svg', viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: 'img', 'aria-label': cfg.summary });
    const grid = s('g', { class: 'grid', 'aria-hidden': 'true' });
    if (!strips) {
      for (const v of ys.ticks) {
        const y = Y(v).toFixed(1);
        grid.append(s('line', { x1: P.l, x2: W - P.r, y1: y, y2: y, class: v === 0 ? 'baseline' : null }));
        grid.append(s('text', { x: P.l - 6, y, class: 'ytick', dy: '0.32em', text: cfg.fmtTick(v) }));
      }
    }
    const tt = timeTicks(t0, t1, Math.max(2, Math.floor(pw / (narrow ? 64 : 84))));
    for (const tv of tt.ticks) {
      const x = X(tv);
      if (x < P.l + 14 || x > W - P.r - 14) continue;
      grid.append(s('text', { x: x.toFixed(1), y: H - 6, class: 'xtick', text: tt.step >= 86400 ? fmtDay(tv) : fmtClock(tv) }));
    }
    svg.append(grid);

    const marks = s('g', { class: 'marks' });
    let dotY;
    if (strips) {
      const m = cfg.series.length, gap = 5;
      const rowH = Math.max(12, (ph - gap * (m - 1)) / m);
      const top = cfg.yMax || 100;
      const rowY = (k, v) => P.t + k * (rowH + gap) + rowH - (clamp(v, 0, top) / top) * (rowH - 2);
      cfg.series.forEach((sr, k) => {
        const y0 = P.t + k * (rowH + gap);
        const pts = sr.values.map((v, i) => (isNum(v) ? [xAt(i), rowY(k, v)] : null));
        marks.append(s('rect', { class: 'strip-bg', x: P.l, y: f1(y0), width: pw, height: f1(rowH), rx: 3 }));
        marks.append(s('path', { class: 'strip-area', d: areaPath(pts, y0 + rowH, true), vars: { '--c': sr.color } }));
        marks.append(s('path', { class: 'strip-line', d: linePath(pts, true), vars: { '--c': sr.color } }));
        const vals = sr.values.filter(isNum);
        const two = rowH >= 26 && vals.length;
        marks.append(s('text', { class: 'strip-name', x: 2, y: f1(y0 + rowH / 2 - (two ? 6 : 0)), dy: '0.32em', text: sr.name }));
        if (two) {
          const avg = vals.reduce((a, b) => a + b, 0) / vals.length;
          marks.append(s('text', { class: 'strip-val', x: 2, y: f1(y0 + rowH / 2 + 8), dy: '0.32em', text: `avg ${cfg.fmtVal(avg)} · max ${cfg.fmtVal(Math.max(...vals))}` }));
        }
      });
      dotY = (k, i) => (isNum(cfg.series[k].values[i]) ? rowY(k, cfg.series[k].values[i]) : null);
    } else if (cfg.kind === 'columns') {
      const bw = (step / (t1 - t0)) * pw;
      const pad = Math.max(1, bw * 0.22);
      const cw = Math.max(1, bw - pad);
      cfg.series.forEach((sr, k) => {
        const g = s('g', { class: 'col', vars: { '--c': sr.color } });
        for (let i = 0; i < n; i++) {
          if (!isNum(sr.values[i]) || sr.values[i] <= 0) continue;
          const y1 = Y(tops[k][i]), y0 = Y(bases[k][i]);
          g.append(s('rect', { x: f1(xAt(i) - cw / 2), y: f1(y1), width: f1(cw), height: f1(Math.max(0.5, y0 - y1)), rx: cw > 5 ? 1.5 : 0 }));
        }
        marks.append(g);
      });
      dotY = (k, i) => (isNum(cfg.series[k].values[i]) ? Y(tops[k][i]) : null);
    } else {
      cfg.series.forEach((sr) => {
        const pts = sr.values.map((v, i) => (isNum(v) ? [xAt(i), Y(v)] : null));
        if (cfg.series.length === 1 || cfg.fill) marks.append(s('path', { class: 'area area-soft', d: areaPath(pts, Y(0), true), vars: { '--c': sr.color } }));
        marks.append(s('path', { class: 'line', d: linePath(pts, true), vars: { '--c': sr.color } }));
      });
      dotY = (k, i) => (isNum(cfg.series[k].values[i]) ? Y(cfg.series[k].values[i]) : null);
    }
    svg.append(marks);

    const cross = s('g', { class: 'cross', 'aria-hidden': 'true' });
    cross.append(s('line', { y1: P.t, y2: P.t + ph, class: 'cross-line' }));
    const dots = cfg.series.map((sr) => s('circle', { r: 4, class: 'cross-dot', vars: { '--c': sr.color } }));
    cross.append(...dots);
    svg.append(cross);

    const tip = h('div', { class: 'tip', role: 'status', 'aria-live': 'off' });
    plot.replaceChildren(svg, tip);
    c.geo = { W, P, pw, t0, t1, xAt, dotY, cross, dots, tip };
  }

  function hover(c, e) {
    if (!c.geo || !c.cfg) return;
    if (e.type === 'pointerdown') charts.forEach((o) => o !== c && hideTip(o));
    const r = c.plot.getBoundingClientRect();
    const { P, pw, t0, t1 } = c.geo;
    const t = c.cfg.t;
    const tx = t0 + clamp((e.clientX - r.left - P.l) / pw, 0, 1) * (t1 - t0);
    showTip(c, clamp(Math.floor((tx - t[0]) / c.cfg.step), 0, t.length - 1));
  }

  function showTip(c, i) {
    const g = c.geo, cfg = c.cfg;
    if (!g) return;
    c.idx = i;
    const x = g.xAt(i);
    g.cross.classList.add('on');
    const line = g.cross.firstChild;
    line.setAttribute('x1', x.toFixed(1)); line.setAttribute('x2', x.toFixed(1));
    g.dots.forEach((d, k) => {
      const y = g.dotY(k, i);
      d.classList.toggle('off', y == null);
      if (y != null) { d.setAttribute('cx', x.toFixed(1)); d.setAttribute('cy', y.toFixed(1)); }
    });
    const rows = cfg.series.map((sr) => h('div', { class: 'tip-row' },
      h('span', { class: 'tip-key', 'aria-hidden': 'true', vars: { '--c': sr.color } }),
      h('b', { class: 'num', text: sr.fmtAt ? sr.fmtAt(i) : cfg.fmtVal(sr.values[i]) }),
      h('span', { class: 'tip-name', text: sr.name })));
    const from = cfg.t[i], to = from + cfg.step;
    const wide = cfg.t[cfg.t.length - 1] - cfg.t[0] > 86400;
    const head = `${wide ? fmtStamp(from) : fmtClock(from)}${cfg.step > 60 ? `–${fmtClock(to)} · average` : ''}`;
    g.tip.replaceChildren(h('div', { class: 'tip-time', text: head }), ...rows, ...(cfg.total ? [cfg.total(i)] : []));
    g.tip.classList.add('on');
    const tw = g.tip.offsetWidth;
    const left = x + 12 + tw > g.W ? Math.max(4, x - 12 - tw) : x + 12;
    g.tip.style.setProperty('--tx', `${Math.round(left)}px`);
  }
  function hideTip(c) {
    if (!c.geo) return;
    c.idx = null;
    c.geo.cross.classList.remove('on');
    c.geo.tip.classList.remove('on');
  }

  function legend(fig, series, show) {
    $('.legend', fig).replaceChildren(...(show ? series.map((sr) =>
      h('li', {}, h('span', { class: 'legend-key', 'aria-hidden': 'true', vars: { '--c': sr.color } }), sr.name)) : []));
  }

  function summarize(title, series, fmt) {
    const parts = series.map((sr) => {
      const vals = sr.values.filter(isNum);
      if (!vals.length) return `${sr.name}: no data`;
      return `${sr.name}: latest ${fmt(vals[vals.length - 1])}, peak ${fmt(Math.max(...vals))}`;
    });
    return `${title}, ${RANGE_LABEL[state.range] || state.range}. ${parts.join('; ')}.`;
  }

  function setChart(c, cfg) {
    c.cfg = cfg;
    legend(c.fig, cfg.series, cfg.kind !== 'strips');
    drawChart(c);
  }

  // `average per 20 min`, `per 2 h`.
  function per(secs) {
    if (secs < 3600) return `${Math.round(secs / 60)} min`;
    const hrs = secs / 3600;
    return `${Number.isInteger(hrs) ? hrs : hrs.toFixed(1)} h`;
  }

  let chartRefs = null;
  function renderCharts() {
    if (!chartRefs) chartRefs = { jobs: setupChart($('#chart-jobs')), cpu: setupChart($('#chart-cpu')), busy: setupChart($('#chart-busy')), ram: setupChart($('#chart-ram')) };
    const m = state.metrics || {};
    assignHostColors();
    const t = m.t || [];
    const step = m.step_secs || 60;
    const hosts = m.hosts || [];  // sorted by name
    const hostSeries = (x) => ({ name: x.name || x.id, color: hostColor(x.id) });
    const pctTick = (v) => `${v}%`;
    const intTick = (v) => (Number.isInteger(v) ? String(v) : v.toFixed(1));
    const fmtAvg = (v) => (isNum(v) ? (v >= 10 || Number.isInteger(v) ? String(Math.round(v)) : v.toFixed(1)) : '—');
    const kCol = groupOf(t.length, COLUMN_COUNT), kLine = groupOf(t.length, LINE_POINTS);

    const jg = regroup(t, step, kCol, [m.running || [], m.queued || []]);
    const jobs = [
      { name: 'Running', color: 'var(--s1)', values: jg.series[0] },
      { name: 'Queued', color: 'var(--s2)', values: jg.series[1] },
    ];
    setChart(chartRefs.jobs, {
      kind: 'columns', t: jg.t, step: jg.step, series: jobs, integer: true, fmtVal: fmtAvg, fmtTick: intTick,
      summary: summarize('Jobs running and queued', jobs, fmtAvg),
    });
    $('#jobs-sub').textContent = jg.step > step ? `Average per ${per(jg.step)}, stacked` : 'Running and queued, stacked';

    const cg = regroup(t, step, kLine, hosts.map((x) => x.cpu || []));
    const cpu = hosts.map((x, k) => ({ ...hostSeries(x), values: cg.series[k] }));
    setChart(chartRefs.cpu, { kind: 'strips', t: cg.t, step: cg.step, series: cpu, yMax: 100, fmtVal: fmtPct, fmtTick: pctTick, summary: summarize('CPU per machine', cpu, fmtPct) });
    $('#cpu-sub').textContent = cg.step > step ? `A row per machine · average per ${per(cg.step)}` : 'A row per machine';

    const bg = regroup(t, step, kCol, [...hosts.map((x) => x.busy || []), ...hosts.map((x) => x.slots || [])]);
    const busy = hosts.map((x, k) => {
      const values = bg.series[k], slots = bg.series[hosts.length + k];
      return { ...hostSeries(x), values, fmtAt: (i) => (isNum(values[i]) ? `${fmtAvg(values[i])}${isNum(slots[i]) ? ` / ${fmtAvg(slots[i])}` : ''}` : '—') };
    });
    setChart(chartRefs.busy, {
      kind: 'columns', t: bg.t, step: bg.step, series: busy, integer: true, fmtVal: fmtAvg, fmtTick: intTick, summary: summarize('Busy runner slots per machine, stacked', busy, fmtAvg),
      total: (i) => {
        const sum = busy.reduce((a, sr) => a + (isNum(sr.values[i]) ? sr.values[i] : 0), 0);
        return h('div', { class: 'tip-row tip-total' }, h('span', { class: 'tip-key tip-key-none' }), h('b', { class: 'num', text: fmtAvg(sum) }), h('span', { class: 'tip-name', text: 'Total busy' }));
      },
    });
    $('#busy-sub').textContent = bg.step > step ? `Average per ${per(bg.step)}, stacked per machine` : 'Stacked per machine';

    const rg = regroup(t, step, kLine, [...hosts.map(ramPct), ...hosts.map((x) => x.ram_used || [])]);
    const ram = hosts.map((x, k) => {
      const values = rg.series[k], used = rg.series[hosts.length + k];
      return { ...hostSeries(x), values, fmtAt: (i) => (isNum(values[i]) ? `${fmtPct(values[i])} · ${fmtBytes(used[i])}` : '—') };
    });
    setChart(chartRefs.ram, { kind: 'lines', t: rg.t, step: rg.step, series: ram, yMax: 100, fmtVal: fmtPct, fmtTick: pctTick, summary: summarize('Memory used per machine', ram, fmtPct) });
    $('#ram-sub').textContent = rg.step > step ? `Used per machine · average per ${per(rg.step)}` : 'Used per machine';

    $('#charts-sub').textContent = m.step_secs ? `${RANGE_LABEL[state.range]} · ${m.step_secs % 60 ? `${m.step_secs}s` : `${m.step_secs / 60} min`} samples` : RANGE_LABEL[state.range];
  }

  function buildRangeSwitch() {
    const box = $('#range');
    box.replaceChildren(...RANGES.map((r) => h('button', {
      type: 'button', class: 'seg-btn', 'aria-pressed': String(r === state.range), 'data-range': r, text: r,
      'aria-label': `Show ${RANGE_LABEL[r]}`,
      onclick: () => {
        if (r === state.range) return;
        state.range = r; saveRange(r);
        $$('.seg-btn', box).forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.range === r)));
        $('#charts-sub').textContent = RANGE_LABEL[r];
        loadMetrics();
      },
    })));
  }

  // ======================================================== remote commands
  // The coordinator relays `runner-manager` argv to a machine; the machine
  // decides what it runs. Nothing here is updated before the machine confirms:
  // every change is followed by a fresh read of its configuration.
  const AUDIT_MS = 15000;
  const MANAGE_MIN = '0.4.61';
  const ALLOW_CMD = 'runner-manager coordinator remote-changes allow';
  const OS_TOKEN = { linux: 'linux', windows: 'win', macos: 'osx' };
  const ARCH_TOKEN = { x64: 'x64', x86_64: 'x64', amd64: 'x64', arm64: 'arm64', aarch64: 'arm64', arm: 'arm' };
  const POLICY_STATE = { active: 'ok', pending: 'dim', draining: 'warn', disabled: 'dim', repair_required: 'err', authentication_failed: 'err' };
  const ERR_HINT = {
    0: 'The coordinator could not be reached.',
    400: 'The coordinator did not accept this command.',
    403: 'The coordinator refused a change from this page.',
    409: `This machine runs a runner-manager older than ${MANAGE_MIN}, which cannot take commands from the coordinator. Update it there, then try again.`,
    502: 'The machine could not carry out the request.',
    503: 'This machine is offline. Try again once it reconnects.',
    504: 'The machine did not answer in time.',
  };
  // Reads the panel itself makes; the activity log hides them unless asked.
  // The host says what each command was; one it refused unjudged counts as a change attempt.
  const isRead = (c) => c.access === 'read';

  const shq = (a) => (/^[A-Za-z0-9_\-.,/:=@%+]+$/.test(String(a)) ? String(a) : `'${String(a).replace(/'/g, `'\\''`)}'`);
  const cmdLine = (argv) => ['runner-manager', ...(argv || []).map(shq)].join(' ');
  const isDefault = (p) => !p.profile || p.profile === 'default';
  const policyKey = (p) => `${p.repository}#${p.profile || 'default'}`;
  // A named profile is changed through `repo profile <verb> --profile NAME`.
  const repoArgv = (p, verb, ...rest) => (isDefault(p)
    ? ['repo', verb, p.repository, ...rest]
    : ['repo', 'profile', verb, p.repository, '--profile', p.profile, ...rest]);
  const hostById = (id) => ((state.ov && state.ov.hosts) || []).find((x) => x.id === id) || null;
  const trimEnd = (t) => String(t || '').replace(/\s+$/, '');
  const capWord = (w) => (w ? w[0].toUpperCase() + w.slice(1) : w);

  function icon(d, size, extra) {
    return s('svg', { viewBox: '0 0 20 20', width: size || 14, height: size || 14, 'aria-hidden': 'true', class: extra || null },
      s('path', { fill: 'none', stroke: 'currentColor', 'stroke-width': 1.7, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', d }));
  }
  const xIcon = (n) => icon('M5.5 5.5l9 9M14.5 5.5l-9 9', n);
  const plusIcon = () => icon('M10 4.5v11M4.5 10h11', 14);
  const lockIcon = () => icon('M6 9V7a4 4 0 0 1 8 0v2M5.5 9h9a1 1 0 0 1 1 1v5.5a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1V10a1 1 0 0 1 1-1z', 11);
  const extIcon = () => icon('M8 5H5.5A1.5 1.5 0 0 0 4 6.5v8A1.5 1.5 0 0 0 5.5 16h8a1.5 1.5 0 0 0 1.5-1.5V12M11 4h5v5M16 4l-7 7', 12, 'ext');
  const copyIcon = () => icon('M7.5 7.5V5A1.5 1.5 0 0 1 9 3.5h6A1.5 1.5 0 0 1 16.5 5v6a1.5 1.5 0 0 1-1.5 1.5h-2.5M5 7.5h6A1.5 1.5 0 0 1 12.5 9v6a1.5 1.5 0 0 1-1.5 1.5H5A1.5 1.5 0 0 1 3.5 15V9A1.5 1.5 0 0 1 5 7.5z', 14);

  // fetch, with the error body kept: these endpoints explain their failures.
  async function call(path, opts = {}) {
    let res;
    try {
      res = await fetch(path, { credentials: 'same-origin', cache: 'no-store', ...opts, headers: { Accept: 'application/json', ...(opts.headers || {}) } });
    } catch (_) {
      return { ok: false, status: 0, hint: ERR_HINT[0], error: '' };
    }
    if (res.status === 401) { showLogin(); return { ok: false, status: 401, hint: 'Your session ended.', error: '' }; }
    let body = null;
    try { body = await res.json(); } catch (_) { /* empty or not JSON */ }
    if (res.ok) return { ok: true, status: res.status, body };
    return { ok: false, status: res.status, hint: ERR_HINT[res.status] || null, error: (body && body.error) || `HTTP ${res.status}` };
  }

  function invalid(input, msg) {
    input.setCustomValidity(msg);
    input.reportValidity();
    input.addEventListener('input', () => input.setCustomValidity(''), { once: true });
  }

  function accessChip(x, rc) {
    if (!x) return null;
    if (!x.manageable) return x.online ? h('span', { class: 'access access-old', title: `runner-manager on this machine is older than ${MANAGE_MIN}`, text: 'Update needed' }) : null;
    return rc
      ? h('span', { class: 'access access-managed', title: 'Changes through the coordinator are allowed', text: 'Managed' })
      : h('span', { class: 'access access-ro', title: 'Its operator has not allowed changes through the coordinator' }, lockIcon(), 'Read-only');
  }

  // ------------------------------------------------------------- versions
  // `X.Y.Z`, or a local build's `X.Y.Z+git.<sha>`, by its `X.Y.Z`.
  function verParts(v) {
    const m = /^(\d+)\.(\d+)\.(\d+)/.exec(String(v || ''));
    return m ? [+m[1], +m[2], +m[3]] : null;
  }
  function cmpVer(a, b) {
    const x = verParts(a), y = verParts(b);
    if (!x || !y) return 0;
    for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
    return 0;
  }
  // The newest release the coordinator knows of: its own build, or the one its updater saw published.
  function newestRelease() {
    const ov = state.ov || {};
    const latest = ov.update && ov.update.latest;
    return latest && cmpVer(latest, ov.version) > 0 ? latest : ov.version || null;
  }
  // The one word on a machine's runner-manager, and its badge colour.
  function versionState(v) {
    const u = v.update;
    if (u && u.state === 'running') return { cls: 'dim', text: 'Updating…' };
    if (v.app && cmpVer(v.app, v.service) > 0) return { cls: 'warn', text: `Restarts into v${v.app} after its jobs` };
    if (u && u.state === 'failed') return { cls: 'err', text: 'Update failed' };
    const newest = newestRelease();
    if (newest && cmpVer(v.app || v.service, newest) < 0) return { cls: 'warn', text: `v${newest} available` };
    return null;
  }
  // The Windows machine a WSL host runs on: WSL keeps the Windows computer name by default.
  function wslParent(x) {
    const name = String(x.hostname || '').toLowerCase();
    if (!name) return null;
    return ((state.ov && state.ov.hosts) || []).find((y) => y.id !== x.id && y.versions && (y.versions.wsl || []).length
      && String(y.hostname || '').toLowerCase() === name) || null;
  }

  // The service a managed WSL distribution runs, from its own host: what
  // `wsl install` last put there (the record) is stale once it updates
  // itself. Only when this machine manages one distribution and one WSL host
  // shares its name, so the match is not a guess.
  function wslVersion(x) {
    const v = x.versions;
    if (!v || (v.wsl || []).length !== 1) return null;
    const name = String(x.hostname || '').toLowerCase();
    const guests = ((state.ov && state.ov.hosts) || []).filter((y) => y.id !== x.id && y.versions && y.versions.wsl_guest
      && String(y.hostname || '').toLowerCase() === name);
    return guests.length === 1 && guests[0].versions.service ? guests[0].versions.service : null;
  }

  function versionLine(x) {
    const v = x.versions;
    if (!v) return x.online ? h('p', { class: 'host-ver', title: 'Machines report their versions from runner-manager 0.4.64' }, h('span', { class: 'muted', text: justConnected(x) ? 'Reading versions…' : 'Version unknown (before 0.4.64)' })) : null;
    const st = versionState(v);
    const appDiffers = v.app && v.app !== v.service;
    const live = wslVersion(x);
    return h('p', { class: 'host-ver' },
      v.wsl_guest ? h('span', { class: 'badge badge-dim', title: 'Runs inside a WSL distribution of a Windows machine', text: 'WSL' }) : null,
      h('span', { title: 'The build the service runs' }, 'Service ', h('b', { class: 'num', text: `v${v.service}` })),
      appDiffers ? h('span', { title: `The installed app the service upgrades from${v.app_source ? ` (${v.app_source})` : ''}` }, 'App ', h('b', { class: 'num', text: `v${v.app}` })) : null,
      (v.wsl || []).map((w) => h('span', { title: live ? `WSL ${w.distribution}: the service its own host runs` : `WSL ${w.distribution}: the runner-manager this machine last installed in it` },
        `WSL ${w.distribution} `, h('b', { class: 'num', text: `v${live || w.installed_version}` }))),
      st ? h('span', { class: `badge badge-${st.cls}`, text: st.text }) : null);
  }

  // Connected so recently that its first heartbeat may still be on its way.
  const justConnected = (x) => isNum(x.connected_since) && serverNow() - x.connected_since < 60;
  // After an Update click, until the host reports an update started at or after it.
  function awaitingUpdate(x) {
    if (!dw.updateSent || dw.updateSent.id !== (x && x.id)) return false;
    const u = x.versions && x.versions.update;
    if ((u && u.at >= dw.updateSent.at - 5) || serverNow() - dw.updateSent.at > 120) { dw.updateSent = null; return false; }
    return true;
  }
  function versionSig(x) {
    const p = x && x.versions && x.versions.wsl_guest ? wslParent(x) : null;
    return JSON.stringify(x && [x.online, x.manageable, x.remote_changes, x.versions, newestRelease(), awaitingUpdate(x), p && (p.name || p.hostname), !x.versions && justConnected(x)]);
  }

  function versionCard(x) {
    const v = x && x.versions;
    const row = (label, value, note) => h('div', { class: 'ver-row' },
      h('dt', { text: label }), h('dd', {}, h('b', { class: 'num', text: value ? `v${value}` : '—' }), note ? h('span', { class: 'muted', text: ` ${note}` }) : null));
    const parent = v && v.wsl_guest ? wslParent(x) : null;
    const waiting = awaitingUpdate(x);
    const u = v && !waiting ? v.update : null;
    const busy = dw.busy.has('update') || waiting || (u && u.state === 'running');
    const can = !!(x && x.online && x.manageable && x.remote_changes && v && v.updatable);
    let hint;
    if (!x || !x.online) hint = 'Shown while the machine is connected.';
    else if (!v) hint = justConnected(x) ? 'Reading this machine’s versions…' : 'This machine runs a runner-manager older than 0.4.64, which does not report its versions or take updates from here. Update it on the machine once.';
    else if (!x.remote_changes) hint = 'Updating from here needs changes through the coordinator allowed on the machine.';
    else if (!v.updatable) hint = `Its app is ${v.app_source || 'not known'}, which the service cannot update. Update it on the machine.`;
    else hint = 'Update installs the newest release the way the app was installed. The service finishes its running jobs first, then restarts into it.';
    const st = v ? versionState(v) : null;
    return h('section', { class: 'card dw-card', 'data-key': 'update', 'data-sig': versionSig(x), 'aria-labelledby': 'dw-h-ver' },
      h('fieldset', { class: 'fs', disabled: busy || null },
        h('div', { class: 'cap-row' },
          h('div', { class: 'cap-text' },
            h('h3', { id: 'dw-h-ver', class: 'cap-title' }, 'runner-manager ', st ? h('span', { class: `badge badge-${st.cls}`, text: st.text }) : null),
            h('p', { class: 'cap-hint', text: hint })),
          can ? h('button', {
            type: 'button', class: 'btn-sm btn-primary', 'data-fk': 'update', 'aria-busy': busy ? 'true' : null,
            text: busy ? 'Updating…' : 'Update',
            onclick: (e) => run('update', ['update'], e.currentTarget),
          }) : null),
        v ? h('dl', { class: 'ver-list' },
          row('Service', v.service, 'running now'),
          row('App', v.app, v.app_source ? `· ${v.app_source}` : null),
          (v.wsl || []).map((w) => {
            const live = wslVersion(x);
            return live ? row(`WSL ${w.distribution}`, live, '· its own host’s service; updated through that host')
              : row(`WSL ${w.distribution}`, w.installed_version, '· installed by this machine; updated through its own host');
          }),
          parent ? h('div', { class: 'ver-row' }, h('dt', { text: 'Runs on' }), h('dd', { text: `${parent.name || parent.hostname} (WSL)` })) : null) : null,
        u ? h('p', { class: `ver-progress ${u.state === 'failed' ? 'text-err' : 'muted'}` },
          u.state === 'running' ? 'Update started ' : u.state === 'failed' ? 'Update failed ' : 'Update finished ', ago(u.at), u.message ? ` · ${u.message}` : '') : null),
      resultNote('update'));
  }

  // Heartbeats bring the versions and an update's progress: the card follows them.
  function refreshVersionCard() {
    if (!dw.id || dw.busy.has('update')) return;
    const old = $('[data-key="update"]', $('#dw-body'));
    if (!old) return;
    const x = hostById(dw.id);
    if (old.dataset.sig === versionSig(x)) return;
    const had = old.contains(document.activeElement);
    const card = versionCard(x);
    old.replaceWith(card);
    if (!had) return;
    const b = $('[data-fk="update"]', card), note = $('[data-result="update"]', card);
    const target = b && !b.closest('fieldset:disabled') ? b : note || $('#dw-body');
    target.focus({ preventScroll: true });
  }

  // ------------------------------------------------------------ audit log
  function buildAuditControls() {
    $('#audit-filter').replaceChildren(...[['changes', 'Changes'], ['all', 'All']].map(([v, t]) => h('button', {
      type: 'button', class: 'seg-btn', 'data-v': v, text: t, 'aria-pressed': String((v === 'all') === state.auditAll),
      onclick: () => { state.auditAll = v === 'all'; saveFlag('rm.audit.all', state.auditAll); renderAudit(true); },
    })));
    $('#audit-toggle').addEventListener('click', () => {
      state.auditOpen = !state.auditOpen; saveFlag('rm.audit.open', state.auditOpen);
      renderAudit(true);
      if (state.auditOpen) loadAudit(); else clearTimeout(state.timers.audit);
    });
  }

  async function loadAudit() {
    clearTimeout(state.timers.audit);
    const r = await call('/api/audit');
    if (r.status === 401) return;
    if (r.ok) { state.audit = Array.isArray(r.body && r.body.commands) ? r.body.commands : []; state.auditErr = null; }
    else state.auditErr = r.status === 404 ? 'gone' : (r.hint || r.error);
    renderAudit();
    if (polling() && state.auditOpen) state.timers.audit = setTimeout(loadAudit, AUDIT_MS);
  }

  function outcomeBadge(o) {
    const m = /^exit (\d+)$/.exec(o || '');
    if (m) {
      return m[1] === '0'
        ? h('span', { class: 'badge badge-ok' }, h('span', { 'aria-hidden': 'true', text: '✓' }), 'ok')
        : h('span', { class: 'badge badge-err' }, h('span', { 'aria-hidden': 'true', text: '✕' }), `exit ${m[1]}`);
    }
    const [kind, label] = { offline: ['warn', 'offline'], too_old: ['warn', 'too old'], timeout: ['err', 'timed out'], malformed: ['err', 'malformed'] }[o] || ['dim', humanize(o || 'unknown')];
    return h('span', { class: `badge badge-${kind}`, text: label });
  }
  // Each argument is one unit, so a line breaks between arguments, never inside `--flag`.
  const cmdCode = (argv) => h('code', { class: 'cmd' }, h('span', { class: 'cmd-tok cmd-pfx', text: 'runner-manager' }),
    (argv || []).map((x) => [' ', h('span', { class: 'cmd-tok', text: shq(x) })]));

  function renderAudit(force) {
    const sec = $('#audit-section');
    if (state.auditErr === 'gone') { sec.hidden = true; return; }
    if (!state.audit && !state.auditErr) return;  // first load still on its way
    sec.hidden = false;
    const all = state.audit || [];
    const list = state.auditAll ? all : all.filter((c) => !isRead(c));
    const sig = JSON.stringify([all, state.auditAll, state.auditOpen, state.showAllAudit, state.auditErr]);
    if (!force && sig === state.auditSig) return;
    state.auditSig = sig;
    sec.classList.toggle('is-collapsed', !state.auditOpen);
    $('#audit-count').textContent = list.length ? String(list.length) : '';
    const tog = $('#audit-toggle');
    tog.textContent = state.auditOpen ? 'Hide' : 'Show';
    tog.setAttribute('aria-expanded', String(state.auditOpen));
    $('#audit-filter').hidden = !state.auditOpen;
    $$('.seg-btn', $('#audit-filter')).forEach((b) => b.setAttribute('aria-pressed', String((b.dataset.v === 'all') === state.auditAll)));
    const box = $('#audit');
    box.hidden = !state.auditOpen;
    if (!state.auditOpen) return;
    const LIMIT = 15;
    const shown = state.showAllAudit ? list : list.slice(0, LIMIT);
    const reads = all.length - list.length;
    box.replaceChildren(...[
      state.auditErr ? h('p', { class: 'notice notice-warn', role: 'status', text: `The log could not be refreshed. ${state.auditErr}` }) : null,
      shown.length
        ? table('Commands run on machines through the coordinator', [['Result'], ['Command'], ['Machine'], ['By'], ['When', 'c-num']], shown.map((c) => h('tr', {},
          td('Result', 'c-result', outcomeBadge(c.outcome)),
          td('Command', 'c-cmd', cmdCode(c.argv)),
          td('Machine', 'c-machine', machine(c.host_id, c.host_name || hostName(c.host_id, c.host_id))),
          td('By', 'c-who', h('span', { text: c.login || '—' })),
          td('When', 'c-num c-when', ago(c.at, 'muted')))))
        : empty(all.length ? 'No changes yet' : 'No remote commands yet',
          reads ? `${reads} read${reads === 1 ? '' : 's'} hidden. Choose All to see them.` : 'Changes made from a machine’s panel are recorded here.'),
      list.length > LIMIT ? h('div', { class: 'tbl-more' }, h('button', {
        type: 'button', class: 'link-btn', 'aria-expanded': String(state.showAllAudit), text: state.showAllAudit ? 'Show fewer' : `Show all ${list.length}`,
        onclick: () => { state.showAllAudit = !state.showAllAudit; renderAudit(true); },
      })) : null,
    ].filter(Boolean));
  }

  // --------------------------------------------------------- machine panel
  const dw = {
    id: null, gen: 0, pushed: false, sig: '',
    cfg: null, rc: null, loading: false, error: null, cfgSeq: 0,
    results: new Map(), busy: new Set(), add: null, confirm: null, updateSent: null,
  };

  function hashHost() {
    const m = /^#host=(.+)$/.exec(location.hash);
    if (!m) return null;
    try { return decodeURIComponent(m[1]); } catch (_) { return null; }
  }

  function setupDrawer() {
    const dlg = $('#drawer');
    $('#dw-close').addEventListener('click', () => closeDrawer());
    dlg.addEventListener('cancel', (e) => { e.preventDefault(); closeDrawer(); });
    dlg.addEventListener('close', () => { if (dw.id) closeDrawer(); });
    dlg.addEventListener('click', (e) => { if (e.target === dlg) closeDrawer(); });
    dlg.addEventListener('keydown', trapTab);
    window.addEventListener('hashchange', () => {
      const id = hashHost();
      if (id) { if (!$('#app').hidden) openDrawer(id, true); } else if (dw.id) closeDrawer(true);
    });
    // The card's name is a link (Enter); Space opens it too, as on a button.
    $('#hosts').addEventListener('keydown', (e) => {
      if (e.key === ' ' && e.target.classList && e.target.classList.contains('host-open')) { e.preventDefault(); e.target.click(); }
    });
  }

  function trapTab(e) {
    if (e.key !== 'Tab') return;
    const dlg = $('#drawer');
    const f = $$('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])', dlg)
      .filter((el) => !el.disabled && !el.closest('fieldset:disabled') && (el.checkVisibility ? el.checkVisibility({ visibilityProperty: true }) : el.getClientRects().length));
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (e.shiftKey && (document.activeElement === first || !dlg.contains(document.activeElement))) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && (document.activeElement === last || !dlg.contains(document.activeElement))) { e.preventDefault(); first.focus(); }
  }

  function openDrawer(id, pushed) {
    const dlg = $('#drawer');
    if (dlg.open && dw.id === id) return;
    if (!dlg.open) dw.pushed = !!pushed;
    dw.id = id; dw.gen++;
    Object.assign(dw, { sig: '', cfg: null, rc: null, loading: false, error: null, add: null, confirm: null });
    dw.results.clear(); dw.busy.clear();
    renderDrawerHead();
    const x = hostById(id);
    if (!state.ov || (x && x.manageable)) loadConfig(); else renderDrawerBody();
    if (!dlg.open) { dlg.showModal(); document.documentElement.classList.add('has-drawer'); }
    $('#dw-body').scrollTop = 0;
    $('#dw-close').focus();
  }

  function closeDrawer(fromHash) {
    if (!dw.id) return;
    if (!fromHash) {
      // Opened by a click: step back so Back does not reopen it.
      if (dw.pushed) { history.back(); return; }
      history.replaceState(null, '', location.pathname + location.search);
    }
    const id = dw.id;
    dw.id = null; dw.gen++;
    const dlg = $('#drawer');
    if (dlg.open) dlg.close();
    document.documentElement.classList.remove('has-drawer');
    const link = $(`.host-open[data-host="${CSS.escape(id)}"]`);
    if (link) link.focus();
  }

  // Overview polls refresh the header; the body is only rebuilt when the
  // machine's reachability or permission actually changed.
  function syncDrawer() {
    if (!dw.id) return;
    const before = dw.sig;
    renderDrawerHead();
    refreshVersionCard();
    if (dw.sig === before) return;
    const x = hostById(dw.id);
    if (x && x.manageable && !dw.loading && !dw.busy.size && (!dw.cfg || dw.rc !== !!x.remote_changes)) loadConfig({ quiet: !!dw.cfg });
    else if (!dw.cfg && !dw.loading) renderDrawerBody();
  }

  function renderDrawerHead() {
    if (!dw.id) return;
    const x = hostById(dw.id);
    const doc = dw.cfg && dw.cfg.config;
    const name = (x && (x.name || x.hostname)) || (doc && doc.host && doc.host.name) || 'Machine';
    const rc = dw.rc != null ? dw.rc : !!(x && x.remote_changes);
    const sig = JSON.stringify([name, !!state.ov, x && [x.hostname, x.os, x.arch, x.online, x.unfit, x.draining, !!x.manageable, !!x.remote_changes], dw.rc]);
    if (sig === dw.sig) return;
    dw.sig = sig;
    $('#dw-title').textContent = name;
    $('#dw-dot').style.setProperty('--c', hostColor(dw.id));
    const sub = $('#dw-sub');
    if (x) {
      const st = hostStatus(x);
      const os = String(x.os || '').toLowerCase();
      const extra = [x.hostname && x.hostname !== name ? x.hostname : null, x.arch, isNum(x.cores) ? `${x.cores} cores` : null].filter(Boolean).join(' · ');
      sub.replaceChildren(...[
        h('span', { class: `os os-${os || 'unknown'}`, text: OS_NAME[os] || os || 'unknown' }),
        h('span', { class: `status status-${st.key}` }, h('i', { 'aria-hidden': 'true' }), st.label),
        x.online ? accessChip(x, rc) : null,
        extra ? h('span', { text: extra }) : null,
      ].filter(Boolean));
    } else sub.replaceChildren();
    const box = $('#dw-access');
    const note = accessNotice(x, rc);
    box.replaceChildren(...(note ? [note] : []));
    box.hidden = !note;
  }

  function accessNotice(x, rc) {
    const note = (kind, title, text) => h('div', { class: `access-note${kind ? ` is-${kind}` : ''}` }, h('strong', { text: title }), h('p', { text }));
    if (!x) return state.ov ? note('', 'Unknown machine', 'The coordinator has no machine with this id. It may have been removed.') : null;
    if (!x.online) return note('', 'Offline', 'This machine is not connected. Its repositories can be read and changed once it reconnects.');
    if (!x.manageable) return note('warn', 'Update needed', `This machine runs a runner-manager older than ${MANAGE_MIN}, which cannot take commands from the coordinator. Update it on the machine to see and change its repositories here.`);
    if (rc) return null;
    const linux = String(x.os || '').toLowerCase() === 'linux';
    return h('div', { class: 'access-note' },
      h('strong', {}, lockIcon(), 'Read-only'),
      h('p', { text: 'This machine’s operator has not allowed changes through the coordinator. To allow them, run this on the machine:' }),
      codeRow(ALLOW_CMD),
      linux ? h('p', { class: 'access-sub', text: 'Installed as a boot service? Run it with sudo:' }) : null,
      linux ? codeRow(`sudo ${ALLOW_CMD}`) : null);
  }

  function codeRow(text) {
    const code = h('code', { text });
    const label = h('span', { text: 'Copy' });
    const btn = h('button', { type: 'button', class: 'btn-sm copy-btn', 'aria-label': `Copy ${text}` }, copyIcon(), label);
    btn.addEventListener('click', async () => {
      let ok = false;
      try { await navigator.clipboard.writeText(text); ok = true; } catch (_) {
        const r = document.createRange(); r.selectNodeContents(code);
        const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r);
        try { ok = document.execCommand('copy'); } catch (__) { ok = false; }
      }
      label.textContent = ok ? 'Copied' : 'Selected';
      btn.classList.toggle('is-done', ok);
      setTimeout(() => { label.textContent = 'Copy'; btn.classList.remove('is-done'); }, 1800);
    });
    return h('div', { class: 'code-row' }, code, btn);
  }

  async function loadConfig(opts = {}) {
    if (!dw.id) return;
    const id = dw.id, gen = dw.gen, seq = ++dw.cfgSeq;
    dw.loading = true;
    if (!opts.quiet) { dw.error = null; if (!dw.cfg) renderDrawerBody(); }
    const r = await call(`/api/hosts/${encodeURIComponent(id)}/config`);
    if (gen !== dw.gen || seq !== dw.cfgSeq) return;
    dw.loading = false;
    if (r.ok && r.body && r.body.config && typeof r.body.config === 'object') {
      dw.cfg = r.body; dw.rc = r.body.remote_changes === true; dw.error = null;
    } else if (r.status !== 401) {
      dw.error = r.ok ? { hint: 'The machine’s answer was not understood.', error: '' } : r;
    }
    renderDrawerHead();
    if (opts.render !== false) renderDrawerBody();
  }

  function renderDrawerBody() {
    if (!dw.id) return;
    const x = hostById(dw.id);
    let view;
    if (dw.cfg) view = configView(x);
    else if (dw.loading) view = skeleton();
    else if (dw.error) view = errorPanel(dw.error);
    else view = unavailablePanel(x);
    $('#dw-body').replaceChildren(view);
  }

  function skeleton() {
    const line = (w) => h('span', { class: `sk ${w}` });
    const card = (...ws) => h('div', { class: 'card sk-card' }, ws.map(line));
    return h('div', { class: 'dw-stack', 'aria-busy': 'true' },
      h('p', { class: 'sr-only', role: 'status', text: 'Reading this machine’s repositories…' }),
      card('w30', 'w60'),
      h('div', { class: 'dw-section' }, h('span', { class: 'sk w20 sk-head' }),
        h('div', { class: 'repos' }, card('w50', 'w70', 'w40', 'w60'), card('w40', 'w60', 'w30'), card('w50', 'w70', 'w40'))));
  }

  function errorPanel(err) {
    return h('div', { class: 'card dw-msg', role: 'alert' },
      h('p', { class: 'dw-msg-title', text: 'Could not read this machine’s repositories' }),
      err.hint ? h('p', { class: 'dw-msg-text', text: err.hint }) : null,
      err.error ? h('pre', { class: 'result-pre', text: err.error }) : null,
      h('div', {}, h('button', { type: 'button', class: 'btn-sm', 'data-fk': 'retry', text: 'Retry', onclick: () => loadConfig() })));
  }

  function unavailablePanel(x) {
    // The header already says why; this only says what is missing.
    const [title, text] = !x ? ['Machine not found', 'Check the link, or open a machine from the Machines list.']
      : ['No repositories to show', 'They are read from the machine itself.'];
    return h('div', { class: 'card dw-msg dw-msg-center' },
      h('span', { class: 'empty-icon', 'aria-hidden': 'true' }),
      h('p', { class: 'dw-msg-title', text: title }),
      h('p', { class: 'dw-msg-text', text }),
      x ? h('div', {}, h('button', { type: 'button', class: 'btn-sm', 'data-fk': 'retry', text: 'Try anyway', onclick: () => loadConfig() })) : null);
  }

  function configView(x) {
    const doc = dw.cfg.config || {};
    const can = dw.rc === true;
    const pols = (Array.isArray(doc.policies) ? doc.policies : []).filter((p) => p && p.repository);
    const groups = [];
    for (const p of pols) {
      let g = groups.find((y) => y.repo === p.repository);
      if (!g) groups.push(g = { repo: p.repository, items: [] });
      g.items.push(p);
    }
    const known = new Set(pols.map(policyKey));
    // Results whose control is gone: a removed policy, or the add form once it closed.
    const orphans = [...dw.results.keys()].filter((k) => (k === 'add' ? !dw.add : k !== 'host' && k !== 'update' && !known.has(k)));
    return h('div', { class: 'dw-stack' },
      dw.error ? h('div', { class: 'result result-err', role: 'alert' },
        h('span', { class: 'result-icon', 'aria-hidden': 'true', text: '!' }),
        h('p', { class: 'result-msg', text: `Showing the last answer: the machine could not be read again. ${dw.error.hint || ''}` }),
        h('button', { type: 'button', class: 'btn-sm', 'data-fk': 'retry', text: 'Retry', onclick: () => loadConfig() }),
        dw.error.error ? h('pre', { class: 'result-pre', text: dw.error.error }) : null) : null,
      doc.schema_version !== 1 ? h('p', { class: 'notice notice-warn', text: `This machine describes its settings in format ${doc.schema_version}; this page reads format 1, so some details may be missing.` }) : null,
      versionCard(x),
      machineCard(doc.host, can, x),
      h('section', { class: 'dw-section', 'aria-labelledby': 'dw-h-repos' },
        h('div', { class: 'section-head' },
          h('h3', { id: 'dw-h-repos', text: 'Repositories' }),
          h('span', { class: 'count num', text: groups.length ? String(groups.length) : '' }),
          can && !dw.add ? h('button', { type: 'button', class: 'btn-sm', 'data-fk': 'add-open', onclick: openAdd }, plusIcon(), 'Add repository') : null),
        h('div', { class: 'repos' },
          dw.add ? addForm(pols, x) : null,
          orphans.map(resultNote),
          groups.length ? groups.map((g) => repoCard(g, can, x))
            : h('div', { class: 'card' }, empty('No repositories on this machine', can ? 'Add one to start runners for it here.' : 'Repositories added on the machine appear here.')))));
  }

  function machineCard(host, can, x) {
    const capv = host && isNum(host.capacity) ? host.capacity : null;
    const now = x && x.online && isNum(x.busy_slots) ? ` ${x.busy_slots} busy now.` : '';
    return h('section', { class: 'card dw-card', 'data-key': 'host', 'aria-labelledby': 'dw-h-host' },
      h('fieldset', { class: 'fs', disabled: dw.busy.has('host') || null },
        h('div', { class: 'cap-row' },
          h('div', { class: 'cap-text' },
            h('h3', { id: 'dw-h-host', class: 'cap-title', text: 'Runner capacity' }),
            h('p', { class: 'cap-hint', text: host ? `Runners this machine may hold at once, across every repository.${now}` : 'This machine has not recorded its host settings yet.' })),
          !host ? null : can
            ? numberForm('host', 'cap', capv, 'runner capacity', (n) => ['host', 'set-capacity', String(n)])
            : h('span', { class: 'cap-val num', text: capv != null ? String(capv) : '—' }))),
      resultNote('host'));
  }

  function repoCard(g, can, x) {
    const i = g.repo.indexOf('/');
    const owner = i > 0 ? g.repo.slice(0, i + 1) : '', name = i > 0 ? g.repo.slice(i + 1) : g.repo;
    return h('article', { class: 'card repo', 'aria-label': g.repo },
      h('header', { class: 'repo-head' },
        h('a', { class: 'repo-name', href: repoUrl(g.repo), target: '_blank', rel: 'noopener' },
          owner ? h('span', { class: 'repo-owner', text: owner }) : null, name, extIcon(), h('span', { class: 'sr-only', text: ' (opens GitHub)' })),
        g.items.length > 1 ? h('span', { class: 'section-meta', text: `${g.items.length} profiles` }) : null),
      g.items.map((p) => profileBlock(p, can, x)));
  }

  function profileBlock(p, can, x) {
    const key = policyKey(p);
    const desc = isDefault(p) ? p.repository : `${p.repository}, profile ${p.profile}`;
    const st = String(p.state || 'unknown');
    const monitor = p.mode === 'monitor_only';
    return h('div', { class: 'prof', 'data-key': key, role: 'group', 'aria-label': `Profile ${p.profile || 'default'}` },
      h('fieldset', { class: 'fs prof-fs', disabled: dw.busy.has(key) || null },
        h('div', { class: 'prof-head' },
          h('span', { class: `prof-chip${isDefault(p) ? '' : ' is-named'}`, title: 'Profile' }, h('span', { class: 'chip-tag', text: 'profile' }), p.profile || 'default'),
          h('span', { class: `badge badge-${POLICY_STATE[st] || 'dim'}`, title: 'State', text: humanize(st) }),
          h('span', { class: 'spacer' }),
          enableControl(key, p, can, desc)),
        h('dl', { class: 'kv' },
          h('dt', { text: 'Mode' }),
          h('dd', {}, h('span', { class: 'kv-text', text: `${monitor ? 'Monitor only' : 'Autoscale'} · ${p.execution === 'isolated' ? 'isolated' : 'native'} execution` })),
          h('dt', { text: 'Max capacity' }),
          h('dd', {}, can
            ? [numberForm(key, 'cap', p.max_capacity, `max capacity for ${desc}`, (n) => repoArgv(p, 'set-capacity', '--max-capacity', String(n)), '—'),
              monitor ? h('p', { class: 'kv-hint', text: 'Setting one turns on autoscaling.' }) : null]
            : h('span', { class: 'kv-text num', text: isNum(p.max_capacity) ? String(p.max_capacity) : 'Not set' })),
          h('dt', { text: 'Labels' }),
          h('dd', {}, labelsBlock(key, p, can, desc)),
          h('dt', { text: 'Workspace' }),
          h('dd', {}, workspaceBlock(key, p, can, desc, x))),
        can ? removeArea(key, p) : null),
      resultNote(key));
  }

  function enableControl(key, p, can, desc) {
    const on = !!p.enabled;
    if (!can) return h('span', { class: `badge badge-${on ? 'ok' : 'dim'}`, text: on ? 'Enabled' : 'Disabled' });
    return h('button', {
      type: 'button', class: 'switch', role: 'switch', 'aria-checked': String(on), 'aria-label': `Scaling for ${desc}`, 'data-fk': `${key}:enabled`,
      title: on ? 'Disable: start no new runners' : 'Enable: start runners for queued jobs',
      onclick: (e) => run(key, repoArgv(p, 'set-scale', '--enabled', String(!on)), e.currentTarget),
    }, h('span', { class: 'switch-text', text: on ? 'Enabled' : 'Disabled' }), h('span', { class: 'switch-track', 'aria-hidden': 'true' }, h('i')));
  }

  function numberForm(key, field, value, label, toArgv, placeholder) {
    const base = isNum(value) ? String(value) : '';
    const input = h('input', {
      class: 'num-input num', type: 'number', min: 1, max: 65535, step: 1, inputmode: 'numeric', value: base,
      placeholder: placeholder || '', 'aria-label': label, 'data-fk': `${key}:${field}`,
    });
    const save = h('button', { type: 'submit', class: 'btn-sm btn-primary when-dirty', 'data-fk': `${key}:${field}-save`, text: 'Save' });
    const form = h('form', { class: 'inline-form', novalidate: true });
    const sync = () => form.classList.toggle('is-dirty', input.value !== base);
    const bump = (d) => {
      const n = parseInt(input.value, 10);
      input.value = String(clamp((isNum(n) ? n : isNum(value) ? value : 0) + d, 1, 65535));
      input.setCustomValidity('');
      sync();
    };
    input.addEventListener('input', sync);
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const n = Number(input.value);
      if (input.value === '' || !Number.isInteger(n) || n < 1 || n > 65535) return invalid(input, 'Enter a whole number from 1 to 65535.');
      if (String(n) === base) return;
      run(key, toArgv(n), save);
    });
    append(form, [h('span', { class: 'stepper' },
      h('button', { type: 'button', class: 'step-btn', tabindex: -1, 'aria-label': `Decrease ${label}`, onclick: () => bump(-1) }, '−'),
      input,
      h('button', { type: 'button', class: 'step-btn', tabindex: -1, 'aria-label': `Increase ${label}`, onclick: () => bump(1) }, '+')), save]);
    return form;
  }

  function labelsBlock(key, p, can, desc) {
    const extra = Array.isArray(p.labels) ? p.labels : [];
    const chipList = h('span', { class: 'chips' },
      p.host_label ? h('span', { class: 'chip chip-host', title: 'Host label: derived from this machine, always answered, cannot be removed' }, h('span', { class: 'chip-tag', text: 'host' }), p.host_label) : null,
      extra.map((l) => (can && p.host_label
        ? h('span', { class: 'chip chip-x' }, l, h('button', {
          type: 'button', class: 'chip-del', 'aria-label': `Remove label ${l}`, title: 'Remove label', 'data-fk': `${key}:del:${l}`,
          onclick: (e) => run(key, repoArgv(p, 'remove-label', '--label', l), e.currentTarget),
        }, xIcon(12)))
        : chip(l))),
      !p.host_label && !extra.length ? h('span', { class: 'kv-text muted', text: 'None while monitor only' }) : null);
    if (!can || !p.host_label) return chipList;
    const input = h('input', {
      class: 'input input-label mono', type: 'text', placeholder: 'new-label', maxlength: 100, autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false',
      'aria-label': `New label for ${desc}`, 'data-fk': `${key}:label`,
    });
    const btn = h('button', { type: 'submit', class: 'btn-sm', 'data-fk': `${key}:label-add` }, plusIcon(), 'Add');
    const form = h('form', { class: 'inline-form label-form', novalidate: true }, input, btn);
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const v = input.value.trim();
      if (!v) return input.focus();
      if (/[\s,]/.test(v)) return invalid(input, 'One label at a time, without spaces or commas.');
      run(key, repoArgv(p, 'add-label', '--label', v), btn);
    });
    return h('div', { class: 'labels-edit' }, chipList, form);
  }

  function workspaceBlock(key, p, can, desc, x) {
    const w = p.workspace || {};
    const kind = w.kind === 'persistent' ? 'persistent' : 'ephemeral';
    const meta = [w.root_source ? humanize(w.root_source) : null, isNum(w.leases) ? `${w.leases} lease${w.leases === 1 ? '' : 's'}` : null].filter(Boolean).join(' · ');
    // While editing, a persistent root is already in the path field.
    const info = h('div', { class: 'ws-info' },
      can && kind === 'persistent' ? null : h('span', { class: 'mono ws-root', title: w.root || null, text: w.root || '—' }),
      h('span', { class: 'ws-meta' }, meta, w.cleanup_blocked ? h('span', { class: 'text-err', text: ` · ${w.cleanup_blocked} cleanup blocked` }) : null));
    if (!can) return h('div', { class: 'ws' }, h('span', { class: 'kv-text', text: capWord(kind) }), info);
    const win = x && String(x.os || '').toLowerCase() === 'windows';
    const base = kind === 'persistent' ? (w.root || '') : '';
    let sel = kind;
    const path = h('input', {
      class: 'input mono ws-path', type: 'text', value: base, autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false',
      placeholder: win ? 'D:\\runner-work\\repo' : '/srv/runner-work/repo', 'aria-label': `Persistent workspace directory for ${desc}`, 'data-fk': `${key}:ws-path`,
    });
    const save = h('button', { type: 'submit', class: 'btn-sm btn-primary when-dirty', 'data-fk': `${key}:ws-save`, text: 'Apply' });
    const form = h('form', { class: 'ws-form', novalidate: true });
    const seg = h('div', { class: 'seg seg-sm', role: 'group', 'aria-label': `Workspace for ${desc}` },
      ['ephemeral', 'persistent'].map((k) => h('button', {
        type: 'button', class: 'seg-btn', 'data-k': k, 'data-fk': `${key}:ws-${k}`, text: capWord(k),
        onclick: () => { sel = k; sync(); if (k === 'persistent') path.focus(); },
      })));
    const pathRow = h('div', { class: 'ws-path-row' }, path);
    const sync = () => {
      $$('.seg-btn', seg).forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.k === sel)));
      pathRow.hidden = sel !== 'persistent';
      form.classList.toggle('is-dirty', sel !== kind || (sel === 'persistent' && path.value.trim() !== base));
    };
    path.addEventListener('input', sync);
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const v = path.value.trim();
      if (sel === 'persistent' && !v) return invalid(path, 'A persistent workspace needs a directory on the machine.');
      run(key, repoArgv(p, 'set-workspace', '--mode', sel, ...(sel === 'persistent' ? ['--path', v] : [])), save);
    });
    append(form, [h('div', { class: 'ws-row' }, seg, save), pathRow, info]);
    sync();
    return form;
  }

  function removeArea(key, p) {
    const label = isDefault(p) ? 'Remove repository…' : 'Remove profile…';
    if (dw.confirm !== key) {
      return h('div', { class: 'prof-foot' }, h('button', {
        type: 'button', class: 'btn-sm btn-quiet-danger', 'data-fk': `${key}:remove`, text: label,
        onclick: () => { dw.confirm = key; rerenderBlock(key, `${key}:confirm`); },
      }));
    }
    const input = h('input', {
      class: 'input mono', type: 'text', placeholder: p.repository, autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false',
      'aria-label': `Type ${p.repository} to confirm`, 'data-fk': `${key}:confirm`,
    });
    const purge = h('input', { type: 'checkbox' });
    const go = h('button', { type: 'submit', class: 'btn-sm btn-danger', 'data-fk': `${key}:confirm-go`, text: 'Remove', disabled: true });
    const preview = h('code', { class: 'cmd-preview' });
    const argv = () => repoArgv(p, 'remove', ...(purge.checked ? ['--purge'] : []));
    const sync = () => { go.disabled = input.value.trim() !== p.repository; preview.textContent = cmdLine(argv()); };
    const cancel = () => { dw.confirm = null; rerenderBlock(key, `${key}:remove`); };
    input.addEventListener('input', sync);
    purge.addEventListener('change', sync);
    const form = h('form', { class: 'confirm', novalidate: true, 'aria-label': 'Confirm removal' },
      h('p', { class: 'confirm-title', text: isDefault(p) ? 'Remove this repository from the machine?' : `Remove profile ${p.profile}?` }),
      h('p', { class: 'confirm-text' }, 'The machine stops starting runners for ', h('b', { text: p.repository }),
        isDefault(p) ? '' : [' with profile ', h('b', { text: p.profile })], '. Type the repository name to confirm.'),
      input,
      h('label', { class: 'check' }, purge, h('span', {}, 'Also delete its runner package cache and diagnostics (', h('code', { class: 'mono', text: '--purge' }), ')')),
      preview,
      h('div', { class: 'form-actions' }, h('button', { type: 'button', class: 'btn-sm', text: 'Cancel', onclick: cancel }), go));
    form.addEventListener('submit', (e) => { e.preventDefault(); if (!go.disabled) run(key, argv(), go); });
    form.addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); cancel(); } });
    sync();
    return form;
  }

  function findPolicy(key) {
    const pols = (dw.cfg && dw.cfg.config && dw.cfg.config.policies) || [];
    return pols.find((p) => p && policyKey(p) === key) || null;
  }

  function rerenderBlock(key, fk) {
    const p = findPolicy(key);
    const old = $(`[data-key="${CSS.escape(key)}"]`, $('#dw-body'));
    if (!p || !old) { renderDrawerBody(); refocus(fk); return; }
    old.replaceWith(profileBlock(p, dw.rc === true, hostById(dw.id)));
    refocus(fk);
  }

  const canFocus = (el) => el && !el.disabled && (el.checkVisibility ? el.checkVisibility({ visibilityProperty: true }) : el.getClientRects().length > 0);
  function refocus(fk, key, preferResult) {
    const body = $('#dw-body');
    const res = key ? $(`[data-result="${CSS.escape(key)}"]`, body) : null;
    const el = fk ? $(`[data-fk="${CSS.escape(fk)}"]`, body) : null;
    if (preferResult && res) return res.focus();
    if (canFocus(el)) return el.focus();
    if (res) return res.focus();
    body.focus({ preventScroll: true });
  }

  // ----------------------------------------------------------- add form
  function guessHostLabel(pols, x) {
    for (const p of pols) {
      if (!p.host_label) continue;
      let l = String(p.host_label);
      if (!isDefault(p) && l.endsWith(`-${p.profile}`)) l = l.slice(0, -(p.profile.length + 1));
      const m = /^rm-(.+)-(?:linux|win|osx)-(?:x64|arm64|arm)$/.exec(l);
      if (m) return m[1];
    }
    const slug = String((x && (x.name || x.hostname)) || '').toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64);
    return slug || 'host';
  }
  function derivedLabel(hl, x) {
    const os = OS_TOKEN[String((x && x.os) || '').toLowerCase()] || 'os';
    const arch = ARCH_TOKEN[String((x && x.arch) || '').toLowerCase()] || 'arch';
    return `rm-${hl || '…'}-${os}-${arch}`;
  }

  function openAdd() {
    const doc = (dw.cfg && dw.cfg.config) || {};
    dw.add = { repo: '', hostLabel: guessHostLabel(doc.policies || [], hostById(dw.id)), labels: '', cap: '2', enable: false };
    dw.results.delete('add');
    renderDrawerBody();
    refocus('add:repo');
  }

  function addForm(pols, x) {
    const d = dw.add;
    const field = (id, label, input, hint) => h('div', { class: 'field' },
      h('label', { class: 'field-label', for: id, text: label }), input, hint ? h('p', { class: 'field-hint' }, hint) : null);
    const txt = { type: 'text', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false' };
    const repo = h('input', { ...txt, id: 'add-repo', class: 'input mono', value: d.repo, placeholder: 'OWNER/REPO', 'data-fk': 'add:repo' });
    const hl = h('input', { ...txt, id: 'add-hl', class: 'input mono', value: d.hostLabel, maxlength: 64, 'data-fk': 'add:hl' });
    const labels = h('input', { ...txt, id: 'add-labels', class: 'input mono', value: d.labels, placeholder: 'self-hosted, gpu', 'data-fk': 'add:labels' });
    const capIn = h('input', { id: 'add-cap', class: 'input num', type: 'number', min: 1, max: 65535, step: 1, inputmode: 'numeric', value: d.cap, placeholder: 'Monitor only', 'data-fk': 'add:cap' });
    const enable = h('input', { type: 'checkbox', checked: d.enable || null, 'data-fk': 'add:enable' });
    const derived = h('code', { class: 'mono' });
    const preview = h('code', { class: 'cmd-preview' });
    const submit = h('button', { type: 'submit', class: 'btn-sm btn-primary', 'data-fk': 'add:go' }, 'Add repository');
    const extra = () => labels.value.split(/[\s,]+/).filter(Boolean);
    const argv = () => ['repo', 'add', repo.value.trim() || 'OWNER/REPO', '--host-label', hl.value.trim(),
      ...(capIn.value.trim() ? ['--max-capacity', capIn.value.trim()] : []),
      ...extra().flatMap((l) => ['--label', l]),
      ...(enable.checked ? ['--enable'] : [])];
    const sync = () => {
      Object.assign(d, { repo: repo.value, hostLabel: hl.value, labels: labels.value, cap: capIn.value, enable: enable.checked });
      derived.textContent = derivedLabel(hl.value.trim(), x);
      preview.textContent = cmdLine(argv());
    };
    const form = h('form', { class: 'card form', 'data-key': 'add', novalidate: true, 'aria-labelledby': 'add-title' },
      h('fieldset', { class: 'fs form-fs', disabled: dw.busy.has('add') || null },
        h('div', { class: 'form-head' },
          h('h3', { id: 'add-title', class: 'form-title', text: 'Add a repository' }),
          h('p', { class: 'field-hint', text: 'Creates its policy on this machine. Nothing starts until scaling is enabled.' })),
        field('add-repo', 'Repository', repo),
        h('div', { class: 'field-row' },
          field('add-hl', 'Host label', hl, h('span', {}, 'Runners answer ', derived)),
          field('add-cap', 'Max capacity', capIn, 'Empty for monitor only.')),
        field('add-labels', 'Extra labels', labels, 'Optional. Separate with commas or spaces.'),
        h('label', { class: 'check' }, enable, h('span', {}, 'Enable scaling now')),
        preview,
        h('div', { class: 'form-actions' },
          h('button', { type: 'button', class: 'btn-sm', text: 'Cancel', onclick: () => { dw.add = null; dw.results.delete('add'); renderDrawerBody(); refocus('add-open'); } }),
          submit)),
      resultNote('add'));
    form.addEventListener('input', sync);
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const r = repo.value.trim();
      if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(r)) return invalid(repo, 'Enter the repository as OWNER/REPO.');
      if (pols.some((p) => p.repository.toLowerCase() === r.toLowerCase() && isDefault(p))) return invalid(repo, 'This machine already has this repository.');
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(hl.value.trim())) return invalid(hl, 'Letters, digits, - and _ only, up to 64.');
      const c = capIn.value.trim();
      if (c && !(/^\d+$/.test(c) && +c >= 1 && +c <= 65535)) return invalid(capIn, 'A whole number from 1 to 65535, or empty for monitor only.');
      if (!c && extra().length) return invalid(labels, 'Extra labels need a max capacity: a monitor-only policy starts no runner.');
      run('add', argv(), submit);
    });
    sync();
    return form;
  }

  // ---------------------------------------------------------- run + result
  function toResult(r, argv) {
    if (!r.ok) return { ok: false, title: r.hint || 'The command did not reach the machine.', detail: r.error || null, argv };
    const b = r.body || {};
    if (b.exit_code === 0) {
      const out = trimEnd(b.stdout).split('\n').filter((l) => l.trim());
      return { ok: true, title: out[0] || 'Done.', detail: out.slice(1).join('\n') || null, argv, truncated: !!b.truncated };
    }
    return { ok: false, title: `Not changed · exit ${b.exit_code}`, detail: trimEnd(b.stderr) || trimEnd(b.stdout) || 'The machine gave no reason.', argv, truncated: !!b.truncated };
  }

  function resultNote(key) {
    const r = dw.results.get(key);
    if (!r) return null;
    const el = h('div', { class: `result result-${r.ok ? 'ok' : 'err'}`, role: r.ok ? 'status' : 'alert', tabindex: -1, 'data-result': key },
      h('span', { class: 'result-icon', 'aria-hidden': 'true', text: r.ok ? '✓' : '!' }),
      h('p', { class: 'result-msg', text: r.title }),
      h('button', {
        type: 'button', class: 'result-x', 'aria-label': 'Dismiss', title: 'Dismiss',
        onclick: () => { dw.results.delete(key); el.remove(); $('#dw-body').focus({ preventScroll: true }); },
      }, xIcon(14)),
      r.detail ? h('pre', { class: 'result-pre', text: r.detail }) : null,
      r.truncated ? h('p', { class: 'result-cmd', text: 'The output was cut short.' }) : null,
      h('p', { class: 'result-cmd', text: `$ ${cmdLine(r.argv)}` }));
    return el;
  }

  async function run(key, argv, btn) {
    if (!dw.id || dw.busy.has(key)) return;
    const id = dw.id, gen = dw.gen;
    const fk = btn && btn.dataset.fk;
    dw.busy.add(key);
    dw.results.delete(key);
    const block = $(`[data-key="${CSS.escape(key)}"]`, $('#dw-body'));
    if (block) {
      const old = $(':scope > .result', block);
      if (old) old.remove();
      const fs = $('fieldset', block);
      if (fs) fs.disabled = true;
    }
    if (btn) btn.setAttribute('aria-busy', 'true');
    const r = await call(`/api/hosts/${encodeURIComponent(id)}/command`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ argv }),
    });
    if (gen !== dw.gen) return;
    const res = toResult(r, argv);
    dw.results.set(key, res);
    if (res.ok && key === 'update') dw.updateSent = { id, at: serverNow() };
    if (res.ok && key === 'add') dw.add = null;
    if (res.ok && dw.confirm === key) dw.confirm = null;
    if (r.status !== 401) await loadConfig({ quiet: true, render: false });
    if (gen !== dw.gen) return;
    dw.busy.delete(key);
    renderDrawerBody();
    refocus(fk, key, !res.ok);
    loadAudit();
    if (res.ok) loadOverview();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
