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
  };
  const serverNow = () => nowSec() + state.skew;

  function loadRange() {
    try { const r = localStorage.getItem('rm.range'); if (RANGES.includes(r)) return r; } catch (_) { /* storage unavailable */ }
    return '6h';
  }
  function saveRange(r) { try { localStorage.setItem('rm.range', r); } catch (_) { /* ignore */ } }

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
  const jobUrl = (j) => `https://github.com/${j.repository}/actions/runs/${j.run_id}/job/${j.id}`;
  const repoUrl = (r) => `https://github.com/${r}`;
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
    if (location.search) history.replaceState(null, '', '/');
    const u = state.session || {};
    const who = $('#who');
    who.replaceChildren();
    append(who, [
      u.avatar_url ? h('img', { class: 'avatar', src: u.avatar_url, alt: '', width: 28, height: 28, referrerpolicy: 'no-referrer' }) : null,
      h('span', { class: 'who-login', text: u.login || '' }),
    ]);
    who.title = u.login ? `Signed in as ${u.login}` : '';
    startTimers();
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
    state.timers.tick = setInterval(tick, 1000);
  }
  function stopTimers() {
    clearTimeout(state.timers.ov); clearTimeout(state.timers.m); clearInterval(state.timers.tick);
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
  }

  function meterBar(pct, extra) {
    const p = isNum(pct) ? clamp(pct, 0, 100) : 0;
    const level = !isNum(pct) ? 'none' : p >= 95 ? 'err' : p >= 80 ? 'warn' : 'ok';
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
    const runHosts = new Set((ov.running || []).map((j) => j.host_id)).size;
    $('#kpis').replaceChildren(
      kpi('Machines online', h('span', { class: 'num' }, fmtInt(sm.hosts_online), h('small', { text: ` / ${fmtInt(sm.hosts_total)}` }))),
      kpi('Runner slots busy', h('span', { class: 'num' }, fmtInt(sm.slots_busy), h('small', { text: ` / ${fmtInt(sm.slots_total)}` })),
        isNum(pct) ? `${Math.round(pct)}% utilised` : null, meterBar(pct, 'kpi-bar')),
      kpi('Jobs queued', h('span', { class: 'num' }, fmtInt(sm.jobs_queued)),
        oldest ? h('span', {}, 'oldest ', since(oldest.queued_at)) : 'nothing waiting'),
      kpi('Jobs running', h('span', { class: 'num' }, fmtInt(sm.jobs_running)),
        runHosts ? `on ${runHosts} machine${runHosts === 1 ? '' : 's'}` : 'all idle'),
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

  function sparkline(hostId) {
    const m = state.metrics;
    const mh = m && (m.hosts || []).find((x) => x.id === hostId);
    if (!mh || !Array.isArray(mh.cpu) || mh.cpu.length < 2) return h('div', { class: 'spark spark-empty', text: 'No CPU history yet' });
    const n = mh.cpu.length, W = 120, H = 32;
    const pts = mh.cpu.map((v, i) => (isNum(v) ? [(i / (n - 1)) * W, H - (clamp(v, 0, 100) / 100) * (H - 2) - 1] : null));
    const vals = mh.cpu.filter(isNum);
    const peak = vals.length ? Math.max(...vals) : null;
    const avg = vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : null;
    return h('div', { class: 'spark' },
      s('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', role: 'img', 'aria-label': `CPU over the ${RANGE_LABEL[m.range] || m.range}: average ${fmtPct(avg)}, peak ${fmtPct(peak)}` },
        s('path', { class: 'spark-area', d: areaPath(pts, H) }),
        s('path', { class: 'spark-line', d: linePath(pts), 'vector-effect': 'non-scaling-stroke' })),
      h('span', { class: 'spark-cap' }, `CPU · ${m.range}`, h('span', { class: 'num', text: `peak ${fmtPct(peak)}` })));
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
          h('h3', { class: 'host-name', text: x.name || x.hostname || x.id, title: x.hostname || null }),
          h('p', { class: 'host-sub' },
            h('span', { class: `os os-${os || 'unknown'}`, text: OS_NAME[os] || os || 'unknown' }),
            [x.arch, isNum(x.cores) ? `${x.cores} cores` : null].filter(Boolean).join(' · '))),
        h('span', { class: `status status-${st.key}` }, h('i', { 'aria-hidden': 'true' }), st.label)),
      h('div', { class: 'host-meters' },
        meterRow('CPU', x.cpu_load_percent, fmtPct(x.cpu_load_percent)),
        meterRow('Memory', used != null && total ? (used / total) * 100 : null, `${fmtBytes(used)} / ${fmtBytes(total)}`),
        meterRow('Slots', slots ? ((x.busy_slots || 0) / slots) * 100 : null, slots ? `${x.busy_slots || 0} / ${slots}` : '—')),
      sparkline(x.id),
      h('footer', { class: 'host-foot' },
        h('span', {}, 'Disk free ', h('b', { class: 'num', text: fmtBytes(x.disk_free_bytes) })),
        !x.online ? h('span', {}, 'Last seen ', ago(x.last_seen_at))
          : isNum(x.connected_since) ? h('span', {}, 'Up ', since(x.connected_since)) : null));
  }

  function renderHosts(ov) {
    const hosts = ov.hosts || [];  // online first, then by name
    const on = hosts.filter((x) => x.online).length;
    $('#machines-count').textContent = hosts.length ? `${on} of ${hosts.length} online` : '';
    $('#hosts').replaceChildren(...(hosts.length ? hosts.map(hostCard)
      : [empty('No machines enrolled yet', 'Machines appear here once their runner-manager agent connects.')]));
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
    return h('span', { class: 'chips' }, list.map((l) => h('span', { class: `chip${l === 'self-hosted' ? ' chip-dim' : ''}`, text: l })));
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
  function linePath(pts) {
    let d = '', pen = false;
    for (const p of pts) {
      if (!p) { pen = false; continue; }
      d += `${pen ? 'L' : 'M'}${p[0].toFixed(1)} ${p[1].toFixed(1)}`;
      if (!pen) d += 'l0 0';
      pen = true;
    }
    return d;
  }
  // Area under a line down to a fixed baseline, one closed shape per run of values.
  function areaPath(pts, base) {
    return runs(pts.map((p, i) => (p ? i : null))).map(([a, b]) =>
      `M${pts[a][0].toFixed(1)} ${base}` + pts.slice(a, b + 1).map((p) => `L${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join('') + `L${pts[b][0].toFixed(1)} ${base}Z`).join('');
  }
  // Area between two point lists (top over bottom), split into runs where top exists.
  function bandPath(top, bottom) {
    return runs(top.map((p, i) => (p ? i : null))).map(([a, b]) => {
      let d = `M${top[a][0].toFixed(1)} ${top[a][1].toFixed(1)}`;
      for (let i = a + 1; i <= b; i++) d += `L${top[i][0].toFixed(1)} ${top[i][1].toFixed(1)}`;
      for (let i = b; i >= a; i--) d += `L${bottom[i][0].toFixed(1)} ${bottom[i][1].toFixed(1)}`;
      return `${d}Z`;
    }).join('');
  }
  function runs(idx) {
    const out = []; let start = null;
    idx.forEach((v, i) => {
      if (v != null && start == null) start = i;
      if ((v == null || i === idx.length - 1) && start != null) { out.push([start, v == null ? i - 1 : i]); start = null; }
    });
    return out;
  }

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
    const P = { l: narrow ? 30 : 38, r: 8, t: 8, b: 22 };
    const pw = W - P.l - P.r, ph = H - P.t - P.b;
    // Stacked series are drawn from cumulative values; tooltips still read raw ones.
    let tops = cfg.series.map((sr) => sr.values);
    let bases = null;
    if (cfg.stacked) {
      const acc = new Array(n).fill(0);
      const anyAt = t.map((_, i) => cfg.series.some((sr) => isNum(sr.values[i])));
      bases = []; tops = [];
      for (const sr of cfg.series) {
        bases.push(acc.map((v, i) => (anyAt[i] ? v : null)));
        for (let i = 0; i < n; i++) if (isNum(sr.values[i])) acc[i] += sr.values[i];
        tops.push(acc.map((v, i) => (anyAt[i] ? v : null)));
      }
    }
    let maxV = 0;
    for (const vals of tops) for (const v of vals) if (isNum(v) && v > maxV) maxV = v;
    const ys = yScale(maxV, cfg.yMax, cfg.integer);
    const t0 = t[0], t1 = t[n - 1];
    const X = (i) => P.l + ((t[i] - t0) / (t1 - t0 || 1)) * pw;
    const Y = (v) => P.t + (1 - v / ys.top) * ph;
    const toPts = (vals) => vals.map((v, i) => (isNum(v) ? [X(i), Y(v)] : null));

    const svg = s('svg', { class: 'chart-svg', viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: 'img', 'aria-label': cfg.summary });
    const grid = s('g', { class: 'grid', 'aria-hidden': 'true' });
    for (const v of ys.ticks) {
      const y = Y(v).toFixed(1);
      grid.append(s('line', { x1: P.l, x2: W - P.r, y1: y, y2: y, class: v === 0 ? 'baseline' : null }));
      grid.append(s('text', { x: P.l - 6, y, class: 'ytick', dy: '0.32em', text: cfg.fmtTick(v) }));
    }
    const tt = timeTicks(t0, t1, Math.max(2, Math.floor(pw / (narrow ? 64 : 84))));
    for (const tv of tt.ticks) {
      const x = P.l + ((tv - t0) / (t1 - t0)) * pw;
      if (x < P.l + 14 || x > W - P.r - 14) continue;
      grid.append(s('text', { x: x.toFixed(1), y: H - 6, class: 'xtick', text: tt.step >= 86400 ? fmtDay(tv) : fmtClock(tv) }));
    }
    svg.append(grid);

    const marks = s('g', { class: 'marks' });
    cfg.series.forEach((sr, k) => {
      const top = toPts(tops[k]);
      if (cfg.stacked) marks.append(s('path', { class: 'area', d: bandPath(top, toPts(bases[k])), vars: { '--c': sr.color } }));
      else if (cfg.series.length === 1 || cfg.fill) marks.append(s('path', { class: 'area area-soft', d: areaPath(top, Y(0)), vars: { '--c': sr.color } }));
      marks.append(s('path', { class: 'line', d: linePath(top), vars: { '--c': sr.color } }));
    });
    svg.append(marks);

    const cross = s('g', { class: 'cross', 'aria-hidden': 'true' });
    cross.append(s('line', { y1: P.t, y2: P.t + ph, class: 'cross-line' }));
    const dots = cfg.series.map((sr) => s('circle', { r: 4, class: 'cross-dot', vars: { '--c': sr.color } }));
    cross.append(...dots);
    svg.append(cross);

    const tip = h('div', { class: 'tip', role: 'status', 'aria-live': 'off' });
    plot.replaceChildren(svg, tip);
    c.geo = { W, H, P, pw, X, Y, tops, cross, dots, tip };
  }

  function hover(c, e) {
    if (!c.geo || !c.cfg) return;
    if (e.type === 'pointerdown') charts.forEach((o) => o !== c && hideTip(o));
    const r = c.plot.getBoundingClientRect();
    const { P, pw } = c.geo;
    const t = c.cfg.t, n = t.length;
    const tx = t[0] + clamp((e.clientX - r.left - P.l) / pw, 0, 1) * (t[n - 1] - t[0]);
    let lo = 0, hi = n - 1;
    while (hi - lo > 1) { const mid = (lo + hi) >> 1; if (t[mid] < tx) lo = mid; else hi = mid; }
    showTip(c, tx - t[lo] < t[hi] - tx ? lo : hi);
  }

  function showTip(c, i) {
    const g = c.geo, cfg = c.cfg;
    if (!g) return;
    c.idx = i;
    const x = g.X(i);
    g.cross.classList.add('on');
    const line = g.cross.firstChild;
    line.setAttribute('x1', x.toFixed(1)); line.setAttribute('x2', x.toFixed(1));
    g.dots.forEach((d, k) => {
      const v = g.tops[k][i];
      d.classList.toggle('off', !isNum(v));
      if (isNum(v)) { d.setAttribute('cx', x.toFixed(1)); d.setAttribute('cy', g.Y(v).toFixed(1)); }
    });
    const rows = cfg.series.map((sr) => h('div', { class: 'tip-row' },
      h('span', { class: 'tip-key', 'aria-hidden': 'true', vars: { '--c': sr.color } }),
      h('b', { class: 'num', text: sr.fmtAt ? sr.fmtAt(i) : cfg.fmtVal(sr.values[i]) }),
      h('span', { class: 'tip-name', text: sr.name })));
    const head = cfg.t[cfg.t.length - 1] - cfg.t[0] > 86400 ? fmtStamp(cfg.t[i]) : fmtClock(cfg.t[i]);
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

  function legend(fig, series) {
    $('.legend', fig).replaceChildren(...series.map((sr) =>
      h('li', {}, h('span', { class: 'legend-key', 'aria-hidden': 'true', vars: { '--c': sr.color } }), sr.name)));
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
    legend(c.fig, cfg.series);
    drawChart(c);
  }

  let chartRefs = null;
  function renderCharts() {
    if (!chartRefs) chartRefs = { jobs: setupChart($('#chart-jobs')), cpu: setupChart($('#chart-cpu')), busy: setupChart($('#chart-busy')), ram: setupChart($('#chart-ram')) };
    const m = state.metrics || {};
    assignHostColors();
    const t = m.t || [];
    const hosts = m.hosts || [];  // sorted by name
    const hostSeries = (x) => ({ name: x.name || x.id, color: hostColor(x.id) });
    const pctTick = (v) => `${v}%`;
    const intTick = (v) => (Number.isInteger(v) ? String(v) : v.toFixed(1));

    const jobs = [
      { name: 'Running', color: 'var(--s1)', values: m.running || [] },
      { name: 'Queued', color: 'var(--s2)', values: m.queued || [] },
    ];
    setChart(chartRefs.jobs, { t, series: jobs, integer: true, fill: true, fmtVal: fmtInt, fmtTick: intTick, summary: summarize('Jobs queued and running', jobs, fmtInt) });

    const cpu = hosts.map((x) => ({ ...hostSeries(x), values: x.cpu || [] }));
    setChart(chartRefs.cpu, { t, series: cpu, yMax: 100, fmtVal: fmtPct, fmtTick: pctTick, summary: summarize('CPU per machine', cpu, fmtPct) });

    const busy = hosts.map((x) => {
      const values = x.busy || [], slots = x.slots || [];
      return { ...hostSeries(x), values, fmtAt: (i) => (isNum(values[i]) ? `${values[i]}${isNum(slots[i]) ? ` / ${slots[i]}` : ''}` : '—') };
    });
    setChart(chartRefs.busy, {
      t, series: busy, stacked: true, integer: true, fmtVal: fmtInt, fmtTick: intTick, summary: summarize('Busy runner slots per machine, stacked', busy, fmtInt),
      total: (i) => {
        const sum = busy.reduce((a, sr) => a + (isNum(sr.values[i]) ? sr.values[i] : 0), 0);
        return h('div', { class: 'tip-row tip-total' }, h('span', { class: 'tip-key tip-key-none' }), h('b', { class: 'num', text: String(sum) }), h('span', { class: 'tip-name', text: 'Total busy' }));
      },
    });

    const ram = hosts.map((x) => {
      const used = x.ram_used || [], total = x.ram_total || [];
      const values = used.map((u, i) => (isNum(u) && isNum(total[i]) && total[i] > 0 ? (u / total[i]) * 100 : null));
      return { ...hostSeries(x), values, fmtAt: (i) => (isNum(values[i]) ? `${fmtPct(values[i])} · ${fmtBytes(used[i])}` : '—') };
    });
    setChart(chartRefs.ram, { t, series: ram, yMax: 100, fmtVal: fmtPct, fmtTick: pctTick, summary: summarize('Memory used per machine', ram, fmtPct) });

    $('#charts-sub').textContent = m.step_secs ? `${RANGE_LABEL[state.range]} · ${m.step_secs % 60 ? `${m.step_secs}s` : `${m.step_secs / 60} min`} steps` : RANGE_LABEL[state.range];
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

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
