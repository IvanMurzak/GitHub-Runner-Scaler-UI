// runner-manager dashboard, Balancing screen: what both of its layouts share.
// The feed polls /api/placement and turns the coordinator's recorded
// decisions and launch events into decision models; the formatting helpers
// and the score parts live here too. The layouts (balancing-flow.js,
// balancing-race.js) register themselves; app.js shows and hides the screen
// through RMBalancing.
'use strict';

(function (root) {
  const GiB = 1073741824;
  const clamp = (v, a, b) => (v < a ? a : v > b ? b : v);
  const isNum = (v) => typeof v === 'number' && isFinite(v);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // ------------------------------------------------------------ formatting
  function fmtBytes(b) {
    if (!isNum(b)) return '–';
    const g = b / GiB;
    if (g >= 100) return Math.round(g) + ' GiB';
    if (g >= 1) return g.toFixed(1) + ' GiB';
    return Math.round(b / 1048576) + ' MiB';
  }
  const gShort = (b) => (!isNum(b) ? '–' : (b / GiB >= 10 ? (b / GiB).toFixed(0) : (b / GiB).toFixed(1)) + 'G');
  // Points (a score part over 1000) with two decimals; `sign` always shows one.
  function pts(v, sign) {
    const s = Math.abs(v).toFixed(2);
    if (!sign) return (v < -0.0005 ? '−' : '') + s;
    return (v < -0.0005 ? '−' : '+') + s;
  }
  // `27s`, `4m 05s`, `2h 10m`.
  function secs(s) {
    s = Math.max(0, Math.round(s));
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + 'm ' + String(s % 60).padStart(2, '0') + 's';
    return Math.floor(s / 3600) + 'h ' + String(Math.floor((s % 3600) / 60)).padStart(2, '0') + 'm';
  }
  // `27 s`, `4 min 5 s`, `2 h 10 min`.
  function fmtWait(s) {
    s = Math.max(0, Math.round(s));
    if (s < 60) return s + ' s';
    if (s < 3600) return Math.floor(s / 60) + ' min ' + (s % 60) + ' s';
    return Math.floor(s / 3600) + ' h ' + Math.floor((s % 3600) / 60) + ' min';
  }
  const shortRepo = (r) => String(r || '').split('/').pop();
  const ownerOf = (r) => String(r || '').split('/')[0];
  const labelList = (csv) => String(csv || '').split(',').filter(Boolean);

  // Why a host was passed over, why a queue waits, why a host refused.
  const REASON_TEXT = {
    offline: 'offline', not_connected: 'offline', unfit: 'unfit', draining: 'draining',
    unfit_or_draining: 'unfit or draining', no_free_slot: 'no free slot', no_memory_fit: 'no memory fit',
    no_candidate: 'no candidate', tried: 'asked already', refused: 'refused', unanswered: 'no answer',
    host_capacity: 'host full', max_capacity: 'profile max', memory: 'memory', stale: 'stale lease',
    disabled: 'profile disabled', unknown_profile: 'unknown profile', not_coordinated: 'not coordinated',
    excluded: 'label excluded', other: 'other', cancelled: 'cancelled', expired: 'expired',
  };
  const reasonText = (r) => REASON_TEXT[r] || String(r || '').replace(/_/g, ' ');
  const SOURCE_TEXT = {
    job: 'p90 of this job’s own runs',
    repository: 'p90 of this repository (job never measured)',
    default: 'default guess (no statistics yet)',
  };

  // The score parts, in the order the coordinator adds them.
  const SEGS = [
    { k: 'cache', name: 'Warm cache', short: 'cache', tip: 'a checkout of this repository is already on the machine (ignored when it measured slower than usual)' },
    { k: 'headroom', name: 'Headroom', short: 'headroom', tip: 'share of the machine’s RAM still free after this job' },
    { k: 'speed', name: 'Speed', short: 'speed', tip: 'how much faster than usual it ran these jobs; a machine that never ran them gets the full bonus so it gets tried' },
    { k: 'cpu', name: 'CPU', short: 'cpu', tip: 'idle cores, relative to the most idle contender' },
    { k: 'bigfit', name: 'Big-fit', short: 'bigfit', neg: true, tip: 'a much heavier queued job fits only here — keep this machine free for it' },
  ];
  const DEFAULT_WEIGHTS = { cache: 4, headroom: 2, speed: 1, cpu: 1, bigfit: 1.5 };

  // A repository's colour: one of eight (balancing.css), by its name.
  function repoVar(repo) {
    let h = 0;
    const s = String(repo || '').toLowerCase();
    for (let i = 0; i < s.length; i++) h = (Math.imul(h, 31) + s.charCodeAt(i)) | 0;
    return '--rp-' + ((Math.abs(h) % 8) + 1);
  }

  function statusOf(h) { return !h.online ? 'offline' : h.unfit ? 'unfit' : h.draining ? 'draining' : 'online'; }

  // The viewer's motion choice (data-motion, set by app.js), else the system's.
  const motionMedia = root.matchMedia('(prefers-reduced-motion: reduce)');
  function reduced() {
    const m = document.documentElement.dataset.motion;
    return m === 'reduce' || (m !== 'full' && motionMedia.matches);
  }
  // Calls `fn` when the theme or the motion choice changes.
  function onLook(fn) {
    new MutationObserver(fn).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme', 'data-motion'] });
    root.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', fn);
    motionMedia.addEventListener('change', fn);
  }

  const opts = { view: 'flow', refresh: 5, clock: '24' };
  function fmtClock(ms) {
    return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: opts.clock === '12' ? 'h12' : 'h23' });
  }

  // --------------------------------------------------------- decision model
  // One recorded decision as the layouts read it: the coordinator's fields,
  // the hosts it names resolved, and its launch's fate from the events.
  function model(raw, snap) {
    const hosts = new Map((snap.hosts || []).map((h) => [h.id, h]));
    const weights = Object.assign({}, DEFAULT_WEIGHTS, snap.weights || {});
    const mostIdle = (raw.most_idle_millicores || 0) / 1000;
    const scores = (raw.scores || []).map((s) => {
      const w = weights.speed || 0;
      return Object.assign({}, s, {
        _ctx: {
          warm: !!s.warm,
          warm_slow: !!s.warm && !s.cache,
          untried: w > 0 && s.speed >= Math.round(w * 1000) - 1,
          available_bytes: s.available_bytes,
          ram_bytes: s.ram_bytes,
          free_ram_bytes: s.free_ram_bytes,
          reserved_bytes: s.reserved_bytes || 0,
          idle_cores: (s.idle_millicores || 0) / 1000,
          most_idle_cores: mostIdle,
          busy_slots: s.busy_slots || 0,
          capacity: (s.busy_slots || 0) + (s.free_slots || 0),
        },
      });
    });
    const named = new Set(scores.map((s) => s.host_id));
    const filtered = [], notServing = [];
    for (const f of raw.filtered || []) {
      named.add(f.host_id);
      if (f.reason === 'no_candidate') notServing.push({ host_id: f.host_id, why: 'other_pool' });
      else filtered.push(Object.assign({ capacity: (f.busy_slots || 0) + (f.free_slots || 0) }, f));
    }
    for (const h of snap.hosts || []) if (!h.online && !named.has(h.id)) notServing.push({ host_id: h.id, why: 'offline' });
    const job = (raw.jobs && raw.jobs[0]) || (raw.job_id ? '#' + raw.job_id : 'queued job');
    return {
      id: raw.id, at_ms: raw.at_ms, repository: raw.repository, labels: raw.labels, labelList: labelList(raw.labels),
      queue: queueId(raw.repository, raw.labels), job_id: raw.job_id, jobs: raw.jobs || [], job_name: job,
      queued: raw.queued, leases: raw.leases,
      estimate_bytes: raw.estimate_bytes, estimate_source: raw.estimate_source || 'default',
      method: raw.method || (scores.length ? 'weighted' : ''), heavier_bytes: raw.heavier_bytes,
      weights, scores, chosen: raw.chosen, filtered, not_serving: notServing,
      reason: raw.reason, refusal: raw.refusal,
      attempts: [], outcome: raw.chosen ? null : raw.reason || 'no_candidate', placed_on: null,
      lease_id: null, claimed_ms: null, finished: null,
      hostName: (id) => (hosts.get(id) || {}).name || id,
    };
  }

  // A pool queue's key: its repository (lower-cased, as the coordinator keys
  // it) and its labels.
  const queueId = (repo, labels) => String(repo || '').toLowerCase() + '|' + labels;

  // What a launch event says about its decision.
  function applyEvent(d, ev) {
    const last = d.attempts[d.attempts.length - 1];
    switch (ev.kind) {
      case 'offered':
        d.attempts.push({ host_id: ev.host_id, lease_id: ev.lease_id, outcome: 'offered', reason: null, t_ms: ev.at_ms, t_end_ms: null });
        d.lease_id = ev.lease_id;
        break;
      case 'accepted':
      case 'refused':
      case 'unanswered':
        if (last) { last.outcome = ev.kind; last.reason = ev.reason || null; last.t_end_ms = ev.at_ms; }
        d.outcome = ev.kind;
        if (ev.kind === 'accepted') d.placed_on = ev.host_id;
        if (ev.kind === 'refused') d.refusal = ev.reason || null;
        break;
      case 'claimed': d.claimed_ms = ev.at_ms; break;
      case 'finished': d.finished = { duration: ev.duration_secs, peak: ev.peak_rss_bytes, at_ms: ev.at_ms }; break;
      case 'cancelled':
      case 'expired':
        if (d.outcome == null) { d.outcome = ev.kind; if (last) { last.outcome = ev.kind; last.t_end_ms = ev.at_ms; } }
        break;
      default:
    }
  }

  // --------------------------------------------------------------- the feed
  const KEEP_DECISIONS = 200, KEEP_EVENTS = 500;

  class Feed {
    constructor() {
      this.cursor = 0;
      this.snap = null;
      this.decisions = [];
      this.byId = new Map();
      this.events = [];
      this.hostById = new Map();
      this.listeners = [];
      this.running = false;
      this.intervalMs = 2000;
      this.timer = 0;
      this.skewMs = 0;
      this.lastOk = 0;
      this.failed = false;
      this.inflight = false;
    }

    // `fn(update)` after every poll: `{ first, reset, decisions, events }`,
    // the new decision models and the new raw events.
    on(fn) { this.listeners.push(fn); }
    now() { return Date.now() + this.skewMs; }

    start() {
      if (this.running) return;
      this.running = true;
      this.poll();
    }
    stop() { this.running = false; clearTimeout(this.timer); }
    setIntervalMs(ms) {
      if (ms === this.intervalMs) return;
      this.intervalMs = ms;
      if (this.running && !this.inflight) { clearTimeout(this.timer); this.timer = setTimeout(() => this.poll(), Math.min(ms, 1000)); }
    }

    async poll() {
      clearTimeout(this.timer);
      if (this.inflight) return;
      this.inflight = true;
      try {
        const res = await fetch('/api/placement?since=' + this.cursor, { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } });
        if (res.status === 401) { location.reload(); return; }
        if (!res.ok) throw new Error('HTTP ' + res.status);
        this.ingest(await res.json());
        this.failed = false;
        this.lastOk = Date.now();
      } catch (_) {
        this.failed = true;
        for (const fn of this.listeners) fn({ failed: true, decisions: [], events: [] });
      } finally {
        this.inflight = false;
      }
      if (this.running && !document.hidden) this.timer = setTimeout(() => this.poll(), this.intervalMs);
    }

    ingest(data) {
      const first = !this.snap;
      if (data.reset && !first) { this.decisions = []; this.byId.clear(); this.events = []; }
      if (isNum(data.generated_at)) this.skewMs = data.generated_at * 1000 - Date.now();
      this.snap = data;
      this.hostById = new Map((data.hosts || []).map((h, i) => Object.assign(h, { _order: i })).map((h) => [h.id, h]));
      const fresh = [];
      for (const raw of data.decisions || []) {
        if (this.byId.has(raw.id)) continue;
        const d = model(raw, data);
        this.byId.set(d.id, d);
        this.decisions.push(d);
        fresh.push(d);
      }
      for (const ev of data.events || []) {
        const d = ev.decision != null ? this.byId.get(ev.decision) : null;
        if (d) applyEvent(d, ev);
        this.events.push(ev);
      }
      while (this.decisions.length > KEEP_DECISIONS) this.byId.delete(this.decisions.shift().id);
      if (this.events.length > KEEP_EVENTS) this.events.splice(0, this.events.length - KEEP_EVENTS);
      this.cursor = isNum(data.cursor) ? data.cursor : this.cursor;
      const update = { first, reset: !!data.reset && !first, decisions: fresh, events: data.events || [] };
      for (const fn of this.listeners) fn(update);
    }

    host(id) { return this.hostById.get(id) || null; }
    hostName(id) { const h = this.hostById.get(id); return h ? h.name || h.hostname || id : id; }
  }

  // ------------------------------------------------------------- the screen
  const views = new Map();
  let feed = null, visible = false, active = null;

  // How often the screen reads the coordinator: every 2 s, or the
  // dashboard's own interval when that is 10 s or longer.
  const intervalFor = (refresh) => (refresh >= 10 ? refresh : 2) * 1000;

  function container(name) { return document.getElementById('bal-' + name); }

  function activate() {
    const name = views.has(opts.view) ? opts.view : 'flow';
    for (const [n] of views) { const el = container(n); if (el) el.hidden = n !== name; }
    const v = views.get(name);
    if (!v) return;
    if (active && active !== v && active.inst) active.inst.stop();
    if (!v.inst) v.inst = v.create(feed);
    active = v;
    v.inst.start();
  }

  function show() {
    if (!feed) feed = new Feed();
    for (const v of views.values()) if (!v.inst) v.inst = v.create(feed);
    visible = true;
    feed.setIntervalMs(intervalFor(opts.refresh));
    feed.start();
    activate();
  }

  function hide() {
    visible = false;
    if (feed) feed.stop();
    if (active && active.inst) active.inst.stop();
  }

  function configure(o) {
    const before = opts.view;
    Object.assign(opts, o || {});
    if (feed) feed.setIntervalMs(intervalFor(opts.refresh));
    if (visible && before !== opts.view) activate();
  }

  document.addEventListener('visibilitychange', () => {
    if (!visible || !feed) return;
    if (document.hidden) feed.stop();
    else feed.start();
  });

  root.RMBalancing = {
    register(name, create) { views.set(name, { create, inst: null }); },
    show, hide, configure,
    get visible() { return visible; },
    get feed() { return feed; },
    // The layout showing, for debugging: its `debug` holds its state.
    get view() { return active && active.inst; },
  };
  root.RMBalance = {
    GiB, clamp, isNum, esc, fmtBytes, gShort, pts, secs, fmtWait, fmtClock, shortRepo, ownerOf, labelList,
    REASON_TEXT, reasonText, SOURCE_TEXT, SEGS, DEFAULT_WEIGHTS, repoVar, statusOf, reduced, onLook, queueId, model, applyEvent, Feed,
  };
})(window);
