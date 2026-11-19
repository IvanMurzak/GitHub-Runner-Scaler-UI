// runner-manager dashboard, Balancing screen: the flow map. GitHub webhooks
// -> pool queues -> coordinator -> machines on one Canvas 2D, with a camera
// (pan, zoom, inertia, eased flights), a minimap and a decision inspector.
//
// The coordinator records each decision and launch event (GET /api/placement);
// LiveWorld replays them in order, each step long enough to be seen (the
// coordinator decides in microseconds), and keeps the queues, slots and jobs
// in line with the coordinator's snapshot. Pausing holds the replay; what
// arrives meanwhile waits and plays faster to catch up.
'use strict';

(function (global) {
  const B = global.RMBalance;
  const { GiB, clamp, esc, fmtBytes, fmtWait, secs, pts, shortRepo, reasonText, SOURCE_TEXT, queueId } = B;

  // How long each step lasts on screen, in seconds.
  const PACE = { webhook: 0.9, pick: 0.7, scan: 0.5, score: 1.0, offer: 0.7, answer: 0.3, bounce: 0.6, stats: 0.9 };
  // While more decisions than this wait, the oldest steps are applied at
  // once, without animation.
  const SKIP_BACKLOG = 4;
  // Queues not seen for this long leave the map.
  const QUEUE_MEMORY = 10 * 60;
  const MAX_QUEUES = 10;

  const lerp = (a, b, t) => a + (b - a) * t;
  const smooth = (a, b, v) => { const t = clamp((v - a) / (b - a), 0, 1); return t * t * (3 - 2 * t); };
  const easeInOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
  const easeOut = (t) => 1 - Math.pow(1 - t, 3);

  // Whether a host's profile labels (comma-separated) cover a queue's.
  function serves(h, labels) {
    const want = B.labelList(labels).map((l) => l.toLowerCase());
    return (h.pools || []).some((p) => {
      const have = B.labelList(p).map((l) => l.toLowerCase());
      return want.every((l) => have.includes(l));
    });
  }

  // ================================================================ LiveWorld
  // What the scene draws, in the shapes the prototype's simulator had:
  // hosts with slots, pool queues, jobs, leases, and a stream of events with
  // a playback time `t`.
  class LiveWorld {
    constructor(feed) {
      this.feed = feed;
      this.t = 0;
      this.timers = [];
      this.listeners = [];
      this.seq = 0;
      this.events = [];
      this.jobs = new Map();
      this.leases = new Map();
      this.hosts = [];
      this.hostById = new Map();
      this.queues = [];
      this.queueSeen = new Map();
      this.decisions = [];
      this.byId = new Map();
      this.backlog = [];
      this.busy = false;
      this.coordBusy = false;
      this.primed = false;
      this.counters = { webhooks: 0, decisions: 0, launches: 0, accepted: 0, refused: 0, unanswered: 0, wakes: 0, finished: 0 };
      this.weights = B.DEFAULT_WEIGHTS;
      feed.on((u) => this.ingest(u));
      if (feed.snap) this.ingest({ first: true, decisions: feed.decisions.slice(), events: [] });
    }

    on(fn) { this.listeners.push(fn); }
    emit(type, data) {
      const ev = Object.assign({ type, t: this.t, seq: ++this.seq }, data);
      this.events.push(ev);
      if (this.events.length > 400) this.events.splice(0, this.events.length - 400);
      for (const fn of this.listeners) fn(ev);
      return ev;
    }
    at(delay, fn) {
      const when = this.t + delay;
      let i = this.timers.length;
      while (i > 0 && this.timers[i - 1].when > when) i--;
      this.timers.splice(i, 0, { when, fn });
    }
    // The coordinator's clock, in playback seconds.
    serverSecs() { return this.feed.now() / 1000; }
    toT(unixSecs) { return this.t - Math.max(0, this.serverSecs() - unixSecs); }

    step(dt) {
      const end = this.t + dt;
      while (this.timers.length && this.timers[0].when <= end) {
        const timer = this.timers.shift();
        this.t = Math.max(this.t, timer.when);
        timer.fn();
      }
      this.t = end;
      let guard = 0;
      while (!this.busy && this.backlog.length && guard++ < 200) this.next();
    }

    // ------------------------------------------------------------ ingest
    ingest(u) {
      if (u.failed || !this.feed.snap) return;
      const snap = this.feed.snap;
      this.weights = Object.assign({}, B.DEFAULT_WEIGHTS, snap.weights || {});
      this.cpuBusy = snap.cpu_busy_percent;
      this.minDisk = snap.min_disk_free_bytes;
      const first = u.first || u.reset || !this.primed;
      if (first) {
        this.backlog = [];
        this.decisions = [];
        this.byId.clear();
        const c = snap.counters || {};
        Object.assign(this.counters, { decisions: c.decisions || 0, launches: c.offered || 0, accepted: c.accepted || 0, refused: c.refused || 0, unanswered: c.unanswered || 0, finished: c.finished || 0 });
        for (const d of this.feed.decisions.slice(-60)) this.remember(Object.assign({}, d, { attempts: d.attempts.map((a) => Object.assign({}, a)) }));
      } else {
        const items = u.decisions.map((d) => ({ seq: d.id, d })).concat(u.events.map((e) => ({ seq: e.seq, e })));
        items.sort((a, b) => a.seq - b.seq);
        this.backlog.push(...items);
      }
      this.sync(snap, first);
      this.primed = true;
    }

    remember(pd) {
      this.decisions.push(pd);
      this.byId.set(pd.id, pd);
      while (this.decisions.length > 60) this.byId.delete(this.decisions.shift().id);
      this.noteQueue(pd.queue, pd.repository, pd.labels, true);
    }

    noteQueue(id, repository, labels, pool) {
      const q = this.queueSeen.get(id);
      if (q) { q.at = this.t; q.pool = q.pool || pool; return; }
      this.queueSeen.set(id, { id, repository: String(repository).toLowerCase(), labels, pool, at: this.t });
    }

    // The coordinator's snapshot: hosts, queues, jobs, leases and slots.
    sync(snap, first) {
      // hosts
      const keep = new Map();
      for (const x of snap.hosts || []) {
        const h = this.hostById.get(x.id) || { slotJobs: [], slots: 1 };
        Object.assign(h, {
          id: x.id, name: x.name || x.hostname || x.id, os: (x.os || 'linux').toLowerCase(), arch: x.arch || '', cores: x.cores || 0,
          ram_bytes: x.ram_bytes, free_ram_bytes: x.free_ram_bytes, cpu_load_percent: x.cpu_load_percent,
          disk_free_bytes: x.disk_free_bytes, online: !!x.online, unfit: !!x.unfit, draining: !!x.draining,
          warm_repos: x.warm_repos || [], pools: x.pools || [], busy_slots: x.busy_slots || 0, free_slots: x.free_slots || 0,
          last_seen_at: x.last_seen_at, view: { at: this.t },
        });
        if (x.online) h.slots = Math.max(1, (x.busy_slots || 0) + (x.free_slots || 0));
        keep.set(h.id, h);
      }
      this.hostById = keep;
      this.hosts = [...keep.values()];

      // queues
      const serverSecs = this.serverSecs();
      for (const j of snap.queued || []) this.noteQueue(queueId(j.repository, j.labels), j.repository, j.labels, !!j.pool);
      for (const q of snap.queues || []) this.noteQueue(queueId(q.repository, q.labels), q.repository, q.labels, true);
      this.pending = new Map((snap.queues || []).map((q) => [queueId(q.repository, q.labels), q]));

      // jobs: queued, then running
      const queuedNow = new Set();
      for (const x of snap.queued || []) {
        const id = 'gh:' + x.id;
        queuedNow.add(id);
        let j = this.jobs.get(id);
        if (!j) {
          j = {
            id, gh_id: x.id, repository: x.repository, job: x.name || '#' + x.id, labels: x.labels, pool: !!x.pool,
            queue: queueId(x.repository, x.labels), queued_t: this.t - Math.max(0, serverSecs - x.queued_at),
            state: 'queued', attempts: [],
          };
          this.jobs.set(id, j);
          if (!first) {
            j.state = 'webhook';
            this.counters.webhooks++;
            this.emit('webhook', { job: id, queue: j.queue });
            this.at(PACE.webhook, () => { if (j.state === 'webhook') { j.state = 'queued'; this.emit('queued', { job: id, queue: j.queue }); } });
          }
        }
      }
      const runningNow = new Set();
      for (const x of snap.running || []) {
        if (!x.host_id) continue;
        const id = 'gh:' + x.id;
        runningNow.add(id);
        let j = this.jobs.get(id);
        const startT = this.t - Math.max(0, serverSecs - (x.started_at || serverSecs));
        if (!j) {
          j = { id, gh_id: x.id, repository: x.repository, job: x.name || '#' + x.id, labels: x.labels, pool: !!x.pool, queue: queueId(x.repository, x.labels), attempts: [] };
          this.jobs.set(id, j);
        } else if (j.state !== 'running' && !first) {
          // It left the queue for a runner: a job outside the pools woke its host.
          if (!j.pool && this.hostById.has(x.host_id)) {
            this.counters.wakes++;
            this.emit('wake', { job: id, queue: j.queue, hosts: [x.host_id] });
            this.at(PACE.pick, () => this.emit('wake_claim', { job: id, host: x.host_id, queue: j.queue }));
          }
        }
        Object.assign(j, { state: 'running', host: x.host_id, started_at: startT, duration: x.expected_secs || null, queued_t: j.queued_t != null ? j.queued_t : this.t - Math.max(0, serverSecs - x.queued_at) });
        if (j.dock_t == null) j.dock_t = first ? -1 : this.t + (j.pool ? 0 : PACE.pick + PACE.offer);
      }
      for (const [id, j] of this.jobs) {
        if (queuedNow.has(id) || runningNow.has(id)) continue;
        if (j.state === 'running' && id.startsWith('gh:')) {
          const slot = this.hostById.get(j.host) ? this.hostById.get(j.host).slotJobs.indexOf(id) : -1;
          if (!first && slot >= 0) {
            this.counters.finished++;
            this.emit('finished', { job: id, host: j.host, duration: this.t - j.started_at, slot, repository: j.repository });
          }
          this.jobs.delete(id);
        } else if (['queued', 'webhook', 'placed'].includes(j.state) && id.startsWith('gh:')) {
          this.jobs.delete(id);
        } else if (j.phantom && j.state === 'queued') {
          this.jobs.delete(id);
        }
      }

      // leases: the ones the replay has reached, while the coordinator holds them
      const open = new Map((snap.leases || []).map((l) => [l.lease_id, l]));
      for (const [id, l] of this.leases) {
        const now = open.get(id);
        if (now) { if (l.state !== 'offered') l.state = now.state; }
        else if (this.t - l.t > 3) this.leases.delete(id);
      }
      if (first) for (const l of open.values()) this.leases.set(l.lease_id, { host_id: l.host_id, state: l.state, t: this.t, repository: l.repository });

      // queues on the map
      for (const [id, q] of this.queueSeen) {
        const busy = this.queuedJobs(q).length || this.pending.has(id) || (this.decisions.length && this.decisions[this.decisions.length - 1].queue === id);
        if (busy) q.at = this.t;
        else if (this.t - q.at > QUEUE_MEMORY) this.queueSeen.delete(id);
      }
      let qs = [...this.queueSeen.values()].sort((a, b) => b.at - a.at).slice(0, MAX_QUEUES);
      qs.sort((a, b) => (b.pool - a.pool) || a.repository.localeCompare(b.repository) || a.labels.localeCompare(b.labels));
      this.queues = qs;
      this.slots();
    }

    // Each host's slots: its running jobs, its accepted launches, and the
    // runners its heartbeat counts that nothing here names. A job keeps its slot.
    slots() {
      const byHost = new Map(this.hosts.map((h) => [h.id, []]));
      for (const j of this.jobs.values()) if (j.state === 'running' && byHost.has(j.host)) byHost.get(j.host).push(j.id);
      for (const [id, l] of this.leases) {
        if (!byHost.has(l.host_id) || l.state === 'offered') continue;
        const jid = 'lease:' + id;
        let j = this.jobs.get(jid);
        if (!j) {
          j = { id: jid, lease: id, repository: l.repository, job: l.job || 'runner', queue: l.queue, host: l.host_id, dock_t: l.dock_t != null ? l.dock_t : -1, attempts: [] };
          this.jobs.set(jid, j);
        }
        j.state = l.state === 'claimed' ? 'running' : 'starting';
        if (j.state === 'running' && j.started_at == null) { j.started_at = this.t; j.duration = null; }
        byHost.get(l.host_id).push(jid);
      }
      for (const [jid, j] of this.jobs) if (j.lease && !this.leases.has(j.lease)) this.jobs.delete(jid);
      for (const h of this.hosts) {
        const want = byHost.get(h.id);
        const named = want.filter((id) => (this.jobs.get(id) || {}).state === 'running').length;
        for (let i = 0; i < Math.max(0, h.busy_slots - named); i++) {
          const jid = 'busy:' + h.id + ':' + i;
          if (!this.jobs.has(jid)) this.jobs.set(jid, { id: jid, anonymous: true, repository: null, job: 'a runner', host: h.id, state: 'running', started_at: null, duration: null, dock_t: -1, attempts: [] });
          want.push(jid);
        }
        for (const [jid, j] of this.jobs) if (j.anonymous && j.host === h.id && !want.includes(jid)) this.jobs.delete(jid);
        h.slots = Math.max(h.slots, want.length);
        const next = h.slotJobs.slice(0, h.slots).map((id) => (want.includes(id) ? id : null));
        while (next.length < h.slots) next.push(null);
        for (const id of want) if (!next.includes(id)) { const i = next.indexOf(null); if (i >= 0) next[i] = id; }
        h.slotJobs = next;
        h.running = want.filter((id) => (this.jobs.get(id) || {}).state === 'running');
      }
      for (const [jid, j] of this.jobs) if (j.anonymous && !this.hostById.has(j.host)) this.jobs.delete(jid);
    }

    // ----------------------------------------------------------- replay
    next() {
      const it = this.backlog.shift();
      // The scene's animations last their own fixed times: a long backlog
      // is caught up by skipping, never by playing faster.
      const instant = this.backlog.filter((x) => x.d).length >= SKIP_BACKLOG;
      this.busy = true;
      const done = () => { this.busy = false; };
      const wait = (secs, fn) => { if (instant) { if (fn) fn(); done(); } else this.at(secs, () => { if (fn) fn(); done(); }); };
      if (it.d) this.playDecision(it.d, wait, instant);
      else this.playEvent(it.e, wait, instant);
    }

    jobFor(d) {
      const own = this.jobs.get('gh:' + d.job_id);
      if (own && ['queued', 'picked', 'offering'].includes(own.state)) return own;
      const picked = [...this.jobs.values()].find((j) => j.queue === d.queue && (j.state === 'picked' || j.state === 'offering'));
      if (picked) return picked;
      const queued = this.queuedJobs({ id: d.queue });
      if (queued.length) return queued[0];
      const j = { id: 'd:' + d.id, phantom: true, repository: d.repository, job: d.job_name, labels: d.labels, pool: true, queue: d.queue, queued_t: this.t, state: 'queued', attempts: [] };
      this.jobs.set(j.id, j);
      return j;
    }

    playDecision(d, wait, instant) {
      const pd = Object.assign({}, d, { attempts: [], outcome: d.chosen ? null : d.outcome, placed_on: null, claimed_ms: null, finished: null, t: this.t });
      this.counters.decisions++;
      const j = this.jobFor(d);
      pd.job = j.id;
      j.decision = pd.id;
      j.estimate_bytes = d.estimate_bytes;
      j.estimate_source = d.estimate_source;
      const settle = () => {
        if (pd.chosen) return;
        j.state = 'queued';
        j.return_t = this.t + PACE.pick;
        this.coordBusy = false;
        this.emit('requeued', { job: j.id, queue: pd.queue, reason: pd.outcome, refusal: pd.refusal, decision: pd.id });
      };
      if (instant) { this.remember(pd); settle(); wait(0); return; }
      const decide = () => {
        this.remember(pd);
        this.emit('decision', { decision: pd, job: j.id, queue: pd.queue });
        wait(PACE.scan + PACE.score, settle);
      };
      if (j.state === 'picked' || j.state === 'offering') { j.state = 'picked'; decide(); return; }
      j.state = 'picked';
      this.coordBusy = true;
      this.emit('pick', { job: j.id, queue: pd.queue });
      this.at(PACE.pick, decide);
    }

    playEvent(e, wait, instant) {
      const pd = e.decision != null ? this.byId.get(e.decision) : null;
      const j = pd && pd.job ? this.jobs.get(pd.job) : null;
      const data = { job: j ? j.id : null, host: e.host_id, lease: e.lease_id, decision: pd ? pd.id : null, reason: e.reason };
      if (pd) B.applyEvent(pd, e);
      const quiet = instant || !this.hostById.has(e.host_id);
      switch (e.kind) {
        case 'offered':
          this.counters.launches++;
          this.leases.set(e.lease_id, { host_id: e.host_id, state: 'offered', t: this.t, repository: pd ? pd.repository : e.repository, job: j ? j.job : null, queue: pd && pd.queue });
          if (j) j.state = 'offering';
          if (j) j.attempts.push({ host_id: e.host_id, outcome: 'offered' });
          if (!quiet) this.emit('offered', data);
          wait(PACE.offer);
          break;
        case 'accepted': {
          this.counters.accepted++;
          const l = this.leases.get(e.lease_id);
          if (l) { l.state = 'accepted'; l.dock_t = this.t; l.t = this.t; }
          if (j) { j.state = 'placed'; j.host = e.host_id; const a = j.attempts[j.attempts.length - 1]; if (a) a.outcome = 'accepted'; }
          this.coordBusy = false;
          this.slots();
          if (!quiet) this.emit('accepted', data);
          wait(PACE.answer);
          break;
        }
        case 'refused':
        case 'unanswered': {
          this.counters[e.kind]++;
          this.leases.delete(e.lease_id);
          if (j) { j.state = 'picked'; const a = j.attempts[j.attempts.length - 1]; if (a) { a.outcome = e.kind; a.reason = e.reason; } }
          if (!quiet) this.emit(e.kind, data);
          wait(PACE.bounce, () => {
            // Placement tries the next host at once; when nothing follows, the job waits.
            const again = this.backlog.some((it) => it.d && pd && it.d.queue === pd.queue);
            if (!again && j) {
              j.state = 'queued';
              j.return_t = this.t + PACE.pick;
              this.coordBusy = false;
              this.emit('requeued', { job: j.id, queue: pd.queue, reason: e.kind, refusal: e.reason, decision: pd.id });
            }
          });
          break;
        }
        case 'claimed': {
          const l = this.leases.get(e.lease_id);
          if (l) l.state = 'claimed';
          this.slots();
          if (!quiet) this.emit('claimed', data);
          wait(0);
          break;
        }
        case 'cancelled':
        case 'expired':
          this.leases.delete(e.lease_id);
          this.slots();
          if (!quiet) this.emit('host', { host: e.host_id, change: e.kind === 'cancelled' ? 'launch cancelled' : 'lease expired' });
          wait(0);
          break;
        default:
          wait(0);
      }
    }

    // ----------------------------------------------------------- queries
    queue(id) { return this.queues.find((q) => q.id === id) || this.queueSeen.get(id) || null; }
    queuedJobs(q) {
      const list = [];
      for (const j of this.jobs.values()) if (j.queue === q.id && j.state === 'queued') list.push(j);
      return list.sort((a, b) => a.queued_t - b.queued_t);
    }
    // A queue as the coordinator reports it, else as the jobs here show it.
    pendingQueue(q) {
      const p = (this.pending && this.pending.get(q.id)) || {};
      const jobs = this.queuedJobs(q);
      const oldest = jobs.length ? Math.round(this.t - jobs[0].queued_t) : null;
      return { repository: q.repository, labels: q.labels, queued: p.queued != null ? p.queued : jobs.length, leases: p.leases || 0,
        oldest_wait_secs: p.oldest_wait_secs != null ? p.oldest_wait_secs : oldest, reason: p.reason || null, refusal: p.refusal || null };
    }
  }

  // ==================================================================== Scene
  const OS_RANK = (os) => ({ linux: 0, windows: 1, macos: 2 }[os] ?? 3);
  // A host's reason for being passed over, as a chip says it.
  function filterText(f) {
    if (f.reason === 'tried') return f.detail ? 'asked · ' + reasonText(f.detail) : 'asked already';
    if (f.reason === 'unfit_or_draining' && f.detail) return reasonText(f.detail);
    return reasonText(f.reason);
  }
  const REASON_TEXT = B.REASON_TEXT;

  function bz(e, t) {
    const u = 1 - t;
    const a = u * u * u, b = 3 * u * u * t, c = 3 * u * t * t, d = t * t * t;
    return { x: a * e[0] + b * e[2] + c * e[4] + d * e[6], y: a * e[1] + b * e[3] + c * e[5] + d * e[7] };
  }
  function splitLeft(e, t) {
    const x01 = lerp(e[0], e[2], t), y01 = lerp(e[1], e[3], t);
    const x12 = lerp(e[2], e[4], t), y12 = lerp(e[3], e[5], t);
    const x23 = lerp(e[4], e[6], t), y23 = lerp(e[5], e[7], t);
    const x012 = lerp(x01, x12, t), y012 = lerp(y01, y12, t);
    const x123 = lerp(x12, x23, t), y123 = lerp(y12, y23, t);
    return [e[0], e[1], x01, y01, x012, y012, lerp(x012, x123, t), lerp(y012, y123, t)];
  }
  function splitRight(e, t) {
    const x01 = lerp(e[0], e[2], t), y01 = lerp(e[1], e[3], t);
    const x12 = lerp(e[2], e[4], t), y12 = lerp(e[3], e[5], t);
    const x23 = lerp(e[4], e[6], t), y23 = lerp(e[5], e[7], t);
    const x012 = lerp(x01, x12, t), y012 = lerp(y01, y12, t);
    const x123 = lerp(x12, x23, t), y123 = lerp(y12, y23, t);
    return [lerp(x012, x123, t), lerp(y012, y123, t), x123, y123, x23, y23, e[6], e[7]];
  }
  function subCurve(e, a, b) {
    let c = e;
    if (b < 1) c = splitLeft(c, b);
    if (a > 0) c = splitRight(c, b > 0 ? a / b : 0);
    return c;
  }

  const colorCache = new Map();
  function rgba(color, alpha) {
    const key = color + '|' + alpha;
    let out = colorCache.get(key);
    if (out) return out;
    let r = 128, g = 128, b = 128, a = 1;
    const c = color.trim();
    if (c[0] === '#') {
      const hex = c.length === 4 ? c.slice(1).split('').map((x) => x + x).join('') : c.slice(1, 7);
      r = parseInt(hex.slice(0, 2), 16); g = parseInt(hex.slice(2, 4), 16); b = parseInt(hex.slice(4, 6), 16);
    } else {
      const m = c.match(/rgba?\(([^)]+)\)/);
      if (m) { const p = m[1].split(',').map((x) => parseFloat(x)); [r, g, b] = p; if (p.length > 3) a = p[3]; }
    }
    out = 'rgba(' + r + ',' + g + ',' + b + ',' + (a * alpha).toFixed(3) + ')';
    colorCache.set(key, out);
    return out;
  }

  const ICONS = {
    github: new Path2D('M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z'),
    apple: new Path2D('M16.37 12.73c-.02-2.3 1.88-3.4 1.96-3.46-1.07-1.56-2.73-1.77-3.32-1.8-1.41-.14-2.76.83-3.47.83-.72 0-1.82-.81-3-.79-1.54.02-2.96.9-3.76 2.28-1.6 2.78-.41 6.9 1.15 9.16.76 1.1 1.67 2.34 2.86 2.3 1.15-.05 1.58-.74 2.97-.74 1.38 0 1.77.74 2.98.72 1.23-.02 2.01-1.12 2.76-2.23.87-1.28 1.23-2.52 1.25-2.58-.03-.01-2.4-.92-2.42-3.65zM14.1 5.98c.63-.77 1.06-1.83.94-2.9-.91.04-2.02.61-2.67 1.37-.58.67-1.1 1.76-.96 2.8 1.02.08 2.06-.52 2.69-1.27z'),
    windows: new Path2D('M3 5.5 10.5 4.4v7.1H3zm8.5-1.25L21 3v8.5h-9.5zM3 12.5h7.5v7.1L3 18.5zm8.5 0H21V21l-9.5-1.3z'),
    tux: new Path2D('M12 2.2c-2.1 0-3.4 1.8-3.4 4.1 0 1.3.2 2.1-.2 3.1-.5 1.2-2.3 2.9-2.9 5-.5 1.6-.3 3 .6 3.8-.8.5-1.7 1-1.3 1.8.4.9 2.4.6 3.8 1.1 1 .4 2.2.6 3.4 0 1.2.6 2.4.4 3.4 0 1.4-.5 3.4-.2 3.8-1.1.4-.8-.5-1.3-1.3-1.8.9-.8 1.1-2.2.6-3.8-.6-2.1-2.4-3.8-2.9-5-.4-1-.2-1.8-.2-3.1 0-2.3-1.3-4.1-3.4-4.1z'),
    tuxBelly: new Path2D('M12 10.6c-1.7 0-3 1.9-3 4.3s1.3 4.3 3 4.3 3-1.9 3-4.3-1.3-4.3-3-4.3z'),
    tuxBeak: new Path2D('M10.7 8.1h2.6L12 9.7z'),
  };

  const HOST_W = 300, HOST_H = 112, HOST_GAP = 121;
  const QUEUE_W = 248, QUEUE_H = 104, QUEUE_GAP = 124;
  const COORD_R = 92;
  const HOST_X = 250, HOST_ARC = 120;

  // =================================================================== Scene
  class Scene {
    constructor(canvas, minimap, sim) {
      this.layoutSig = null;
      this.canvas = canvas;
      this.ctx = canvas.getContext('2d');
      this.mini = minimap;
      this.mctx = minimap ? minimap.getContext('2d') : null;
      this.sim = sim;
      this.dpr = 1;
      this.w = 0; this.h = 0;
      this.cam = { tx: 0, ty: 0, s: 0.6 };
      this.target = { tx: 0, ty: 0, s: 0.6 };
      this.vel = { x: 0, y: 0 };
      this.flight = null;
      this.pointers = new Map();
      this.drag = null;
      this.hover = null;
      this.selected = null;
      this.hotHost = null;
      this.reduced = B.reduced();
      this.insets = { left: 16, right: 16, top: 60, bottom: 76 };
      this.tokens = new Map();
      this.fx = [];
      this.blockFx = new Map();
      this.wakeFx = [];
      this.hostFx = new Map();
      this.finished = [];
      this.ghPulses = [];
      this.pinned = null; // a past decision drawn statically
      this.onSelect = null;
      this.onHover = null;
      this.lastFont = '';
      this.readTheme();
      this.layout();
      sim.on((ev) => this.onEvent(ev));
      this.bindInput();
    }

    // ------------------------------------------------------------ layout
    // Where everything sits: queues in an arc left of the coordinator,
    // machines in an arc right of it, GitHub further left. Rebuilt when the
    // queues or machines change.
    layout() {
      this.layoutSig = this.sim.queues.map((q) => q.id).join(';') + '#' + this.sim.hosts.map((h) => h.id).join(';');
      this.nodes = [];
      this.hostNode = new Map();
      this.queueNode = new Map();
      this.coord = { kind: 'coord', id: 'coordinator', x: 0, y: 0, r: COORD_R };
      this.github = { kind: 'github', id: 'github', x: -880, y: -88, w: 144, h: 176 };
      const qn = this.sim.queues.length;
      this.sim.queues.forEach((q, i) => {
        const cy = (i - (qn - 1) / 2) * QUEUE_GAP;
        const f = qn > 1 ? cy / (((qn - 1) / 2) * QUEUE_GAP) : 0;
        const cx = -500 + 56 * f * f;
        const node = { kind: 'queue', id: q.id, q, x: cx - QUEUE_W / 2, y: cy - QUEUE_H / 2, w: QUEUE_W, h: QUEUE_H, cy, i };
        this.queueNode.set(q.id, node);
        this.nodes.push(node);
      });
      const hosts = this.sim.hosts.slice().sort((a, b) => (b.online - a.online) || OS_RANK(a.os) - OS_RANK(b.os) || a.name.localeCompare(b.name));
      const hn = hosts.length;
      hosts.forEach((h, i) => {
        const cy = (i - (hn - 1) / 2) * HOST_GAP;
        const f = hn > 1 ? cy / (((hn - 1) / 2) * HOST_GAP) : 0;
        const x = HOST_X + HOST_ARC * (1 - f * f);
        const node = { kind: 'host', id: h.id, h, x, y: cy - HOST_H / 2, w: HOST_W, h2: HOST_H, cy, i };
        node.hh = HOST_H;
        this.hostNode.set(h.id, node);
        this.nodes.push(node);
      });
      this.nodes.push(this.coord, this.github);
      // edges
      this.edges = new Map();
      const g = this.github;
      for (const node of this.queueNode.values()) {
        const x0 = g.x + g.w, y0 = g.y + g.h / 2 + clamp(node.i - (qn - 1) / 2, -3.5, 3.5) * 18;
        const x3 = node.x, y3 = node.cy;
        const d = x3 - x0;
        this.edges.set('gh:' + node.id, [x0, y0, x0 + d * 0.5, y0, x3 - d * 0.5, y3, x3, y3]);
        const ax = node.x + node.w, ay = node.cy;
        const ang = Math.atan2(ay, ax);
        const px = Math.cos(ang) * COORD_R, py = Math.sin(ang) * COORD_R;
        const dd = Math.hypot(px - ax, py - ay);
        this.edges.set('qc:' + node.id, [ax, ay, ax + dd * 0.45, ay, px + Math.cos(ang) * dd * 0.32, py + Math.sin(ang) * dd * 0.32, px, py]);
      }
      for (const node of this.hostNode.values()) {
        const x3 = node.x, y3 = node.cy;
        const ang = Math.atan2(y3, x3);
        const px = Math.cos(ang) * COORD_R, py = Math.sin(ang) * COORD_R;
        const dd = Math.hypot(x3 - px, y3 - py);
        this.edges.set('ch:' + node.id, [px, py, px + Math.cos(ang) * dd * 0.3, py + Math.sin(ang) * dd * 0.3, x3 - dd * 0.42, y3, x3, y3]);
      }
      // bounds
      let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
      for (const n of this.nodes) {
        const b = this.nodeBounds(n);
        minX = Math.min(minX, b.x); minY = Math.min(minY, b.y);
        maxX = Math.max(maxX, b.x + b.w); maxY = Math.max(maxY, b.y + b.h);
      }
      this.bounds = { x: minX - 30, y: minY - 84, w: maxX - minX + 60, h: maxY - minY + 124 };
    }

    // Lays out again when the queues or machines changed; refits the camera
    // when it showed everything before.
    relayout() {
      const sig = this.sim.queues.map((q) => q.id).join(';') + '#' + this.sim.hosts.map((h) => h.id).join(';');
      if (sig === this.layoutSig) {
        for (const n of this.queueNode.values()) n.q = this.sim.queue(n.id) || n.q;
        for (const n of this.hostNode.values()) n.h = this.sim.hostById.get(n.id) || n.h;
        return;
      }
      const fitted = this.fittedOnce && this.isFitted();
      this.layout();
      if (fitted) this.fit();
    }

    isFitted() {
      const f = this.fitCam(this.bounds, 1.1);
      return Math.abs(f.s - this.target.s) / f.s < 0.08 && Math.abs(f.tx - this.target.tx) < 60 && Math.abs(f.ty - this.target.ty) < 60;
    }

    nodeBounds(n) {
      if (n.kind === 'coord') return { x: -COORD_R - 26, y: -COORD_R - 26, w: COORD_R * 2 + 52, h: COORD_R * 2 + 52 };
      return { x: n.x, y: n.y, w: n.w, h: n.kind === 'host' ? n.hh : n.h };
    }

    readTheme() {
      const cs = getComputedStyle(document.documentElement);
      const v = (name) => cs.getPropertyValue(name).trim();
      this.dark = cs.colorScheme ? cs.colorScheme.indexOf('dark') >= 0 : global.matchMedia('(prefers-color-scheme: dark)').matches;
      const theme = document.documentElement.getAttribute('data-theme');
      if (theme) this.dark = theme === 'dark';
      this.c = {
        bg: v('--canvas'), surface: v('--surface'), surface2: v('--surface-2'), surface3: v('--surface-3'),
        border: v('--border'), border2: v('--border-2'), text: v('--text'), text2: v('--text-2'), muted: v('--muted'),
        accent: v('--accent'), ok: v('--ok'), warn: v('--warn'), err: v('--err'), dot: v('--dot'),
        cache: v('--sc-cache'), headroom: v('--sc-headroom'), speed: v('--sc-speed'), cpu: v('--sc-cpu'), bigfit: v('--sc-bigfit'),
        barOk: v('--bar-ok'), barWarn: v('--bar-warn'), barErr: v('--bar-err'), ram: v('--spark-ram'),
      };
      this.font = v('--font') || 'system-ui, sans-serif';
      this.mono = v('--mono') || 'monospace';
      this.cs = cs;
      this.repoColors = new Map();
      this.sprites = new Map();
      this.lastFont = '';
    }

    // A repository's colour; a runner nothing here names is muted.
    color(repo) {
      if (!repo) return this.c.muted;
      const key = String(repo).toLowerCase();
      let c = this.repoColors.get(key);
      if (!c) { c = this.cs.getPropertyValue(B.repoVar(key)).trim() || this.c.accent; this.repoColors.set(key, c); }
      return c;
    }

    sprite(color) {
      let s = this.sprites.get(color);
      if (s) return s;
      s = document.createElement('canvas');
      s.width = s.height = 64;
      const g = s.getContext('2d');
      const grad = g.createRadialGradient(32, 32, 0, 32, 32, 32);
      grad.addColorStop(0, rgba(color, this.dark ? 0.9 : 0.6));
      grad.addColorStop(0.25, rgba(color, this.dark ? 0.45 : 0.28));
      grad.addColorStop(1, rgba(color, 0));
      g.fillStyle = grad;
      g.fillRect(0, 0, 64, 64);
      this.sprites.set(color, s);
      return s;
    }

    resize() {
      const r = this.canvas.getBoundingClientRect();
      this.dpr = Math.min(global.devicePixelRatio || 1, 2);
      this.w = r.width; this.h = r.height;
      this.canvas.width = Math.round(r.width * this.dpr);
      this.canvas.height = Math.round(r.height * this.dpr);
      if (this.mini) {
        const m = this.mini.getBoundingClientRect();
        this.mw = m.width; this.mh = m.height;
        this.mini.width = Math.round(m.width * this.dpr);
        this.mini.height = Math.round(m.height * this.dpr);
      }
      this.lastFont = '';
    }

    // ------------------------------------------------------------ camera
    fitCam(b, maxScale) {
      const ins = this.insets;
      const vw = Math.max(80, this.w - ins.left - ins.right);
      const vh = Math.max(80, this.h - ins.top - ins.bottom);
      const s = clamp(Math.min(vw / b.w, vh / b.h), 0.12, maxScale || 3);
      return { s, tx: ins.left + vw / 2 - (b.x + b.w / 2) * s, ty: ins.top + vh / 2 - (b.y + b.h / 2) * s };
    }

    fit(instant) { this.fittedOnce = true; this.flyTo(this.fitCam(this.bounds, 1.1), instant); }

    focusNode(n, instant) {
      const b = this.nodeBounds(n);
      const pad = n.kind === 'coord' ? 120 : 60;
      this.flyTo(this.fitCam({ x: b.x - pad, y: b.y - pad, w: b.w + pad * 2, h: b.h + pad * 2 }, 1.5), instant);
    }

    flyTo(to, instant) {
      this.vel.x = this.vel.y = 0;
      if (instant || this.reduced) {
        Object.assign(this.cam, to); Object.assign(this.target, to); this.flight = null; return;
      }
      const from = Object.assign({}, this.cam);
      // fly between centres in world space, zooming in log space with a small dip on long hops
      const cw = (c) => ({ x: (this.w / 2 - c.tx) / c.s, y: (this.h / 2 - c.ty) / c.s });
      const a = cw(from), b = cw(to);
      const dist = Math.hypot(a.x - b.x, a.y - b.y) * Math.min(from.s, to.s);
      this.flight = { from, to, a, b, t0: performance.now(), dur: clamp(520 + dist * 0.45, 520, 1100), dip: clamp(dist / 1800, 0, 0.35) };
    }

    zoomAt(sx, sy, factor) {
      this.flight = null;
      const t = this.target;
      const s = clamp(t.s * factor, 0.12, 3.2);
      const k = s / t.s;
      t.tx = sx - (sx - t.tx) * k;
      t.ty = sy - (sy - t.ty) * k;
      t.s = s;
      if (this.reduced) Object.assign(this.cam, t);
    }

    zoomBy(factor) { this.zoomAt(this.w / 2, this.h / 2, factor); }

    centerOn(wx, wy) {
      this.flight = null;
      this.target.tx = this.w / 2 - wx * this.target.s;
      this.target.ty = this.h / 2 - wy * this.target.s;
      if (this.reduced) Object.assign(this.cam, this.target);
    }

    updateCamera(dt) {
      if (this.flight) {
        const f = this.flight;
        const p = clamp((performance.now() - f.t0) / f.dur, 0, 1);
        const e = easeInOut(p);
        const ls = lerp(Math.log(f.from.s), Math.log(f.to.s), e) - f.dip * Math.sin(Math.PI * e);
        const s = Math.exp(ls);
        const cx = lerp(f.a.x, f.b.x, e), cy = lerp(f.a.y, f.b.y, e);
        this.cam.s = s; this.cam.tx = this.w / 2 - cx * s; this.cam.ty = this.h / 2 - cy * s;
        Object.assign(this.target, this.cam);
        if (p >= 1) { Object.assign(this.cam, f.to); Object.assign(this.target, f.to); this.flight = null; }
        return;
      }
      if (!this.drag && (Math.abs(this.vel.x) > 0.5 || Math.abs(this.vel.y) > 0.5)) {
        this.target.tx += this.vel.x * dt; this.target.ty += this.vel.y * dt;
        this.cam.tx += this.vel.x * dt; this.cam.ty += this.vel.y * dt;
        const k = Math.exp(-dt * 4.2);
        this.vel.x *= k; this.vel.y *= k;
      }
      const k = 1 - Math.exp(-dt * 14);
      const c = this.cam, t = this.target;
      // interpolate scale in log space and keep the zoom anchor stable
      c.s = Math.exp(lerp(Math.log(c.s), Math.log(t.s), k));
      c.tx = lerp(c.tx, t.tx, k);
      c.ty = lerp(c.ty, t.ty, k);
    }

    toWorld(sx, sy) { return { x: (sx - this.cam.tx) / this.cam.s, y: (sy - this.cam.ty) / this.cam.s }; }

    // ------------------------------------------------------------- input
    bindInput() {
      const cv = this.canvas;
      cv.addEventListener('pointerdown', (e) => {
        cv.setPointerCapture(e.pointerId);
        this.pointers.set(e.pointerId, { x: e.offsetX, y: e.offsetY });
        this.flight = null;
        if (this.pointers.size === 1) {
          this.drag = { x: e.offsetX, y: e.offsetY, sx: e.offsetX, sy: e.offsetY, t: performance.now(), moved: false, vx: 0, vy: 0 };
          this.vel.x = this.vel.y = 0;
        } else if (this.pointers.size === 2) {
          const [p, q] = [...this.pointers.values()];
          this.pinch = { d: Math.hypot(p.x - q.x, p.y - q.y), mx: (p.x + q.x) / 2, my: (p.y + q.y) / 2 };
          if (this.drag) this.drag.moved = true;
        }
      });
      cv.addEventListener('pointermove', (e) => {
        const p = this.pointers.get(e.pointerId);
        if (p) { p.x = e.offsetX; p.y = e.offsetY; }
        if (this.pointers.size === 2 && this.pinch) {
          const [a, b] = [...this.pointers.values()];
          const d = Math.hypot(a.x - b.x, a.y - b.y);
          const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
          this.target.tx += mx - this.pinch.mx; this.target.ty += my - this.pinch.my;
          this.cam.tx += mx - this.pinch.mx; this.cam.ty += my - this.pinch.my;
          this.zoomAt(mx, my, d / Math.max(1, this.pinch.d));
          Object.assign(this.cam, this.target);
          this.pinch = { d, mx, my };
          return;
        }
        if (this.drag && this.pointers.size === 1) {
          const dx = e.offsetX - this.drag.x, dy = e.offsetY - this.drag.y;
          if (!this.drag.moved && Math.hypot(e.offsetX - this.drag.sx, e.offsetY - this.drag.sy) > 4) {
            this.drag.moved = true;
            cv.classList.add('is-grabbing');
          }
          if (this.drag.moved) {
            const now = performance.now();
            const dt = Math.max(1, now - this.drag.t) / 1000;
            this.drag.vx = lerp(this.drag.vx, dx / dt, 0.35);
            this.drag.vy = lerp(this.drag.vy, dy / dt, 0.35);
            this.drag.t = now;
            this.cam.tx += dx; this.cam.ty += dy;
            this.target.tx = this.cam.tx; this.target.ty = this.cam.ty; this.target.s = this.cam.s;
          }
          this.drag.x = e.offsetX; this.drag.y = e.offsetY;
          return;
        }
        const hit = this.hitTest(e.offsetX, e.offsetY);
        this.setHover(hit, e.offsetX, e.offsetY);
      });
      const up = (e) => {
        this.pointers.delete(e.pointerId);
        if (this.pointers.size < 2) this.pinch = null;
        if (this.pointers.size === 0 && this.drag) {
          const d = this.drag;
          this.drag = null;
          cv.classList.remove('is-grabbing');
          if (!d.moved) {
            const hit = this.hitTest(e.offsetX, e.offsetY);
            this.select(hit);
          } else if (!this.reduced && performance.now() - d.t < 90) {
            this.vel.x = clamp(d.vx, -2600, 2600); this.vel.y = clamp(d.vy, -2600, 2600);
          }
        }
      };
      cv.addEventListener('pointerup', up);
      cv.addEventListener('pointercancel', up);
      cv.addEventListener('pointerleave', () => { if (!this.drag) this.setHover(null); });
      cv.addEventListener('dblclick', (e) => {
        const hit = this.hitTest(e.offsetX, e.offsetY);
        const node = hit && this.nodeOf(hit);
        if (node) this.focusNode(node); else this.fit();
      });
      cv.addEventListener('wheel', (e) => {
        e.preventDefault();
        this.vel.x = this.vel.y = 0;
        const pixel = e.deltaMode === 0;
        const zoom = e.ctrlKey || !pixel || (Math.abs(e.deltaY) >= 40 && Math.abs(e.deltaX) < 1 && Number.isInteger(e.deltaY));
        if (zoom) {
          const dy = pixel ? e.deltaY : e.deltaY * 40;
          this.zoomAt(e.offsetX, e.offsetY, Math.exp(-dy * (e.ctrlKey ? 0.01 : 0.0016)));
        } else {
          this.flight = null;
          this.target.tx -= e.deltaX; this.target.ty -= e.deltaY;
        }
      }, { passive: false });
      cv.addEventListener('keydown', (e) => {
        const step = 80;
        if (e.key === 'ArrowLeft') this.target.tx += step;
        else if (e.key === 'ArrowRight') this.target.tx -= step;
        else if (e.key === 'ArrowUp') this.target.ty += step;
        else if (e.key === 'ArrowDown') this.target.ty -= step;
        else return;
        this.flight = null;
        e.preventDefault();
      });
      if (this.mini) {
        const move = (e) => {
          const m = this.miniMap;
          if (!m) return;
          this.centerOn((e.offsetX - m.ox) / m.k, (e.offsetY - m.oy) / m.k);
        };
        this.mini.addEventListener('pointerdown', (e) => { this.mini.setPointerCapture(e.pointerId); this.miniDrag = true; move(e); });
        this.mini.addEventListener('pointermove', (e) => { if (this.miniDrag) move(e); });
        this.mini.addEventListener('pointerup', () => { this.miniDrag = false; });
        this.mini.addEventListener('pointercancel', () => { this.miniDrag = false; });
      }
    }

    setHover(hit, sx, sy) {
      const same = (a, b) => (a && b ? a.kind === b.kind && a.id === b.id : a === b);
      const changed = !same(hit, this.hover);
      this.hover = hit;
      this.canvas.classList.toggle('is-pointing', !!hit);
      if (this.onHover) this.onHover(hit, sx, sy, changed);
    }

    select(hit) {
      this.selected = hit;
      if (this.onSelect) this.onSelect(hit);
    }

    nodeOf(hit) {
      if (!hit) return null;
      if (hit.kind === 'host') return this.hostNode.get(hit.id);
      if (hit.kind === 'queue') return this.queueNode.get(hit.id);
      if (hit.kind === 'coord') return this.coord;
      if (hit.kind === 'github') return this.github;
      if (hit.kind === 'job') {
        const j = this.sim.jobs.get(hit.id);
        if (j && j.host && (j.state === 'running' || j.state === 'starting')) return this.hostNode.get(j.host);
        if (j) return this.queueNode.get(j.queue);
      }
      return null;
    }

    hitTest(sx, sy) {
      const p = this.toWorld(sx, sy);
      const s = this.cam.s;
      // tokens in flight first: small, on top
      const r = 12 / s;
      for (const [id, tk] of this.tokens) {
        if (tk.kind !== 'job' || !tk.pos) continue;
        if (Math.hypot(tk.pos.x - p.x, tk.pos.y - p.y) < r) return { kind: 'job', id };
      }
      for (const n of this.hostNode.values()) {
        if (p.x < n.x || p.x > n.x + n.w || p.y < n.y || p.y > n.y + n.hh) continue;
        if (s > 0.42) {
          for (let i = 0; i < n.h.slots; i++) {
            const b = this.slotRect(n, i);
            const jid = n.h.slotJobs[i];
            if (jid != null && p.x >= b.x && p.x <= b.x + b.w && p.y >= b.y && p.y <= b.y + b.h) return { kind: 'job', id: jid };
          }
        }
        return { kind: 'host', id: n.id };
      }
      for (const n of this.queueNode.values()) {
        if (p.x < n.x || p.x > n.x + n.w || p.y < n.y || p.y > n.y + n.h) continue;
        if (s > 0.42) {
          const jobs = this.queueJobs(n.q);
          for (let i = 0; i < Math.min(jobs.length, 12); i++) {
            const b = this.queueChipRect(n, i);
            if (p.x >= b.x - 2 && p.x <= b.x + b.w + 2 && p.y >= b.y - 3 && p.y <= b.y + b.h + 3) return { kind: 'job', id: jobs[i].id };
          }
        }
        return { kind: 'queue', id: n.id };
      }
      if (Math.hypot(p.x, p.y) < COORD_R + 14) return { kind: 'coord', id: 'coordinator' };
      const g = this.github;
      if (p.x >= g.x && p.x <= g.x + g.w && p.y >= g.y && p.y <= g.y + g.h) return { kind: 'github', id: 'github' };
      return null;
    }

    slotRect(n, i) {
      const slots = n.h.slots;
      const avail = 184;
      const gap = 6;
      const w = Math.min(46, (avail - gap * (slots - 1)) / slots);
      return { x: n.x + 16 + i * (w + gap), y: n.y + 55, w, h: 26 };
    }

    queueChipRect(n, i) { return { x: n.x + 18 + i * 15, y: n.y + 66, w: 11, h: 11 }; }

    queueJobs(q) {
      const t = this.sim.t;
      const list = [];
      for (const j of this.sim.jobs.values()) {
        if (j.queue !== q.id) continue;
        if (j.state === 'queued' && !(j.return_t > t)) list.push(j);
      }
      return list.sort((a, b) => a.queued_t - b.queued_t);
    }

    // ------------------------------------------------------------ events
    token(jobId, kind) {
      let tk = this.tokens.get(jobId);
      if (!tk) {
        const j = this.sim.jobs.get(jobId);
        tk = { kind: kind || 'job', segs: [], color: j ? this.color(j.repository) : this.c.muted, repo: j && j.repository, removeAt: Infinity, hold: null, pos: null };
        this.tokens.set(jobId, tk);
      }
      return tk;
    }

    onEvent(ev) {
      const t = ev.t;
      switch (ev.type) {
        case 'webhook': {
          const tk = this.token(ev.job);
          tk.segs.push({ edge: 'gh:' + ev.queue, t0: t, dur: PACE.webhook, dir: 1 });
          tk.removeAt = t + PACE.webhook;
          this.ghPulses.push(t);
          if (this.ghPulses.length > 12) this.ghPulses.shift();
          break;
        }
        case 'queued': { const tk = this.tokens.get(ev.job); if (tk) tk.removeAt = t; break; }
        case 'pick': {
          const tk = this.token(ev.job);
          tk.segs = [{ edge: 'qc:' + ev.queue, t0: t, dur: PACE.pick, dir: 1 }];
          tk.removeAt = Infinity; tk.hold = 'orbit'; tk.holdFrom = t + PACE.pick;
          break;
        }
        case 'decision': {
          for (const f of this.fx) f.end = Math.min(f.end, t + 0.4);
          this.fx.push({ d: ev.decision, t0: t, offers: [], end: Infinity, job: ev.job });
          break;
        }
        case 'offered': {
          const f = this.fxFor(ev.decision);
          if (f) f.offers.push({ host: ev.host, t, outcome: 'offered', tEnd: null, reason: null });
          const tk = this.token(ev.job);
          tk.segs = [{ edge: 'ch:' + ev.host, t0: t, dur: PACE.offer, dir: 1 }];
          tk.hold = 'end';
          break;
        }
        case 'accepted': {
          const f = this.fxFor(ev.decision);
          if (f) { const o = f.offers[f.offers.length - 1]; if (o) { o.outcome = 'accepted'; o.tEnd = t; } f.end = t + 1.6; }
          const tk = this.tokens.get(ev.job); if (tk) tk.removeAt = t;
          this.hostFx.set(ev.host, { kind: 'ok', t0: t, text: 'accepted' });
          break;
        }
        case 'refused':
        case 'unanswered': {
          const f = this.fxFor(ev.decision);
          if (f) { const o = f.offers[f.offers.length - 1]; if (o) { o.outcome = ev.type; o.tEnd = t; o.reason = ev.reason || 'unanswered'; } }
          const tk = this.token(ev.job);
          tk.segs = [{ edge: 'ch:' + ev.host, t0: t, dur: PACE.bounce, dir: -1 }];
          tk.hold = 'orbit'; tk.holdFrom = t + PACE.bounce;
          this.hostFx.set(ev.host, { kind: 'err', t0: t, text: ev.type === 'refused' ? 'refused · ' + (REASON_TEXT[ev.reason] || ev.reason) : 'no answer' });
          break;
        }
        case 'requeued': {
          const f = this.fxFor(ev.decision);
          if (f) f.end = t + 1.8;
          const tk = this.token(ev.job);
          tk.segs = [{ edge: 'qc:' + ev.queue, t0: t, dur: PACE.pick, dir: -1 }];
          tk.hold = null; tk.removeAt = t + PACE.pick;
          this.blockFx.set(ev.queue, { reason: ev.reason, refusal: ev.refusal, t0: t, filtered: [], scores: [] });
          break;
        }
        case 'blocked':
          this.blockFx.set(ev.queue, { reason: ev.reason, t0: t, filtered: ev.filtered, scores: ev.scores });
          break;
        case 'wake': {
          const wj = this.sim.jobs.get(ev.job);
          this.wakeFx.push({ queue: ev.queue, hosts: ev.hosts, t0: t, claim: null, job: ev.job, repo: wj && wj.repository });
          if (this.wakeFx.length > 6) this.wakeFx.shift();
          const tk = this.token(ev.job);
          tk.segs = [{ edge: 'qc:' + ev.queue, t0: t, dur: PACE.pick, dir: 1 }];
          tk.removeAt = Infinity; tk.hold = 'orbit'; tk.holdFrom = t + PACE.pick;
          break;
        }
        case 'wake_claim': {
          const w = this.wakeFx.find((x) => x.job === ev.job);
          if (w) { w.claim = ev.host; w.tClaim = t; }
          const tk = this.token(ev.job);
          tk.segs = [{ edge: 'ch:' + ev.host, t0: t, dur: PACE.offer, dir: 1 }];
          tk.hold = null; tk.removeAt = t + PACE.offer;
          break;
        }
        case 'finished': {
          this.finished.push({ host: ev.host, slot: ev.slot, t0: t });
          const tk = { kind: 'stats', segs: [{ edge: 'ch:' + ev.host, t0: t, dur: PACE.stats, dir: -1 }], color: this.c.ok, removeAt: t + PACE.stats, hold: null, pos: null };
          this.tokens.set('s' + ev.seq, tk);
          this.hostFx.set(ev.host, { kind: 'done', t0: t, text: 'finished · ' + secs(ev.duration) });
          break;
        }
        case 'host':
          this.hostFx.set(ev.host, { kind: 'info', t0: t, text: ev.change });
          break;
        default:
      }
    }

    fxFor(decisionId) {
      for (let i = this.fx.length - 1; i >= 0; i--) if (this.fx[i].d.id === decisionId) return this.fx[i];
      return null;
    }

    currentFx() { return this.fx.length ? this.fx[this.fx.length - 1] : null; }

    // ------------------------------------------------------------ render
    render(dt) {
      this.updateCamera(dt);
      const ctx = this.ctx;
      const t = this.sim.t;
      const { s, tx, ty } = this.cam;
      const dpr = this.dpr;
      this.lastFont = '';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.fillStyle = this.c.bg;
      ctx.fillRect(0, 0, this.w, this.h);
      ctx.setTransform(dpr * s, 0, 0, dpr * s, dpr * tx, dpr * ty);
      this.mid = smooth(0.24, 0.32, s);
      this.near = smooth(0.92, 1.2, s);
      this.drawGrid();
      this.drawLanes();
      this.drawBaseEdges(t);
      this.drawWake(t);
      this.drawBlocked(t);
      this.drawDecisionEdges(t);
      this.drawGithub(t);
      for (const n of this.queueNode.values()) this.drawQueue(n, t);
      this.drawCoordinator(t);
      for (const n of this.hostNode.values()) this.drawHost(n, t);
      this.drawDecisionBadges(t);
      this.drawHostFx(t);
      this.drawTokens(t);
      this.cleanup(t);
      if (this.mctx) this.drawMinimap(t);
    }

    setFont(size, weight, mono) {
      const f = (weight || 400) + ' ' + size.toFixed(2) + 'px ' + (mono ? this.mono : this.font);
      if (f !== this.lastFont) { this.ctx.font = f; this.lastFont = f; }
    }

    // `text` cut with an ellipsis to `max` wide in the current font.
    clip(text, max, size) {
      const ctx = this.ctx;
      if (size) this.setFont(size, 500);
      text = String(text);
      if (ctx.measureText(text).width <= max) return text;
      let lo = 0, hi = text.length;
      while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (ctx.measureText(text.slice(0, mid) + '…').width <= max) lo = mid; else hi = mid - 1; }
      return text.slice(0, lo) + '…';
    }
    fitText(text, x, y, max) { this.ctx.fillText(this.clip(text, Math.max(10, max)), x, y); }

    rr(x, y, w, h, r) {
      const ctx = this.ctx;
      r = Math.min(r, w / 2, h / 2);
      ctx.beginPath();
      ctx.moveTo(x + r, y);
      ctx.arcTo(x + w, y, x + w, y + h, r);
      ctx.arcTo(x + w, y + h, x, y + h, r);
      ctx.arcTo(x, y + h, x, y, r);
      ctx.arcTo(x, y, x + w, y, r);
      ctx.closePath();
    }

    /** A pill label sized in screen pixels, wherever the camera is. */
    chip(x, y, text, fg, bg, opts) {
      const o = opts || {};
      const ctx = this.ctx;
      const k = 1 / this.cam.s * (o.scale || 1);
      const fs = (o.size || 11) * k;
      this.setFont(fs, o.weight || 600, o.mono);
      const tw = ctx.measureText(text).width;
      const px = 6 * k, h = fs + 7 * k;
      const w = tw + px * 2;
      let x0 = x - w / 2;
      if (o.align === 'left') x0 = x;
      if (o.align === 'right') x0 = x - w;
      const y0 = y - h / 2;
      this.rr(x0, y0, w, h, h / 2);
      ctx.fillStyle = bg;
      ctx.fill();
      if (o.stroke) { ctx.strokeStyle = o.stroke; ctx.lineWidth = 1 * k; ctx.stroke(); }
      ctx.fillStyle = fg;
      ctx.textAlign = 'left';
      ctx.textBaseline = 'middle';
      ctx.fillText(text, x0 + px, y + 0.5 * k);
      return { x: x0, y: y0, w, h };
    }

    drawGrid() {
      const ctx = this.ctx;
      const s = this.cam.s;
      let step = 40;
      while (step * s < 18) step *= 2;
      // one dot per tile, repeated by a pattern in device pixels (far cheaper than a dot per rect)
      const dpr = this.dpr;
      const tile = Math.max(4, Math.round(step * s * dpr));
      const key = tile + '|' + this.c.dot;
      if (this.gridKey !== key) {
        const cv = this.gridTile || (this.gridTile = document.createElement('canvas'));
        cv.width = cv.height = tile;
        const g = cv.getContext('2d');
        g.clearRect(0, 0, tile, tile);
        g.fillStyle = this.c.dot;
        const d = Math.max(1, Math.round(1.4 * dpr));
        g.fillRect(0, 0, d, d);
        this.gridPattern = ctx.createPattern(cv, 'repeat');
        this.gridKey = key;
      }
      ctx.save();
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      const ox = ((this.cam.tx * dpr) % tile + tile) % tile, oy = ((this.cam.ty * dpr) % tile + tile) % tile;
      ctx.translate(ox, oy);
      ctx.fillStyle = this.gridPattern;
      ctx.fillRect(-ox, -oy, this.canvas.width, this.canvas.height);
      ctx.restore();
      // a soft glow under the coordinator
      const g = ctx.createRadialGradient(0, 0, 40, 0, 0, 520);
      g.addColorStop(0, rgba(this.c.accent, this.dark ? 0.1 : 0.07));
      g.addColorStop(1, rgba(this.c.accent, 0));
      ctx.fillStyle = g;
      ctx.fillRect(-520, -520, 1040, 1040);
    }

    drawLanes() {
      const ctx = this.ctx;
      const k = 1 / this.cam.s;
      const top = this.bounds.y + 22;
      const lanes = [
        [this.github.x + this.github.w / 2, 'WEBHOOKS', 'GitHub workflow_job'],
        [-500, 'POOL QUEUES', 'repository + labels'],
        [0, 'COORDINATOR', 'filter · estimate · score'],
        [HOST_X + HOST_ARC + HOST_W / 2 - 30, 'MACHINES', 'connected hosts'],
      ];
      if (this.mid < 0.05) return;
      ctx.globalAlpha = this.mid;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'alphabetic';
      for (const [x, title, sub] of lanes) {
        this.setFont(10.5 * k, 650);
        ctx.fillStyle = this.c.muted;
        if (ctx.letterSpacing !== undefined) ctx.letterSpacing = (1.2 * k).toFixed(2) + 'px';
        ctx.fillText(title, x, top);
        if (ctx.letterSpacing !== undefined) ctx.letterSpacing = '0px';
        this.setFont(11 * k, 450);
        ctx.fillStyle = rgba(this.c.muted, 0.75);
        ctx.fillText(sub, x, top + 15 * k);
      }
      ctx.globalAlpha = 1;
    }

    strokeEdge(e, width, color, dash, offset) {
      const ctx = this.ctx;
      ctx.beginPath();
      ctx.moveTo(e[0], e[1]);
      ctx.bezierCurveTo(e[2], e[3], e[4], e[5], e[6], e[7]);
      ctx.lineWidth = width;
      ctx.strokeStyle = color;
      if (dash) { ctx.setLineDash(dash); ctx.lineDashOffset = offset || 0; }
      ctx.stroke();
      if (dash) ctx.setLineDash([]);
    }

    drawBaseEdges(t) {
      const k = 1 / this.cam.s;
      const base = rgba(this.c.text, this.dark ? 0.09 : 0.1);
      for (const node of this.queueNode.values()) {
        const active = this.queueJobs(node.q).length > 0;
        this.strokeEdge(this.edges.get('gh:' + node.id), Math.max(1, 1.2 * k), base);
        this.strokeEdge(this.edges.get('qc:' + node.id), Math.max(1.4, 1.4 * k),
          active ? rgba(this.color(node.q.repository), this.dark ? 0.34 : 0.4) : base);
      }
      for (const node of this.hostNode.values()) {
        this.strokeEdge(this.edges.get('ch:' + node.id), Math.max(1, 1.1 * k), rgba(this.c.text, this.dark ? 0.06 : 0.07));
      }
    }

    /** The probe fan of the current decision (and of a pinned one). */
    drawDecisionEdges(t) {
      const list = this.pinned ? [{ d: this.pinned, t0: -1e9, offers: this.pinned.attempts.map((a) => ({ host: a.host_id, t: -1e9, outcome: a.outcome, tEnd: -1e9, reason: a.reason })), end: Infinity, pinned: true }] : this.fx;
      const ctx = this.ctx;
      const k = 1 / this.cam.s;
      for (const f of list) {
        const age = t - f.t0;
        const fade = f.pinned ? 1 : clamp(1 - (t - f.end) / 0.8, 0, 1);
        if (fade <= 0) continue;
        const d = f.d;
        // filtered: dashed red
        const scanP = f.pinned ? 1 : easeOut(clamp(age / PACE.scan, 0, 1));
        for (const fl of d.filtered) {
          const e = this.edges.get('ch:' + fl.host_id);
          if (!e) continue;
          const c = subCurve(e, 0, scanP);
          const col = fl.reason === 'not_connected' ? rgba(this.c.muted, 0.5 * fade) : rgba(this.c.err, 0.62 * fade);
          this.strokeEdge(c, Math.max(1.2 * k, 1.6), col, [7, 6], f.pinned ? 0 : -age * 18);
        }
        // candidates: grow with score
        const n = d.scores.length;
        d.scores.forEach((sc, rank) => {
          const e = this.edges.get('ch:' + sc.host_id);
          if (!e) return;
          const start = PACE.scan * 0.6 + rank * 0.09;
          const p = f.pinned ? 1 : easeOut(clamp((age - start) / (PACE.score * 0.6), 0, 1));
          if (p <= 0) return;
          const norm = clamp(sc.total / this.scoreScale(), 0, 1);
          if (!sc.fits) {
            this.strokeEdge(subCurve(e, 0, p), Math.max(1.2 * k, 1.6), rgba(this.c.err, 0.6 * fade), [7, 6], -age * 18);
            return;
          }
          const offer = f.offers.find((o) => o.host === sc.host_id);
          const width = 2 + 9 * norm;
          let col = rgba(this.c.accent, (0.22 + 0.55 * norm) * fade);
          if (offer && offer.outcome === 'accepted') col = rgba(this.c.ok, 0.4 * fade);
          if (offer && (offer.outcome === 'refused' || offer.outcome === 'unanswered')) col = rgba(this.c.err, 0.35 * fade);
          this.strokeEdge(subCurve(e, 0, p), width, col);
          // a scanning pulse while scoring
          if (!f.pinned && !this.reduced && age < PACE.scan + PACE.score && p >= 1) {
            const ph = ((age * 0.9 + rank * 0.13) % 1);
            const seg = subCurve(e, Math.max(0, ph - 0.12), ph);
            this.strokeEdge(seg, width + 1.5, rgba(this.c.accent, 0.55 * fade));
          }
          void n;
        });
        // the offer currently travelling or settled
        for (const o of f.offers) {
          const e = this.edges.get('ch:' + o.host);
          if (!e) continue;
          const oa = t - o.t;
          let col = this.c.accent;
          let alpha = 0.95;
          if (o.outcome === 'accepted') col = this.c.ok;
          if (o.outcome === 'refused' || o.outcome === 'unanswered') { col = this.c.err; alpha = clamp(1 - (t - o.tEnd) / 1.2, 0.2, 1); }
          const p = f.pinned ? 1 : easeInOut(clamp(oa / PACE.offer, 0, 1));
          const c = subCurve(e, 0, p);
          ctx.save();
          if (this.dark) ctx.globalCompositeOperation = 'lighter';
          this.strokeEdge(c, 10, rgba(col, 0.16 * alpha * fade));
          this.strokeEdge(c, 3.2, rgba(col, alpha * fade));
          ctx.restore();
        }
      }
    }

    // The most a host can score: the positive weights, in thousandths.
    scoreScale() {
      const W = this.sim.weights;
      return Math.max(1000, (W.cache + W.headroom + W.speed + W.cpu) * 1000);
    }

    drawDecisionBadges(t) {
      const list = this.pinned ? [{ d: this.pinned, t0: -1e9, end: Infinity, pinned: true, offers: [] }] : this.fx.slice(-1);
      for (const f of list) {
        const age = t - f.t0;
        const fade = f.pinned ? 1 : clamp(1 - (t - f.end) / 0.8, 0, 1);
        if (fade <= 0.02) continue;
        const d = f.d;
        const ctx = this.ctx;
        ctx.globalAlpha = fade;
        for (const fl of d.filtered) {
          if (!f.pinned && age < PACE.scan * 0.7) continue;
          const e = this.edges.get('ch:' + fl.host_id);
          if (!e) continue;
          const p = bz(e, 0.56);
          const muted = fl.reason === 'not_connected';
          this.chip(p.x, p.y, filterText(fl), muted ? this.c.muted : this.c.err,
            muted ? this.c.surface2 : this.mixSurface(this.c.err, 0.16), { stroke: muted ? this.c.border2 : rgba(this.c.err, 0.35) });
        }
        d.scores.forEach((sc, rank) => {
          const start = PACE.scan * 0.6 + rank * 0.09 + PACE.score * 0.45;
          if (!f.pinned && age < start) return;
          const e = this.edges.get('ch:' + sc.host_id);
          if (!e) return;
          const p = bz(e, 0.8);
          const text = sc.fits ? '#' + (rank + 1) + '  ' + (sc.total / 1000).toFixed(2) : 'no memory fit';
          const isWin = d.chosen === sc.host_id;
          const fg = !sc.fits ? this.c.err : isWin ? (this.dark ? '#0a0b0d' : '#ffffff') : this.c.text;
          const bg = !sc.fits ? this.mixSurface(this.c.err, 0.16) : isWin ? this.c.accent : this.c.surface;
          const box = this.chip(p.x, p.y - 16 / this.cam.s, text, fg, bg, { stroke: isWin ? null : this.c.border2, size: 11.5 });
          if (sc.fits && this.mid > 0.2) this.miniStack(box.x, box.y + box.h + 3 / this.cam.s, box.w, sc);
        });
        ctx.globalAlpha = 1;
      }
    }

    /** A tiny stacked bar of the score parts under a rank chip. */
    miniStack(x, y, w, sc) {
      const ctx = this.ctx;
      const k = 1 / this.cam.s;
      const h = 4 * k;
      const total = this.scoreScale();
      const parts = [['cache', sc.cache], ['headroom', sc.headroom], ['speed', Math.max(0, sc.speed)], ['cpu', sc.cpu]];
      let cx = x;
      for (const [name, v] of parts) {
        const pw = (v / total) * w;
        if (pw <= 0) continue;
        ctx.fillStyle = this.c[name];
        ctx.fillRect(cx, y, Math.max(0, pw - 0.8 * k), h);
        cx += pw;
      }
      if (sc.bigfit > 0) {
        const pw = (sc.bigfit / total) * w;
        ctx.fillStyle = this.c.bigfit;
        ctx.fillRect(cx - pw, y + h + 1 * k, pw, h * 0.7);
      }
    }

    mixSurface(color, a) {
      // an opaque tint of `color` over the surface, so chips stay legible over edges
      const key = 'mix|' + color + '|' + a + '|' + this.c.surface;
      let out = colorCache.get(key);
      if (out) return out;
      const parse = (c) => {
        const r = rgba(c, 1).match(/rgba\(([^)]+)\)/)[1].split(',').map(Number);
        return r;
      };
      const p = parse(color), q = parse(this.c.surface);
      out = 'rgb(' + Math.round(lerp(q[0], p[0], a)) + ',' + Math.round(lerp(q[1], p[1], a)) + ',' + Math.round(lerp(q[2], p[2], a)) + ')';
      colorCache.set(key, out);
      return out;
    }

    drawWake(t) {
      const k = 1 / this.cam.s;
      for (const w of this.wakeFx) {
        const age = t - w.t0;
        const life = PACE.pick + PACE.offer + 1.2;
        if (age > life) continue;
        const fade = clamp(1 - (age - (life - 0.6)) / 0.6, 0, 1);
        for (const hid of w.hosts) {
          const e = this.edges.get('ch:' + hid);
          if (!e) continue;
          const p = easeOut(clamp((age - PACE.pick * 0.7) / 0.5, 0, 1));
          if (p <= 0) continue;
          const claimed = w.claim === hid;
          this.ctx.lineCap = 'round';
          this.strokeEdge(subCurve(e, 0, p), claimed ? 2.4 : Math.max(1.6, 1.4 * k),
            rgba(claimed ? this.color(w.repo) : this.c.muted, (claimed ? 0.8 : 0.55) * fade), claimed ? null : [1, 7], -age * 20);
          this.ctx.lineCap = 'butt';
          if (p >= 1 && !this.reduced) {
            const n = this.hostNode.get(hid);
            const rp = (age * 1.6) % 1;
            this.ctx.beginPath();
            this.ctx.arc(n.x, n.cy, 6 + rp * 26, 0, Math.PI * 2);
            this.ctx.strokeStyle = rgba(this.c.muted, (1 - rp) * 0.5 * fade);
            this.ctx.lineWidth = 1.5;
            this.ctx.stroke();
          }
        }
        if (age > PACE.pick * 0.7 && age < PACE.pick + 0.9) {
          this.ctx.globalAlpha = fade;
          this.chip(0, COORD_R + 44 / this.cam.s, 'wake · hosts decide', this.c.text2, this.c.surface2, { stroke: this.c.border2 });
          this.ctx.globalAlpha = 1;
        }
      }
    }

    drawBlocked(t) {
      for (const [qid, b] of this.blockFx) {
        const age = t - b.t0;
        if (age > 2.4) continue;
        const fade = clamp(1 - (age - 1.6) / 0.8, 0, 1);
        const e = this.edges.get('qc:' + qid);
        this.strokeEdge(e, 2.6, rgba(this.c.warn, 0.7 * fade), [6, 5], -age * 16);
        for (const fl of b.filtered || []) {
          if (fl.reason === 'not_connected') continue;
          const he = this.edges.get('ch:' + fl.host_id);
          if (he) this.strokeEdge(subCurve(he, 0, easeOut(clamp(age / 0.5, 0, 1))), 1.6, rgba(this.c.err, 0.45 * fade), [5, 6], -age * 16);
        }
        for (const sc of b.scores || []) {
          if (sc.fits) continue;
          const he = this.edges.get('ch:' + sc.host_id);
          if (he) this.strokeEdge(subCurve(he, 0, easeOut(clamp(age / 0.5, 0, 1))), 1.6, rgba(this.c.err, 0.45 * fade), [5, 6], -age * 16);
        }
      }
    }

    // ------------------------------------------------------------- nodes
    cardBase(x, y, w, h, r, opts) {
      const ctx = this.ctx;
      const o = opts || {};
      if (!this.dark) {
        ctx.save();
        ctx.shadowColor = 'rgba(16,24,40,0.10)';
        ctx.shadowBlur = 18 * this.cam.s * this.dpr;
        ctx.shadowOffsetY = 4 * this.cam.s * this.dpr;
        this.rr(x, y, w, h, r);
        ctx.fillStyle = o.fill || this.c.surface;
        ctx.fill();
        ctx.restore();
      } else {
        this.rr(x, y, w, h, r);
        ctx.fillStyle = o.fill || this.c.surface;
        ctx.fill();
      }
      ctx.lineWidth = o.borderWidth || Math.max(1, 1 / this.cam.s);
      ctx.strokeStyle = o.border || this.c.border2;
      if (o.dash) ctx.setLineDash(o.dash);
      ctx.stroke();
      if (o.dash) ctx.setLineDash([]);
    }

    isSel(kind, id) { return this.selected && this.selected.kind === kind && this.selected.id === id; }
    isHover(kind, id) { return this.hover && this.hover.kind === kind && this.hover.id === id; }

    ring(n, w, h, r) {
      const ctx = this.ctx;
      const k = 1 / this.cam.s;
      if (this.isSel(n.kind, n.id)) {
        this.rr(n.x - 5 * k, n.y - 5 * k, w + 10 * k, h + 10 * k, r + 5 * k);
        ctx.strokeStyle = this.c.accent;
        ctx.lineWidth = 2 * k;
        ctx.stroke();
      } else if (this.isHover(n.kind, n.id) || this.hotHost === n.id) {
        this.rr(n.x - 4 * k, n.y - 4 * k, w + 8 * k, h + 8 * k, r + 4 * k);
        ctx.strokeStyle = rgba(this.c.accent, 0.5);
        ctx.lineWidth = 1.5 * k;
        ctx.stroke();
      }
    }

    drawGithub(t) {
      const ctx = this.ctx;
      const g = this.github;
      this.cardBase(g.x, g.y, g.w, g.h, 18);
      this.ring(g, g.w, g.h, 18);
      // pulse per webhook
      for (const p of this.ghPulses) {
        const a = t - p;
        if (a < 0 || a > 0.9 || this.reduced) continue;
        this.rr(g.x - a * 14, g.y - a * 14, g.w + a * 28, g.h + a * 28, 18 + a * 14);
        ctx.strokeStyle = rgba(this.c.accent, 0.4 * (1 - a / 0.9));
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }
      const cx = g.x + g.w / 2;
      ctx.save();
      ctx.translate(cx - 19, g.y + 22);
      ctx.scale(38 / 16, 38 / 16);
      ctx.fillStyle = this.c.text;
      ctx.fill(ICONS.github);
      ctx.restore();
      ctx.textAlign = 'center';
      ctx.textBaseline = 'alphabetic';
      ctx.fillStyle = this.c.text;
      this.setFont(17, 650);
      ctx.fillText('GitHub', cx, g.y + 90);
      ctx.fillStyle = this.c.muted;
      this.setFont(11.5, 500, true);
      ctx.fillText('workflow_job', cx, g.y + 108);
      const rate = this.sim.events.filter((e) => e.type === 'webhook' && e.t > t - 60).length;
      this.setFont(22, 650);
      ctx.fillStyle = this.c.text;
      ctx.fillText(String(rate), cx - 14, g.y + 148);
      this.setFont(12, 500);
      ctx.fillStyle = this.c.muted;
      ctx.textAlign = 'left';
      ctx.fillText('/ min', cx + 2 + (rate >= 10 ? 6 : 0), g.y + 148);
      ctx.textAlign = 'center';
      this.setFont(10.5, 500);
      ctx.fillText('queued events', cx, g.y + 164);
    }

    drawQueue(n, t) {
      const ctx = this.ctx;
      const q = n.q;
      const color = this.color(q.repository);
      const jobs = this.queueJobs(q);
      const pending = this.sim.pendingQueue(q);
      const block = this.blockFx.get(q.id);
      const flash = block ? clamp(1 - (t - block.t0) / 1.6, 0, 1) : 0;
      const active = this.fx.length && this.currentFx().d.queue === q.id && t < this.currentFx().end;
      this.cardBase(n.x, n.y, n.w, n.h, 16, {
        border: flash > 0 ? rgba(this.c.warn, 0.35 + 0.5 * flash) : active ? rgba(color, 0.8) : this.c.border2,
        borderWidth: active || flash > 0 ? 2 : undefined,
      });
      this.ring(n, n.w, n.h, 16);
      // colour rail
      this.rr(n.x + 7, n.y + 16, 3.5, n.h - 32, 2);
      ctx.fillStyle = color;
      ctx.fill();
      const far = 1 - this.mid;
      ctx.textBaseline = 'alphabetic';
      if (this.mid > 0.01) {
        ctx.globalAlpha = this.mid;
        const name = shortRepo(q.repository);
        const owner = B.ownerOf(q.repository) + '/';
        ctx.textAlign = 'left';
        this.setFont(12.5, 500);
        ctx.fillStyle = this.c.muted;
        ctx.fillText(owner, n.x + 20, n.y + 30);
        const pw = ctx.measureText(owner).width;
        this.setFont(18, 650);
        ctx.fillStyle = this.c.text;
        this.fitText(name, n.x + 20 + pw, n.y + 30, n.w - 92 - pw);
        // labels
        this.setFont(11, 500, true);
        const lbl = this.clip(q.labels, n.w - 110);
        const lw = ctx.measureText(lbl).width;
        this.rr(n.x + 19, n.y + 39, lw + 12, 17, 5);
        ctx.fillStyle = this.c.surface2;
        ctx.fill();
        ctx.strokeStyle = this.c.border;
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.fillStyle = this.c.text2;
        ctx.fillText(lbl, n.x + 25, n.y + 51.5);
        // count
        ctx.textAlign = 'right';
        this.setFont(32, 680);
        ctx.fillStyle = jobs.length ? this.c.text : this.c.muted;
        ctx.fillText(String(jobs.length), n.x + n.w - 18, n.y + 42);
        this.setFont(11, 500);
        ctx.fillStyle = this.c.muted;
        ctx.fillText('queued', n.x + n.w - 18, n.y + 58);
        // queued job chips
        const shown = Math.min(jobs.length, 12);
        for (let i = 0; i < shown; i++) {
          const b = this.queueChipRect(n, i);
          const j = jobs[i];
          const wait = t - j.queued_t;
          this.rr(b.x, b.y, b.w, b.h, 3);
          ctx.fillStyle = rgba(color, i === 0 ? 1 : 0.78);
          ctx.fill();
          if (wait > 30 && !this.reduced) {
            ctx.strokeStyle = rgba(this.c.warn, 0.5 + 0.4 * Math.sin(t * 4));
            ctx.lineWidth = 1.5;
            ctx.stroke();
          }
          const sel = this.isSel('job', j.id) || this.isHover('job', j.id);
          if (sel) { this.rr(b.x - 2.5, b.y - 2.5, b.w + 5, b.h + 5, 4); ctx.strokeStyle = this.c.accent; ctx.lineWidth = 1.6; ctx.stroke(); }
        }
        ctx.textAlign = 'left';
        if (jobs.length > 12) {
          this.setFont(11, 600);
          ctx.fillStyle = this.c.text2;
          ctx.fillText('+' + (jobs.length - 12), n.x + 18 + 12 * 15 + 2, n.y + 76);
        }
        if (!jobs.length) {
          this.setFont(11.5, 450);
          ctx.fillStyle = rgba(this.c.muted, 0.8);
          ctx.fillText('nothing waiting', n.x + 20, n.y + 76);
        }
        // footer
        this.setFont(11.5, 500);
        ctx.fillStyle = this.c.muted;
        let foot = pending.oldest_wait_secs != null && jobs.length ? 'oldest ' + fmtWait(pending.oldest_wait_secs) : '';
        if (pending.leases) foot += (foot ? ' · ' : '') + pending.leases + ' on the way';
        if (!q.pool) foot = (foot ? foot + ' · ' : '') + 'non-pool';
        const reason = pending.reason;
        this.fitText(foot, n.x + 20, n.y + n.h - 13, reason || !q.pool ? n.w - 150 : n.w - 40);
        if (reason) {
          const text = (REASON_TEXT[reason] || reason) + (pending.refusal ? ' · ' + (REASON_TEXT[pending.refusal] || pending.refusal) : '');
          ctx.textAlign = 'right';
          this.setFont(10.5, 650);
          const tw = ctx.measureText(text).width;
          this.rr(n.x + n.w - 18 - tw - 12, n.y + n.h - 27, tw + 12, 18, 9);
          ctx.fillStyle = rgba(this.c.warn, this.dark ? 0.16 : 0.13);
          ctx.fill();
          ctx.fillStyle = this.c.warn;
          ctx.fillText(text, n.x + n.w - 24, n.y + n.h - 14);
        } else if (!q.pool) {
          ctx.textAlign = 'right';
          this.setFont(10.5, 600);
          ctx.fillStyle = this.c.muted;
          ctx.fillText('wake · host decides', n.x + n.w - 18, n.y + n.h - 13);
        }
        ctx.globalAlpha = 1;
      }
      if (far > 0.01) {
        ctx.save();
        this.rr(n.x, n.y, n.w, n.h, 16);
        ctx.clip();
        ctx.globalAlpha = far;
        const k = 1 / this.cam.s;
        ctx.textAlign = 'left';
        ctx.textBaseline = 'middle';
        this.setFont(Math.min(13 * k, 40), 650);
        ctx.fillStyle = this.c.text;
        this.fitText(shortRepo(q.repository), n.x + 22, n.cy, n.w - 80);
        ctx.textAlign = 'right';
        this.setFont(Math.min(18 * k, 60), 700);
        ctx.fillStyle = jobs.length ? color : this.c.muted;
        ctx.fillText(String(jobs.length), n.x + n.w - 16, n.cy);
        ctx.restore();
      }
    }

    drawCoordinator(t) {
      const ctx = this.ctx;
      const f = this.currentFx();
      const busy = this.sim.coordBusy || (f && t < f.end);
      const R = COORD_R;
      // weight ring: the five score parts, proportional to their weights
      const W = this.sim.weights;
      const parts = [['cache', W.cache], ['headroom', W.headroom], ['speed', W.speed], ['cpu', W.cpu], ['bigfit', W.bigfit]];
      const sum = parts.reduce((a, p) => a + p[1], 0);
      const gap = 0.05;
      let a0 = -Math.PI / 2;
      const spin = this.reduced ? 0 : t * 0.08;
      for (const [name, wgt] of parts) {
        const span = (wgt / sum) * Math.PI * 2;
        ctx.beginPath();
        ctx.arc(0, 0, R + 13, a0 + spin + gap, a0 + spin + span - gap);
        ctx.strokeStyle = rgba(this.c[name], busy ? 0.95 : 0.55);
        ctx.lineWidth = 5;
        ctx.lineCap = 'round';
        ctx.stroke();
        a0 += span;
      }
      ctx.lineCap = 'butt';
      // spinning scan ring while deciding
      if (busy) {
        const sp = this.reduced ? 0 : t * 2.2;
        ctx.beginPath();
        ctx.arc(0, 0, R + 26, sp, sp + Math.PI * 0.6);
        ctx.strokeStyle = rgba(this.c.accent, 0.55);
        ctx.lineWidth = 2;
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(0, 0, R + 26, sp + Math.PI, sp + Math.PI * 1.35);
        ctx.strokeStyle = rgba(this.c.accent, 0.3);
        ctx.stroke();
      }
      // disc
      if (!this.dark) {
        ctx.save();
        ctx.shadowColor = 'rgba(16,24,40,0.14)';
        ctx.shadowBlur = 24 * this.cam.s * this.dpr;
        ctx.shadowOffsetY = 6 * this.cam.s * this.dpr;
      }
      ctx.beginPath();
      ctx.arc(0, 0, R, 0, Math.PI * 2);
      ctx.fillStyle = this.c.surface;
      ctx.fill();
      if (!this.dark) ctx.restore();
      const g = ctx.createRadialGradient(0, -20, 10, 0, 0, R);
      g.addColorStop(0, rgba(this.c.accent, busy ? (this.dark ? 0.2 : 0.12) : 0.05));
      g.addColorStop(1, rgba(this.c.accent, 0));
      ctx.fillStyle = g;
      ctx.fill();
      ctx.lineWidth = this.isSel('coord', 'coordinator') ? 2.5 : 1.2;
      ctx.strokeStyle = this.isSel('coord', 'coordinator') ? this.c.accent : this.isHover('coord', 'coordinator') ? rgba(this.c.accent, 0.6) : this.c.border2;
      ctx.stroke();
      // text
      ctx.textAlign = 'center';
      ctx.textBaseline = 'alphabetic';
      if (ctx.letterSpacing !== undefined) ctx.letterSpacing = '1.4px';
      this.setFont(10, 650);
      ctx.fillStyle = this.c.muted;
      ctx.fillText('COORDINATOR', 0, -46);
      if (ctx.letterSpacing !== undefined) ctx.letterSpacing = '0px';
      let phase = 'Idle', sub = this.sim.counters.decisions + ' decisions', chip = null;
      if (f && t < f.end + 0.2) {
        const age = t - f.t0;
        const last = f.offers[f.offers.length - 1];
        if (age < PACE.scan) phase = 'Filtering';
        else if (age < PACE.scan + PACE.score) phase = 'Scoring';
        else if (last && last.outcome === 'offered') phase = 'Offering';
        else if (last && last.outcome === 'accepted') phase = 'Placed';
        else if (last && (last.outcome === 'refused' || last.outcome === 'unanswered')) phase = last.outcome === 'refused' ? 'Refused' : 'No answer';
        else if (f.d.outcome && f.d.outcome !== 'accepted') phase = 'Waiting';
        sub = this.clip(shortRepo(f.d.repository) + ' · ' + f.d.job_name, COORD_R * 1.7, 12.5);
        chip = f.d.method || null;
      } else if (this.sim.coordBusy) {
        phase = 'Picking';
        sub = '';
      }
      this.setFont(phase.length > 8 ? 20 : 22, 680);
      ctx.fillStyle = phase === 'Refused' || phase === 'No answer' ? this.c.err : phase === 'Placed' ? this.c.ok : this.c.text;
      ctx.fillText(phase, 0, -12);
      this.setFont(12.5, 500);
      ctx.fillStyle = this.c.text2;
      ctx.fillText(sub, 0, 10);
      if (chip) {
        this.setFont(11, 600, true);
        const tw = ctx.measureText(chip).width;
        this.rr(-tw / 2 - 8, 24, tw + 16, 19, 9.5);
        ctx.fillStyle = chip === 'weighted' ? rgba(this.c.accent, 0.14) : rgba(this.c.warn, 0.15);
        ctx.fill();
        ctx.fillStyle = chip === 'weighted' ? this.c.accent : this.c.warn;
        ctx.fillText(chip, 0, 37.5);
      } else {
        this.setFont(11, 500);
        ctx.fillStyle = this.c.muted;
        ctx.fillText(this.sim.counters.launches + ' launches · ' + this.sim.counters.accepted + ' accepted', 0, 36);
      }
      if (f && t < f.end && t - f.t0 < PACE.scan + PACE.score + 6) {
        this.setFont(11, 550);
        ctx.fillStyle = this.c.muted;
        const est = fmtBytes(f.d.estimate_bytes) + ' · ' + f.d.estimate_source;
        ctx.fillText(est, 0, 62);
      }
    }

    drawHost(n, t) {
      const ctx = this.ctx;
      const h = n.h;
      const x = n.x, y = n.y, w = n.w, hh = n.hh;
      const status = !h.online ? 'offline' : h.unfit ? 'unfit' : h.draining ? 'draining' : 'online';
      const stColor = { online: this.c.ok, draining: this.c.warn, unfit: this.c.err, offline: this.c.muted }[status];
      // decision tint
      const f = this.pinned ? { d: this.pinned, end: Infinity, offers: this.pinned.attempts.map((a) => ({ host: a.host_id, outcome: a.outcome })) } : this.currentFx();
      let border = this.c.border2, bw;
      if (f && (this.pinned || t < f.end + 0.4)) {
        const sc = f.d.scores.find((s) => s.host_id === h.id);
        const fl = f.d.filtered.find((s) => s.host_id === h.id);
        const offer = f.offers.find((o) => o.host === h.id);
        if (offer && offer.outcome === 'accepted') { border = this.c.ok; bw = 2; }
        else if (offer && offer.outcome === 'offered') { border = this.c.accent; bw = 2; }
        else if (offer) { border = this.c.err; bw = 2; }
        else if (sc && sc.fits) border = rgba(this.c.accent, 0.55);
        else if ((sc && !sc.fits) || (fl && fl.reason !== 'not_connected')) border = rgba(this.c.err, 0.45);
      }
      this.cardBase(x, y, w, hh, 16, {
        fill: status === 'offline' ? this.c.surface2 : this.c.surface,
        border: status === 'offline' ? this.c.border2 : border, borderWidth: bw,
        dash: status === 'offline' ? [6, 5] : null,
      });
      this.ring(n, w, hh, 16);
      const alpha = status === 'offline' ? 0.55 : 1;
      const far = 1 - this.mid;
      if (this.mid > 0.01) {
        ctx.globalAlpha = this.mid * alpha;
        this.osIcon(h.os, x + 14, y + 12, 20);
        ctx.textAlign = 'left';
        ctx.textBaseline = 'alphabetic';
        this.setFont(18, 650);
        ctx.fillStyle = this.c.text;
        this.fitText(h.name, x + 42, y + 28, w - 140);
        this.setFont(11.5, 500);
        ctx.fillStyle = this.c.muted;
        const sub = [h.arch, h.cores ? h.cores + ' cores' : null, h.ram_bytes ? Math.round(h.ram_bytes / GiB) + ' GiB' : null].filter(Boolean).join(' · ');
        ctx.fillText(sub, x + 42, y + 44);
        const subW = ctx.measureText(sub).width;
        // status pill
        this.setFont(11, 650);
        const tw = ctx.measureText(status).width;
        const px = x + w - 16 - tw - 22;
        this.rr(px, y + 12, tw + 22, 20, 10);
        ctx.fillStyle = rgba(stColor, this.dark ? 0.15 : 0.12);
        ctx.fill();
        ctx.beginPath();
        ctx.arc(px + 9, y + 22, 3, 0, Math.PI * 2);
        ctx.fillStyle = stColor;
        ctx.fill();
        ctx.fillText(status, px + 15, y + 26);
        // slots
        for (let i = 0; i < h.slots; i++) this.drawSlot(n, i, t);
        // rings
        const cpu = h.online ? h.cpu_load_percent : null;
        const ramUsed = h.online && h.ram_bytes && h.free_ram_bytes != null ? 1 - h.free_ram_bytes / h.ram_bytes : null;
        this.gauge(x + w - 80, y + 64, 16, cpu == null ? null : cpu / 100, 'CPU', cpu == null ? '–' : Math.round(cpu) + '',
          cpu != null && cpu >= 90 ? this.c.err : cpu != null && cpu >= 70 ? this.c.warn : this.c.barOk);
        this.gauge(x + w - 34, y + 64, 16, ramUsed, 'RAM', ramUsed == null ? '–' : Math.round(ramUsed * 100) + '',
          ramUsed != null && ramUsed >= 0.9 ? this.c.err : ramUsed != null && ramUsed >= 0.75 ? this.c.warn : this.c.ram);
        // bottom row: disk, warm repositories, last resort
        const by = y + hh - 14;
        const disk = h.disk_free_bytes;
        const low = disk != null && disk < (this.sim.minDisk || 10 * GiB);
        this.setFont(11, 500);
        ctx.fillStyle = low ? this.c.warn : this.c.muted;
        ctx.fillText(fmtBytes(disk) + ' free', x + 16, by + 4);
        let wx = x + 16 + ctx.measureText(fmtBytes(disk) + ' free').width + 12;
        if (h.warm_repos.length) {
          ctx.fillStyle = this.c.muted;
          ctx.fillText('warm', wx, by + 4);
          wx += ctx.measureText('warm').width + 6;
          for (const repo of h.warm_repos.slice(0, 4)) {
            this.rr(wx, by - 4, 9, 9, 2.5);
            ctx.fillStyle = this.color(repo);
            ctx.fill();
            wx += 12;
            if (this.near > 0.01) {
              ctx.globalAlpha = this.mid * alpha * this.near;
              this.setFont(10.5, 500);
              ctx.fillStyle = this.c.text2;
              const nm = shortRepo(repo);
              ctx.fillText(nm, wx, by + 4);
              wx += ctx.measureText(nm).width * this.near + 8 * this.near;
              ctx.globalAlpha = this.mid * alpha;
              this.setFont(11, 500);
            }
          }
        }
        const lr = low ? 'low_disk' : cpu != null && cpu >= (this.sim.cpuBusy || 90) ? 'cpu_busy' : null;
        if (lr && h.online) {
          this.setFont(10, 650, true);
          const lw = ctx.measureText(lr).width;
          const lx = x + 42 + subW + 8;
          this.rr(lx, y + 34, lw + 12, 15, 5);
          ctx.fillStyle = rgba(this.c.warn, this.dark ? 0.16 : 0.13);
          ctx.fill();
          ctx.fillStyle = this.c.warn;
          ctx.fillText(lr, lx + 6, y + 45);
        }
        if (this.near > 0.01) {
          // extra near detail: why not available
          ctx.globalAlpha = this.mid * alpha * this.near;
          this.setFont(10.5, 500);
          ctx.fillStyle = status === 'online' ? this.c.muted : stColor;
          const note = status === 'draining' ? 'draining: takes no new jobs' : status === 'unfit' ? 'unfit: a host doctor check fails' : status === 'offline' ? (h.last_seen_at ? 'last seen ' + fmtWait(this.sim.serverSecs() - h.last_seen_at) + ' ago' : 'not connected') : '';
          if (note) { ctx.textAlign = 'left'; ctx.fillText(note, x + 18, y + hh + 16); }
        }
        ctx.globalAlpha = 1;
      }
      if (far > 0.01) {
        ctx.save();
        this.rr(x, y, w, hh, 16);
        ctx.clip();
        ctx.globalAlpha = far * alpha;
        const k = 1 / this.cam.s;
        ctx.beginPath();
        ctx.arc(x + 22, n.cy, Math.min(6 * k, 22), 0, Math.PI * 2);
        ctx.fillStyle = stColor;
        ctx.fill();
        ctx.textAlign = 'left';
        ctx.textBaseline = 'middle';
        this.setFont(Math.min(13 * k, 44), 650);
        ctx.fillStyle = this.c.text;
        this.fitText(h.name, x + 22 + Math.min(14 * k, 46), n.cy, w - 60 - h.slots * Math.min(4.5 * k, 16) * 3);
        // slot pips
        const pr = Math.min(4.5 * k, 16);
        for (let i = 0; i < h.slots; i++) {
          const jid = h.slotJobs[i];
          const j = jid != null ? this.sim.jobs.get(jid) : null;
          const cx = x + w - 20 - (h.slots - 1 - i) * pr * 3;
          ctx.beginPath();
          ctx.arc(cx, n.cy, pr, 0, Math.PI * 2);
          if (j) { ctx.fillStyle = this.color(j.repository); ctx.fill(); }
          else { ctx.strokeStyle = this.c.border2; ctx.lineWidth = Math.min(1.5 * k, 5); ctx.stroke(); }
        }
        ctx.restore();
      }
    }

    drawSlot(n, i, t) {
      const ctx = this.ctx;
      const h = n.h;
      const b = this.slotRect(n, i);
      const jid = h.slotJobs[i];
      const j = jid != null ? this.sim.jobs.get(jid) : null;
      const usable = h.online && !h.unfit && !h.draining;
      this.rr(b.x, b.y, b.w, b.h, 6);
      if (!j || (j.dock_t && t < j.dock_t)) {
        ctx.fillStyle = usable ? this.c.surface2 : rgba(this.c.surface3, 0.6);
        ctx.fill();
        ctx.setLineDash([3, 3]);
        ctx.strokeStyle = this.c.border2;
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.setLineDash([]);
        // an offer on its way to this host: ghost slot
        const pending = !j && this.pendingOfferFor(h.id) && i === h.slotJobs.indexOf(null);
        if (pending) {
          this.rr(b.x, b.y, b.w, b.h, 6);
          ctx.strokeStyle = rgba(this.c.accent, this.reduced ? 0.8 : 0.5 + 0.4 * Math.sin(t * 10));
          ctx.lineWidth = 1.6;
          ctx.stroke();
        }
      } else {
        const color = this.color(j.repository);
        const prog = j.duration ? clamp((t - j.started_at) / j.duration, 0, 1) : null;
        if (j.state === 'starting') {
          ctx.fillStyle = rgba(color, 0.12);
          ctx.fill();
          ctx.setLineDash([4, 3]);
          ctx.lineDashOffset = this.reduced ? 0 : -t * 12;
          ctx.strokeStyle = color;
          ctx.lineWidth = 1.6;
          ctx.stroke();
          ctx.setLineDash([]);
          ctx.lineDashOffset = 0;
        } else {
          ctx.fillStyle = rgba(color, this.dark ? 0.22 : 0.18);
          ctx.fill();
          ctx.save();
          this.rr(b.x, b.y, b.w, b.h, 6);
          ctx.clip();
          ctx.fillStyle = rgba(color, this.dark ? 0.85 : 0.8);
          if (prog != null) ctx.fillRect(b.x, b.y, b.w * prog, b.h);
          else {
            // Its usual run time is not known: a full slot with a slow sheen.
            ctx.fillStyle = rgba(color, j.anonymous ? 0.45 : this.dark ? 0.7 : 0.65);
            ctx.fillRect(b.x, b.y, b.w, b.h);
            if (!this.reduced) {
              const p = ((t * 0.35) + (i * 0.27)) % 1;
              const gr = ctx.createLinearGradient(b.x + b.w * (p * 2 - 1), 0, b.x + b.w * p * 2, 0);
              gr.addColorStop(0, 'rgba(255,255,255,0)');
              gr.addColorStop(0.5, 'rgba(255,255,255,' + (this.dark ? 0.16 : 0.28) + ')');
              gr.addColorStop(1, 'rgba(255,255,255,0)');
              ctx.fillStyle = gr;
              ctx.fillRect(b.x, b.y, b.w, b.h);
            }
          }
          ctx.restore();
        }
        if (this.near > 0.01) {
          ctx.globalAlpha = this.near * ctx.globalAlpha;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          this.setFont(9.5, 650);
          ctx.fillStyle = j.state === 'starting' ? color : (this.dark ? '#0a0b0d' : '#ffffff');
          const label = j.state === 'starting' ? 'start' : prog != null ? Math.round(prog * 100) + '%' : j.started_at != null ? secs(t - j.started_at) : 'busy';
          ctx.fillText(label, b.x + b.w / 2, b.y + b.h / 2 + 0.5);
          ctx.globalAlpha = this.mid * (n.h.online ? 1 : 0.55);
          ctx.textAlign = 'left';
          ctx.textBaseline = 'alphabetic';
        }
        if (this.isSel('job', j.id) || this.isHover('job', j.id)) {
          this.rr(b.x - 3, b.y - 3, b.w + 6, b.h + 6, 8);
          ctx.strokeStyle = this.c.accent;
          ctx.lineWidth = 1.8;
          ctx.stroke();
        }
      }
      // finished flash
      for (const fin of this.finished) {
        if (fin.host !== h.id || fin.slot !== i) continue;
        const a = t - fin.t0;
        if (a < 0 || a > 1.1) continue;
        const k = 1 - a / 1.1;
        this.rr(b.x, b.y, b.w, b.h, 6);
        ctx.fillStyle = rgba(this.c.ok, 0.35 * k);
        ctx.fill();
        ctx.beginPath();
        const cx = b.x + b.w / 2, cy = b.y + b.h / 2;
        ctx.moveTo(cx - 6, cy);
        ctx.lineTo(cx - 1.5, cy + 4.5);
        ctx.lineTo(cx + 7, cy - 5);
        ctx.strokeStyle = rgba(this.c.ok, k);
        ctx.lineWidth = 2.2;
        ctx.lineCap = 'round';
        ctx.lineJoin = 'round';
        ctx.stroke();
        ctx.lineCap = 'butt';
        ctx.lineJoin = 'miter';
      }
    }

    pendingOfferFor(hostId) {
      for (const l of this.sim.leases.values()) if (l.host_id === hostId && l.state === 'offered') return true;
      return false;
    }

    gauge(cx, cy, r, v, label, text, color) {
      const ctx = this.ctx;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.strokeStyle = this.c.surface3;
      ctx.lineWidth = 4.5;
      ctx.stroke();
      if (v != null && v > 0.002) {
        ctx.beginPath();
        ctx.arc(cx, cy, r, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * clamp(v, 0, 1));
        ctx.strokeStyle = color;
        ctx.lineCap = 'round';
        ctx.stroke();
        ctx.lineCap = 'butt';
      }
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      this.setFont(12, 680);
      ctx.fillStyle = this.c.text;
      ctx.fillText(text, cx, cy + 0.5);
      this.setFont(9.5, 600);
      ctx.fillStyle = this.c.muted;
      ctx.fillText(label, cx, cy + r + 9);
      ctx.textAlign = 'left';
      ctx.textBaseline = 'alphabetic';
    }

    osIcon(os, x, y, size) {
      const ctx = this.ctx;
      ctx.save();
      ctx.translate(x, y);
      ctx.scale(size / 24, size / 24);
      ctx.fillStyle = this.c.text;
      if (os === 'macos') ctx.fill(ICONS.apple);
      else if (os === 'windows') { ctx.fillStyle = this.dark ? '#5aa9ff' : '#2a78d6'; ctx.fill(ICONS.windows); }
      else {
        ctx.fill(ICONS.tux);
        ctx.fillStyle = this.c.surface;
        ctx.fill(ICONS.tuxBelly);
        ctx.beginPath(); ctx.arc(10.7, 6.3, 0.9, 0, Math.PI * 2); ctx.arc(13.3, 6.3, 0.9, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = '#f0b429';
        ctx.fill(ICONS.tuxBeak);
      }
      ctx.restore();
    }

    drawHostFx(t) {
      for (const [hid, fx] of this.hostFx) {
        const age = t - fx.t0;
        const life = fx.kind === 'err' ? 2.2 : 1.6;
        if (age > life) { this.hostFx.delete(hid); continue; }
        if (fx.kind === 'info') continue;
        const n = this.hostNode.get(hid);
        const fade = clamp(1 - (age - (life - 0.5)) / 0.5, 0, 1);
        const rise = this.reduced ? 0 : easeOut(clamp(age / 0.4, 0, 1)) * 10;
        const col = fx.kind === 'err' ? this.c.err : this.c.ok;
        this.ctx.globalAlpha = fade;
        this.chip(n.x + n.w / 2, n.y - 4 - rise / this.cam.s, fx.text, col, this.mixSurface(col, 0.16), { stroke: rgba(col, 0.4), size: 11 });
        this.ctx.globalAlpha = 1;
        if (fx.kind === 'err' && age < 0.5 && !this.reduced) {
          const ctx = this.ctx;
          this.rr(n.x - age * 18, n.y - age * 18, n.w + age * 36, n.hh + age * 36, 16 + age * 18);
          ctx.strokeStyle = rgba(this.c.err, 0.6 * (1 - age / 0.5));
          ctx.lineWidth = 2;
          ctx.stroke();
        }
      }
    }

    tokenPos(tk, t) {
      let seg = null;
      for (const sgm of tk.segs) { if (t >= sgm.t0) seg = sgm; }
      if (!seg) return null;
      const e = this.edges.get(seg.edge);
      if (!e) return null;
      const p = clamp((t - seg.t0) / seg.dur, 0, 1);
      if (p >= 1 && tk.hold === 'orbit' && t >= (tk.holdFrom || 0)) {
        const a = this.reduced ? 0 : (t - tk.holdFrom) * 3.2;
        return { x: Math.cos(a) * 36, y: Math.sin(a) * 36 + 0, orbit: true };
      }
      const e2 = easeInOut(p);
      return bz(e, seg.dir > 0 ? e2 : 1 - e2);
    }

    drawTokens(t) {
      const ctx = this.ctx;
      const k = 1 / this.cam.s;
      ctx.save();
      if (this.dark) ctx.globalCompositeOperation = 'lighter';
      for (const tk of this.tokens.values()) {
        if (t > tk.removeAt) { tk.pos = null; continue; }
        const p = this.tokenPos(tk, t);
        tk.pos = p;
        if (!p) continue;
        const stats = tk.kind === 'stats';
        const r = stats ? Math.max(3, 2.5 * k) : Math.max(6, 4 * k);
        // trail
        if (!this.reduced && !p.orbit) {
          for (let i = 1; i <= 5; i++) {
            const q = this.tokenPos(tk, t - i * 0.03);
            if (!q || q.orbit) break;
            ctx.globalAlpha = (1 - i / 6) * 0.45;
            ctx.beginPath();
            ctx.arc(q.x, q.y, r * (1 - i / 8), 0, Math.PI * 2);
            ctx.fillStyle = tk.color;
            ctx.fill();
          }
          ctx.globalAlpha = 1;
        }
        const sp = this.sprite(tk.color);
        const gs = r * (stats ? 5 : 6);
        ctx.drawImage(sp, p.x - gs / 2, p.y - gs / 2, gs, gs);
        ctx.beginPath();
        ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
        ctx.fillStyle = tk.color;
        ctx.fill();
        if (!stats) {
          ctx.beginPath();
          ctx.arc(p.x, p.y, r * 0.42, 0, Math.PI * 2);
          ctx.fillStyle = this.dark ? 'rgba(255,255,255,0.85)' : 'rgba(255,255,255,0.9)';
          ctx.fill();
        }
      }
      ctx.restore();
    }

    cleanup(t) {
      for (const [id, tk] of this.tokens) if (t > tk.removeAt + 0.1) this.tokens.delete(id);
      while (this.fx.length > 3) this.fx.shift();
      this.fx = this.fx.filter((f) => t < f.end + 1 || f === this.currentFx());
      this.finished = this.finished.filter((f) => t - f.t0 < 1.5);
      this.wakeFx = this.wakeFx.filter((w) => t - w.t0 < 4);
      for (const [q, b] of this.blockFx) if (t - b.t0 > 3) this.blockFx.delete(q);
    }

    // ----------------------------------------------------------- minimap
    drawMinimap(t) {
      const ctx = this.mctx;
      const dpr = this.dpr;
      const W = this.mw, H = this.mh;
      if (!W || !H) return;
      const b = this.bounds;
      const k = Math.min((W - 16) / b.w, (H - 16) / b.h);
      const ox = (W - b.w * k) / 2 - b.x * k, oy = (H - b.h * k) / 2 - b.y * k;
      this.miniMap = { k, ox, oy };
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, W, H);
      ctx.setTransform(dpr * k, 0, 0, dpr * k, dpr * ox, dpr * oy);
      ctx.lineWidth = 1 / k;
      ctx.strokeStyle = rgba(this.c.text, 0.12);
      for (const e of this.edges.values()) {
        ctx.beginPath(); ctx.moveTo(e[0], e[1]); ctx.bezierCurveTo(e[2], e[3], e[4], e[5], e[6], e[7]); ctx.stroke();
      }
      const f = this.currentFx();
      for (const n of this.nodes) {
        const nb = this.nodeBounds(n);
        if (n.kind === 'coord') {
          ctx.beginPath(); ctx.arc(0, 0, COORD_R, 0, Math.PI * 2);
          ctx.fillStyle = rgba(this.c.accent, this.sim.coordBusy ? 0.55 : 0.3); ctx.fill();
          continue;
        }
        let col = rgba(this.c.text, 0.18);
        if (n.kind === 'host') {
          const h = n.h;
          col = !h.online ? rgba(this.c.muted, 0.2) : h.unfit ? rgba(this.c.err, 0.45) : h.draining ? rgba(this.c.warn, 0.45) : rgba(this.c.text, 0.22);
          if (f && t < f.end && f.d.chosen === n.id) col = rgba(this.c.ok, 0.7);
        }
        if (n.kind === 'queue') col = rgba(this.color(n.q.repository), 0.5);
        ctx.fillStyle = col;
        ctx.fillRect(nb.x, nb.y, nb.w, nb.h);
      }
      for (const tk of this.tokens.values()) {
        if (!tk.pos) continue;
        ctx.beginPath(); ctx.arc(tk.pos.x, tk.pos.y, 3 / k, 0, Math.PI * 2);
        ctx.fillStyle = tk.color; ctx.fill();
      }
      // viewport
      const a = this.toWorld(0, 0), z = this.toWorld(this.w, this.h);
      ctx.strokeStyle = this.c.accent;
      ctx.lineWidth = 1.5 / k;
      ctx.fillStyle = rgba(this.c.accent, 0.07);
      ctx.fillRect(a.x, a.y, z.x - a.x, z.y - a.y);
      ctx.strokeRect(a.x, a.y, z.x - a.x, z.y - a.y);
    }
  }

  // =================================================================== panels
  // The inspector, the details panel, the tooltip, the HUD and the toolbar,
  // around one Scene over one LiveWorld. Created when the screen first shows.
  function create(feed) {
    const $ = (id) => document.getElementById('bf-' + id);
    const root = document.getElementById('bal-flow');
    const repoVarOf = (repo) => 'var(' + B.repoVar(repo) + ')';
    const sim = new LiveWorld(feed);
    const canvas = $('world');
    const scene = new Scene(canvas, $('minimap'), sim);
    const inspector = $('inspector');
    const state = { paused: false, live: true, shown: null, tipHit: null, tipX: 0, tipY: 0, running: false, raf: 0 };

    // ----------------------------------------------------------- sizing
    function insets() {
      const wide = root.clientWidth > 760;
      const insOpen = wide && !inspector.classList.contains('is-collapsed');
      scene.insets = {
        left: wide && !$('details').hidden ? 344 : 16, top: wide ? 58 : 50,
        bottom: wide ? 66 : 70 + (inspector.classList.contains('is-collapsed') ? 56 : root.clientHeight * 0.46),
        right: insOpen ? inspector.offsetWidth + 32 : 16,
      };
    }
    function resize() { if (!state.running) return; scene.resize(); insets(); }
    global.addEventListener('resize', resize);
    B.onLook(() => requestAnimationFrame(() => { scene.readTheme(); scene.reduced = B.reduced(); }));

    // --------------------------------------------------------- inspector
    function repoColorStyle(el, repo) { el.style.setProperty('--c', repoVarOf(repo)); }
    const hostName = (id) => feed.hostName(id);

    function currentDecision() {
      if (!state.live && state.pinned) return state.pinned;
      return sim.decisions[sim.decisions.length - 1] || null;
    }

    function explain(d) {
      const fitting = d.scores.filter((s) => s.fits);
      const est = '<b>' + fmtBytes(d.estimate_bytes) + '</b>';
      if (!d.scores.length) return 'No host is left after the filters: the queue waits (' + esc(reasonText(d.reason || 'no_candidate')) + ').';
      if (!fitting.length) return 'No host has ' + est + ' + ' + fmtBytes((feed.snap || {}).ram_margin_bytes) + ' margin free right now (measured from this job\'s own runs), so the job waits instead of failing out of memory.';
      const win = fitting[0];
      const parts = [];
      if (win.cache) parts.push('warm checkout +' + pts(win.cache / 1000));
      if (win.headroom) parts.push(fmtBytes(win.free_after_bytes) + ' left after it +' + pts(win.headroom / 1000));
      if (win.speed > 0) parts.push((win._ctx.untried ? 'never ran these jobs +' : 'runs these jobs faster +') + pts(win.speed / 1000));
      if (win.speed < 0) parts.push('slower than usual ' + pts(win.speed / 1000));
      if (win.cpu) parts.push('idle cores +' + pts(win.cpu / 1000));
      let s;
      if (d.method === 'stage3') {
        s = 'No samples of this job yet, so the estimate is a guess (' + esc(SOURCE_TEXT[d.estimate_source] || d.estimate_source) + ') and placement uses <b>stage 3</b>: warm checkout, then most free memory, then fewest busy slots. Scores are shown but do not order. ';
        s += '<b>' + esc(hostName(win.host_id)) + '</b> goes first.';
      } else {
        s = '<b>' + esc(hostName(win.host_id)) + '</b> leads with ' + pts(win.total / 1000) + ': ' + esc(parts.join(', ') || 'the only one left') + '.';
      }
      const big = d.scores.find((x) => x.bigfit > 0);
      if (big) s += ' <b>' + esc(hostName(big.host_id)) + '</b> pays −' + pts(big.bigfit / 1000) + ' (bigfit): it alone can hold a heavier job that is waiting (' + fmtBytes(d.heavier_bytes) + ').';
      const lr = d.scores.filter((x) => x.last_resort && x.fits);
      const better = d.method === 'weighted' && win.last_resort ? fitting.find((x) => x.total > win.total) : null;
      if (better) s += ' Every host that fits is a last resort, and busy CPU is tried before low disk: that is why it goes before <b>' + esc(hostName(better.host_id)) + '</b> (' + pts(better.total / 1000) + ').';
      else if (lr.length) s += ' Last resort: ' + lr.map((x) => '<b>' + esc(hostName(x.host_id)) + '</b> (' + esc(x.last_resort) + ')').join(', ') + ' — tried only after the others.';
      return s;
    }

    function outcomeText(d) {
      if (d.outcome === 'accepted') return 'placed on ' + hostName(d.placed_on);
      if (d.outcome === 'refused') return 'refused · ' + reasonText(d.refusal);
      if (d.outcome) return 'waits · ' + reasonText(d.outcome);
      return d.attempts.length ? 'offered' : 'in progress';
    }

    function renderInspector() {
      const d = currentDecision();
      state.shown = d;
      const mode = $('insp-mode');
      mode.className = 'mode-chip ' + (!state.live ? 'is-pinned' : state.paused ? 'is-paused' : 'is-live');
      mode.lastChild.textContent = !state.live ? 'Pinned #' + (d ? d.id : '') : state.paused ? 'Paused' : 'Live';
      $('insp-live').hidden = state.live;
      $('insp-empty').hidden = !!d;
      $('insp-content').hidden = !d;
      renderHistory();
      if (!d) return;
      repoColorStyle($('dec-dot'), d.repository);
      $('dec-repo').textContent = d.repository;
      $('dec-job').textContent = '· ' + d.job_name;
      $('dec-labels').innerHTML = d.labelList.map((l) => '<span class="lbl">' + esc(l) + '</span>').join('');
      $('dec-est').textContent = d.scores.length ? fmtBytes(d.estimate_bytes) : '–';
      $('dec-src').textContent = d.scores.length ? SOURCE_TEXT[d.estimate_source] || d.estimate_source : '';
      $('dec-method').textContent = d.method || '–';
      const oc = $('dec-outcome');
      oc.textContent = outcomeText(d);
      oc.className = d.outcome === 'accepted' ? 'text-ok' : d.outcome ? 'text-err' : '';
      $('dec-why').innerHTML = explain(d);

      // ranked candidates
      const ol = $('dec-rank');
      const attempts = new Map(d.attempts.map((a) => [a.host_id, a]));
      const scale = scene.scoreScale();
      const rows = d.scores.map((sc, i) => {
        const a = attempts.get(sc.host_id);
        const cls = ['rank-row'];
        if (d.placed_on === sc.host_id) cls.push('is-chosen');
        if (a && (a.outcome === 'refused' || a.outcome === 'unanswered')) cls.push('is-refused');
        if (!sc.fits) cls.push('is-nofit');
        const tags = [];
        if (!sc.fits) tags.push('<span class="rank-tags is-err">no memory fit</span>');
        else if (a && a.outcome === 'refused') tags.push('<span class="rank-tags is-err">refused · ' + esc(reasonText(a.reason)) + '</span>');
        else if (a && a.outcome === 'unanswered') tags.push('<span class="rank-tags is-err">no answer</span>');
        else if (sc.last_resort) tags.push('<span class="rank-tags">' + esc(sc.last_resort) + ' · last resort</span>');
        const title = 'cache ' + pts(sc.cache / 1000) + ' · headroom ' + pts(sc.headroom / 1000) + ' · speed ' + pts(sc.speed / 1000) + ' · cpu ' + pts(sc.cpu / 1000) + (sc.bigfit ? ' · bigfit −' + pts(sc.bigfit / 1000) : '') +
          (sc.free_after_bytes != null ? ' · free after ' + fmtBytes(sc.free_after_bytes) : '');
        return '<li class="' + cls.join(' ') + '" data-host="' + esc(sc.host_id) + '" title="' + esc(title) + '">' +
          '<span class="rank-n">' + (sc.fits ? i + 1 : '–') + '</span>' +
          '<span class="rank-name">' + esc(hostName(sc.host_id)) + tags.join('') + '</span>' +
          '<span class="sbar' + (sc.fits ? '' : ' is-nofit') + '"><span class="sbar-zero"></span>' +
          '<span class="sbar-neg"><i class="seg-part p-bigfit" data-w="' + sc.bigfit + '"></i></span>' +
          '<span class="sbar-pos">' +
          '<i class="seg-part p-cache" data-w="' + sc.cache + '"></i>' +
          '<i class="seg-part p-headroom" data-w="' + sc.headroom + '"></i>' +
          '<i class="seg-part p-speed" data-w="' + Math.max(0, sc.speed) + '"></i>' +
          '<i class="seg-part p-cpu" data-w="' + sc.cpu + '"></i></span></span>' +
          '<span class="rank-total">' + pts(sc.total / 1000) + '</span></li>';
      });
      const sig = d.id + ':' + d.attempts.map((a) => a.outcome).join(',');
      if (ol.dataset.sig !== sig) {
        const fresh = ol.dataset.id !== String(d.id);
        ol.innerHTML = rows.join('') || '<li class="muted">No host to score.</li>';
        ol.dataset.sig = sig;
        ol.dataset.id = d.id;
        // The parts on the right of the zero axis share its 84% by the top
        // score; bigfit on its left uses the same scale.
        const set = () => ol.querySelectorAll('.seg-part').forEach((el) => {
          const w = Number(el.dataset.w) / scale * 84;
          el.style.width = (el.classList.contains('p-bigfit') ? Math.min(100, (w / 16) * 100) : (w / 84) * 100) + '%';
        });
        if (fresh && !scene.reduced) requestAnimationFrame(() => requestAnimationFrame(set)); else set();
      }

      // filtered
      $('dec-filtered-wrap').hidden = !d.filtered.length;
      $('dec-filtered').innerHTML = d.filtered.map((f) => {
        const cls = f.reason === 'no_free_slot' || f.reason === 'tried' ? 'reason is-warn' : 'reason';
        return '<li data-host="' + esc(f.host_id) + '">' + esc(hostName(f.host_id)) + '<span class="' + cls + '">' + esc(filterText(f)) + '</span></li>';
      }).join('');

      // launch timeline, in the coordinator's own times
      const items = d.attempts.map((a) => {
        const label = a.outcome === 'offered' ? 'offered to' : a.outcome === 'accepted' ? 'accepted by' : a.outcome === 'refused' ? 'refused by' : a.outcome === 'unanswered' ? 'no answer from' : a.outcome + ' ·';
        const extra = a.outcome === 'refused' ? ' <span class="reason">' + esc(reasonText(a.reason)) + '</span>' : '';
        const dt = a.t_end_ms != null ? ((a.t_end_ms - a.t_ms) / 1000).toFixed(1) + ' s' : '…';
        return '<li class="att is-' + esc(a.outcome) + '"><i></i>' + label + ' <b>' + esc(hostName(a.host_id)) + '</b>' + extra + '<span class="muted">' + dt + '</span></li>';
      });
      if (!d.attempts.length) {
        items.push('<li class="att"><i></i>' + (d.outcome ? 'not launched · ' + esc(reasonText(d.outcome)) : 'scoring…') + '</li>');
      } else if (d.outcome === 'accepted') {
        if (d.claimed_ms) items.push('<li class="att is-accepted"><i></i>claimed · its runner took a job</li>');
        if (d.finished) items.push('<li class="att is-accepted"><i></i>finished' + (d.finished.duration != null ? ' in <b>' + secs(d.finished.duration) + '</b>' : '') + (d.finished.peak ? ', peak ' + fmtBytes(d.finished.peak) : '') + '</li>');
      } else if (d.outcome) {
        items.push('<li class="att is-refused"><i></i>next host, or back to the queue</li>');
      }
      $('dec-attempts').innerHTML = items.join('');
    }

    function renderHistory() {
      const list = sim.decisions.slice(-8).reverse();
      const cur = state.shown;
      $('history').innerHTML = list.map((d) => {
        const out = d.outcome === 'accepted' ? '→ ' + esc(hostName(d.placed_on)) : d.outcome ? esc(reasonText(d.outcome === 'refused' ? d.refusal || 'refused' : d.outcome)) : '…';
        const err = d.outcome && d.outcome !== 'accepted';
        return '<li class="hist' + (cur && cur.id === d.id ? ' is-current' : '') + '" data-id="' + d.id + '">' +
          '<i class="repo-dot" data-repo="' + esc(d.repository) + '"></i>' +
          '<span class="hist-main"><b>' + esc(shortRepo(d.repository)) + '</b> ' + esc(d.job_name) + ' <span class="muted">' + esc(d.method === 'stage3' ? 'stage3' : '') + '</span></span>' +
          '<span class="hist-out' + (err ? ' is-err' : '') + '">' + out + '</span></li>';
      }).join('');
      $('history').querySelectorAll('.repo-dot').forEach((el) => repoColorStyle(el, el.dataset.repo));
    }

    function pin(d) { state.live = false; state.pinned = d; scene.pinned = d; renderInspector(); }
    $('history').addEventListener('click', (e) => {
      const li = e.target.closest('.hist');
      if (!li) return;
      const d = sim.decisions.find((x) => String(x.id) === li.dataset.id);
      if (!d) return;
      const latest = sim.decisions[sim.decisions.length - 1];
      if (latest && d.id === latest.id) { goLive(); return; }
      pin(d);
    });
    function goLive() { state.live = true; state.pinned = null; scene.pinned = null; renderInspector(); }
    $('insp-live').addEventListener('click', goLive);

    const rankHover = (e) => {
      const row = e.target.closest('[data-host]');
      scene.hotHost = row ? row.dataset.host : null;
    };
    for (const id of ['dec-rank', 'dec-filtered']) {
      $(id).addEventListener('mouseover', rankHover);
      $(id).addEventListener('mouseleave', () => { scene.hotHost = null; });
      $(id).addEventListener('click', (e) => {
        const row = e.target.closest('[data-host]');
        if (row && scene.hostNode.has(row.dataset.host)) scene.select({ kind: 'host', id: row.dataset.host });
      });
    }
    $('insp-toggle').addEventListener('click', () => {
      const collapsed = inspector.classList.toggle('is-collapsed');
      $('insp-toggle').setAttribute('aria-expanded', String(!collapsed));
      insets();
    });

    let inspPending = false;
    function queueInspector() {
      if (inspPending) return;
      inspPending = true;
      requestAnimationFrame(() => { inspPending = false; renderInspector(); });
    }
    sim.on((ev) => {
      if (['decision', 'offered', 'accepted', 'refused', 'unanswered', 'requeued', 'claimed', 'finished'].includes(ev.type)) queueInspector();
    });
    feed.on(() => { if (state.running && sim.decisions.length && !state.shown) queueInspector(); });

    // ----------------------------------------------------------- details
    function kv(rows) {
      return '<dl class="f-kv">' + rows.filter(Boolean).map(([k, v]) => '<dt>' + esc(k) + '</dt><dd>' + v + '</dd>').join('') + '</dl>';
    }
    const lbls = (csv) => B.labelList(csv).map((l) => '<span class="lbl">' + esc(l) + '</span>').join(' ');

    function hostDetails(h) {
      const st = B.statusOf(h);
      const jobs = h.slotJobs.map((id) => (id == null ? null : sim.jobs.get(id))).filter(Boolean);
      const cpuBusy = sim.cpuBusy || 90, minDisk = sim.minDisk || 10 * GiB;
      let html = kv([
        ['OS', esc([h.os, h.arch].filter(Boolean).join(' · '))],
        ['Cores', h.cores || '–'],
        ['Memory free', h.online ? fmtBytes(h.free_ram_bytes) + ' of ' + fmtBytes(h.ram_bytes) : '–'],
        ['CPU load', h.online && h.cpu_load_percent != null ? h.cpu_load_percent + '%' + (h.cpu_load_percent >= cpuBusy ? ' <span class="reason is-warn">cpu_busy</span>' : '') : '–'],
        ['Disk free', fmtBytes(h.disk_free_bytes) + (h.disk_free_bytes != null && h.disk_free_bytes < minDisk ? ' <span class="reason is-warn">low_disk</span>' : '')],
        ['Slots', h.online ? h.busy_slots + ' busy · ' + h.free_slots + ' free' : '–'],
        ['Profiles', h.pools.length ? h.pools.map((p) => '<span class="f-chips">' + lbls(p) + '</span>').join('') : '<span class="muted">none reported</span>'],
        ['Warm checkouts', h.warm_repos.length ? h.warm_repos.map((r) => esc(shortRepo(r) || r)).join(', ') : '<span class="muted">none</span>'],
      ]);
      const notes = [];
      if (st === 'draining') notes.push('Draining: filtered out (<b>unfit_or_draining</b>) and refuses launches with <b>draining</b>.');
      if (st === 'unfit') notes.push('A required host doctor check fails: filtered out until it passes.');
      if (st === 'offline') notes.push(h.last_seen_at ? 'Not connected; last seen ' + esc(fmtWait(sim.serverSecs() - h.last_seen_at)) + ' ago.' : 'Not connected.');
      if (notes.length) html += '<p class="d-note">' + notes.join('<br>') + '</p>';
      html += '<div class="d-sec">Slots</div>';
      html += jobs.length ? '<ul class="d-list">' + jobs.map((j) => {
        const p = j.state === 'running' && j.duration ? clamp((sim.t - j.started_at) / j.duration, 0, 1) : 0;
        const right = j.state === 'starting' ? 'starting' : j.duration ? Math.round(p * 100) + '%' : j.started_at != null ? secs(sim.t - j.started_at) : 'busy';
        return '<li class="d-job" data-repo="' + esc(j.repository || '') + '" data-p="' + p + '"><i class="repo-dot"></i><span>' + (j.repository ? esc(shortRepo(j.repository)) + ' · ' : '') + esc(j.job) + '</span>' +
          '<span class="muted">' + esc(right) + '</span><span class="d-prog"><i></i></span></li>';
      }).join('') + '</ul>' : '<p class="muted">No job.</p>';
      const mine = sim.decisions.filter((d) => d.scores.some((s) => s.host_id === h.id) || d.chosen === h.id).slice(-5).reverse();
      if (mine.length) {
        html += '<div class="d-sec">In recent decisions</div><ul class="d-list">' + mine.map((d) => {
          const i = d.scores.findIndex((s) => s.host_id === h.id);
          const s = d.scores[i];
          const what = d.placed_on === h.id ? 'placed here' : s && !s.fits ? 'no memory fit' : s ? '#' + (i + 1) + ' · ' + pts(s.total / 1000) : '';
          return '<li class="d-job" data-repo="' + esc(d.repository) + '"><i class="repo-dot"></i><span>' + esc(shortRepo(d.repository)) + ' · ' + esc(d.job_name) + '</span><span class="muted">' + esc(what) + '</span></li>';
        }).join('') + '</ul>';
      }
      html += '<div class="d-actions"><button class="d-btn" type="button" data-act="focus">Focus</button></div>';
      return { kind: 'Machine', title: esc(h.name) + ' <span class="status-pill st-' + st + '">' + st + '</span>', html };
    }

    function jobDetails(j) {
      const d = j.decision ? sim.byId.get(j.decision) : null;
      const stateText = { webhook: 'webhook in flight', queued: 'queued', picked: 'picked by the coordinator', offering: 'launch offered',
        placed: 'a runner is starting for its queue', starting: 'runner starting (lease accepted)', running: 'running' }[j.state] || j.state;
      const html = kv([
        j.repository ? ['Repository', esc(j.repository)] : null,
        ['Job', esc(j.job) + (j.gh_id ? ' <span class="muted">#' + j.gh_id + '</span>' : '')],
        j.labels ? ['Labels', lbls(j.labels)] : null,
        ['State', esc(stateText)],
        j.pool != null ? ['Path', j.pool ? 'pool: placed by score' : 'not a pool job: hosts are woken and decide'] : null,
        j.estimate_bytes ? ['Estimate', fmtBytes(j.estimate_bytes) + ' <span class="muted">' + esc(SOURCE_TEXT[j.estimate_source] || '') + '</span>'] : null,
        j.queued_t != null ? ['Waited', fmtWait(Math.max(0, Math.round((j.started_at != null ? j.started_at : sim.t) - j.queued_t)))] : null,
        j.host ? ['Machine', esc(hostName(j.host))] : null,
        j.state === 'running' && j.started_at != null ? ['Running for', secs(sim.t - j.started_at) + (j.duration ? ' of ~' + secs(j.duration) : '')] : null,
        j.attempts.length ? ['Attempts', j.attempts.map((a) => esc(hostName(a.host_id)) + ' ' + esc(a.outcome) + (a.reason ? ' (' + esc(reasonText(a.reason)) + ')' : '')).join('<br>')] : null,
      ]);
      const more = d ? '<div class="d-actions"><button class="d-btn" type="button" data-act="decision" data-id="' + d.id + '">Show its decision</button></div>' : '';
      return { kind: 'Job', title: (j.repository ? esc(shortRepo(j.repository)) + ' · ' : '') + esc(j.job), html: html + more };
    }

    function queueDetails(id) {
      const q = sim.queue(id);
      if (!q) return null;
      const pq = sim.pendingQueue(q);
      const jobs = sim.queuedJobs(q);
      const cands = sim.hosts.filter((h) => serves(h, q.labels));
      let html = kv([
        ['Labels', lbls(q.labels)],
        ['Queued', pq.queued != null ? pq.queued : jobs.length],
        ['Runners on the way', pq.leases || 0],
        ['Oldest wait', pq.oldest_wait_secs == null ? '–' : fmtWait(pq.oldest_wait_secs)],
        ['Reason', pq.reason ? '<span class="reason is-warn">' + esc(reasonText(pq.reason)) + '</span>' + (pq.refusal ? ' <span class="reason">' + esc(reasonText(pq.refusal)) + '</span>' : '') : '<span class="muted">none</span>'],
        [q.pool ? 'Served by' : 'Woken hosts', cands.length ? cands.map((h) => esc(h.name)).join(', ') : '<span class="muted">none connected</span>'],
      ]);
      html += '<p class="d-note">' + (q.pool
        ? 'A <b>pool queue</b>: jobs with the same repository and labels. The coordinator scores the candidates for the heaviest job queued here and offers a launch to the best one.'
        : 'Not placed: the coordinator only <b>wakes</b> the hosts that serve these labels, and they decide themselves. No score.') + '</p>';
      html += '<div class="d-sec">Jobs</div>' + (jobs.length ? '<ul class="d-list">' + jobs.slice(0, 12).map((j) =>
        '<li class="d-job" data-repo="' + esc(j.repository) + '"><i class="repo-dot"></i><span>' + esc(j.job) + ' <span class="muted">#' + esc(j.gh_id || '') + '</span></span><span class="muted">' + fmtWait(Math.round(sim.t - j.queued_t)) + '</span></li>').join('') + '</ul>' : '<p class="muted">Nothing waiting.</p>');
      return { kind: q.pool ? 'Pool queue' : 'Queue', title: esc(q.repository), html };
    }

    function coordDetails() {
      const c = (feed.snap && feed.snap.counters) || {};
      const W = sim.weights;
      let html = '<div class="d-sec">Weights</div>' + kv([
        ['cache', W.cache.toFixed(1) + ' × warm checkout'],
        ['headroom', W.headroom.toFixed(1) + ' × RAM share left'],
        ['speed', W.speed.toFixed(1) + ' × faster than usual'],
        ['cpu', W.cpu.toFixed(1) + ' × idle-core share'],
        ['bigfit', '−' + W.bigfit.toFixed(1) + ' keep for heavier'],
      ]);
      html += '<p class="d-note">Order: hosts that fit first; last-resort hosts (CPU ≥ ' + (sim.cpuBusy || 90) + '%, then disk under ' + fmtBytes(sim.minDisk) + ') after the rest; then by score. Without this job\'s own samples: <b>stage 3</b> order (warm, free memory, fewest busy slots).</p>';
      html += '<div class="d-sec">Since the coordinator started</div>' + kv([
        ['Decisions', c.decisions || 0], ['Launches offered', c.offered || 0], ['Accepted', c.accepted || 0],
        ['Refused', c.refused || 0], ['Unanswered', c.unanswered || 0], ['Claimed', c.claimed || 0], ['Finished', c.finished || 0],
        ['Cancelled', c.cancelled || 0], ['Expired', c.expired || 0],
      ]);
      return { kind: 'Decision engine', title: 'Coordinator', html };
    }

    function githubDetails() {
      const last = sim.events.filter((e) => e.type === 'webhook').slice(-6).reverse();
      let html = '<p class="d-note">Each <span class="lbl">workflow_job</span> webhook with action <b>queued</b> adds a job to the queue of its repository and labels.</p>';
      html += '<div class="d-sec">Latest</div>' + (last.length ? '<ul class="d-list">' + last.map((e) => {
        const j = sim.jobs.get(e.job);
        if (!j) return '';
        return '<li class="d-job" data-repo="' + esc(j.repository) + '"><i class="repo-dot"></i><span>' + esc(shortRepo(j.repository)) + ' · ' + esc(j.job) + '</span><span class="muted">' + Math.round(sim.t - e.t) + ' s ago</span></li>';
      }).join('') + '</ul>' : '<p class="muted">None since this page opened.</p>');
      return { kind: 'Source', title: 'GitHub webhooks', html };
    }

    function renderDetails() {
      const sel = scene.selected;
      const panel = $('details');
      let out = null;
      if (sel && sel.kind === 'host') { const h = sim.hostById.get(sel.id); if (h) out = hostDetails(h); }
      else if (sel && sel.kind === 'job') { const j = sim.jobs.get(sel.id); if (j) out = jobDetails(j); }
      else if (sel && sel.kind === 'queue') out = queueDetails(sel.id);
      else if (sel && sel.kind === 'coord') out = coordDetails();
      else if (sel && sel.kind === 'github') out = githubDetails();
      if (!out) { panel.hidden = true; return; }
      panel.hidden = false;
      $('details-kind').textContent = out.kind;
      $('details-title').innerHTML = out.title;
      const body = $('details-body');
      const top = body.scrollTop;
      body.innerHTML = out.html;
      body.scrollTop = top;
      body.querySelectorAll('[data-repo]').forEach((el) => {
        if (el.dataset.repo) repoColorStyle(el, el.dataset.repo);
        const bar = el.querySelector('.d-prog i');
        if (bar) bar.style.width = (Number(el.dataset.p || 0) * 100).toFixed(1) + '%';
      });
    }

    scene.onSelect = () => { renderDetails(); insets(); };
    $('details-close').addEventListener('click', () => { scene.select(null); });
    $('details-body').addEventListener('click', (e) => {
      const b = e.target.closest('[data-act]');
      if (!b) return;
      const sel = scene.selected;
      if (b.dataset.act === 'focus' && sel) { const n = scene.nodeOf(sel); if (n) scene.focusNode(n); }
      if (b.dataset.act === 'decision') {
        const d = sim.byId.get(Number(b.dataset.id));
        if (d) pin(d);
      }
    });

    // ----------------------------------------------------------- tooltip
    const tip = $('tip');
    function tipHtml(hit) {
      if (!hit) return null;
      if (hit.kind === 'host') {
        const h = sim.hostById.get(hit.id);
        if (!h) return null;
        return '<b>' + esc(h.name) + '</b> · ' + B.statusOf(h) + '<br><span class="muted">' + (h.busy_slots || 0) + '/' + h.slots + ' slots · cpu ' +
          (h.online && h.cpu_load_percent != null ? h.cpu_load_percent + '%' : '–') + ' · ' + fmtBytes(h.online ? h.free_ram_bytes : null) + ' free</span>';
      }
      if (hit.kind === 'job') {
        const j = sim.jobs.get(hit.id);
        if (!j) return null;
        return '<b>' + (j.repository ? esc(shortRepo(j.repository)) + ' · ' : '') + esc(j.job) + '</b><br><span class="muted">' + esc(j.state) + (j.host ? ' on ' + esc(hostName(j.host)) : '') + (j.estimate_bytes ? ' · est. ' + fmtBytes(j.estimate_bytes) : '') + '</span>';
      }
      if (hit.kind === 'queue') {
        const q = sim.queue(hit.id);
        return q ? '<b>' + esc(q.repository) + '</b><br><span class="muted">' + esc(q.labels) + ' · click for details</span>' : null;
      }
      if (hit.kind === 'coord') return '<b>Coordinator</b><br><span class="muted">filters, estimates, scores, offers</span>';
      if (hit.kind === 'github') return '<b>GitHub webhooks</b><br><span class="muted">workflow_job · queued</span>';
      return null;
    }
    function placeTip() {
      const html = tipHtml(state.tipHit);
      if (!html) { tip.hidden = true; return; }
      tip.innerHTML = html;
      tip.hidden = false;
      const w = tip.offsetWidth, h = tip.offsetHeight;
      let x = state.tipX + 14, y = state.tipY + 16;
      if (x + w > scene.w - 8) x = state.tipX - w - 14;
      if (y + h > scene.h - 8) y = state.tipY - h - 12;
      tip.style.left = x + 'px';
      tip.style.top = y + 'px';
    }
    scene.onHover = (hit, x, y) => {
      state.tipHit = hit; state.tipX = x; state.tipY = y;
      placeTip();
    };

    // ----------------------------------------------------------- toolbar
    function setPaused(p) {
      state.paused = p;
      $('btn-pause').setAttribute('aria-pressed', String(p));
      $('btn-pause').setAttribute('aria-label', p ? 'Play' : 'Pause');
      renderPauseLabel();
      renderInspector();
    }
    function renderPauseLabel() {
      const waiting = sim.backlog.filter((it) => it.d).length;
      $('pause-label').textContent = state.paused ? (waiting ? 'Play · ' + waiting + ' new' : 'Play') : 'Pause';
    }
    $('btn-pause').addEventListener('click', () => setPaused(!state.paused));
    $('btn-zin').addEventListener('click', () => scene.zoomBy(1.35));
    $('btn-zout').addEventListener('click', () => scene.zoomBy(1 / 1.35));
    $('btn-zoom').addEventListener('click', () => scene.fit());
    $('btn-fit').addEventListener('click', () => scene.fit());

    $('legend-toggle').addEventListener('click', () => {
      const lg = $('legend');
      const c = lg.classList.toggle('is-collapsed');
      $('legend-toggle').setAttribute('aria-expanded', String(!c));
    });

    document.addEventListener('keydown', (e) => {
      if (!state.running || e.defaultPrevented) return;
      if (e.target.closest && e.target.closest('input, textarea, select, dialog')) return;
      if (e.key === ' ' && e.target.tagName !== 'BUTTON' && e.target.tagName !== 'A') { e.preventDefault(); setPaused(!state.paused); }
      else if (e.key === 'f' || e.key === 'F' || e.key === '0') scene.fit();
      else if (e.key === '+' || e.key === '=') scene.zoomBy(1.35);
      else if (e.key === '-' || e.key === '_') scene.zoomBy(1 / 1.35);
      else if (e.key === 'Escape') { scene.select(null); if (!state.live) goLive(); }
    });

    // --------------------------------------------------------------- HUD
    function renderHud() {
      let queued = 0, slots = 0, oldest = null, running = 0;
      const snap = feed.snap || {};
      for (const j of snap.queued || []) { queued++; oldest = Math.max(oldest || 0, sim.serverSecs() - j.queued_at); }
      for (const h of sim.hosts) { if (h.online && !h.unfit && !h.draining) slots += h.slots; running += h.busy_slots || 0; }
      $('hud-queued').textContent = queued;
      $('hud-running').textContent = running;
      $('hud-slots').textContent = '/ ' + slots + ' slots';
      $('hud-decisions').textContent = sim.counters.decisions;
      const nowMs = feed.now();
      const recent = feed.decisions.filter((d) => nowMs - d.at_ms < 60000).length;
      $('hud-rate').textContent = recent + '/min';
      $('hud-refused').textContent = sim.counters.refused + sim.counters.unanswered;
      $('hud-wait').textContent = oldest == null ? '–' : fmtWait(oldest);
      $('btn-zoom').textContent = Math.round(scene.cam.s * 100) + '%';
      root.classList.toggle('is-stale', feed.failed);
      renderPauseLabel();
    }

    // -------------------------------------------------------------- loop
    let last = performance.now();
    let acc = 0;
    function frame(now) {
      if (!state.running) return;
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      if (!state.paused) sim.step(dt);
      scene.relayout();
      scene.render(dt);
      acc += dt;
      if (acc > 0.25) {
        acc = 0;
        renderHud();
        if (scene.selected) renderDetails();
        if (state.tipHit) placeTip();
      }
      state.raf = requestAnimationFrame(frame);
    }

    let first = true;
    return {
      start() {
        if (state.running) return;
        state.running = true;
        if (first) {
          if (root.clientWidth < 1700 || root.clientHeight < 1000) {
            $('legend').classList.add('is-collapsed');
            $('legend-toggle').setAttribute('aria-expanded', 'false');
          }
          if (root.clientWidth <= 760) {
            inspector.classList.add('is-collapsed');
            $('insp-toggle').setAttribute('aria-expanded', 'false');
          }
        }
        scene.reduced = B.reduced();
        scene.readTheme();
        resize();
        scene.relayout();
        if (first) { scene.fit(true); first = false; }
        renderInspector();
        renderHud();
        last = performance.now();
        state.raf = requestAnimationFrame(frame);
      },
      stop() {
        state.running = false;
        cancelAnimationFrame(state.raf);
        tip.hidden = true;
      },
      // For screenshots and debugging.
      debug: { sim, scene, state, setPaused },
    };
  }

  global.RMBalancing.register('flow', create);
})(window);
