// runner-manager dashboard, Balancing screen: the decision theatre. One
// recorded decision at a time is staged as a race: every candidate machine is
// a lane, its score grows part by part, lanes re-sort into rank order, the
// launch goes to the best and its host accepts or refuses. A playhead `t`
// drives it, so a decision can be scrubbed and past ones replayed. The
// what-if weights re-rank a recorded decision in the browser only.
'use strict';

(function (global) {
  const B = global.RMBalance;
  const { GiB, clamp, SOURCE_TEXT } = B;

  const SEGS = B.SEGS;
  const SEG_BY = Object.fromEntries(SEGS.map((s) => [s.k, s]));
  const REASON = {
    no_free_slot: 'No free slot', unfit_or_draining: 'Unfit or draining', unfit: 'Unfit', draining: 'Draining',
    no_memory_fit: 'Not enough memory', no_candidate: 'No candidate', tried: 'Asked already', refused: 'Refused',
    unanswered: 'No answer', cancelled: 'Cancelled', expired: 'Expired',
  };
  const REFUSAL = {
    max_capacity: 'profile at max capacity', host_capacity: 'host at capacity', memory: 'not enough memory',
    stale: 'lease stale', draining: 'draining', unfit: 'unfit', disabled: 'profile disabled',
    unknown_profile: 'no such profile', not_coordinated: 'not coordinated', excluded: 'a label is excluded',
  };
  const PHASE_CHIPS = [
    ['queue', 'Queue'], ['candidates', 'Candidates'], ['filter', 'Filter'], ['score', 'Score'],
    ['order', 'Rank'], ['launch', 'Launch'], ['result', 'Result'],
  ];
  // Staged decisions waiting beyond this are not animated: the newest is.
  const MAX_WAITING = 6;

  // --------------------------------------------------------------------- utils
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  const easeOut = (x) => 1 - Math.pow(1 - x, 3);
  function gib(b, digits) {
    if (!B.isNum(b)) return '—';
    const g = b / GiB;
    const d = digits != null ? digits : g >= 100 ? 0 : 1;
    return g.toFixed(d) + ' GiB';
  }
  const gShort = B.gShort;
  const pts = B.pts;
  const secs = B.secs;
  const shortRepo = B.shortRepo;
  function poolText(labels) {
    if (typeof labels === 'string') labels = B.labelList(labels);
    if (labels.length === 1) return labels[0];
    return labels.filter((l) => l !== 'self-hosted').join(' · ');
  }
  function osOfLabels(labels) {
    const l = labels.join(',').toLowerCase();
    return l.includes('macos') || l.includes('-mac') ? 'macos' : l.includes('windows') ? 'windows' : 'linux';
  }
  const SVGNS = 'http://www.w3.org/2000/svg';
  const OS_PATHS = {
    linux: [['rect', { x: 1, y: 2, width: 14, height: 12, rx: 3, fill: 'currentColor', 'fill-opacity': 0.18, stroke: 'currentColor', 'stroke-width': 1.2 }],
      ['path', { d: 'M4.3 5.6 6.8 8l-2.5 2.4M8.4 10.6h3.6', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.8, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }]],
    windows: [['path', { d: 'M2 2h5.4v5.4H2zM8.6 2H14v5.4H8.6zM2 8.6h5.4V14H2zM8.6 8.6H14V14H8.6z', fill: 'currentColor' }]],
    macos: [['path', { d: 'M11.3 8.5c0-1.5 1.2-2.2 1.3-2.3-.7-1-1.8-1.2-2.2-1.2-.9-.1-1.8.6-2.3.6-.5 0-1.2-.5-2-.5C5 5.1 4 5.7 3.5 6.7c-1.1 1.9-.3 4.7.8 6.2.5.7 1.1 1.6 1.9 1.5.8 0 1-.5 2-.5s1.2.5 2 .5c.8 0 1.3-.8 1.8-1.5.6-.8.8-1.6.8-1.7 0 0-1.5-.6-1.5-2.7zM9.8 4c.4-.5.7-1.2.6-1.9-.6 0-1.3.4-1.8.9-.4.4-.7 1.1-.6 1.8.7.1 1.4-.3 1.8-.8z', fill: 'currentColor' }]],
  };
  function osIcon(os) {
    const svg = document.createElementNS(SVGNS, 'svg');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('class', 'osi osi-' + os);
    svg.setAttribute('aria-hidden', 'true');
    (OS_PATHS[os] || OS_PATHS.linux).forEach(([tag, attrs]) => {
      const n = document.createElementNS(SVGNS, tag);
      Object.keys(attrs).forEach((a) => n.setAttribute(a, attrs[a]));
      svg.appendChild(n);
    });
    return svg;
  }
  function setText(node, text) { if (node.textContent !== text) node.textContent = text; }
  function setCls(node, cls, on) { if (node.classList.contains(cls) !== !!on) node.classList.toggle(cls, !!on); }

  function create(feed) {
    const $ = (id) => document.getElementById('br-' + id);
    const root = document.getElementById('bal-race');
    const reduceMotion = { get matches() { return B.reduced(); } };

    // ------------------------------------------------------------------ data
    // The machines as the stage reads them, from the coordinator's snapshot.
    const raceHosts = new Map();
    function hostOf(id) {
      const h = raceHosts.get(id);
      if (h) return h;
      return { id, name: feed.hostName(id), os: 'linux', cores: 0, ram_bytes: null, online: false, warm_repos: [], pools: [], capacity: 0, _order: 999 };
    }
    function syncHosts() {
      const snap = feed.snap;
      if (!snap) return;
      const seen = new Set();
      (snap.hosts || []).forEach((x, i) => {
        const h = raceHosts.get(x.id) || {};
        Object.assign(h, x, {
          name: x.name || x.hostname || x.id, os: (x.os || 'linux').toLowerCase(), capacity: (x.busy_slots || 0) + (x.free_slots || 0),
          warm_repos: x.warm_repos || [], pools: x.pools || [], _order: i,
        });
        raceHosts.set(x.id, h);
        seen.add(x.id);
      });
      for (const id of [...raceHosts.keys()]) if (!seen.has(id)) raceHosts.delete(id);
    }
    // What holds a machine's slots: its running jobs, its launches on their
    // way, and runners its heartbeat counts that nothing here names.
    function activeOn(h) {
      const snap = feed.snap || {};
      const nowS = feed.now() / 1000;
      const out = [];
      for (const j of snap.running || []) {
        if (j.host_id !== h.id) continue;
        const elapsed = Math.max(0, nowS - (j.started_at || nowS));
        out.push({ state: 'claimed', repository: j.repository, jobName: j.name || '#' + j.id, progress: j.expected_secs ? clamp(elapsed / j.expected_secs, 0, 1) : null, elapsed });
      }
      for (const l of snap.leases || []) {
        if (l.host_id !== h.id || l.state === 'claimed') continue;
        out.push({ state: 'accepted', repository: l.repository, jobName: l.state === 'offered' ? 'launch offered' : 'runner starting', lease: l.lease_id });
      }
      const named = out.filter((x) => x.state === 'claimed').length;
      for (let i = named; i < (h.busy_slots || 0); i++) out.push({ state: 'claimed', repository: null, jobName: 'a runner', progress: null, elapsed: null });
      return out;
    }
    function lastResort(h) {
      const snap = feed.snap || {};
      if (h.disk_free_bytes != null && h.disk_free_bytes < (snap.min_disk_free_bytes || 10 * GiB)) return 'low_disk';
      if (h.cpu_load_percent != null && h.cpu_load_percent >= (snap.cpu_busy_percent || 90)) return 'cpu_busy';
      return null;
    }
    const weightsNow = () => Object.assign({}, B.DEFAULT_WEIGHTS, (feed.snap && feed.snap.weights) || {});

    // A decision model as the stage reads it.
    function staged(d) {
      if (d._race) return d._race;
      const job = { id: d.job_id != null ? 'gh:' + d.job_id : 'd:' + d.id, repository: d.repository, job: d.job_name, labels: d.labelList };
      const R = Object.assign(Object.create(d), { job });
      d._race = R;
      return R;
    }
    // Its fate, from the launch events so far.
    function settle(R) {
      R.unplaced = R.outcome === 'accepted' ? null : R.outcome;
      if (R.outcome === 'accepted') R.chosen = R.placed_on;
      return R;
    }
    const complete = (d) => d.outcome != null && d.outcome !== 'offered';

    // --------------------------------------------------------------------- state
    const S = {
      paused: false, speed: 1,
      mode: 'live',            // 'live' | 'replay'
      stagePlaying: true,
      t: 0, prevT: 0,
      cur: null,               // staged decision {D, tl, rows, …}
      history: [],
      waiting: [],             // decisions not staged yet, oldest first
      whatIf: null,
      detachedCount: 0,
      selected: null,
      lastStrip: 0, lastConv: 0,
      running: false, raf: 0,
    };

    // --------------------------------------------------------------------- timeline
    function buildTimeline(D) {
      const P = [];
      let t = 0;
      const add = (key, dur, extra) => { P.push(Object.assign({ key, start: t, end: t + dur }, extra)); t += dur; };
      add('intro', 380);
      add('candidates', 520);
      add('filter', 560);
      const nElig = D.scores.filter((s) => s.fits).length;
      if (D.scores.length) {
        if (D.method !== 'stage3') SEGS.forEach((s) => add('seg:' + s.k, s.k === 'bigfit' && !D.scores.some((x) => x.bigfit) ? 160 : 320));
        else add('stage3', 900);
        add('order', 640);
      }
      if (nElig && D.attempts.length) {
        add('launch', 440);
        D.attempts.forEach((a, i) => add('attempt', a.outcome === 'accepted' ? 520 : 820, { i }));
      }
      if (D.outcome === 'accepted') add('fly', 600);
      else add('unplaced', 1100);
      add('hold', 900);
      return { P, end: t };
    }
    const phase = (tl, key) => tl.P.find((p) => p.key === key);
    function phaseAt(tl, t) {
      for (const p of tl.P) if (t < p.end) return p;
      return tl.P[tl.P.length - 1];
    }
    function prog(tl, key, t) {
      const p = phase(tl, key);
      if (!p) return 1;
      return clamp((t - p.start) / (p.end - p.start), 0, 1);
    }
    function reached(tl, key, t) {
      const p = phase(tl, key);
      return p ? t >= p.start : false;
    }
    function chipOf(p) {
      if (!p) return 'result';
      if (p.key === 'intro') return 'queue';
      if (p.key.startsWith('seg:') || p.key === 'stage3') return 'score';
      if (p.key === 'attempt') return 'launch';
      if (p.key === 'fly' || p.key === 'unplaced' || p.key === 'hold') return 'result';
            return p.key;
    }

    // --------------------------------------------------------------------- scoring view (what-if aware)
    function weightsFor(D) { return S.whatIf && D.method !== 'stage3' ? S.whatIf : D.weights; }
    function itemsFor(D) {
      const W = weightsFor(D);
      const lr = (s) => (s.last_resort === 'cpu_busy' ? 1 : s.last_resort === 'low_disk' ? 2 : 0);
      const items = D.scores.map((s, idx) => {
        const c = {};
        SEGS.forEach(({ k }) => {
          const server = s[k] / 1000;
          c[k] = D.weights[k] ? (server / D.weights[k]) * W[k] : 0;
        });
        const total = c.cache + c.headroom + c.speed + c.cpu - c.bigfit;
        return { s, id: s.host_id, c, total, serverRank: idx, lr: lr(s) };
      });
      const ranked = items.slice().sort((a, b) => (b.s.fits - a.s.fits) || (a.lr - b.lr) ||
        (D.method !== 'stage3' ? b.total - a.total : 0) || (a.serverRank - b.serverRank));
      ranked.forEach((it, i) => { it.rank = i; });
      return { items, ranked, W };
    }

    // --------------------------------------------------------------------- DOM refs
    const lanesEl = $('lanes');
    const flyLayer = $('fly-layer');

    // --------------------------------------------------------------------- stage build
    const ROW_H = 40, OUT_H = 34, GROUP_H = 28;

    function buildStage(D) {
      lanesEl.textContent = '';
      const cur = { D, tl: buildTimeline(D), rows: new Map(), fired: new Set(), whyKey: '', phaseKey: '', domain: null, memo: null };
      S.cur = cur;
      S.t = 0; S.prevT = -1;
      renderJobCard(D);
      renderMeta(D);
      // initial (candidate) order: the hosts' natural order
      const order = (id) => hostOf(id)._order;
      const ids = D.scores.map((s) => s.host_id).concat(D.filtered.map((f) => f.host_id)).sort((a, b) => order(a) - order(b));
      cur.initial = ids;

      // domain: positive up to the sum of positive weights, negative to the worst penalty in this decision
      computeDomain(cur);

      ids.forEach((id, idx) => {
        const h = hostOf(id);
        const score = D.scores.find((s) => s.host_id === id) || null;
        const filt = D.filtered.find((f) => f.host_id === id) || null;
        const row = el('div', 'lane');
        row.setAttribute('role', 'listitem');
        row.tabIndex = 0;
        const rank = el('span', 'ln-rank num', '·');
        const name = laneName(h, score);
        const bar = el('span', 'ln-bar' + (D.method === 'stage3' ? ' is-s3' : ''));
        const zero = el('i', 'ln-zero');
        bar.appendChild(zero);
        const segs = {};
        if (score && D.method !== 'stage3') {
          SEGS.forEach(({ k }) => {
            const sg = el('span', 'sg sg-' + k);
            const lab = el('em', 'sg-l');
            sg.appendChild(lab);
            bar.appendChild(sg);
            segs[k] = { el: sg, lab, last: '' };
          });
        }
        const why = el('span', 'ln-out');
        bar.appendChild(why);
        if (score && D.method === 'stage3') {
          const keys = el('span', 'ln-s3');
          const c = score._ctx;
          keys.append(
            s3chip('warm', c.warm ? 'warm ✓' : 'cold'),
            s3chip('free', gib(c.free_ram_bytes) + ' free'),
            s3chip('busy', c.busy_slots + ' busy'),
          );
          bar.appendChild(keys);
        }
        const tot = el('span', 'ln-tot num');
        const badge = el('span', 'ln-badges');
        row.append(rank, name, bar, tot, badge);
        row.style.transitionDelay = '0s, ' + idx * 55 + 'ms, 0s, 0s, 0s, 0s';
        row.addEventListener('click', () => openDetails('host', id, D));
        row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDetails('host', id, D); } });
        lanesEl.appendChild(row);
        cur.rows.set(id, { id, el: row, rankEl: rank, bar, segs, why, tot, badgeEl: badge, score, filt, y: null, badgeKey: '', idx });
      });

      cur.groupEl = el('div', 'lane-group');
      cur.groupEl.append(el('span', 'lg-t', 'Not eligible'), el('span', 'lg-c num', ''));
      lanesEl.appendChild(cur.groupEl);

      cur.nsEl = el('div', 'lane-ns');
      if (D.not_serving.length) {
        const other = D.not_serving.filter((n) => n.why === 'other_pool').map((n) => n.host_id);
        const off = D.not_serving.filter((n) => n.why === 'offline').map((n) => n.host_id);
        const parts = [];
        if (other.length) parts.push(other.map(hostName).join(', ') + ' — serve other labels');
        if (off.length) parts.push(off.map(hostName).join(', ') + ' — offline');
        cur.nsEl.textContent = 'Not candidates: ' + parts.join(' · ');
      }
      lanesEl.appendChild(cur.nsEl);
      buildTicks(cur);
    }

    function s3chip(k, text) { return el('span', 's3 s3-' + k, text); }

    function laneName(h, score) {
      const wrap = el('span', 'ln-name');
      const top = el('span', 'ln-n1');
      top.append(osIcon(h.os), el('b', '', h.name));
      const sub = el('small', 'ln-n2 num');
      if (score) {
        const c = score._ctx;
        sub.textContent = c.busy_slots + '/' + c.capacity + ' busy · CPU ' + (score.cpu_load_percent != null ? Math.round(score.cpu_load_percent) + '%' : '–') + ' · ' + gShort(c.available_bytes) + ' free';
      } else {
        sub.textContent = [h.cores ? h.cores + ' cores' : null, h.ram_bytes ? gShort(h.ram_bytes) : null].filter(Boolean).join(' · ') || (h.online ? '' : 'offline');
      }
      wrap.append(top, sub);
      return wrap;
    }

    function computeDomain(cur) {
      const D = cur.D;
      const W = weightsFor(D);
      const pos = W.cache + W.headroom + W.speed + W.cpu;
      let neg = 0.6;
      if (D.method !== 'stage3') {
        itemsFor(D).items.forEach((it) => { neg = Math.max(neg, it.c.bigfit + Math.max(0, -it.c.speed)); });
      }
      cur.domain = { pos: Math.max(1, pos), neg };
    }

    function buildTicks(cur) {
      const bar = root.querySelector('.lh-bar');
      bar.querySelectorAll('.tick').forEach((t) => t.remove());
      if (cur.D.method !== 'weighted') return;
      const { pos, neg } = cur.domain;
      const span = pos + neg;
      const step = pos > 12 ? 4 : 2;
      if (neg >= 1) { const t = el('span', 'tick num', '−1'); t.style.left = ((neg - 1) / span) * 100 + '%'; bar.appendChild(t); }
      for (let v = 0; v <= pos + 0.001; v += step) {
        const t = el('span', 'tick num', String(v));
        t.style.left = ((neg + v) / span) * 100 + '%';
        bar.appendChild(t);
      }
    }

    // --------------------------------------------------------------------- stage header
    function renderJobCard(D) {
      const c = $('st-jobcard');
      c.textContent = '';
      c.append(jobChipContent(D.job, D.scores.length ? D.estimate_bytes : null, D.estimate_source));
      c.onclick = () => openDetails('job', D.job.id, D);
    }
    function jobChipContent(job, est, source) {
      const f = document.createDocumentFragment();
      const top = el('span', 'jc-top');
      top.append(el('span', 'jc-repo', shortRepo(job.repository)), el('span', 'jc-est num', gShort(est)));
      const name = el('span', 'jc-job', job.job);
      const lab = el('span', 'jc-lab');
      lab.append(osIcon(osOfLabels(job.labels)), document.createTextNode(poolText(job.labels)));
      f.append(top, name, lab);
      return f;
    }
    const SOURCE_TEXT = {
      job: 'p90 of this job’s own runs',
      repository: 'p90 of this repository (job never measured)',
      default: 'default guess (no statistics yet)',
    };
    function renderMeta(D) {
      const m = $('st-meta');
      m.textContent = '';
      const row1 = el('div', 'sm-1');
      row1.append(el('span', 'sm-id num', '#' + D.id), el('span', 'sm-at num muted', B.fmtClock(D.at_ms)));
      if (D.scores.length) row1.appendChild(el('span', 'pill ' + (D.method !== 'stage3' ? 'pill-w' : 'pill-s3'), D.method !== 'stage3' ? 'weighted score' : 'stage 3 · fallback order'));
      else row1.appendChild(el('span', 'pill pill-un', 'nothing to score'));
      const row2 = el('div', 'sm-2');
      const est = el('span', 'sm-kv');
      if (D.scores.length) est.append(el('span', 'muted', 'Needs '), el('b', 'num', gib(D.estimate_bytes)), el('span', 'muted', ' · ' + (SOURCE_TEXT[D.estimate_source] || D.estimate_source)));
      else est.append(el('span', 'muted', D.queued + ' queued · ' + D.leases + ' on the way · ' + poolText(D.labelList)));
      row2.appendChild(est);
      if (D.heavier_bytes && D.scores.some((s) => s.bigfit)) {
        row2.appendChild(el('span', 'sm-kv sm-heavy', 'heavier job waiting: ' + gib(D.heavier_bytes)));
      }
      m.append(row1, row2);
    }
    function renderPhases(tl, t, D) {
      const box = $('phases');
      if (!box.firstChild) {
        PHASE_CHIPS.forEach(([k, label], i) => {
          const c = el('span', 'ph');
          c.dataset.k = k;
          c.append(el('i', 'ph-n num', String(i + 1)), el('span', 'ph-l', label));
          box.appendChild(c);
        });
      }
      const active = chipOf(phaseAt(tl, t));
      const done = t >= tl.end - 1;
      let seen = false;
      Array.from(box.children).forEach((c) => {
        const k = c.dataset.k;
        const isActive = !done && k === active;
        if (isActive) seen = true;
        setCls(c, 'is-on', isActive);
        setCls(c, 'is-done', done || (!seen && !isActive));
        const skipped = (!D.scores.length && ['score', 'order', 'launch'].includes(k)) || (!D.attempts.length && k === 'launch');
        setCls(c, 'is-skip', skipped);
        if (k === 'score') setText(c.lastChild, D.method === 'stage3' ? 'Order' : 'Score');
      });
    }

    // --------------------------------------------------------------------- narration
    function hostName(id) { return hostOf(id).name; }
    function narrate(cur, t, view) {
      const D = cur.D, tl = cur.tl;
      const p = phaseAt(tl, t);
      const key = p.key + (p.i != null ? p.i : '') + (p.key === 'attempt' && (t - p.start) / (p.end - p.start) > 0.45 ? 'm' : '') + (S.whatIf ? JSON.stringify(S.whatIf) : '');
      if (key === cur.whyKey) return;
      cur.whyKey = key;
      const box = $('st-why');
      box.textContent = '';
      const add = (cls, text) => { const s = el('span', cls, text); box.appendChild(s); return s; };
      const pool = poolText(D.labels);
      const nServe = D.scores.length + D.filtered.length;
      if (S.whatIf && D.method !== 'stage3' && reached(tl, 'order', t) && view.ranked.length) {
        const fit = view.ranked.filter((it) => it.s.fits);
        const top = fit[0];
        add('w-h wi', 'What-if: ');
        if (!top) { add('', 'nothing fits, whatever the weights.'); return; }
        add('w-h', hostName(top.id) + ' would rank first with ' + pts(top.total));
        if (fit[1]) add('', ', ' + hostName(fit[1].id) + ' second (' + pts(fit[1].total) + ')');
        add('', '. ');
        const srv = D.scores.find((x) => x.fits);
        if (srv && srv.host_id === top.id) add('muted', 'Same first choice as the coordinator (' + hostName(srv.host_id) + ').');
        else if (srv) add('err', 'The coordinator ranked ' + hostName(srv.host_id) + ' first with its weights.');
        return;
      }
      switch (p.key) {
        case 'intro':
          add('w-h', 'A job for ' + D.repository + ' arrives. ');
          add('', 'It joins the pool queue ' + pool + '. Estimated peak memory: ' + gib(D.estimate_bytes) + ' (' + SOURCE_TEXT[D.estimate_source] + ').');
          break;
        case 'candidates':
          add('w-h', nServe + ' machine' + (nServe === 1 ? '' : 's') + ' serve ' + pool + '. ');
          if (D.not_serving.length) add('muted', D.not_serving.length + ' other' + (D.not_serving.length === 1 ? ' does' : 's do') + ' not.');
          break;
        case 'filter': {
          const out = D.filtered.length + D.scores.filter((s) => !s.fits).length;
          add('w-h', out ? 'Filtering out ' + out + ' that can’t take a job now. ' : 'Every candidate can take a job now. ');
          add('muted', 'Draining or unfit machines and full machines are skipped' + (D.estimate_source === 'job' ? '; with measured samples, so are machines without the memory.' : '; a guessed estimate filters nothing on memory.'));
          break;
        }
        case 'stage3':
          add('w-h', 'No statistics for this queue yet, so no score. ');
          add('', 'Fallback order: a warm checkout first, then the most free memory, then the fewest busy slots.');
          break;
        case 'order':
          add('w-h', 'Ranking. ');
          add('', D.method === 'stage3'
            ? 'Busy-CPU or low-disk machines go last; the rest by warm checkout, then most free memory, then fewest busy slots.'
            : 'Machines that fit first; busy-CPU or low-disk machines are a last resort; then by total score.');
          break;
        case 'launch':
        case 'attempt': {
          const a = p.key === 'attempt' ? D.attempts[p.i] : D.attempts[0];
          if (p.key === 'launch') { add('w-h', 'Launch → ' + hostName(a.host_id) + '. '); add('muted', 'The coordinator offers it a lease and waits for an answer.'); break; }
          const mid = (t - p.start) / (p.end - p.start) > 0.45;
          if (!mid) { add('w-h', 'Asking ' + hostName(a.host_id) + '… '); break; }
          if (a.outcome === 'accepted') add('w-h ok', hostName(a.host_id) + ' accepted the lease. ');
          else if (a.outcome === 'refused') { add('w-h err', hostName(a.host_id) + ' refused: ' + (REFUSAL[a.reason] || B.reasonText(a.reason)) + '. '); add('', 'The coordinator asks the next machine at once: that is the next decision.'); }
          else if (a.outcome === 'unanswered') { add('w-h err', hostName(a.host_id) + ' did not answer in time. '); add('', 'The coordinator asks the next machine: that is the next decision.'); }
          else add('w-h', 'Launch ' + B.reasonText(a.outcome) + '. ');
          break;
        }
        default:
          if (p.key.startsWith('seg:')) {
            const s = SEG_BY[p.key.slice(4)];
            const W = weightsFor(D);
            add('w-h seg-t seg-t-' + s.k, s.name + ' ' + (s.neg ? '−' : '×') + W[s.k].toFixed(1) + ' ');
            add('', '· ' + s.tip + '.');
          } else explainResult(cur, view, add);
      }
    }

    function explainResult(cur, view, add) {
      const D = cur.D;
      if (D.outcome !== 'accepted') {
        const a = D.attempts[0];
        if (a && a.outcome === 'refused') { add('w-h err', hostName(a.host_id) + ' refused (' + (REFUSAL[a.reason] || B.reasonText(a.reason)) + '). '); add('', 'The next decision asks the machine next in line.'); return; }
        if (a && a.outcome === 'unanswered') { add('w-h err', hostName(a.host_id) + ' did not answer. '); add('', 'The next decision asks the machine next in line.'); return; }
        if (D.unplaced === 'no_free_slot') add('w-h err', 'No machine can take it right now: every candidate is full. ');
        else if (D.unplaced === 'no_memory_fit') add('w-h err', 'No machine has the memory for it right now. ');
        else if (D.unplaced === 'unfit_or_draining') add('w-h err', 'Every machine that serves it is unfit or draining. ');
        else if (D.unplaced === 'refused' || D.unplaced === 'unanswered') add('w-h err', 'Every machine asked this round refused or did not answer. ');
        else if (D.unplaced === 'cancelled' || D.unplaced === 'expired') add('w-h err', 'The launch was ' + D.unplaced + ' before its runner started. ');
        else add('w-h err', 'No connected machine serves it right now. ');
        add('', 'The job keeps waiting; the coordinator tries again when something changes.');
        return;
      }
      const win = view.items.find((it) => it.id === D.chosen);
      const refusals = D.attempts.filter((a) => a.outcome !== 'accepted');
      if (D.method === 'stage3') {
        if (!win) { add('w-h ok', hostName(D.chosen) + ' got the job.'); return; }
        add('w-h ok', hostName(D.chosen) + ' wins on the fallback order');
        add('', ' — ' + (win.s._ctx.warm ? 'it has a warm checkout' : 'most free memory') + '.');
        return;
      }
      const others = view.ranked.filter((it) => it.id !== D.chosen && it.s.fits);
      if (!win) { add('w-h ok', hostName(D.chosen) + ' got the job.'); return; }
      add('w-h ok', hostName(D.chosen) + ' wins with ' + pts(win.total) + '. ');
      const top = SEGS.map(({ k }) => ({ k, v: k === 'bigfit' ? -win.c[k] : win.c[k] })).filter((x) => x.v > 0.05).sort((a, b) => b.v - a.v).slice(0, 2);
      if (top.length) add('', 'Mostly ' + top.map((x) => SEG_BY[x.k].name.toLowerCase() + ' (' + pts(x.v, true) + ')').join(' and ') + '. ');
      if (refusals.length) add('err', refusals.map((a) => hostName(a.host_id) + (a.outcome === 'refused' ? ' refused' : ' did not answer')).join(', ') + ' first. ');
      if (win.s.last_resort) add('warn', 'It is a last resort (' + (win.s.last_resort === 'cpu_busy' ? 'busy CPU' : 'low disk') + '), the only one left. ');
      const next = others[0];
      if (next) {
        const diffs = SEGS.map(({ k }) => {
          const a = k === 'bigfit' ? -win.c[k] : win.c[k];
          const b = k === 'bigfit' ? -next.c[k] : next.c[k];
          return { k, d: a - b };
        }).sort((x, y) => y.d - x.d);
        const lead = diffs[0];
        const gap = win.total - next.total;
        let txt = hostName(next.id) + (next.lr && !win.lr ? ' scores ' + pts(next.total) + ' but is a last resort' : ' is ' + Math.abs(gap).toFixed(2) + (gap >= 0 ? ' behind' : ' ahead but ranked lower'));
        if (lead && lead.d > 0.05 && !(next.lr && !win.lr)) txt += ' — the gap is ' + SEG_BY[lead.k].name.toLowerCase() + ' (' + pts(lead.d, true) + ')';
        add('muted', txt + '.');
      }
      if (S.whatIf) {
        const wiTop = view.ranked[0];
        if (wiTop && wiTop.id !== D.chosen) add('wi', ' With your what-if weights, ' + hostName(wiTop.id) + ' would rank first.');
        else add('wi', ' Your what-if weights keep the same winner.');
      }
    }

    // --------------------------------------------------------------------- stage frame
    function renderStage() {
      const cur = S.cur;
      if (!cur) return;
      const D = cur.D, tl = cur.tl, t = S.t;
      renderPhases(tl, t, D);
      const view = itemsFor(D);
      narrate(cur, t, view);


      const filterOn = reached(tl, 'filter', t);
      const orderOn = reached(tl, 'order', t);
      const candP = prog(tl, 'candidates', t);
      const fitIds = new Set(view.items.filter((it) => it.s.fits).map((it) => it.id));
      const eligOrder = orderOn ? view.ranked.filter((it) => it.s.fits).map((it) => it.id) : cur.initial.filter((id) => fitIds.has(id));
      const outIds = cur.initial.filter((id) => !fitIds.has(id));

      // layout
      let y = 0;
      const place = (row, ny) => {
        if (row.y !== ny) { row.y = ny; row.el.style.transform = 'translateY(' + ny + 'px)'; }
      };
      if (!filterOn) {
        cur.initial.forEach((id) => { place(cur.rows.get(id), y); y += ROW_H; });
        cur.groupEl.classList.remove('is-on');
      } else {
        eligOrder.forEach((id) => { place(cur.rows.get(id), y); y += ROW_H; });
        if (outIds.length) {
          cur.groupEl.style.transform = 'translateY(' + (y + 4) + 'px)';
          cur.groupEl.classList.add('is-on');
          setText(cur.groupEl.lastChild, String(outIds.length));
          y += GROUP_H + 4;
          outIds.forEach((id) => { place(cur.rows.get(id), y); y += OUT_H; });
        } else cur.groupEl.classList.remove('is-on');
      }
      cur.nsEl.style.transform = 'translateY(' + (y + 6) + 'px)';
      setCls(cur.nsEl, 'is-on', reached(tl, 'candidates', t) && !!D.not_serving.length);
      const h = y + (D.not_serving.length ? 34 : 6);
      if (cur.h !== h) { cur.h = h; lanesEl.style.height = h + 'px'; }

      // attempts state
      const att = {};
      tl.P.filter((p) => p.key === 'attempt').forEach((p) => {
        const a = D.attempts[p.i];
        if (t < p.start) return;
        const mid = p.start + (p.end - p.start) * 0.45;
        att[a.host_id] = t < mid ? 'trying' : a.outcome;
      });
      const launchOn = reached(tl, 'launch', t) && !reached(tl, 'attempt', t);
      const flyOn = reached(tl, 'fly', t);

      const { pos, neg } = cur.domain;
      const span = pos + neg;
      const zeroPct = (neg / span) * 100;
      if (!cur.barPx) { const r0 = cur.rows.values().next().value; cur.barPx = r0 && r0.bar ? r0.bar.clientWidth : 500; }
      const segP = {};
      SEGS.forEach(({ k }) => { segP[k] = easeOut(prog(tl, 'seg:' + k, t)); });

      cur.rows.forEach((row) => {
        const id = row.id;
        const out = filterOn && !fitIds.has(id);
        const visible = candP * cur.initial.length > row.idx - 0.2 || reached(tl, 'filter', t);
        setCls(row.el, 'is-in', visible);
        setCls(row.el, 'is-out', out);
        row.bar.firstChild.style.left = zeroPct + '%';
        const it = view.items.find((x) => x.id === id);
        const rankIdx = eligOrder.indexOf(id);
        setText(row.rankEl, orderOn && rankIdx >= 0 ? String(rankIdx + 1) : out ? '–' : '·');

        if (it && D.method !== 'stage3' && !out) {
          let right = zeroPct, left = zeroPct, total = 0;
          SEGS.forEach(({ k }) => {
            const sg = row.segs[k];
            const v = it.c[k] * segP[k];
            const isNeg = k === 'bigfit' || v < 0;
            const mag = Math.abs(k === 'bigfit' ? v : v);
            const w = (mag / span) * 100;
            let x;
            if (isNeg) { left -= w; x = left; } else { x = right; right += w; }
            sg.el.style.left = x + '%';
            sg.el.style.width = w + '%';
            setCls(sg.el, 'is-neg', isNeg);
            const show = mag > 0.004;
            setCls(sg.el, 'is-on', show);
            const txt = (w / 100) * cur.barPx > 40 ? pts(k === 'bigfit' ? -mag : v, true) : '';
            if (sg.last !== txt) { sg.last = txt; sg.lab.textContent = txt; }
            total += k === 'bigfit' ? -v : v;
          });
          setText(row.tot, segP.cache > 0 ? pts(total) : '');
          row.why.textContent = '';
        } else if (it && D.method === 'stage3' && !out) {
          setText(row.tot, '');
          setCls(row.bar, 'show-s3', reached(tl, 'stage3', t));
        } else {
          setText(row.tot, '');
          if (out) setText(row.why, outText(row, it, D));
          else setText(row.why, '');
        }

        // badges
        const b = [];
        const state = att[id];
        if (out) b.push(['bad', outBadge(row, it)]);
        if (orderOn && it && it.s.fits && it.s.last_resort) b.push(['warn', it.s.last_resort === 'cpu_busy' ? 'Last resort · CPU ' + Math.round(it.s.cpu_load_percent) + '%' : 'Last resort · disk ' + gib(it.s.disk_free_bytes)]);
        if (state === 'trying') b.push(['try', 'Asking…']);
        if (state === 'accepted') b.push(['ok', 'Accepted']);
        if (state === 'refused') b.push(['err', 'Refused · ' + B.reasonText(D.attempts.find((a) => a.host_id === id).reason)]);
        if (state === 'unanswered') b.push(['err', 'No answer']);
        if (S.whatIf && orderOn && D.chosen === id && state !== 'accepted') b.push(['srv', 'Server’s pick']);
        if (S.whatIf && orderOn && it && it.s.fits && it.rank !== it.serverRank) b.push(['wi', 'was #' + (it.serverRank + 1)]);
        const key = b.map((x) => x.join(':')).join('|');
        if (key !== row.badgeKey) {
          row.badgeKey = key;
          row.badgeEl.textContent = '';
          b.forEach(([cls, text]) => row.badgeEl.appendChild(el('span', 'bdg bdg-' + cls, text)));
        }

        const firstTry = D.attempts[0] && D.attempts[0].host_id === id;
        setCls(row.el, 'is-launch', launchOn && firstTry);
        setCls(row.el, 'is-try', state === 'trying');
        setCls(row.el, 'is-won', state === 'accepted');
        setCls(row.el, 'is-ref', state === 'refused' || state === 'unanswered');
        setCls(row.el, 'is-lr', orderOn && it && it.s.fits && !!it.s.last_resort);
        setCls(row.el, 'is-wi-top', !!S.whatIf && orderOn && rankIdx === 0);
        setCls(row.el, 'is-final', flyOn && D.chosen === id);
      });
      setCls($('stage'), 'is-unplaced', reached(tl, 'unplaced', t));
    }

    function outBadge(row) {
      if (row.filt) return row.filt.reason === 'unfit_or_draining' ? REASON[row.filt.detail] || 'Unfit or draining' : REASON[row.filt.reason] || B.reasonText(row.filt.reason);
      return REASON.no_memory_fit;
    }
    function outText(row, it, D) {
      const f = row.filt;
      if (f && f.reason === 'no_free_slot') return f.capacity ? 'all ' + f.capacity + ' slots taken' : 'no free slot';
      if (f && f.reason === 'tried') return 'asked this round: ' + (f.detail === 'unanswered' ? 'no answer' : REFUSAL[f.detail] || B.reasonText(f.detail));
      if (f && f.detail === 'draining') return 'draining — takes no new jobs';
      if (f && f.detail === 'unfit') return 'host doctor check failing';
      if (it) {
        const margin = (feed.snap && feed.snap.ram_margin_bytes) || 0;
        return 'needs ' + gib(D.estimate_bytes + margin) + ' (estimate + ' + gib(margin) + ' margin), has ' + gib(it.s._ctx.available_bytes) + (D.method !== 'stage3' ? ' · would score ' + pts(it.total) : '');
      }
      return '';
    }

    // --------------------------------------------------------------------- flying chips
    function fly(fromRect, toRect, D, dur) {
      if (reduceMotion.matches || !fromRect || !toRect) return;
      const f = el('div', 'fly');
      f.appendChild(jobChipContent(D.job, D.scores.length ? D.estimate_bytes : null, D.estimate_source));
      flyLayer.appendChild(f);
      f.style.left = fromRect.left + 'px';
      f.style.top = fromRect.top + 'px';
      f.style.width = fromRect.width + 'px';
      f.style.height = fromRect.height + 'px';
      const dx = toRect.left + toRect.width / 2 - (fromRect.left + fromRect.width / 2);
      const dy = toRect.top + toRect.height / 2 - (fromRect.top + fromRect.height / 2);
      const sc = clamp(Math.min(toRect.width / fromRect.width, toRect.height / fromRect.height), 0.35, 1);
      const lift = -Math.min(80, Math.abs(dx) * 0.15 + 20);
      const anim = f.animate([
        { transform: 'translate(0,0) scale(1)', opacity: 1 },
        { transform: 'translate(' + dx * 0.5 + 'px,' + (dy * 0.5 + lift) + 'px) scale(' + (1 + sc) / 2 + ')', opacity: 1, offset: 0.55 },
        { transform: 'translate(' + dx + 'px,' + dy + 'px) scale(' + sc + ')', opacity: 0 },
      ], { duration: dur / Math.max(1, S.speed * 0.7), easing: 'cubic-bezier(.45,.05,.25,1)' });
      anim.onfinish = () => f.remove();
    }
    const rectOf = (node) => (node ? node.getBoundingClientRect() : null);
    function stripCard(id) { return root.querySelector('.mc[data-host="' + CSS.escape(id) + '"]'); }
    function pulse(node, cls) {
      if (!node) return;
      node.classList.remove(cls);
      void node.offsetWidth;
      node.classList.add(cls);
    }

    function fireEvents(cur, from, to) {
      if (!(to > from) || to - from > 1500) return; // only on normal forward playback
      const D = cur.D;
      cur.tl.P.forEach((p, idx) => {
        if (p.start <= from || p.start > to) return;
        const key = p.key + idx;
        if (cur.fired.has(key)) return;
        cur.fired.add(key);
        if (p.key === 'launch') {
          const row = cur.rows.get(D.attempts[0].host_id);
          fly(rectOf($('st-jobcard')), rectOf(row && row.el.querySelector('.ln-name')), D, 480);
        }
        if (p.key === 'attempt' && D.attempts[p.i].outcome !== 'accepted') {
          const row = cur.rows.get(D.attempts[p.i].host_id);
          if (row) setTimeout(() => pulse(row.el, 'shake'), (p.end - p.start) * 0.45 / (S.pace || 1));
        }
        if (p.key === 'fly') {
          const id = D.chosen;
          const row = cur.rows.get(id);
          fly(rectOf(row && row.el.querySelector('.ln-name')), rectOf(stripCard(id)), D, 620);
          setTimeout(() => pulse(stripCard(id), 'land'), 420 / Math.max(1, S.speed * 0.7));
        }
      });
    }

    // --------------------------------------------------------------------- live orchestration
    function stageFollowsLive() { return S.mode === 'live' && S.stagePlaying && !S.paused; }
    function pushHistory(D) {
      if (D._inHistory) return;
      D._inHistory = true;
      S.history.unshift(D);
      if (S.history.length > 80) S.history.length = 80;
      S.histDirty = true;
    }
    // A launch's answer comes within the coordinator's ack timeout (10 s).
    const settled = (D) => complete(D) || feed.now() - D.at_ms > 15000;

    feed.on((u) => {
      if (u.failed) return;
      syncHosts();
      if (u.first || u.reset) {
        S.history = [];
        S.waiting = [];
        for (const d of feed.decisions.slice(-40)) pushHistory(settle(staged(d)));
        S.idleShown = false;
      } else {
        S.waiting.push(...u.decisions.map(staged));
      }
      S.histDirty = true;
      S.lastStrip = 0;
      S.lastConv = 0;
    });

    // The next decision worth staging: in order, once its launch is answered;
    // when too many wait, the older ones go straight to the history.
    function takeDecision() {
      while (S.waiting.length > MAX_WAITING) pushHistory(settle(S.waiting.shift()));
      const D = S.waiting[0];
      if (!D || !settled(D)) return null;
      S.waiting.shift();
      return settle(D);
    }
    function resolveInstant() {
      // The stage is not following live: the decisions go to the history as they come.
      while (S.waiting.length && settled(S.waiting[0])) {
        pushHistory(settle(S.waiting.shift()));
        S.detachedCount++;
      }
      if (S.detachedCount) setText($('sc-live'), 'Back to live · ' + S.detachedCount + ' new');
    }

    function startDecision(D, still) {
      const fromCard = root.querySelector('.jc[data-job="' + CSS.escape(D.job.id) + '"]');
      const fromRect = still ? null : rectOf(fromCard);
      buildStage(D);
      S.stagePlaying = true;
      S.pace = paceFor();
      $('st-kicker').textContent = still ? 'Last decision · waiting for work' : 'Now placing';
      $('stage').classList.toggle('is-idle', !!still);
      $('stage').classList.remove('is-unplaced');
      if (still) { S.t = S.cur.tl.end; S.cur.done = true; }
      layoutConveyor(true);
      if (fromRect) requestAnimationFrame(() => fly(fromRect, rectOf($('st-jobcard')), D, 420));
    }

    function paceFor() {
      const boost = reduceMotion.matches ? 3 : 1 + Math.min(1.6, Math.max(0, S.waiting.length - 1) * 0.35);
      return S.speed * boost;
    }

    // --------------------------------------------------------------------- conveyor
    const convLane = $('conv-lane');
    const convCards = new Map();
    const CARD_W = 168, CARD_GAP = 10;
    function queuedJobs() {
      const snap = feed.snap || {};
      const onStage = S.cur && !S.cur.done ? S.cur.D.job.id : null;
      const last = new Map();
      for (const d of feed.decisions) if (d.scores.length) last.set(d.queue, d);
      const pending = new Map((snap.queues || []).map((q) => [B.queueId(q.repository, q.labels), q]));
      return (snap.queued || []).slice().sort((a, b) => a.queued_at - b.queued_at).map((x) => {
        const queue = B.queueId(x.repository, x.labels);
        const d = last.get(queue);
        const p = pending.get(queue);
        return {
          id: 'gh:' + x.id, gh_id: x.id, repository: x.repository, job: x.name || '#' + x.id, labels: B.labelList(x.labels), pool: x.pool,
          queued_at: x.queued_at, estimate_bytes: d ? d.estimate_bytes : null, estimate_source: d ? d.estimate_source : null,
          blocked: p && p.reason ? p.reason : null, queue,
        };
      }).filter((j) => j.id !== onStage);
    }
    function layoutConveyor() {
      const jobs = queuedJobs();
      const ids = new Set(jobs.map((j) => j.id));
      convCards.forEach((c, id) => {
        if (!ids.has(id)) { c.el.remove(); convCards.delete(id); }
      });
      const W = convLane.clientWidth;
      const nowS = feed.now() / 1000;
      jobs.forEach((j, i) => {
        let c = convCards.get(j.id);
        if (!c) {
          const node = el('button', 'jc');
          node.type = 'button';
          node.dataset.job = j.id;
          node.appendChild(jobChipContent(j, j.estimate_bytes, j.estimate_source));
          const wait = el('span', 'jc-wait');
          const track = el('span', 'jc-wtr');
          const bar = el('i', 'jc-wb');
          track.appendChild(bar);
          const wt = el('span', 'jc-wt num');
          const tag = el('span', 'jc-tag');
          wait.append(track, tag, wt);
          node.appendChild(wait);
          node.addEventListener('click', () => openDetails('job', j.id));
          node.style.transform = 'translateX(' + (W + 40) + 'px)';
          convLane.appendChild(node);
          c = { el: node, bar, wt, tag, x: W + 40, tagText: '' };
          convCards.set(j.id, c);
          void node.offsetWidth;
        }
        const x = i * (CARD_W + CARD_GAP);
        if (c.x !== x) { c.x = x; c.el.style.transform = 'translateX(' + x + 'px)'; }
        const wait = Math.max(0, nowS - j.queued_at);
        c.bar.style.width = clamp(wait / 300, 0, 1) * 100 + '%';
        setCls(c.el, 'w-warn', wait > 60 && wait <= 300);
        setCls(c.el, 'w-err', wait > 300);
        setText(c.wt, secs(wait));
        const tagText = j.blocked ? REASON[j.blocked] || B.reasonText(j.blocked) : j.pool ? '' : 'wake';
        if (c.tagText !== tagText) { c.tagText = tagText; c.tag.textContent = tagText; setCls(c.el, 'is-blocked', !!j.blocked); setCls(c.el, 'is-wake', !j.pool); }
        setCls(c.el, 'is-sel', S.selected && S.selected.kind === 'job' && S.selected.id === j.id);
      });
      $('conv-empty').hidden = jobs.length > 0;
      const oldest = jobs.length ? nowS - jobs[0].queued_at : 0;
      setText($('conv-meta'), jobs.length + ' waiting' + (jobs.length ? ' · oldest ' + secs(oldest) : ''));
      convLane.style.width = Math.max(0, jobs.length * (CARD_W + CARD_GAP)) + 'px';
    }

    // --------------------------------------------------------------------- machine strip
    const stripList = $('strip-list');
    const stripCards = new Map();
    function renderStrip() {
      let online = 0, busy = 0, cap = 0;
      const hosts = [...raceHosts.values()].sort((a, b) => a._order - b._order);
      stripCards.forEach((c, id) => { if (!raceHosts.has(id)) { c.el.remove(); stripCards.delete(id); } });
      hosts.forEach((h) => {
        let c = stripCards.get(h.id);
        if (!c) {
          const node = el('button', 'mc');
          node.type = 'button';
          node.dataset.host = h.id;
          const top = el('span', 'mc-top');
          const nm = el('b', 'mc-n', h.name);
          const st = el('span', 'mc-st');
          const slots = el('span', 'mc-slots');
          top.append(osIcon(h.os), nm, slots, st);
          const gauges = el('span', 'mc-gs');
          const g = (label) => {
            const row = el('span', 'mc-g');
            const track = el('i', 'mc-gt');
            const fill = el('b', 'mc-gf');
            track.appendChild(fill);
            const val = el('span', 'mc-gv num');
            row.append(el('span', 'mc-gl', label), track, val);
            gauges.appendChild(row);
            return { fill, val, row };
          };
          const cpu = g('CPU'), ram = g('RAM');
          node.append(top, gauges);
          node.addEventListener('click', () => openDetails('host', h.id));
          c = { el: node, nm, st, slots, cpu, ram, slotKey: '' };
          stripCards.set(h.id, c);
        }
        stripList.appendChild(c.el);
        setText(c.nm, h.name);
        if (h.online) { online++; cap += h.capacity; }
        const active = h.online ? activeOn(h) : [];
        busy += Math.min(active.length, h.capacity);
        const lr = h.online ? lastResort(h) : null;
        const status = !h.online ? 'offline' : h.draining ? 'draining' : h.unfit ? 'unfit' : lr === 'cpu_busy' ? 'cpu busy' : lr === 'low_disk' ? 'low disk' : 'online';
        setText(c.st, status);
        c.st.className = 'mc-st st-' + status.replace(' ', '-');
        setCls(c.el, 'is-off', !h.online);
        setCls(c.el, 'is-drain', h.draining);
        // slots
        const n = Math.max(h.capacity, Math.min(active.length, 16));
        const key = active.map((l) => l.state + (l.progress == null ? '?' : '')).join(',') + '/' + n;
        if (key !== c.slotKey) {
          c.slotKey = key;
          c.slots.textContent = '';
          for (let i = 0; i < n; i++) {
            const l = active[i];
            const s = el('i', 'slot ' + (l ? (l.state === 'claimed' ? 'sl-run' + (l.progress == null ? ' sl-unk' : '') : 'sl-acc') : 'sl-free'));
            if (l) s.appendChild(el('b', 'sl-p'));
            c.slots.appendChild(s);
          }
        }
        Array.from(c.slots.children).forEach((s, i) => {
          const l = active[i];
          if (l && l.state === 'claimed' && s.firstChild) s.firstChild.style.width = l.progress == null ? '100%' : Math.round(l.progress * 100) + '%';
        });
        const cpu = h.online && h.cpu_load_percent != null ? h.cpu_load_percent : null;
        c.cpu.fill.style.width = (cpu || 0) + '%';
        setCls(c.cpu.row, 'g-hot', cpu != null && cpu >= ((feed.snap && feed.snap.cpu_busy_percent) || 90));
        setText(c.cpu.val, cpu != null ? Math.round(cpu) + '%' : '—');
        const used = h.online && h.ram_bytes && h.free_ram_bytes != null ? 1 - h.free_ram_bytes / h.ram_bytes : null;
        c.ram.fill.style.width = (used || 0) * 100 + '%';
        setCls(c.ram.row, 'g-hot', used != null && used >= 0.85);
        setText(c.ram.val, used != null ? gShort(h.free_ram_bytes) + ' free' : '—');
        setCls(c.el, 'is-sel', S.selected && S.selected.kind === 'host' && S.selected.id === h.id);
        const cur = S.cur;
        setCls(c.el, 'is-cand', !!cur && cur.rows.has(h.id) && S.t > 0);
      });
      setText($('strip-meta'), online + ' online · ' + busy + '/' + cap + ' slots busy');
    }

    // --------------------------------------------------------------------- history
    const histList = $('hist-list');
    function renderHistory() {
      S.histDirty = false;
      histList.textContent = '';
      S.history.slice(0, 40).forEach((D) => {
        const c = el('button', 'hc');
        c.type = 'button';
        c.setAttribute('role', 'listitem');
        if (S.cur && S.cur.D === D) c.classList.add('is-sel');
        const top = el('span', 'hc-top');
        const okCls = D.outcome === 'accepted' ? 'ok' : 'err';
        top.append(el('span', 'hc-id num', '#' + D.id), el('span', 'hc-at num', B.fmtClock(D.at_ms)), el('i', 'hc-o hc-' + okCls));
        const job = el('span', 'hc-job', shortRepo(D.repository) + ' · ' + D.job.job);
        const win = el('span', 'hc-win');
        const mini = el('span', 'hc-bar');
        const sub = el('span', 'hc-sub');
        const a = D.attempts[0];
        if (D.outcome === 'accepted') {
          const s = D.scores.find((x) => x.host_id === D.chosen);
          win.append(el('span', 'muted', '→ '), el('b', '', hostName(D.chosen)), el('span', 'hc-tot num', s && D.method !== 'stage3' ? pts(s.total / 1000) : 'stage 3'));
          if (s && D.method !== 'stage3') {
            const total = SEGS.reduce((acc, { k }) => acc + Math.abs(s[k]), 0) || 1;
            SEGS.forEach(({ k }) => {
              if (!s[k]) return;
              const b = el('i', 'sg-' + k + (k === 'bigfit' || s[k] < 0 ? ' is-neg' : ''));
              b.style.width = (Math.abs(s[k]) / total) * 100 + '%';
              mini.appendChild(b);
            });
          }
          const fit = s ? D.scores.filter((x) => x.fits && x.host_id !== D.chosen) : [];
          if (s && fit.length && D.method !== 'stage3' && fit[0].last_resort && !s.last_resort) sub.textContent = 'ahead of ' + hostName(fit[0].host_id) + ' (last resort)';
          else if (s && fit.length && D.method !== 'stage3') sub.textContent = pts((s.total - fit[0].total) / 1000, true) + ' over ' + hostName(fit[0].host_id);
          else sub.textContent = fit.length + ' other' + (fit.length === 1 ? '' : 's') + ' eligible';
        } else if (a && (a.outcome === 'refused' || a.outcome === 'unanswered')) {
          win.append(el('span', 'hc-un', hostName(a.host_id) + ' · ' + (a.outcome === 'refused' ? 'refused' : 'no answer')));
          sub.textContent = a.outcome === 'refused' ? REFUSAL[a.reason] || B.reasonText(a.reason) : 'the next host is asked';
        } else {
          win.append(el('span', 'hc-un', 'unplaced · ' + (REASON[D.unplaced] || B.reasonText(D.unplaced))));
          sub.textContent = D.filtered.length + ' filtered · job waits';
        }
        c.append(top, job, win, mini, sub);
        c.addEventListener('click', () => replay(D));
        histList.appendChild(c);
      });
      $('hist-empty').hidden = S.history.length > 0;
      setText($('hist-meta'), S.history.length + ' decision' + (S.history.length === 1 ? '' : 's'));
    }

    // --------------------------------------------------------------------- replay / scrub
    function replay(D) {
      if (S.cur && S.cur.D && S.mode === 'live' && !S.cur.done) pushHistory(S.cur.D);
      S.mode = 'replay';
      S.detachedCount = 0;
      buildStage(D);
      S.stagePlaying = true;
      S.pace = S.speed;
      $('st-kicker').textContent = 'Replay';
      $('stage').classList.add('is-replay');
      $('stage').classList.remove('is-idle');
      updateScrubUi();
      renderHistory();
    }
    function backToLive() {
      S.mode = 'live';
      S.detachedCount = 0;
      $('stage').classList.remove('is-replay');
      if (S.cur) { pushHistory(S.cur.D); S.cur.done = true; }
      S.stagePlaying = true;
      updateScrubUi();
      renderHistory();
    }
    function updateScrubUi() {
      const replayMode = S.mode === 'replay';
      $('sc-live').hidden = !(replayMode || !S.stagePlaying);
      if (!S.detachedCount) setText($('sc-live'), 'Back to live');
      const label = replayMode ? 'Replay #' + (S.cur ? S.cur.D.id : '') : S.paused ? 'Paused' : S.stagePlaying ? 'Live' : 'Held';
      setText($('sc-mode'), label);
      setCls($('sc-play'), 'is-playing', S.stagePlaying);
      setCls($('sc-mode'), 'is-live', !replayMode && S.stagePlaying && !S.paused);
    }

    // --------------------------------------------------------------------- what-if
    function buildWhatIf() {
      const box = $('wi-sliders');
      box.textContent = '';
      const server = weightsNow();
      SEGS.forEach(({ k, name, neg }) => {
        const w = el('label', 'wi-s');
        w.title = 'the coordinator’s weight: ' + server[k].toFixed(1);
        const head = el('span', 'wi-sh');
        head.append(el('i', 'wi-dot sg-' + k), el('span', 'wi-n', name + (neg ? ' (−)' : '')));
        const val = el('span', 'wi-v num', '');
        const r = document.createElement('input');
        r.type = 'range'; r.min = '0'; r.max = '8'; r.step = '0.1';
        r.value = String(S.whatIf[k]);
        r.setAttribute('aria-label', name + ' weight, what-if');
        w.append(head, r, val);
        const upd = () => {
          S.whatIf[k] = parseFloat(r.value);
          setText(val, S.whatIf[k].toFixed(1));
          setCls(w, 'is-changed', Math.abs(S.whatIf[k] - server[k]) > 0.001);
          whatIfChanged();
        };
        r.addEventListener('input', upd);
        setText(val, S.whatIf[k].toFixed(1));
        box.appendChild(w);
      });
    }
    function whatIfChanged() {
      if (!S.cur) return;
      computeDomain(S.cur);
      buildTicks(S.cur);
      S.cur.whyKey = '';
      renderStage();
    }
    function toggleWhatIf(on) {
      const btn = $('btn-whatif');
      on = on == null ? !S.whatIf : on;
      btn.setAttribute('aria-pressed', String(on));
      $('whatif').hidden = !on;
      $('stage').classList.toggle('is-whatif', on);
      if (on) {
        S.whatIf = weightsNow();
        buildWhatIf();
        // Hold the stage on the ranked state so the effect is visible.
        if (S.cur) {
          const o = phase(S.cur.tl, 'order');
          if (o && S.t < o.end) S.t = o.end - 1;
          S.stagePlaying = false;
        }
      } else {
        S.whatIf = null;
        if (S.cur) { computeDomain(S.cur); buildTicks(S.cur); S.cur.whyKey = ''; }
        if (S.mode === 'live') S.stagePlaying = true;
      }
      updateScrubUi();
      renderStage();
    }

    // --------------------------------------------------------------------- details drawer
    function openDetails(kind, id, D) {
      S.selected = { kind, id, D: D || null };
      $('rdrawer').hidden = false;
      requestAnimationFrame(() => $('rdrawer').classList.add('is-open'));
      renderDetails();
      S.lastStrip = 0;
    }
    function closeDetails() {
      S.selected = null;
      $('rdrawer').classList.remove('is-open');
      setTimeout(() => { if (!S.selected) $('rdrawer').hidden = true; }, 260);
    }
    function kv(dl, k, v, cls) {
      const row = el('div', 'kvr' + (cls ? ' ' + cls : ''));
      row.append(el('dt', '', k), el('dd', 'num', v));
      dl.appendChild(row);
    }
    function renderDetails() {
      const sel = S.selected;
      if (!sel) return;
      const body = $('dr-body');
      body.textContent = '';
      const snap = feed.snap || {};
      if (sel.kind === 'host') {
        const h = hostOf(sel.id);
        const title = $('dr-title');
        title.textContent = '';
        title.append(osIcon(h.os), document.createTextNode(' ' + h.name));
        const dl = el('dl', 'kvs');
        const lr = h.online ? lastResort(h) : null;
        kv(dl, 'Status', B.statusOf(h));
        kv(dl, 'Platform', [h.os, h.arch].filter(Boolean).join(' · '));
        kv(dl, 'Cores', h.cores ? String(h.cores) : '—');
        kv(dl, 'RAM', h.online ? gib(h.free_ram_bytes) + ' free of ' + gib(h.ram_bytes, 0) : '—');
        kv(dl, 'CPU load', h.online && h.cpu_load_percent != null ? Math.round(h.cpu_load_percent) + '%' : '—', lr === 'cpu_busy' ? 'kvr-warn' : '');
        kv(dl, 'Disk free', gib(h.disk_free_bytes), lr === 'low_disk' ? 'kvr-warn' : '');
        kv(dl, 'Slots', h.online ? (h.busy_slots || 0) + ' of ' + h.capacity + ' in use' : '—');
        body.appendChild(dl);
        const D = sel.D || (S.cur && S.cur.D);
        const s = D && D.scores.find((x) => x.host_id === h.id);
        const f = D && D.filtered.find((x) => x.host_id === h.id);
        if (D && (s || f)) {
          body.appendChild(el('h3', 'dr-sh', 'In decision #' + D.id + ' · ' + shortRepo(D.repository) + ' · ' + D.job.job));
          if (f) body.appendChild(el('p', 'dr-p', 'Not eligible: ' + outText({ filt: f }, null, D) + '.'));
          if (s) {
            const fit = D.scores.filter((x) => x.fits);
            const r = fit.indexOf(s);
            let line;
            if (!s.fits) line = 'Did not fit in memory, so it was not ranked.';
            else if (D.outcome === 'accepted' && D.chosen === s.host_id) line = 'Ranked #' + (r + 1) + ' and got the job.';
            else if (D.outcome === 'accepted' && D.method !== 'stage3') {
              const w = D.scores.find((x) => x.host_id === D.chosen);
              line = 'Ranked #' + (r + 1) + ' of ' + fit.length + '; ' + hostName(D.chosen) + ' got the job' + (w ? ' with ' + pts(w.total / 1000) + ' (' + pts((s.total - w.total) / 1000, true) + ' here)' : '') + '.';
            } else line = 'Ranked #' + (r + 1) + ' of ' + fit.length + '.';
            body.appendChild(el('p', 'dr-p', line));
            body.appendChild(breakdown(D, s));
          }
        }
        body.appendChild(el('h3', 'dr-sh', 'Profiles'));
        const pools = el('div', 'r-chips');
        h.pools.forEach((p) => pools.appendChild(el('span', 'r-chip mono', p)));
        if (!h.pools.length) pools.appendChild(el('span', 'muted', 'none reported'));
        body.appendChild(pools);
        body.appendChild(el('h3', 'dr-sh', 'Warm checkouts'));
        const warm = el('div', 'r-chips');
        h.warm_repos.forEach((r) => warm.appendChild(el('span', 'r-chip r-chip-cache', shortRepo(r) || r)));
        if (!h.warm_repos.length) warm.appendChild(el('span', 'muted', 'none'));
        body.appendChild(warm);

        body.appendChild(el('h3', 'dr-sh', 'Running here'));
        const act = h.online ? activeOn(h) : [];
        if (!act.length) body.appendChild(el('p', 'muted', 'Nothing.'));
        const ul = el('ul', 'runs');
        act.forEach((l) => {
          const li = el('li');
          li.append(el('span', 'run-n', (l.repository ? shortRepo(l.repository) + ' · ' : '') + l.jobName),
            el('span', 'run-s num', l.state === 'claimed' ? (l.progress != null ? Math.round(l.progress * 100) + '%' : l.elapsed != null ? secs(l.elapsed) : 'busy') : 'starting'));
          ul.appendChild(li);
        });
        body.appendChild(ul);
        body.appendChild(el('h3', 'dr-sh', 'Launch events'));
        const ev = el('ul', 'evs');
        const mine = feed.events.filter((e) => e.host_id === h.id).slice(-8).reverse();
        if (!mine.length) body.appendChild(el('p', 'muted', 'None lately.'));
        mine.forEach((e) => {
          const li = el('li', 'ev ev-' + e.kind);
          li.append(el('span', 'ev-k', e.kind + (e.reason ? ' · ' + B.reasonText(e.reason) : '')), el('span', 'ev-t num muted', secs((feed.now() - e.at_ms) / 1000) + ' ago'));
          ev.appendChild(li);
        });
        body.appendChild(ev);
      } else {
        const gh = Number(String(sel.id).replace(/^gh:/, ''));
        const q = (snap.queued || []).find((x) => x.id === gh);
        const r = (snap.running || []).find((x) => x.id === gh);
        const x = q || r;
        const D = sel.D || S.history.find((y) => y.job.id === sel.id) || null;
        const job = x ? { repository: x.repository, job: x.name || '#' + x.id, labels: B.labelList(x.labels), queued_at: x.queued_at } : D && D.job;
        if (!job) { $('dr-title').textContent = 'Job'; body.appendChild(el('p', 'muted', 'No longer queued or running.')); return; }
        $('dr-title').textContent = shortRepo(job.repository) + ' · ' + job.job;
        const dl = el('dl', 'kvs');
        kv(dl, 'Repository', job.repository);
        kv(dl, 'Labels', job.labels.join(', '));
        if (job.queued_at) kv(dl, 'Queued at', B.fmtClock(job.queued_at * 1000));
        const nowS = feed.now() / 1000;
        if (q) {
          kv(dl, 'Waiting', secs(nowS - q.queued_at), nowS - q.queued_at > 300 ? 'kvr-warn' : '');
          const p = (snap.queues || []).find((y) => B.queueId(y.repository, y.labels) === B.queueId(q.repository, q.labels));
          if (p && p.reason) kv(dl, 'Its queue waits', REASON[p.reason] || B.reasonText(p.reason), 'kvr-warn');
          kv(dl, 'Path', q.pool ? 'pool queue ' + q.labels : 'not placed · hosts are woken');
        } else if (r) {
          kv(dl, 'State', 'running on ' + hostName(r.host_id));
        } else kv(dl, 'State', 'no longer queued');
        body.appendChild(dl);
        const ds = S.history.filter((y) => y.job.id === sel.id);
        if (ds.length) {
          body.appendChild(el('h3', 'dr-sh', 'Decisions naming this job'));
          const ul = el('ul', 'evs');
          ds.forEach((y) => {
            const li = el('li', 'ev ev-click');
            li.append(el('span', 'ev-k', '#' + y.id + ' · ' + (y.outcome === 'accepted' ? '→ ' + hostName(y.chosen) : B.reasonText(y.outcome))), el('span', 'ev-t num muted', B.fmtClock(y.at_ms)));
            li.addEventListener('click', () => replay(y));
            ul.appendChild(li);
          });
          body.appendChild(ul);
        }
      }
    }
    function breakdown(D, s) {
      const box = el('div', 'bd');
      if (D.method === 'stage3') {
        box.appendChild(el('p', 'dr-p', 'Stage 3 (no statistics for this queue): ranked by warm checkout, then free memory, then fewest busy slots.'));
        return box;
      }
      const c = s._ctx;
      const lines = [
        ['cache', c.warm ? (c.warm_slow ? 'warm, but measured slower than usual → no bonus' : 'warm checkout of ' + shortRepo(D.repository)) : 'no checkout of ' + shortRepo(D.repository)],
        ['headroom', gib(s.free_after_bytes) + ' free after the job, of ' + gib(c.ram_bytes, 0)],
        ['speed', c.untried ? 'never measured on these jobs → tried with the full bonus' : s.speed >= 0 ? 'ran these jobs faster than usual' : 'ran these jobs slower than usual'],
        ['cpu', c.idle_cores.toFixed(1) + ' idle cores of the best ' + c.most_idle_cores.toFixed(1)],
        ['bigfit', s.bigfit ? 'the only machine a ' + gib(D.heavier_bytes) + ' job waiting fits' : 'no heavier job depends on it'],
      ];
      lines.forEach(([k, text]) => {
        const row = el('div', 'bd-r');
        const v = (k === 'bigfit' ? -s[k] : s[k]) / 1000;
        row.append(el('i', 'bd-d sg-' + k), el('span', 'bd-n', SEG_BY[k].name), el('span', 'bd-t', text), el('b', 'bd-v num' + (v < 0 ? ' neg' : ''), pts(v, true)));
        box.appendChild(row);
      });
      const tot = el('div', 'bd-r bd-tot');
      tot.append(el('i', ''), el('span', 'bd-n', 'Total'), el('span', 'bd-t', s.fits ? (s.last_resort ? 'last resort: ' + s.last_resort.replace('_', ' ') : 'fits') : 'does not fit in memory'), el('b', 'bd-v num', pts(s.total / 1000)));
      box.appendChild(tot);
      return box;
    }

    // --------------------------------------------------------------------- legend + controls
    let legendSig = '';
    function buildLegend() {
      const W = weightsNow();
      const sig = JSON.stringify(W);
      if (sig === legendSig) return;
      legendSig = sig;
      const lg = $('legend');
      lg.textContent = '';
      SEGS.forEach(({ k, name, neg, tip }) => {
        const s = el('span', 'lg');
        s.title = tip;
        s.append(el('i', 'lg-sw sg-' + k + (neg ? ' is-neg' : '')), document.createTextNode(name + ' ' + (neg ? '−' : '×') + W[k].toFixed(1)));
        lg.appendChild(s);
      });
      const lr = el('span', 'lg lg-b');
      lr.append(el('span', 'bdg bdg-warn', 'Last resort'), el('span', 'bdg bdg-bad', 'Not eligible'));
      lg.appendChild(lr);
    }
    function setPaused(p) {
      S.paused = p;
      $('btn-pause').setAttribute('aria-pressed', String(p));
      setText($('btn-pause-l'), p ? 'Resume' : 'Pause');
      $('btn-pause').classList.toggle('is-paused', p);
      updateScrubUi();
    }
    function bindControls() {
      $('btn-pause').addEventListener('click', () => setPaused(!S.paused));
      $('btn-whatif').addEventListener('click', () => toggleWhatIf());
      $('wi-reset').addEventListener('click', () => {
        S.whatIf = weightsNow();
        buildWhatIf();
        whatIfChanged();
      });
      $('dr-close').addEventListener('click', closeDetails);
      document.addEventListener('keydown', (e) => {
        if (!S.running || e.defaultPrevented) return;
        if (e.key === 'Escape') { if (S.selected) closeDetails(); else if (S.whatIf) toggleWhatIf(false); }
        if (e.key === ' ' && e.target === document.body) { e.preventDefault(); setPaused(!S.paused); }
      });
      const range = $('sc-range');
      range.addEventListener('input', () => {
        if (!S.cur) return;
        S.stagePlaying = false;
        S.t = (Number(range.value) / 1000) * S.cur.tl.end;
        updateScrubUi();
        renderStage();
      });
      $('sc-play').addEventListener('click', () => {
        if (!S.cur) return;
        if (!S.stagePlaying && S.t >= S.cur.tl.end - 1) { S.t = 0; S.cur.fired.clear(); S.cur.done = false; }
        S.stagePlaying = !S.stagePlaying;
        if (S.stagePlaying && S.whatIf && S.mode === 'live') toggleWhatIf(false);
        updateScrubUi();
      });
      $('sc-live').addEventListener('click', backToLive);
    }

    // --------------------------------------------------------------------- main loop
    let last = performance.now();
    function frame(now) {
      if (!S.running) return;
      const dt = Math.min(100, now - last);
      last = now;
      if (S.cur && S.stagePlaying && !S.paused) {
        const pace = S.mode === 'live' ? S.pace || 1 : S.speed;
        const before = S.t;
        S.t = Math.min(S.cur.tl.end, S.t + dt * pace);
        fireEvents(S.cur, before, S.t);
      }
      if (!stageFollowsLive()) {
        if (S.mode === 'live' && S.cur && !S.cur.done && S.t >= S.cur.tl.end) { pushHistory(S.cur.D); S.cur.done = true; }
        if (!S.paused && (S.mode === 'replay' || !S.stagePlaying)) resolveInstant();
      } else if (!S.cur || S.cur.done || S.t >= S.cur.tl.end) {
        if (S.cur && !S.cur.done) { pushHistory(S.cur.D); S.cur.done = true; }
        const D = takeDecision();
        if (D) startDecision(D);
        else if (S.cur) { $('stage').classList.add('is-idle'); setText($('st-kicker'), 'Last decision · waiting for work'); }
        else if (S.history.length && !S.idleShown) { S.idleShown = true; startDecision(S.history[0], true); }
      }
      if (S.cur) {
        renderStage();
        const r = $('sc-range');
        if (document.activeElement !== r) r.value = String(Math.round((S.t / S.cur.tl.end) * 1000));
      } else setText($('st-why'), feed.snap ? 'No placement decision yet. One appears here as soon as a pool job is queued.' : 'Reading the coordinator…');
      $('stage').classList.toggle('is-empty', !S.cur);
      if (S.histDirty) renderHistory();
      if (now - S.lastConv > 250) { S.lastConv = now; layoutConveyor(); }
      if (now - S.lastStrip > 400) {
        S.lastStrip = now;
        buildLegend();
        renderStrip();
        root.classList.toggle('is-stale', feed.failed);
        if (S.selected && now - (S.lastDetails || 0) > 1000) { S.lastDetails = now; renderDetails(); }
      }
      S.raf = requestAnimationFrame(frame);
    }

    global.addEventListener('resize', () => { if (S.cur) S.cur.barPx = 0; });
    bindControls();
    syncHosts();
    if (feed.snap) for (const d of feed.decisions.slice(-40)) pushHistory(settle(staged(d)));
    updateScrubUi();

    return {
      start() {
        if (S.running) return;
        S.running = true;
        if (S.cur) S.cur.barPx = 0;
        last = performance.now();
        S.raf = requestAnimationFrame(frame);
      },
      stop() {
        S.running = false;
        cancelAnimationFrame(S.raf);
      },
      debug: { S, setPaused, replay, toggleWhatIf },
    };
  }

  global.RMBalancing.register('race', create);
})(window);
