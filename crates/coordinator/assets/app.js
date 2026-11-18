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

  // --------------------------------------------------------------- settings
  // The viewer's settings (settings.js has their shape and rules): this
  // browser's copy at once, then the coordinator's, which follows the
  // signed-in person to any browser. `cfg` is always normalized.
  const RS = window.RMSettings;
  const SETTINGS_KEY = 'rm.settings';
  let cfg = loadLocalSettings();

  function loadLocalSettings() {
    try {
      const raw = localStorage.getItem(SETTINGS_KEY);
      if (raw) return RS.normalize(JSON.parse(raw));
      // Before settings: the range and the audit filter were kept on their own.
      return RS.fromLegacy(localStorage.getItem('rm.range'), localStorage.getItem('rm.audit.all') === '1');
    } catch (_) { return RS.defaults(); }
  }
  function storeLocal() { try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(cfg)); } catch (_) { /* storage unavailable */ } }
  // Set while this browser's copy holds a change the coordinator has not
  // confirmed: a reload, or another tab, then sends it rather than taking
  // the coordinator's older copy.
  const UNSAVED_KEY = 'rm.settings.unsaved';
  // Holds the unsaved copy itself, so a save of another copy (another tab's)
  // does not clear it: `markUnsaved(copy)` sets it, `markUnsaved(null, saved)`
  // clears it only when `saved` is that copy.
  function markUnsaved(copy, saved) {
    try {
      if (copy != null) localStorage.setItem(UNSAVED_KEY, copy);
      else if (localStorage.getItem(UNSAVED_KEY) === saved) localStorage.removeItem(UNSAVED_KEY);
    } catch (_) { /* storage unavailable */ }
  }
  function unsaved() { try { return localStorage.getItem(UNSAVED_KEY) != null; } catch (_) { return false; } }

  // ------------------------------------------------------------------ state
  const RANGES = RS.RANGES;
  const RANGE_LABEL = { '1h': 'last hour', '6h': 'last 6 hours', '24h': 'last 24 hours', '7d': 'last 7 days' };
  const METRICS_MIN_MS = 60000;
  const overviewMs = () => cfg.general.refresh * 1000;
  // Stale after a few missed refreshes, and never sooner than 20 s.
  const staleSecs = () => Math.max(20, cfg.general.refresh * 3);

  const state = {
    session: null, ov: null, metrics: null,
    range: cfg.charts.range,
    skew: 0,            // server clock minus local clock, seconds
    lastOk: 0,          // local time of the last successful overview fetch
    failed: false,
    timers: {},
    showAllRecent: false,
    hostColors: new Map(), colorSig: '',
    audit: null, auditErr: null, auditSig: '', showAllAudit: false,
    auditOpen: loadFlag('rm.audit.open', true),
    painted: false,     // the first overview is on screen: changes from here on animate
  };
  const serverNow = () => nowSec() + state.skew;

  function loadFlag(k, dflt) {
    try { const v = localStorage.getItem(k); if (v === '1' || v === '0') return v === '1'; } catch (_) { /* storage unavailable */ }
    return dflt;
  }
  function saveFlag(k, v) { try { localStorage.setItem(k, v ? '1' : '0'); } catch (_) { /* ignore */ } }

  // ----------------------------------------------------------------- motion
  // Every animated change on the page goes through these helpers, so nothing
  // jumps and the rules live in one place:
  //   reconcile(box, items, key, create, update)  keyed children, updated in place;
  //                         new ones fade and grow in, gone ones fade out of the
  //                         flow, the rest slide to their new places
  //   flip(els, mutate)     slide elements from where they were to where `mutate` put them
  //   resize(el, mutate)    let `el`'s height follow a change instead of jumping
  //   tweenNumber(el, v, fmt)  count an element's number to its new value
  //   frames(owner, draw)   run draw(p), p 0..1 eased, for SVG morphs
  //   collapse(el, show)    show or hide an element with a height and fade
  // Only transform, opacity and (for a container) height are animated, with
  // the Web Animations API: CSP-safe and off the main layout path. Motion is
  // skipped when the viewer asks for reduced motion or the tab is hidden; the
  // first data only fades in.
  const EASE = 'cubic-bezier(.2,.8,.2,1)';
  const DUR = { fast: 160, base: 260, slow: 360 };
  const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
  // The viewer's own choice in the settings, else the system's.
  const lessMotion = () => (cfg.general.motion === 'system' ? reducedMotion.matches : cfg.general.motion === 'reduce');
  const motionOk = () => !lessMotion() && !document.hidden;
  // Data updates: full motion once the first overview is on screen.
  const liveMotion = () => state.painted && motionOk();
  const easeOut = (p) => 1 - (1 - p) ** 3;
  const mix = (a, b, p) => (isNum(a) && isNum(b) ? a + (b - a) * p : b);

  function fadeIn(el, dur) {
    if (el instanceof Element && motionOk()) el.animate([{ opacity: 0 }, { opacity: 1 }], { duration: dur || DUR.base, easing: 'ease-out' });
  }

  // An element about to go must not keep keyboard focus: it moves to the
  // section around it (read out as that section), or the page.
  function dropFocus(el) {
    if (!el.contains(document.activeElement)) return;
    const to = (el.parentElement && el.parentElement.closest('section')) || $('#main');
    if (!to.hasAttribute('tabindex')) to.tabIndex = -1;
    to.focus({ preventScroll: true });
  }

  const rectsOf = (els) => new Map(els.map((el) => [el, el.getBoundingClientRect()]));

  // Plays the move from each element's `first` rect to where it is now.
  function playFlip(first) {
    const moves = [];
    for (const el of first.keys()) for (const a of el.getAnimations()) if (a.id === 'flip') a.cancel();
    for (const [el, r] of first) {
      if (!el.isConnected) continue;
      const n = el.getBoundingClientRect();
      const dx = r.left - n.left, dy = r.top - n.top;
      if (Math.abs(dx) > 0.5 || Math.abs(dy) > 0.5) moves.push([el, dx, dy]);
    }
    for (const [el, dx, dy] of moves) {
      el.animate([{ transform: `translate(${dx}px, ${dy}px)` }, { transform: 'none' }], { duration: DUR.slow, easing: EASE }).id = 'flip';
    }
  }

  // Runs `mutate`, then slides `els` from their old places to their new ones.
  function flip(els, mutate) {
    if (!liveMotion()) return mutate();
    const first = rectsOf(els);
    const out = mutate();
    playFlip(first);
    return out;
  }

  // Runs `mutate`, then animates `el`'s height from before to after, so what
  // follows it on the page glides instead of jumping.
  function resize(el, mutate) {
    if (!liveMotion() || !el.isConnected) return mutate();
    const before = el.getBoundingClientRect().height;
    for (const a of el.getAnimations()) if (a.id === 'resize') a.cancel();
    const out = mutate();
    const after = el.getBoundingClientRect().height;
    if (Math.abs(after - before) > 1) {
      // While it shrinks, what leaves it stays inside it.
      el.classList.add('is-resizing');
      const a = el.animate([{ height: `${before}px` }, { height: `${after}px` }], { duration: DUR.slow, easing: EASE });
      a.id = 'resize';
      const end = () => { if (!el.getAnimations().some((x) => x.id === 'resize')) el.classList.remove('is-resizing'); };
      a.finished.then(end, end);
    }
    return out;
  }

  // Takes a leaving element out of the flow where it stands and fades it out.
  // `r`: its rect, `cols`: its cells' widths when it is a table row.
  function ghost(box, el, r, cols) {
    const br = box.getBoundingClientRect();
    el.classList.add('is-leaving');
    el.inert = true;
    el.setAttribute('aria-hidden', 'true');
    if (cols) { el.style.display = 'grid'; el.style.gridTemplateColumns = cols; el.style.alignItems = 'center'; }
    for (const [k, v] of Object.entries({
      position: 'absolute', margin: '0', left: `${r.left - br.left - box.clientLeft}px`, top: `${r.top - br.top - box.clientTop}px`,
      width: `${r.width}px`, height: `${r.height}px`, pointerEvents: 'none',
    })) el.style[k] = v;
    const a = el.animate([{ opacity: 1, transform: 'none' }, { opacity: 0, transform: 'scale(0.96)' }], { duration: DUR.base, easing: EASE, fill: 'forwards' });
    a.finished.then(() => el.remove(), () => el.remove());
  }

  // Makes `box`'s children one element per item, in order, matched by key
  // (`data-key`; a repeated key gets a `#n` suffix). Kept elements are passed
  // to `update`, so their transitions and focus carry over; `create` makes new
  // ones. Children without a key (a skeleton) are replaced. When most of the
  // list changes at once (a filter), the whole list crossfades instead: rows
  // sliding through rows that fade out read as noise.
  function reconcile(box, items, keyOf, create, update) {
    let mode = !motionOk() || !box.getClientRects().length ? 'none' : state.painted ? 'full' : 'fade';
    const seen = new Map();
    const keys = items.map((it, i) => {
      const k = String(keyOf(it, i));
      const n = (seen.get(k) || 0) + 1;
      seen.set(k, n);
      return n > 1 ? `${k}#${n}` : k;
    });
    const want = new Set(keys);
    const old = new Map(), leaving = [];
    for (const el of box.children) {
      if (el.classList.contains('is-leaving')) continue;
      if (el.dataset.key != null && want.has(el.dataset.key)) old.set(el.dataset.key, el);
      else leaving.push(el);
    }
    const fresh = keys.filter((k) => !old.has(k)).length;
    if (mode === 'full' && leaving.length && fresh && leaving.length + fresh > old.size) mode = 'swap';
    // Read everything first, then write: one layout pass each way.
    const first = mode === 'full' ? rectsOf([...old.values(), ...leaving]) : null;
    const cols = mode === 'full' ? new Map(leaving.filter((el) => getComputedStyle(el).display === 'table-row')
      .map((el) => [el, [...el.children].map((c) => `${c.getBoundingClientRect().width}px`).join(' ')])) : null;
    for (const el of leaving) {
      dropFocus(el);
      if (mode === 'full') ghost(box, el, first.get(el), cols.get(el)); else el.remove();
    }
    const entering = [];
    // A kept element that moves leaves the document for a moment, and its
    // focus with it, unless the browser can move it in place.
    const focused = document.activeElement;
    const keep = focused && focused !== document.body && [...old.values()].some((el) => el.contains(focused)) ? focused : null;
    let ref = box.firstElementChild;
    items.forEach((it, i) => {
      let el = old.get(keys[i]);
      if (el) { if (update) update(el, it); }
      else { el = create(it); el.dataset.key = keys[i]; entering.push(el); }
      while (ref && ref !== el && ref.classList.contains('is-leaving')) ref = ref.nextElementSibling;
      if (el === ref) ref = ref.nextElementSibling;
      else if (box.moveBefore && el.parentNode === box) box.moveBefore(el, ref);
      else box.insertBefore(el, ref);
    });
    if (keep && keep.isConnected && document.activeElement !== keep) keep.focus({ preventScroll: true });
    if (mode === 'none') return;
    if (mode === 'swap') { box.animate([{ opacity: 0.2 }, { opacity: 1 }], { duration: DUR.base, easing: 'ease-out' }); return; }
    if (mode === 'full') { for (const el of leaving) first.delete(el); playFlip(first); }
    const enter = mode === 'full'
      ? [{ opacity: 0, transform: 'translateY(6px) scale(0.97)' }, { opacity: 1, transform: 'none' }]
      : [{ opacity: 0 }, { opacity: 1 }];
    for (const el of entering) el.animate(enter, { duration: mode === 'full' ? DUR.slow : DUR.slow + 60, easing: EASE });
  }

  // ---- numbers and frames: one requestAnimationFrame loop for all of them
  const tweens = new Map();   // element -> { from, to, t0, dur, fmt, value }
  const loops = new Set();    // frames() runs: { owner, draw, t0, dur }
  let raf = 0;
  function kick() { if (!raf) raf = requestAnimationFrame(step); }
  function step(now) {
    raf = 0;
    for (const [el, tw] of tweens) {
      const p = Math.min(1, (now - tw.t0) / tw.dur);
      tw.value = p >= 1 ? tw.to : tw.from + (tw.to - tw.from) * easeOut(p);
      el.textContent = tw.fmt(tw.value);
      if (p >= 1) tweens.delete(el);
    }
    for (const run of loops) {
      const p = Math.min(1, Math.max(0, (now - run.t0) / run.dur));
      if (p >= 1) loops.delete(run);
      run.draw(easeOut(p));
    }
    if (tweens.size || loops.size) kick();
  }
  // Ends every running tween and frame run at its final value (the tab hid).
  function settleMotion() {
    for (const [el, tw] of tweens) el.textContent = tw.fmt(tw.to);
    tweens.clear();
    const runs = [...loops];
    loops.clear();
    for (const run of runs) run.draw(1);
  }

  // Sets `el`'s text to fmt(to), counting from the number it shows now.
  function tweenNumber(el, to, fmt) {
    const from = el._num;
    el._num = to;
    const run = tweens.get(el);
    if (!isNum(to) || !isNum(from) || !liveMotion()) {
      tweens.delete(el);
      el.textContent = fmt(to);
      return;
    }
    if (from === to) { if (run) run.fmt = fmt; else el.textContent = fmt(to); return; }
    tweens.set(el, { from: run ? run.value : from, to, t0: performance.now(), dur: DUR.slow + 240, fmt, value: from });
    kick();
  }

  const animating = (owner) => [...loops].some((run) => run.owner === owner);

  // Calls draw(p) each frame with p eased from 0 to 1, replacing `owner`'s
  // previous run; with `dur` 0 or without motion, draw(1) at once.
  function frames(owner, draw, dur) {
    for (const run of loops) if (run.owner === owner) loops.delete(run);
    if (dur === 0 || !liveMotion()) { draw(1); return; }
    loops.add({ owner, draw, t0: performance.now(), dur: dur || DUR.slow + 120 });
    kick();
  }

  // Shows or hides `el` (its `hidden`) with a height and fade; in a grid or
  // flex parent its gap folds along.
  function collapse(el, show) {
    if (el._collapse) {
      if (el._collapse.show === show) return;  // already on its way there
      el._collapse.cancel();
      el._collapse = null;
    }
    if (show === !el.hidden) return;
    if (!liveMotion()) { el.hidden = !show; return; }
    el.hidden = false;
    const h0 = el.getBoundingClientRect().height;
    const gap = parseFloat(getComputedStyle(el.parentElement).rowGap) || 0;
    const open = { height: `${h0}px`, opacity: 1, marginBottom: '0px' };
    const shut = { height: '0px', opacity: 0, marginBottom: `${-gap}px` };
    el.style.overflow = 'hidden';
    const a = el.animate(show ? [shut, open] : [open, shut], { duration: DUR.slow, easing: EASE });
    a.show = show;
    el._collapse = a;
    const done = () => { el.style.overflow = ''; if (el._collapse === a) el._collapse = null; };
    a.finished.then(() => { done(); if (!show) { dropFocus(el); el.hidden = true; } }, done);
  }

  // A segmented control's active background slides between its buttons.
  function segThumb(seg) {
    if (!seg._thumb) {
      seg._thumb = h('span', { class: 'seg-thumb', 'aria-hidden': 'true' });
      seg.prepend(seg._thumb);
      seg.classList.add('has-thumb');
      new ResizeObserver(() => placeThumb(seg, false)).observe(seg);
    }
    placeThumb(seg, true);
  }
  const segThumbs = (root) => $$('.seg', root).forEach(segThumb);
  function placeThumb(seg, animate) {
    const th = seg._thumb, b = $('.seg-btn[aria-pressed="true"], .seg-btn[aria-selected="true"]', seg);
    if (!b || !b.offsetWidth) { th.classList.remove('on'); return; }
    th.classList.toggle('no-anim', !animate || !th.classList.contains('on') || !motionOk());
    th.style.setProperty('--x', `${b.offsetLeft}px`);
    th.style.setProperty('--w', `${b.offsetWidth}px`);
    th.classList.add('on');
  }

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
  // `3 min ago`, or with absolute times chosen `14:32`, `Mon 14:32`.
  function fmtAgo(t) {
    if (!isNum(t)) return '—';
    if (cfg.general.time === 'absolute') return fmtWhen(t);
    const d = serverNow() - t;
    if (d < 10) return 'just now';
    if (d < 60) return `${Math.floor(d)}s ago`;
    if (d < 3600) return `${Math.floor(d / 60)} min ago`;
    if (d < 86400) return `${Math.floor(d / 3600)} h ago`;
    return `${Math.floor(d / 86400)} d ago`;
  }
  // GiB (1024³) or, with decimal units chosen, GB (1000³).
  function fmtBytes(b) {
    if (!isNum(b)) return '—';
    const dec = cfg.general.bytes === 'decimal';
    const k = dec ? 1000 : 1024, i = dec ? '' : 'i';
    const g = b / k ** 3;
    if (g >= k) return `${(g / k).toFixed(g >= 10 * k ? 0 : 1)} T${i}B`;
    if (g >= 100) return `${g.toFixed(0)} G${i}B`;
    if (g >= 1) return `${g.toFixed(1)} G${i}B`;
    return `${Math.round(b / k ** 2)} M${i}B`;
  }
  const gigabyte = () => (cfg.general.bytes === 'decimal' ? 1e9 : 2 ** 30);
  const fmtPct = (v) => (isNum(v) ? `${Math.round(v)}%` : '—');
  const fmtInt = (v) => (isNum(v) ? String(Math.round(v)) : '—');
  function fmtClock(t) {
    const d = new Date(t * 1000);
    const hr = d.getHours();
    if (cfg.general.clock === '12') return `${hr % 12 || 12}:${pad2(d.getMinutes())} ${hr < 12 ? 'AM' : 'PM'}`;
    return `${pad2(hr)}:${pad2(d.getMinutes())}`;
  }
  function fmtDay(t) {
    return new Date(t * 1000).toLocaleDateString(undefined, { weekday: 'short', day: 'numeric' });
  }
  function fmtStamp(t) {
    return new Date(t * 1000).toLocaleString(undefined, {
      weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', hourCycle: cfg.general.clock === '12' ? 'h12' : 'h23',
    });
  }
  // A moment as a time of day: today `14:32`, this week `Mon 14:32`, else `3 Nov 14:32`.
  function fmtWhen(t) {
    const d = new Date(t * 1000), now = new Date(serverNow() * 1000);
    if (d.toDateString() === now.toDateString()) return fmtClock(t);
    const opts = Math.abs(now - d) < 6 * 86400e3 ? { weekday: 'short' } : { day: 'numeric', month: 'short' };
    return `${d.toLocaleDateString(undefined, opts)} ${fmtClock(t)}`;
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
  // What every row and slot that shows a formatted value depends on: a
  // change rebuilds them.
  const fmtSig = () => JSON.stringify([cfg.general.time, cfg.general.clock, cfg.general.bytes]);

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
    applyGeneral();
    applyLayout();
    $('#signout').addEventListener('click', signOut);
    $('#recent-toggle').addEventListener('click', () => { state.showAllRecent = !state.showAllRecent; if (state.ov) renderRecent(state.ov); });
    reducedMotion.addEventListener('change', settleMotion);
    darkScheme.addEventListener('change', applyGeneral);
    buildRangeSwitch();
    buildAuditControls();
    setupDrawer();
    setupSettings();
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
    renderSkeletons();
    renderChartFrames();
    startTimers();
    loadServerSettings();
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
    if (document.hidden) { stopTimers(); settleMotion(); } else startTimers();
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
    if (polling()) state.timers.ov = setTimeout(loadOverview, overviewMs());
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
    const stale = state.failed || age > staleSecs();
    el.classList.toggle('is-stale', stale);
    $('#live-text').textContent = stale ? (state.lastOk ? `Stale · ${fmtDur(age)}` : 'Connecting') : 'Live';
    el.title = state.lastOk ? `Last update ${new Date(state.lastOk * 1000).toLocaleTimeString()}${state.failed ? ' · last refresh failed' : ''}` : 'Waiting for first update';
  }

  function renderUpdate(ov) {
    const u = ov.update;
    const banner = $('#banner'), chip = $('#update-chip');
    const failed = u && (u.state === 'rolled_back' || u.state === 'failed');
    if (failed) {
      const title = u.state === 'rolled_back' ? 'Update rolled back' : 'Update failed';
      const meta = [
        u.current && `running v${u.current}`,
        u.latest && u.latest !== u.current && `target v${u.latest}`,
      ].filter(Boolean).join(' · ');
      // Rebuilt only when it says something new: a role=alert is read out again on every rebuild.
      const sig = JSON.stringify([title, u.message, meta, u.checked_at]);
      if (banner.dataset.sig !== sig) {
        banner.dataset.sig = sig;
        banner.replaceChildren(h('div', { class: 'banner', role: 'alert' },
          h('span', { class: 'banner-icon', 'aria-hidden': 'true', text: '!' }),
          h('div', { class: 'banner-body' },
            h('strong', { text: title }),
            u.message ? h('p', { text: u.message }) : null,
            h('p', { class: 'banner-meta' }, meta, meta ? ' · ' : '', 'checked ', ago(u.checked_at)))));
      }
    } else banner.dataset.sig = '';
    collapse(banner, !!failed);
    const fresh = u && !failed && u.state === 'updated' && isNum(u.changed_at) && serverNow() - u.changed_at < 86400;
    chip.hidden = !fresh;
    if (fresh) {
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
    state.painted = true;
  }

  // Placeholders of about the size of what comes, so the first data does not push the page around.
  function renderSkeletons() {
    if (state.painted) return;
    const line = (w) => h('span', { class: `sk ${w}` });
    $('#kpis').replaceChildren(...shownKpis().map(() => h('div', { class: 'kpi kpi-sk', 'aria-hidden': 'true' }, line('w50'), line('w30 sk-big'), line('w60'))));
    $('#hosts').replaceChildren(...[1, 2, 3].map(() => h('div', { class: 'host host-sk', 'aria-hidden': 'true' },
      line('w40 sk-big'), line('w70'), line('w60'), line('w70'), h('span', { class: 'sk sk-spark' }), line('w50'))));
    const rows = (n) => h('div', { class: 'tbl-sk', 'aria-hidden': 'true' }, Array.from({ length: n }, (_, i) => line(['w70', 'w50', 'w60'][i % 3])));
    for (const [id, n] of [['#queue', 3], ['#running', 3], ['#recent', 5]]) $(id).replaceChildren(rows(n));
  }

  function setBar(el, pct) {
    const p = isNum(pct) ? clamp(pct, 0, 100) : 0;
    const level = !isNum(pct) ? 'none' : p >= 90 ? 'err' : p >= 75 ? 'high' : p >= 50 ? 'warn' : 'ok';
    el.setAttribute('class', `bar bar-${level}${el.dataset.extra ? ` ${el.dataset.extra}` : ''}`);
    el.style.setProperty('--pct', `${p}%`);
  }
  function meterBar(pct, extra) {
    const el = h('span', { role: 'presentation', 'data-extra': extra || null });
    setBar(el, pct);
    return el;
  }

  // ------------------------------------------------------------------ KPIs
  // The summary tiles (settings.js lists them). Each fills its own tile:
  // `value` gives the big number and what it is out of (`single`: nothing),
  // `fmt` formats both, `sub` fills the line under it. Which show, and in
  // what order, is a setting.
  const KPI_FILL = {
    machines: { value: (c) => [c.sm.hosts_online, c.sm.hosts_total] },
    slots: {
      value: (c) => [c.sm.slots_busy, c.sm.slots_total], bar: (c) => c.pct,
      sub: (c, el) => { el.textContent = isNum(c.pct) ? `${Math.round(c.pct)}% utilised` : ''; },
    },
    jobs: {
      value: (c) => [c.sm.jobs_running, c.sm.jobs_queued],
      sub: (c, el) => {
        const sig = JSON.stringify([c.runHosts, !!c.sm.jobs_running, c.oldest && c.oldest.queued_at]);
        if (el.dataset.sig !== sig) { el.dataset.sig = sig; el.replaceChildren(...[jobsSub(c.sm, c.runHosts, c.oldest)].filter(Boolean)); }
      },
    },
    wait: {
      value: (c) => [c.sm.p50_queue_wait_secs], fmt: fmtDur, single: true,
      sub: (c, el) => {
        if (!el.firstChild) el.append('p90 ', h('b', { class: 'num' }));
        tweenNumber(el.lastChild, c.sm.p90_queue_wait_secs, fmtDur);
      },
    },
    cpu: {
      value: (c) => [c.cpu.avg], fmt: fmtPct, single: true, bar: (c) => c.cpu.avg,
      sub: (c, el) => { el.textContent = c.cpu.top ? `busiest ${c.cpu.top.name || c.cpu.top.hostname} · ${fmtPct(c.cpu.top.cpu_load_percent)}` : 'no machine reports CPU'; },
    },
    memory: {
      value: (c) => [c.mem.used, c.mem.total], fmt: fmtBytes, bar: (c) => c.mem.pct,
      sub: (c, el) => { el.textContent = isNum(c.mem.pct) ? `${Math.round(c.mem.pct)}% of the online machines’ memory` : ''; },
    },
  };
  const kpiByKey = new Map(RS.KPIS.map((d) => [d.key, { ...KPI_FILL[d.key], key: d.key, label: d.label }]));
  const shownKpis = () => RS.shown(cfg.kpis.order, cfg.kpis.hidden).map((key) => kpiByKey.get(key)).filter(Boolean);

  function kpiTile(k) {
    return h('div', { class: 'kpi' },
      h('p', { class: 'kpi-label', text: k.label }),
      h('p', { class: 'kpi-value' }, h('span', { class: 'num' }, h('span', { class: 'kpi-a' }), k.single ? null : h('small', {}, ' / ', h('span', { class: 'kpi-b' })))),
      k.sub ? h('p', { class: 'kpi-sub' }) : null,
      k.bar ? meterBar(null, 'kpi-bar') : null);
  }
  function fillKpi(el, k, c) {
    const [a, b] = k.value(c);
    tweenNumber($('.kpi-a', el), a, k.fmt || fmtInt);
    if (!k.single) tweenNumber($('.kpi-b', el), b, k.fmt || fmtInt);
    if (k.sub) k.sub(c, $('.kpi-sub', el));
    if (k.bar) setBar($('.bar', el), k.bar(c));
  }

  // The fleet's CPU and memory, from the online machines that report them.
  function fleetLoad(hosts) {
    const on = hosts.filter((x) => x.online);
    const cpus = on.filter((x) => isNum(x.cpu_load_percent));
    const rams = on.filter((x) => isNum(x.ram_bytes) && isNum(x.free_ram_bytes) && x.ram_bytes > 0);
    const total = rams.reduce((a, x) => a + x.ram_bytes, 0);
    const used = rams.reduce((a, x) => a + x.ram_bytes - x.free_ram_bytes, 0);
    return {
      cpu: {
        avg: cpus.length ? cpus.reduce((a, x) => a + x.cpu_load_percent, 0) / cpus.length : null,
        top: cpus.reduce((a, x) => (!a || x.cpu_load_percent > a.cpu_load_percent ? x : a), null),
      },
      mem: { used: rams.length ? used : null, total: rams.length ? total : null, pct: total ? (used / total) * 100 : null },
    };
  }

  function renderKpis(ov) {
    const sm = ov.summary || {};
    const c = {
      sm,
      pct: isNum(sm.slots_busy) && sm.slots_total > 0 ? (sm.slots_busy / sm.slots_total) * 100 : null,
      oldest: (ov.queue || [])[0],
      runHosts: new Set((ov.running || []).map((j) => j.host_id).filter(Boolean)).size,
      ...fleetLoad(ov.hosts || []),
    };
    const box = $('#kpis');
    const n = shownKpis().length;
    box.style.setProperty('--kpi-cols', String(n > 5 ? 3 : Math.max(1, n)));
    reconcile(box, shownKpis(), (k) => k.key, (k) => { const el = kpiTile(k); fillKpi(el, k, c); return el; }, (el, k) => fillKpi(el, k, c));
  }

  // `on 3 machines · oldest waits 1m 12s`, or `all idle`.
  function jobsSub(sm, runHosts, oldest) {
    const parts = [
      runHosts ? `on ${runHosts} machine${runHosts === 1 ? '' : 's'}` : sm.jobs_running ? null : 'all idle',
      oldest ? h('span', {}, 'oldest waits ', since(oldest.queued_at)) : null,
    ].filter(Boolean);
    return parts.length ? h('span', {}, ...parts.flatMap((part, i) => (i ? [' · ', part] : [part]))) : null;
  }

  // ---------------------------------------------------------------- hosts
  // Colours follow the name order of every known host in either list, and a
  // host keeps its colour while it stays known, so one that appears or goes
  // offline does not recolour the others.
  function assignHostColors() {
    const names = new Map();
    for (const x of (state.ov && state.ov.hosts) || []) names.set(x.id, x.name || x.hostname || x.id);
    for (const x of (state.metrics && state.metrics.hosts) || []) if (!names.has(x.id)) names.set(x.id, x.name || x.id);
    const ids = [...names.keys()].sort((a, b) => String(names.get(a)).localeCompare(String(names.get(b))));
    const prev = state.hostColors, next = new Map(), used = new Set();
    for (const id of ids) {
      const c = prev.get(id);
      if (c && !used.has(c) && used.size < 8) { next.set(id, c); used.add(c); }
    }
    let i = 0;
    for (const id of ids) {
      if (next.has(id)) continue;
      while (used.size < 8 && used.has(`var(--s${(i % 8) + 1})`)) i++;
      const c = `var(--s${(i % 8) + 1})`;
      next.set(id, c); used.add(c); i++;
    }
    state.hostColors = next;
    state.colorSig = JSON.stringify([...next]);
  }
  const hostColor = (id) => state.hostColors.get(id) || 'var(--muted)';
  const hostDot = (id) => h('span', { class: 'host-dot', 'aria-hidden': 'true', vars: { '--c': hostColor(id) } });
  const machine = (id, name) => h('span', { class: 'machine' }, hostDot(id), name);

  const STATUS_LABEL = Object.fromEntries(RS.STATUS);
  function hostStatus(x) {
    const key = RS.statusOf(x);
    return { key, label: STATUS_LABEL[key] };
  }
  const OS_NAME = RS.OS_NAME;
  const osTag = (os) => h('span', { class: `os os-${os || 'unknown'}`, text: OS_NAME[os] || os || 'unknown' });

  function meterRow(label) {
    return h('div', { class: 'meter' },
      h('span', { class: 'meter-label', text: label }),
      h('span', { class: 'meter-value num' }),
      meterBar(null));
  }
  function setMeter(row, pct, value, fmt) {
    tweenNumber($('.meter-value', row), value, fmt);
    setBar($('.bar', row), pct);
  }

  const peakOf = (vals) => { const v = (vals || []).filter(isNum); return v.length ? Math.max(...v) : null; };

  // A machine's memory used, as a percent of its total, per sample.
  function ramPct(x) {
    return (x.ram_used || []).map((u, i) => {
      const total = (x.ram_total || [])[i];
      return isNum(u) && isNum(total) && total > 0 ? (u / total) * 100 : null;
    });
  }

  // A series' value at time `t`, from the group that holds it.
  const sampleAt = (d, vals, t) => {
    if (!d || !vals || !d.t.length) return null;
    const i = Math.floor((t - d.t[0]) / d.step);
    return i >= 0 && i < d.t.length ? vals[i] : null;
  };

  // The CPU and memory sparkline: on new samples the lines slide left by
  // their time and the values ease to their new heights.
  function setSpark(box, hostId) {
    const m = state.metrics;
    const mh = m && (m.hosts || []).find((x) => x.id === hostId);
    if (!mh || !Array.isArray(mh.cpu) || mh.cpu.filter(isNum).length < 2) {
      if (!box.classList.contains('spark-empty')) { box._d = null; box.className = 'spark spark-empty'; box.replaceChildren('No CPU history yet'); fadeIn(box); }
      return;
    }
    const rawRam = ramPct(mh);
    const g = regroup(m.t || [], m.step_secs || 60, groupOf(mh.cpu.length, SPARK_POINTS), [mh.cpu, rawRam]);
    const d = { t: g.t, step: g.step, vals: g.series };
    const sig = JSON.stringify([d, m.range]);
    const cpuPeak = peakOf(mh.cpu), ramPeak = peakOf(rawRam);
    const W = 120, H = 32;
    if (box.classList.contains('spark-empty') || !box.firstChild) {
      box.className = 'spark';
      box.replaceChildren(
        s('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', role: 'img' },
          s('path', { class: 'spark-area' }),
          s('path', { class: 'spark-line spark-ram', 'vector-effect': 'non-scaling-stroke' }),
          s('path', { class: 'spark-line', 'vector-effect': 'non-scaling-stroke' })),
        h('span', { class: 'spark-cap' },
          h('span', {}, h('i', { class: 'spark-key', 'aria-hidden': 'true' }), 'CPU', h('i', { class: 'spark-key spark-key-ram', 'aria-hidden': 'true' }), h('span', { class: 'spark-range' })),
          h('span', { class: 'num spark-peak' })));
      box._d = null;
      box._sig = null;
      fadeIn(box);
    }
    if (box._sig === sig) return;
    box._sig = sig;
    const svg = $('svg', box);
    const [area, ram, cpu] = svg.children;
    svg.setAttribute('aria-label', `CPU and memory over the ${RANGE_LABEL[m.range] || m.range}: CPU peak ${fmtPct(cpuPeak)}, memory peak ${fmtPct(ramPeak)}`);
    $('.spark-range', box).textContent = `RAM · ${m.range}`;
    $('.spark-peak', box).textContent = `peak ${fmtPct(cpuPeak)} · ${fmtPct(ramPeak)}`;
    const from = box._d;
    const n = d.t.length;
    const draw = (p) => {
      const t0 = mix(from && from.t[0], d.t[0], p), t1 = mix(from && from.t[from.t.length - 1], d.t[n - 1], p);
      const pts = (k) => d.vals[k].map((v, i) => {
        const val = mix(sampleAt(from, from && from.vals[k], d.t[i]), v, p);
        return isNum(val) ? [((d.t[i] - t0) / (t1 - t0 || 1)) * W, H - (clamp(val, 0, 100) / 100) * (H - 2) - 1] : null;
      });
      const cpuPts = pts(0);
      area.setAttribute('d', areaPath(cpuPts, H, true));
      cpu.setAttribute('d', linePath(cpuPts, true));
      ram.setAttribute('d', linePath(pts(1), true));
    };
    box._d = d;
    frames(box, draw, from ? null : 0);
  }

  // A slot of a card that is rebuilt only when what it shows (`sig`) changed.
  function slot(card, name, sig, build) {
    const r = card._r;
    if (r[`${name}Sig`] === sig) return;
    const fresh = r[`${name}Sig`] !== undefined;
    r[`${name}Sig`] = sig;
    const node = build() || document.createComment(name);
    r[name].replaceWith(node);
    r[name] = node;
    if (fresh && liveMotion()) fadeIn(node, DUR.slow);
  }

  function hostCard() {
    const el = h('article', { class: 'host' });
    const r = {
      dot: hostDot(null),
      link: h('a', { class: 'host-open' }),
      pin: pinButton('pin-card'),
      sub: document.createComment('sub'),
      status: h('span', { class: 'status' }, h('i', { 'aria-hidden': 'true' }), h('span')),
      reboot: document.createComment('reboot'),
      access: document.createComment('access'),
      cpu: meterRow('CPU'), mem: meterRow('Memory'), slots: meterRow('Slots'),
      spark: h('div', { class: 'spark' }),
      ver: document.createComment('ver'),
      disk: document.createComment('disk'),
      up: document.createComment('up'),
    };
    r.head = h('header', { class: 'host-head' }, r.dot,
      h('div', { class: 'host-id' }, h('h3', { class: 'host-name' }, r.link), r.sub),
      r.pin,
      h('div', { class: 'host-badges' }, r.status, r.reboot, r.access));
    el._r = r;
    layoutCard(el);
    return el;
  }

  // Lays a card out with the parts the settings show, in their order:
  // neighbouring meters share a block, disk and uptime sit in the footer.
  // A part left out keeps updating off the page, ready to come back.
  function layoutCard(el) {
    const ms = cfg.machines;
    const parts = RS.shown(ms.fields, ms.fieldsHidden);
    const sig = parts.join();
    if (el._layout === sig) return;
    const first = el._layout != null;
    el._layout = sig;
    const r = el._r;
    const body = [], foot = [];
    for (const key of parts) {
      if (key === 'disk' || key === 'up') foot.push(r[key]);
      else if (key === 'cpu' || key === 'mem' || key === 'slots') {
        const last = body[body.length - 1];
        if (last && last.classList && last.classList.contains('host-meters')) last.append(r[key]);
        else body.push(h('div', { class: 'host-meters' }, r[key]));
      } else body.push(r[key]);
    }
    el.replaceChildren(r.head, ...body, foot.length ? h('footer', { class: 'host-foot' }, foot) : '');
    if (first && liveMotion()) for (const n of [...body, el.lastElementChild]) if (n !== r.head) fadeIn(n, DUR.slow);
  }

  // Updates a machine card in place: its meters and numbers glide, its status crossfades.
  function fillHost(el, x) {
    const r = el._r;
    const st = hostStatus(x);
    const name = x.name || x.hostname || x.id;
    el.setAttribute('class', `host is-${st.key}`);
    el.setAttribute('aria-label', `${name}, ${st.label}`);
    r.dot.style.setProperty('--c', hostColor(x.id));
    r.link.textContent = name;
    r.link.href = `#host=${encodeURIComponent(x.id)}`;
    r.link.dataset.host = x.id;
    r.link.parentNode.title = x.hostname || '';
    r.status.setAttribute('class', `status status-${st.key}`);
    r.status.lastChild.textContent = st.label;
    setPin(r.pin, x.id, name);
    layoutCard(el);
    const os = String(x.os || '').toLowerCase();
    slot(el, 'sub', JSON.stringify([os, x.arch, x.cores]), () => h('p', { class: 'host-sub' },
      osTag(os),
      [x.arch, isNum(x.cores) ? `${x.cores} cores` : null].filter(Boolean).join(' · ')));
    slot(el, 'access', JSON.stringify([x.online, x.manageable, !!x.remote_changes]), () => accessChip(x, !!x.remote_changes));
    const reboot = rebootState(x);
    slot(el, 'reboot', JSON.stringify(reboot && [reboot.state, reboot.message]), () => rebootBadge(x));

    const total = isNum(x.ram_bytes) ? x.ram_bytes : null;
    const used = total != null && isNum(x.free_ram_bytes) ? total - x.free_ram_bytes : null;
    const slots = (x.busy_slots || 0) + (x.free_slots || 0);
    setMeter(r.cpu, x.cpu_load_percent, isNum(x.cpu_load_percent) ? x.cpu_load_percent : null, fmtPct);
    setMeter(r.mem, used != null && total ? (used / total) * 100 : null, used, (v) => `${fmtBytes(v)} / ${fmtBytes(total)}`);
    setMeter(r.slots, slots ? ((x.busy_slots || 0) / slots) * 100 : null, slots ? x.busy_slots || 0 : null, (v) => (isNum(v) ? `${Math.round(v)} / ${slots}` : '—'));
    setSpark(r.spark, x.id);
    slot(el, 'ver', versionSig(x), () => versionLine(x));

    const dt = x.disk_total_bytes, df = x.disk_free_bytes;
    const sized = isNum(dt) && dt > 0 && isNum(df);
    slot(el, 'disk', String(sized) + fmtSig(), () => (sized
      ? h('span', { class: 'disk' }, h('span', {}, 'Disk ', h('b', { class: 'num' })), meterBar(null))
      : h('span', {}, 'Disk free ', h('b', { class: 'num' }))));
    // `Disk 176 GiB / 1.5 TiB` with a meter, from 0.4.66; free space before.
    if (sized) {
      const usedDisk = Math.max(0, dt - df);
      r.disk.title = `${fmtBytes(df)} free`;
      tweenNumber($('b', r.disk), usedDisk, (v) => `${fmtBytes(v)} / ${fmtBytes(dt)}`);
      setBar($('.bar', r.disk), (usedDisk / dt) * 100);
    } else tweenNumber($('b', r.disk), df, fmtBytes);
    slot(el, 'up', JSON.stringify(x.online ? [x.connected_since] : [null, x.last_seen_at]) + fmtSig(), () => (!x.online ? h('span', {}, 'Last seen ', ago(x.last_seen_at))
      : isNum(x.connected_since) ? h('span', {}, 'Up ', since(x.connected_since)) : null));
  }

  // The machine cards in the order the settings give (settings.js
  // `arrangeHosts`): pinned first, then by the chosen rule, perhaps under
  // group headings. Each item is a host or a heading `{ head }`.
  function hostItems(hosts) {
    const groups = RS.arrangeHosts(hosts, cfg.machines);
    return groups.flatMap((g) => (g.label ? [{ head: g }, ...g.hosts] : g.hosts));
  }

  function renderHosts(ov) {
    const all = ov.hosts || [];
    const items = hostItems(all);
    const on = all.filter((x) => x.online).length;
    const away = all.length - items.filter((x) => !x.head).length;
    $('#machines-count').textContent = all.length ? `${on} of ${all.length} online${away ? ` · ${away} not shown` : ''}` : '';
    const box = $('#hosts');
    box.classList.toggle('is-compact', cfg.machines.density === 'compact');
    const none = !all.length ? 'none' : !items.length ? 'filtered' : null;
    resize(box, () => reconcile(box, none ? [none] : items, (x) => (typeof x === 'string' ? x : x.head ? `g:${x.head.key}` : x.id),
      (x) => {
        if (x === 'none') return empty('No machines enrolled yet', 'Machines appear here once their runner-manager agent connects.');
        if (x === 'filtered') return empty('Every machine is hidden', 'Settings → Machines chooses which machines show.');
        if (x.head) return groupHead(x.head);
        const el = hostCard();
        fillHost(el, x);
        return el;
      },
      (el, x) => { if (x.head) fillGroupHead(el, x.head); else if (typeof x !== 'string') fillHost(el, x); }));
  }

  function groupHead(g) {
    const el = h('h3', { class: 'host-group' }, h('span', { class: 'host-group-name' }), h('span', { class: 'count num' }));
    fillGroupHead(el, g);
    return el;
  }
  function fillGroupHead(el, g) {
    el.firstChild.textContent = g.label;
    tweenNumber(el.lastChild, g.hosts.length, countText);
  }

  // ----------------------------------------------------------------- pins
  const isPinned = (id) => cfg.machines.pinned.includes(id);
  function togglePin(id) {
    update((c) => {
      const ms = c.machines;
      if (ms.pinned.includes(id)) ms.pinned = ms.pinned.filter((x) => x !== id);
      else { ms.pinned.push(id); ms.hidden = ms.hidden.filter((x) => x !== id); }
    });
  }
  const pinIcon = (n) => icon('M7.5 3.5h5M8.5 3.5v4.2L6 10.5v1.5h8v-1.5l-2.5-2.8V3.5M10 12v4.5', n || 14);
  function pinButton(cls) {
    const b = h('button', { type: 'button', class: `pin-btn ${cls}`, 'aria-pressed': 'false' }, pinIcon(15));
    b.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (b.dataset.host) togglePin(b.dataset.host);
    });
    return b;
  }
  function setPin(b, id, name) {
    const on = isPinned(id);
    b.dataset.host = id;
    b.setAttribute('aria-pressed', String(on));
    b.setAttribute('aria-label', `${on ? 'Unpin' : 'Pin'} ${name}`);
    b.title = on ? 'Pinned: shown first. Click to unpin.' : 'Pin: show this machine first';
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

  // A table of `spec.items` in `box`, a row per item keyed by `spec.key`, or
  // `spec.empty()` when there are none. Rows come and go animated; a row is
  // rebuilt only when its item (or a machine's name or colour) changed.
  // `spec.before` / `spec.after`: more keyed blocks around it ({ key, create, update }).
  function renderTable(box, spec) {
    const blocks = [
      ...(spec.before || []),
      spec.items.length ? { key: 'tbl', create: () => table(spec.caption, spec.heads, []) } : {
        key: 'empty', create: spec.empty,
        update: (el) => { const n = spec.empty(); if (n.textContent !== el.textContent) el.replaceChildren(...n.childNodes); },
      },
      ...(spec.after || []),
    ];
    resize(box, () => {
      reconcile(box, blocks, (b) => b.key, (b) => b.create(), (el, b) => { if (b.update) b.update(el); });
      const tb = $(':scope > table:not(.is-leaving) > tbody', box);
      if (!tb) return;
      const fill = (tr, it) => {
        const sig = JSON.stringify([it, spec.sig ? spec.sig(it) : null]) + state.colorSig + fmtSig();
        if (tr._sig === sig) return;
        tr._sig = sig;
        tr.replaceChildren(...spec.row(it));
      };
      reconcile(tb, spec.items, spec.key, (it) => { const tr = h('tr'); fill(tr, it); return tr; }, fill);
    });
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
  const countText = (v) => (isNum(v) && Math.round(v) > 0 ? String(Math.round(v)) : '');

  function renderQueue(ov) {
    const q = ov.queue || [];
    tweenNumber($('#queue-count'), q.length, countText);
    renderTable($('#queue'), {
      caption: 'Queued jobs', heads: [['Job'], ['Labels', 'c-labels'], ['Waiting', 'c-num']], items: q, key: (j) => j.id,
      row: (j) => [jobCell(j), td('Labels', 'c-labels', chips(j.labels)), td('Waiting', 'c-num', since(j.queued_at, 'num wait'))],
      empty: () => empty('Queue is clear', 'New jobs are placed as soon as a slot frees up.'),
    });
  }

  function renderRunning(ov) {
    const r = ov.running || [];
    tweenNumber($('#running-count'), r.length, countText);
    renderTable($('#running'), {
      caption: 'Running jobs', heads: [['Job'], ['Machine'], ['Elapsed', 'c-num']], items: r, key: (j) => j.id,
      row: (j) => [jobCell(j), machineCell(j), td('Elapsed', 'c-num', since(j.started_at))],
      sig: (j) => hostName(j.host_id),
      empty: () => empty('No jobs running', 'Every runner slot is idle.'),
    });
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
    const LIMIT = cfg.general.recentRows;
    const list = state.showAllRecent ? all : all.slice(0, LIMIT);
    const btn = $('#recent-toggle');
    btn.hidden = all.length <= LIMIT;
    btn.textContent = state.showAllRecent ? 'Show fewer' : `Show all ${all.length}`;
    btn.setAttribute('aria-expanded', String(state.showAllRecent));
    renderTable($('#recent'), {
      caption: 'Recently completed jobs', heads: [['Result'], ['Job'], ['Machine'], ['Duration', 'c-num'], ['Finished', 'c-num']],
      items: list, key: (j) => `${j.id}:${j.completed_at}`,
      row: (j) => [td('Result', 'c-result', conclusion(j.conclusion)), jobCell(j), machineCell(j),
        numCell('Duration', fmtDur(j.duration_secs)), td('Finished', 'c-num c-when', ago(j.completed_at, 'muted'))],
      sig: (j) => hostName(j.host_id),
      empty: () => empty('No completed jobs yet', null),
    });
  }

  function renderPools(ov) {
    const pools = ov.pools || [], leases = ov.leases || [];
    const sec = $('#pools-section');
    if (!pools.length && !leases.length) { collapse(sec, false); return; }
    const cards = [
      pools.length ? {
        key: 'pools', caption: 'Pools', heads: [['Repository'], ['Labels'], ['Queued', 'c-num'], ['Leases', 'c-num'], ['Oldest', 'c-num'], ['Reason']],
        items: pools, key: (p) => `${p.repository} ${p.labels}`,
        row: (p) => [h('td', { class: 'c-job' }, repoLink(p.repository, 'job-link')), td('Labels', '', chips(p.labels)),
          numCell('Queued', fmtInt(p.queued)), numCell('Leases', fmtInt(p.leases)), numCell('Oldest', fmtDur(p.oldest_wait_secs)),
          td('Reason', '', h('span', { class: p.refusal ? 'text-err' : 'muted', text: p.refusal || humanize(p.reason) }))],
      } : null,
      leases.length ? {
        key: 'leases', caption: 'Leases', heads: [['Machine'], ['Repository'], ['State'], ['Age', 'c-num']],
        items: leases, key: (l) => l.lease_id || `${l.host_id} ${l.repository}`, sig: (l) => hostName(l.host_id),
        row: (l) => [h('td', { class: 'c-job' }, machine(l.host_id, hostName(l.host_id))),
          td('Repository', '', l.repository ? repoLink(l.repository) : '—'),
          td('State', '', h('span', { class: 'badge badge-dim', text: humanize(l.state) })), numCell('Age', fmtDur(l.age_secs))],
      } : null,
    ].filter(Boolean);
    const box = $('#pools');
    resize(box, () => {
      reconcile(box, cards, (c) => c.key,
        (c) => h('div', { class: 'card' }, h('h3', { class: 'card-title', text: c.caption }), h('div', { class: 'tbl-box' })),
        null);
      for (const c of cards) renderTable($(`:scope > [data-key="${c.key}"]:not(.is-leaving) .tbl-box`, box), c);
    });
    collapse(sec, true);
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
  // A stacked band: along `top` and back along `base` (points or null, by
  // index), one closed shape per run of values.
  function bandPath(top, base, smooth) {
    let d = '', run = [];
    const flush = () => {
      if (run.length) d += `${curve(run.map((i) => top[i]), smooth)}${curve(run.map((i) => base[i]).reverse(), smooth).replace(/^M/, 'L')}Z`;
      run = [];
    };
    top.forEach((p, i) => { if (p) run.push(i); else flush(); });
    flush();
    return d;
  }
  // Kinds drawn from values summed up per step.
  const stacks = (kind) => kind === 'columns' || kind === 'stacked';

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

  let chartSeq = 0;
  function setupChart(fig, id) {
    const plot = $('.plot', fig);
    // Its own clip id: a chart removed in settings fades out beside the one that replaces it.
    const c = { id: `${id}-${++chartSeq}`, fig, plot, cfg: null, idx: null, frame: 0, view: null, sk: null };
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
    // Mid-morph the running frames redraw at the new size anyway.
    new ResizeObserver(() => { cancelAnimationFrame(c.frame); c.frame = requestAnimationFrame(() => { if (!animating(c)) drawChart(c); }); }).observe(plot);
    return c;
  }
  const hideAllTips = () => chartById.forEach(hideTip);

  // What a chart draws: its time domain [d0, d1), the value at its top, and
  // a value array per series over `t`. A change animates between two views:
  // the domain slides (new samples come in from the right) and the values
  // and the scale ease to their new heights.
  function viewOf(cfg) {
    const t = cfg.t, n = t.length;
    const vals = cfg.series.map((sr) => sr.values);
    let top = cfg.yMax || 100;
    // Rows share a fixed top when given one; otherwise every kind fits its data.
    if (cfg.kind !== 'strips' || !cfg.yMax) {
      let maxV = 0;
      for (let i = 0; i < n; i++) {
        let sum = 0;
        for (const v of vals) {
          if (!isNum(v[i])) continue;
          if (stacks(cfg.kind)) sum += v[i]; else if (v[i] > maxV) maxV = v[i];
        }
        if (sum > maxV) maxV = sum;
      }
      top = yScale(maxV, cfg.yMax, cfg.integer).top;
    }
    return { t, step: cfg.step, d0: t[0], d1: n ? t[n - 1] + cfg.step : 0, vals, top, keys: cfg.series.map((sr) => sr.key).join('\n') };
  }
  function morphView(from, to, p) {
    return {
      ...to, d0: mix(from.d0, to.d0, p), d1: mix(from.d1, to.d1, p), top: mix(from.top, to.top, p),
      vals: to.vals.map((arr, k) => arr.map((v, i) => mix(sampleAt(from, from.vals[k], to.t[i]), v, p))),
    };
  }

  // The chart's SVG and tooltip, made once and redrawn in place, so a hover
  // survives a refresh.
  function scaffold(c) {
    if (c.sk && c.sk.svg.parentNode === c.plot) return c.sk;
    const clip = s('rect', {});
    const svg = s('svg', { class: 'chart-svg', role: 'img' },
      s('defs', {}, s('clipPath', { id: `clip-${c.id}` }, clip)));
    const grid = s('g', { class: 'grid', 'aria-hidden': 'true' });
    const marks = s('g', { class: 'marks', 'clip-path': `url(#clip-${c.id})` });
    const cross = s('g', { class: 'cross', 'aria-hidden': 'true' }, s('line', { class: 'cross-line' }));
    svg.append(grid, marks, cross);
    const tip = h('div', { class: 'tip', role: 'status', 'aria-live': 'off' });
    c.plot.replaceChildren(svg, tip);
    fadeIn(svg, DUR.slow);
    c.sk = { svg, clip, grid, marks, cross, tip, dots: [] };
    return c.sk;
  }

  // cfg.kind: 'lines' (one per series), 'area' (a filled line per series),
  // 'columns' or 'stacked' (columns or areas, stacked) or 'strips' (a row per
  // series, each 0..top); `cfg.smooth` curves the lines. `view`: a frame of
  // a morph; the config's own view when omitted.
  function drawChart(c, view) {
    const { plot, cfg } = c;
    if (!cfg) return;
    const W = Math.round(plot.clientWidth), H = Math.round(plot.clientHeight);
    if (W < 40 || H < 40) return;
    const t = cfg.t || [];
    const n = t.length;
    if (n < 2 || !cfg.series.length) {
      if (!$('.plot-empty', plot)) { plot.replaceChildren(h('div', { class: 'plot-empty', text: 'No data for this range yet' })); fadeIn(plot.firstChild); }
      c.geo = null; c.view = null; c.sk = null; c.idx = null;
      return;
    }
    const v = view || viewOf(cfg);
    c.view = v;
    const sk = scaffold(c);
    const narrow = W < 420;
    const strips = cfg.kind === 'strips';
    const P = { l: strips ? (narrow ? 74 : 96) : narrow ? 30 : 38, r: 8, t: 8, b: 22 };
    const pw = W - P.l - P.r, ph = H - P.t - P.b;
    const step = cfg.step;
    const t0 = v.d0, t1 = v.d1;
    const X = (tv) => P.l + ((tv - t0) / (t1 - t0 || 1)) * pw;
    const xAt = (i) => X(t[i] + step / 2);
    const vals = v.vals;
    apply(sk.svg, { viewBox: `0 0 ${W} ${H}`, width: W, height: H, 'aria-label': cfg.summary });
    apply(sk.clip, { x: P.l, y: 0, width: pw, height: H - P.b + 2 });

    // Stacks are drawn from cumulative values; tooltips read raw ones.
    let tops = vals;
    let bases = null;
    const smooth = cfg.smooth !== false;
    if (stacks(cfg.kind)) {
      const acc = new Array(n).fill(0);
      bases = []; tops = [];
      for (const sv of vals) {
        bases.push(acc.slice());
        for (let i = 0; i < n; i++) if (isNum(sv[i])) acc[i] += sv[i];
        tops.push(acc.slice());
      }
    }
    const top = v.top || 1;
    const Y = (val) => P.t + (1 - val / top) * ph;

    const grid = [];
    if (!strips) {
      for (const tv of yScale(top, cfg.yMax, cfg.integer).ticks) {
        if (tv > top * 1.001) continue;
        const y = Y(tv).toFixed(1);
        grid.push(s('line', { x1: P.l, x2: W - P.r, y1: y, y2: y, class: tv === 0 ? 'baseline' : null }));
        grid.push(s('text', { x: P.l - 6, y, class: 'ytick', dy: '0.32em', text: cfg.fmtTick(tv) }));
      }
    }
    const tt = timeTicks(t0, t1, Math.max(2, Math.floor(pw / (narrow ? 64 : 84))));
    for (const tv of tt.ticks) {
      const x = X(tv);
      if (x < P.l + 14 || x > W - P.r - 14) continue;
      grid.push(s('text', { x: x.toFixed(1), y: H - 6, class: 'xtick', text: tt.step >= 86400 ? fmtDay(tv) : fmtClock(tv) }));
    }

    const marks = [];
    let dotY;
    if (strips) {
      const m = cfg.series.length, gap = m > 8 ? 2 : 5;
      const rowH = Math.max(2, (ph - gap * (m - 1)) / m);
      const rowY = (k, val) => P.t + k * (rowH + gap) + rowH - (clamp(val, 0, top) / top) * (rowH - 2);
      cfg.series.forEach((sr, k) => {
        const y0 = P.t + k * (rowH + gap);
        const pts = vals[k].map((val, i) => (isNum(val) ? [xAt(i), rowY(k, val)] : null));
        marks.push(s('rect', { class: 'strip-bg', x: P.l, y: f1(y0), width: pw, height: f1(rowH), rx: 3 }));
        marks.push(s('path', { class: 'strip-area', d: areaPath(pts, y0 + rowH, smooth), vars: { '--c': sr.color } }));
        marks.push(s('path', { class: 'strip-line', d: linePath(pts, smooth), vars: { '--c': sr.color } }));
      });
      // Names sit left of the plot, outside its clip.
      cfg.series.forEach((sr, k) => {
        const y0 = P.t + k * (rowH + gap);
        const raw = sr.values.filter(isNum);
        const two = rowH >= 26 && raw.length;
        grid.push(s('text', { class: 'strip-name', x: 2, y: f1(y0 + rowH / 2 - (two ? 6 : 0)), dy: '0.32em', text: sr.name }));
        if (two) {
          const avg = raw.reduce((a, b) => a + b, 0) / raw.length;
          grid.push(s('text', { class: 'strip-val', x: 2, y: f1(y0 + rowH / 2 + 8), dy: '0.32em', text: `avg ${cfg.fmtVal(avg)} · max ${cfg.fmtVal(peakOf(sr.raw || raw))}` }));
        }
      });
      dotY = (k, i) => (isNum(vals[k][i]) ? rowY(k, vals[k][i]) : null);
    } else if (cfg.kind === 'columns') {
      const bw = (step / (t1 - t0)) * pw;
      const pad = Math.max(1, bw * 0.22);
      const cw = Math.max(1, bw - pad);
      cfg.series.forEach((sr, k) => {
        const g = s('g', { class: 'col', vars: { '--c': sr.color } });
        for (let i = 0; i < n; i++) {
          if (!isNum(vals[k][i]) || vals[k][i] <= 0) continue;
          const y1 = Y(tops[k][i]), y0 = Y(bases[k][i]);
          g.append(s('rect', { x: f1(xAt(i) - cw / 2), y: f1(y1), width: f1(cw), height: f1(Math.max(0.5, y0 - y1)), rx: cw > 5 ? 1.5 : 0 }));
        }
        marks.push(g);
      });
      dotY = (k, i) => (isNum(vals[k][i]) ? Y(tops[k][i]) : null);
    } else if (cfg.kind === 'stacked') {
      cfg.series.forEach((sr, k) => {
        // A machine without a value is a band of no height, so the bands
        // above it stay joined to it.
        const top = vals[k].map((_, i) => [xAt(i), Y(tops[k][i])]);
        const base = vals[k].map((_, i) => [xAt(i), Y(bases[k][i])]);
        marks.push(s('path', { class: 'band', d: bandPath(top, base, smooth), vars: { '--c': sr.color } }));
        marks.push(s('path', { class: 'line line-thin', d: linePath(top, smooth), vars: { '--c': sr.color } }));
      });
      dotY = (k, i) => (isNum(vals[k][i]) ? Y(tops[k][i]) : null);
    } else {
      const filled = cfg.kind === 'area', one = cfg.series.length === 1;
      cfg.series.forEach((sr, k) => {
        const pts = vals[k].map((val, i) => (isNum(val) ? [xAt(i), Y(val)] : null));
        if (filled || one) marks.push(s('path', { class: `area${filled ? (one ? '' : ' area-many') : ' area-soft'}`, d: areaPath(pts, Y(0), smooth), vars: { '--c': sr.color } }));
        marks.push(s('path', { class: 'line', d: linePath(pts, smooth), vars: { '--c': sr.color } }));
      });
      dotY = (k, i) => (isNum(vals[k][i]) ? Y(vals[k][i]) : null);
    }
    sk.grid.replaceChildren(...grid);
    sk.marks.replaceChildren(...marks);

    const line = sk.cross.firstChild;
    line.setAttribute('y1', P.t); line.setAttribute('y2', P.t + ph);
    if (sk.dots.length !== cfg.series.length) {
      for (const d of sk.dots) d.remove();
      sk.dots = cfg.series.map(() => s('circle', { r: 4, class: 'cross-dot' }));
      sk.cross.append(...sk.dots);
    }
    sk.dots.forEach((d, k) => d.style.setProperty('--c', cfg.series[k].color));
    c.geo = { W, P, pw, t0, t1, xAt, dotY, cross: sk.cross, dots: sk.dots, tip: sk.tip };
    if (c.idx != null) showTip(c, Math.min(c.idx, n - 1));
  }

  function hover(c, e) {
    if (!c.geo || !c.cfg) return;
    if (e.type === 'pointerdown') chartById.forEach((o) => o !== c && hideTip(o));
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
    // The first and last groups can reach past the samples: said as they are.
    const from = Math.max(cfg.t[i], cfg.from), to = Math.min(cfg.t[i] + cfg.step, cfg.to);
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

  function legend(c, series, show) {
    reconcile($('.legend', c.fig), show ? series : [], (sr) => sr.key,
      (sr) => h('li', {}, h('span', { class: 'legend-key', 'aria-hidden': 'true', vars: { '--c': sr.color } }), h('span', { text: sr.name })),
      (li, sr) => { li.firstChild.style.setProperty('--c', sr.color); li.lastChild.textContent = sr.name; });
  }

  function summarize(title, series, fmt) {
    const parts = series.map((sr) => {
      const vals = sr.values.filter(isNum);
      if (!vals.length) return `${sr.name}: no data`;
      return `${sr.name}: latest ${fmt(vals[vals.length - 1])}, peak ${fmt(peakOf(sr.raw || vals))}`;
    });
    return `${title}, ${RANGE_LABEL[state.range] || state.range}. ${parts.join('; ')}.`;
  }

  // New data morphs from what is drawn when the same series are shown the
  // same way; otherwise (a machine came or went) the marks crossfade.
  function setChart(c, cfg) {
    const from = c.view, prev = c.cfg;
    c.cfg = cfg;
    legend(c, cfg.series, cfg.kind !== 'strips' && cfg.legend !== false);
    const to = viewOf(cfg);
    if (from && prev && prev.kind === cfg.kind && from.keys === to.keys && to.t.length >= 2) {
      frames(c, (p) => drawChart(c, p < 1 ? morphView(from, to, p) : null));
      return;
    }
    frames(c, () => drawChart(c), 0);
    if (from && c.sk && liveMotion()) c.sk.marks.animate([{ opacity: 0 }, { opacity: 1 }], { duration: DUR.slow, easing: 'ease-out' });
  }

  // `average per 20 min`, `per 2 h`.
  function per(secs) {
    if (secs < 3600) return `${Math.round(secs / 60)} min`;
    const hrs = secs / 3600;
    return `${Number.isInteger(hrs) ? hrs : hrs.toFixed(1)} h`;
  }

  // The Activity charts (settings.js lists them): `build(x, o)` gives a
  // chart's config and subtitle from the shared context `chartContext()`
  // makes and the chart's own settings `o`. Which show, in what order, is a
  // setting too.
  const CHART_BUILD = { jobs: jobsChart, cpu: cpuChart, busy: busyChart, ram: ramChart, util: utilChart, disk: diskChart };
  const CHARTS = RS.CHARTS.map((d) => ({ id: d.key, title: d.label, sub: d.sub, build: CHART_BUILD[d.key] }));
  const chartDef = new Map(CHARTS.map((d) => [d.id, d]));
  const shownCharts = () => RS.shown(cfg.charts.order, cfg.charts.hidden).map((k) => chartDef.get(k)).filter(Boolean);
  const chartById = new Map();

  // The chart cards, before any data: their plots hold their height.
  function renderChartFrames() {
    const grid = $('#charts-grid');
    grid.style.setProperty('--chart-cols', String(cfg.charts.columns));
    grid.style.setProperty('--plot-h', `${RS.HEIGHTS[cfg.charts.height]}px`);
    grid.dataset.cols = String(cfg.charts.columns);
    resize(grid, () => reconcile(grid, shownCharts(), (d) => d.id, (d) => {
      const fig = h('figure', { class: 'chart card' },
        h('figcaption', {}, h('h3', { text: d.title }), h('p', { class: 'chart-sub', text: d.sub })),
        h('ul', { class: 'legend' }),
        h('div', { class: 'plot' }));
      chartById.set(d.id, setupChart(fig, d.id));
      return fig;
    }, null));
  }

  function chartContext() {
    const m = state.metrics || {};
    const t = m.t || [];
    const step = m.step_secs || 60;
    return {
      t, step,
      m, hosts: m.hosts || [],  // sorted by name
      hostSeries: (x) => ({ key: x.id, name: x.name || x.id, color: hostColor(x.id) }),
      pctTick: (v) => `${v}%`,
      intTick: (v) => (Number.isInteger(v) ? String(v) : v.toFixed(1)),
      fmtAvg: (v) => (isNum(v) ? (v >= 10 || Number.isInteger(v) ? String(Math.round(v)) : v.toFixed(1)) : '—'),
      kCol: groupOf(t.length, COLUMN_COUNT), kLine: groupOf(t.length, LINE_POINTS),
      span: { from: t[0], to: t.length ? t[t.length - 1] + step : 0 },
    };
  }

  // What every chart's config carries from its settings.
  const common = (x, o) => ({ ...x.span, kind: o.style, smooth: o.smooth, legend: cfg.charts.legend });
  // Columns and stacks average into fewer, wider groups than lines.
  const groupFor = (x, o) => (stacks(o.style) ? x.kCol : x.kLine);
  const meanOf = (vals) => { const v = (vals || []).filter(isNum); return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null; };

  // The machines a chart shows: all, its top N by `score` over the range, or
  // the ones picked (a picked machine not in the data is skipped). In name
  // order, so their colours and rows stay put.
  function chartHosts(o, hosts, score) {
    if (o.hosts === 'pick') return hosts.filter((y) => o.pick.includes(y.id));
    if (o.hosts !== 'top') return hosts;
    const ranked = hosts.map((y) => [y, score(y)]).filter((p) => isNum(p[1])).sort((a, b) => b[1] - a[1]).slice(0, o.top);
    const keep = new Set(ranked.map((p) => p[0]));
    return hosts.filter((y) => keep.has(y));
  }
  // `· top 3 by average` and the like, for a subtitle.
  function hostsNote(o, by) {
    if (o.hosts === 'top') return ` · top ${o.top} by ${by}`;
    if (o.hosts === 'pick') return ` · ${o.pick.length} chosen`;
    return '';
  }
  const averaged = (g, x) => (g.step > x.step ? ` · average per ${per(g.step)}` : '');
  const pctTop = (o) => (o.scale === 'full' ? 100 : undefined);

  function jobsChart(x, o) {
    const jg = regroup(x.t, x.step, groupFor(x, o), [x.m.running || [], x.m.queued || []]);
    const jobs = [
      { key: 'running', name: 'Running', color: 'var(--s1)', values: jg.series[0] },
      { key: 'queued', name: 'Queued', color: 'var(--s2)', values: jg.series[1] },
    ];
    return {
      sub: `Running and queued${stacks(o.style) ? ', stacked' : ''}${averaged(jg, x)}`,
      cfg: {
        ...common(x, o), t: jg.t, step: jg.step, series: jobs, integer: true, fmtVal: x.fmtAvg, fmtTick: x.intTick,
        summary: summarize('Jobs running and queued', jobs, x.fmtAvg),
      },
    };
  }

  function cpuChart(x, o) {
    const hosts = chartHosts(o, x.hosts, (y) => meanOf(y.cpu));
    const cg = regroup(x.t, x.step, groupFor(x, o), hosts.map((y) => y.cpu || []));
    const cpu = hosts.map((y, k) => ({ ...x.hostSeries(y), values: cg.series[k], raw: y.cpu }));
    return {
      sub: `${o.style === 'strips' ? 'A row per machine' : 'Per machine'}${hostsNote(o, 'average')}${averaged(cg, x)}`,
      cfg: { ...common(x, o), t: cg.t, step: cg.step, series: cpu, yMax: pctTop(o), fmtVal: fmtPct, fmtTick: x.pctTick, summary: summarize('CPU per machine', cpu, fmtPct) },
    };
  }

  function busyChart(x, o) {
    const hosts = chartHosts(o, x.hosts, (y) => meanOf(y.busy));
    const n = hosts.length;
    const bg = regroup(x.t, x.step, groupFor(x, o), [...hosts.map((y) => y.busy || []), ...hosts.map((y) => y.slots || [])]);
    const busy = hosts.map((y, k) => {
      const values = bg.series[k], slots = bg.series[n + k];
      return { ...x.hostSeries(y), values, fmtAt: (i) => (isNum(values[i]) ? `${x.fmtAvg(values[i])}${isNum(slots[i]) ? ` / ${x.fmtAvg(slots[i])}` : ''}` : '—') };
    });
    return {
      sub: `${stacks(o.style) ? 'Stacked per machine' : 'Per machine'}${hostsNote(o, 'average')}${averaged(bg, x)}`,
      cfg: {
        ...common(x, o), t: bg.t, step: bg.step, series: busy, integer: true, fmtVal: x.fmtAvg, fmtTick: x.intTick, summary: summarize('Busy runner slots per machine', busy, x.fmtAvg),
        total: (i) => {
          const sum = busy.reduce((a, sr) => a + (isNum(sr.values[i]) ? sr.values[i] : 0), 0);
          return h('div', { class: 'tip-row tip-total' }, h('span', { class: 'tip-key tip-key-none' }), h('b', { class: 'num', text: x.fmtAvg(sum) }), h('span', { class: 'tip-name', text: 'Total busy' }));
        },
      },
    };
  }

  function ramChart(x, o) {
    const hosts = chartHosts(o, x.hosts, (y) => meanOf(ramPct(y)));
    const n = hosts.length;
    const rg = regroup(x.t, x.step, groupFor(x, o), [...hosts.map(ramPct), ...hosts.map((y) => y.ram_used || [])]);
    const ram = hosts.map((y, k) => {
      const values = rg.series[k], used = rg.series[n + k];
      return { ...x.hostSeries(y), values, raw: ramPct(y), fmtAt: (i) => (isNum(values[i]) ? `${fmtPct(values[i])} · ${fmtBytes(used[i])}` : '—') };
    });
    return {
      sub: `${o.style === 'strips' ? 'A row per machine' : 'Used per machine'}${hostsNote(o, 'average')}${averaged(rg, x)}`,
      cfg: { ...common(x, o), t: rg.t, step: rg.step, series: ram, yMax: pctTop(o), fmtVal: fmtPct, fmtTick: x.pctTick, summary: summarize('Memory used per machine', ram, fmtPct) },
    };
  }

  // The fleet's busy share of all its slots, per sample.
  function utilChart(x, o) {
    const util = x.t.map((_, i) => {
      let busy = 0, slots = 0;
      for (const y of x.hosts) {
        const b = (y.busy || [])[i], n = (y.slots || [])[i];
        if (isNum(b) && isNum(n)) { busy += b; slots += n; }
      }
      return slots > 0 ? (busy / slots) * 100 : null;
    });
    const ug = regroup(x.t, x.step, groupFor(x, o), [util]);
    const series = [{ key: 'util', name: 'Slots busy', color: 'var(--s3)', values: ug.series[0] }];
    return {
      sub: `Busy share of every slot${averaged(ug, x)}`,
      cfg: { ...common(x, o), t: ug.t, step: ug.step, series, yMax: pctTop(o), fmtVal: fmtPct, fmtTick: x.pctTick, summary: summarize('Share of runner slots busy', series, fmtPct) },
    };
  }

  // Free disk per machine, in GiB (or GB), the least free first for top N.
  function diskChart(x, o) {
    const gb = gigabyte();
    const hosts = chartHosts(o, x.hosts, (y) => { const m = meanOf(y.disk_free); return isNum(m) ? -m : null; });
    const dg = regroup(x.t, x.step, groupFor(x, o), hosts.map((y) => (y.disk_free || []).map((v) => (isNum(v) ? v / gb : null))));
    const fmtGb = (v) => (isNum(v) ? fmtBytes(v * gb) : '—');
    const disk = hosts.map((y, k) => ({ ...x.hostSeries(y), values: dg.series[k] }));
    return {
      sub: `${o.style === 'strips' ? 'A row per machine' : 'Per machine'}${hostsNote(o, 'least free')}${averaged(dg, x)}`,
      cfg: { ...common(x, o), t: dg.t, step: dg.step, series: disk, fmtVal: fmtGb, fmtTick: fmtGb, summary: summarize('Free disk per machine', disk, fmtGb) },
    };
  }

  function renderCharts() {
    renderChartFrames();
    assignHostColors();
    const x = chartContext();
    for (const d of shownCharts()) {
      const c = chartById.get(d.id);
      const built = d.build(x, cfg.charts.per[d.id]);
      $('.chart-sub', c.fig).textContent = built.sub;
      setChart(c, built.cfg);
    }
    const m = x.m;
    $('#charts-sub').textContent = m.step_secs ? `${RANGE_LABEL[state.range]} · ${m.step_secs % 60 ? `${m.step_secs}s` : `${m.step_secs / 60} min`} samples` : RANGE_LABEL[state.range];
  }

  function buildRangeSwitch() {
    const box = $('#range');
    box.replaceChildren(...RANGES.map((r) => h('button', {
      type: 'button', class: 'seg-btn', 'aria-pressed': String(r === state.range), 'data-range': r, text: r,
      'aria-label': `Show ${RANGE_LABEL[r]}`,
      onclick: () => { if (r !== state.range) update((c) => { c.charts.range = r; }); },
    })));
    segThumb(box);
  }

  // The range switch follows the setting, wherever it was changed.
  function syncRange() {
    if (cfg.charts.range === state.range) return;
    const r = state.range = cfg.charts.range;
    const box = $('#range');
    $$('.seg-btn', box).forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.range === r)));
    segThumb(box);
    $('#charts-sub').textContent = RANGE_LABEL[r];
    if (!$('#app').hidden) loadMetrics();
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
    if (v.app_missing) return { cls: 'err', text: 'App missing' };
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
    if (!name) return null;
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
    else if (v.app_missing) hint = 'The binary its service was installed from no longer exists, so there is nothing to update. On the machine, install runner-manager again, then, while no job runs: runner-manager service uninstall && runner-manager service install --start-at boot|login (as it was installed).';
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
          v.app_missing ? h('div', { class: 'ver-row' }, h('dt', { text: 'App' }),
            h('dd', {}, h('b', { class: 'text-err', text: 'missing' }), h('span', { class: 'muted', text: ` · ${v.app_missing}` })))
            : row('App', v.app, v.app_source ? `· ${v.app_source}` : null),
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

  // --------------------------------------------------------------- reboot
  // A restart asked through `host reboot`, from 0.4.73: shown while it lasts.
  function rebootState(x) {
    const r = x && x.online && x.versions && x.versions.reboot;
    return r && (r.state === 'pending' || r.state === 'rebooting') ? r : null;
  }
  function rebootBadge(x) {
    const r = rebootState(x);
    if (!r) return null;
    return r.state === 'rebooting'
      ? h('span', { class: 'badge badge-err', title: r.message || 'Every job finished; the machine is restarting', text: 'Rebooting' })
      : h('span', { class: 'badge badge-warn', title: r.message || 'Restarts once its running jobs finish', text: 'Reboot pending' });
  }
  function rebootSig(x) {
    const v = x && x.versions;
    return JSON.stringify(x && [x.online, x.manageable, x.remote_changes, v && [v.rebootable, v.starts_at_login, v.reboot, (v.wsl || []).length], dw.confirm === 'reboot']);
  }

  // Only for a machine that says it can (0.4.73 and later, not a WSL guest).
  function rebootCard(x) {
    const v = x && x.versions;
    if (!v || !(v.rebootable || v.reboot)) return null;
    const r = v.reboot;
    const live = rebootState(x);
    const busy = dw.busy.has('reboot');
    const can = !!(x.online && x.manageable && x.remote_changes && v.rebootable);
    let hint = (v.wsl || []).length
      ? 'Restarts this machine once every running job has finished, its WSL distributions’ included. It takes no new job meanwhile, however long that takes.'
      : 'Restarts this machine once every running job has finished. It takes no new job meanwhile, however long that takes.';
    if (v.starts_at_login) hint += ' Its service starts when its account signs in: after the restart it works again only once that account is signed in (automatic sign-in, or a person).';
    if (!x.online) hint = 'Shown while the machine is connected.';
    else if (!x.remote_changes) hint += ' Rebooting from here needs changes through the coordinator allowed on the machine.';
    let action = null;
    if (can && live && live.state === 'pending') {
      action = h('button', {
        type: 'button', class: 'btn-sm', 'data-fk': 'reboot:cancel', 'aria-busy': busy ? 'true' : null, text: 'Cancel reboot',
        onclick: (e) => run('reboot', ['host', 'reboot', '--cancel'], e.currentTarget),
      });
    } else if (can && !live && dw.confirm !== 'reboot') {
      action = h('button', {
        type: 'button', class: 'btn-sm btn-quiet-danger', 'data-fk': 'reboot:open', text: 'Reboot…',
        onclick: () => { dw.confirm = 'reboot'; refreshRebootCard('reboot:go'); },
      });
    }
    let confirm = null;
    if (can && !live && dw.confirm === 'reboot') {
      const cancel = () => { dw.confirm = null; refreshRebootCard('reboot:open'); };
      confirm = h('form', { class: 'confirm', novalidate: true, 'aria-label': 'Confirm reboot' },
        h('p', { class: 'confirm-title', text: `Reboot ${x.name || x.hostname || 'this machine'}?` }),
        h('p', { class: 'confirm-text', text: 'The machine stops taking jobs now, waits for every running job to finish, then restarts. You can cancel until the restart begins.' }),
        h('code', { class: 'cmd-preview', text: cmdLine(['host', 'reboot']) }),
        h('div', { class: 'form-actions' },
          h('button', { type: 'button', class: 'btn-sm', 'data-fk': 'reboot:back', text: 'Cancel', onclick: cancel }),
          h('button', { type: 'submit', class: 'btn-sm btn-danger', 'data-fk': 'reboot:go', text: 'Reboot' })));
      confirm.addEventListener('submit', (e) => { e.preventDefault(); run('reboot', ['host', 'reboot'], $('[data-fk="reboot:go"]', confirm)); });
      confirm.addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); cancel(); } });
    }
    let progress = null;
    if (r && x.online) {
      const lead = { pending: 'Reboot asked ', rebooting: 'Rebooting · asked ', failed: 'Reboot failed ', cancelled: 'Reboot cancelled ' }[r.state] || 'Reboot ';
      progress = h('p', { class: `ver-progress ${r.state === 'failed' ? 'text-err' : 'muted'}`, role: 'status' },
        lead, ago(r.at), r.message ? ` · ${r.message}` : '');
    }
    return h('section', { class: 'card dw-card', 'data-key': 'reboot', 'data-sig': rebootSig(x), 'aria-labelledby': 'dw-h-reboot' },
      h('fieldset', { class: 'fs', disabled: busy || null },
        h('div', { class: 'cap-row' },
          h('div', { class: 'cap-text' },
            h('h3', { id: 'dw-h-reboot', class: 'cap-title' }, 'Reboot ', rebootBadge(x)),
            h('p', { class: 'cap-hint', text: hint })),
          action),
        confirm,
        progress),
      resultNote('reboot'));
  }

  // Heartbeats bring the reboot's progress: the card follows them.
  function refreshRebootCard(fk) {
    if (!dw.id || dw.busy.has('reboot')) return;
    const body = $('#dw-body');
    const old = $('[data-key="reboot"]', body);
    const x = hostById(dw.id);
    if (!old) {
      // The machine said it can reboot after the panel was built: the card
      // joins it below the versions.
      const after = $('[data-key="update"]', body);
      const card = after && rebootCard(x);
      if (card) { after.after(card); if (liveMotion()) fadeIn(card, DUR.slow); }
      return;
    }
    if (!fk && old.dataset.sig === rebootSig(x)) return;
    // Focus stays on the control it was on, never moved onto another one.
    const focused = old.contains(document.activeElement) ? document.activeElement.dataset.fk || '' : null;
    const want = fk || focused;
    const card = rebootCard(x);
    if (!card) { old.remove(); if (want != null) body.focus({ preventScroll: true }); return; }
    old.replaceWith(card);
    if (want == null) return;
    const target = want && $(`[data-fk="${CSS.escape(want)}"]`, card);
    if (target && !target.closest('fieldset:disabled')) target.focus({ preventScroll: true });
    else body.focus({ preventScroll: true });
  }

  // ------------------------------------------------------------ audit log
  function buildAuditControls() {
    $('#audit-filter').replaceChildren(...[['changes', 'Changes'], ['all', 'All']].map(([v, t]) => h('button', {
      type: 'button', class: 'seg-btn', 'data-v': v, text: t, 'aria-pressed': String(v === cfg.general.auditFilter),
      onclick: () => update((c) => { c.general.auditFilter = v; }),
    })));
    segThumb($('#audit-filter'));
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
    if (state.auditErr === 'gone') { collapse(sec, false); return; }
    if (!state.audit && !state.auditErr) return;  // first load still on its way
    fillAudit(force);
    // Shown once filled, so it opens to its full height.
    collapse(sec, true);
  }

  function fillAudit(force) {
    const all = state.audit || [];
    const showAll = cfg.general.auditFilter === 'all';
    const list = showAll ? all : all.filter((c) => !isRead(c));
    const sig = JSON.stringify([all, showAll, state.auditOpen, state.showAllAudit, state.auditErr, cfg.general.auditRows]);
    if (!force && sig === state.auditSig) return;
    state.auditSig = sig;
    $('#audit-section').classList.toggle('is-collapsed', !state.auditOpen);
    tweenNumber($('#audit-count'), list.length, countText);
    const tog = $('#audit-toggle');
    tog.textContent = state.auditOpen ? 'Hide' : 'Show';
    tog.setAttribute('aria-expanded', String(state.auditOpen));
    const filter = $('#audit-filter');
    filter.hidden = !state.auditOpen;
    $$('.seg-btn', filter).forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.v === cfg.general.auditFilter)));
    segThumb(filter);
    const box = $('#audit');
    if (!state.auditOpen) { collapse(box, false); return; }
    const LIMIT = cfg.general.auditRows;
    const shown = state.showAllAudit ? list : list.slice(0, LIMIT);
    const reads = all.length - list.length;
    const errText = state.auditErr ? `The log could not be refreshed. ${state.auditErr}` : null;
    const moreText = () => (state.showAllAudit ? 'Show fewer' : `Show all ${list.length}`);
    renderTable(box, {
      before: errText ? [{
        key: 'err', create: () => h('p', { class: 'notice notice-warn', role: 'status', text: errText }),
        update: (el) => { if (el.textContent !== errText) el.textContent = errText; },
      }] : [],
      caption: 'Commands run on machines through the coordinator', heads: [['Result'], ['Command'], ['Machine'], ['By'], ['When', 'c-num']],
      items: shown, key: (c) => `${c.at} ${c.host_id} ${(c.argv || []).join(' ')}`, sig: (c) => hostName(c.host_id, c.host_id),
      row: (c) => [
        td('Result', 'c-result', outcomeBadge(c.outcome)),
        td('Command', 'c-cmd', cmdCode(c.argv)),
        td('Machine', 'c-machine', machine(c.host_id, c.host_name || hostName(c.host_id, c.host_id))),
        td('By', 'c-who', h('span', { text: c.login || '—' })),
        td('When', 'c-num c-when', ago(c.at, 'muted'))],
      empty: () => empty(all.length ? 'No changes yet' : 'No remote commands yet',
        reads ? `${reads} read${reads === 1 ? '' : 's'} hidden. Choose All to see them.` : 'Changes made from a machine’s panel are recorded here.'),
      after: list.length > LIMIT ? [{
        key: 'more',
        create: () => h('div', { class: 'tbl-more' }, h('button', {
          type: 'button', class: 'link-btn', 'aria-expanded': String(state.showAllAudit), text: moreText(),
          onclick: () => { state.showAllAudit = !state.showAllAudit; renderAudit(true); },
        })),
        update: (el) => { el.firstChild.textContent = moreText(); el.firstChild.setAttribute('aria-expanded', String(state.showAllAudit)); },
      }] : [],
    });
    collapse(box, true);
  }

  // --------------------------------------------------------- machine panel
  const dw = {
    id: null, gen: 0, pushed: false, sig: '',
    cfg: null, rc: null, loading: false, error: null, cfgSeq: 0,
    results: new Map(), busy: new Set(), add: null, confirm: null, updateSent: null, closing: null,
  };

  function hashHost() {
    const m = /^#host=(.+)$/.exec(location.hash);
    if (!m) return null;
    try { return decodeURIComponent(m[1]); } catch (_) { return null; }
  }

  function setupDrawer() {
    const dlg = $('#drawer');
    $('#dw-close').before(pinButton('pin-drawer'));
    $('#dw-close').addEventListener('click', () => closeDrawer());
    dlg.addEventListener('cancel', (e) => { e.preventDefault(); closeDrawer(); });
    dlg.addEventListener('close', () => { if (dw.id) closeDrawer(); });
    dlg.addEventListener('click', (e) => { if (e.target === dlg) closeDrawer(); });
    dlg.addEventListener('keydown', trapTab);
    window.addEventListener('hashchange', () => {
      const id = hashHost();
      if (id) {
        if ($('#app').hidden) return;
        // One panel at a time: Back or Forward to a machine closes Settings first.
        if (st.open) closeSettings(true);
        openDrawer(id, true);
      } else if (dw.id) closeDrawer(true);
    });
    // The card's name is a link (Enter); Space opens it too, as on a button.
    $('#hosts').addEventListener('keydown', (e) => {
      if (e.key === ' ' && e.target.classList && e.target.classList.contains('host-open')) { e.preventDefault(); e.target.click(); }
    });
  }

  function trapTab(e) {
    if (e.key !== 'Tab') return;
    const dlg = e.currentTarget;
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
    if (!dlg.open || dw.closing) dw.pushed = !!pushed;
    dw.id = id; dw.gen++;
    Object.assign(dw, { sig: '', cfg: null, rc: null, loading: false, error: null, add: null, confirm: null });
    dw.results.clear(); dw.busy.clear();
    renderDrawerHead();
    const x = hostById(id);
    if (!state.ov || (x && x.manageable)) loadConfig(); else renderDrawerBody();
    if (dw.closing) { for (const a of dw.closing) a.cancel(); dw.closing = null; }
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
    const done = () => {
      const anims = dw.closing || [];
      dw.closing = null;
      if (dlg.open) dlg.close();
      for (const a of anims) a.cancel();
      document.documentElement.classList.remove('has-drawer');
      const link = $(`.host-open[data-host="${CSS.escape(id)}"]`);
      if (link) link.focus();
    };
    if (!dlg.open || !motionOk()) { done(); return; }
    const closing = slideOut(dlg, () => { if (dw.closing === closing) done(); });
    dw.closing = closing;
  }

  // Slides a side panel out the way it came in, with its backdrop fading,
  // then calls `end`. Its animations, which opening it again meanwhile cancels.
  function slideOut(dlg, end) {
    const away = matchMedia('(max-width: 720px)').matches ? 'translateY(24px)' : 'translateX(28px)';
    const out = { duration: 200, easing: 'cubic-bezier(.4,0,1,1)', fill: 'forwards' };
    const closing = [dlg.animate([{ transform: 'none', opacity: 1 }, { transform: away, opacity: 0 }], out)];
    closing[0].finished.then(end, () => {});
    try { closing.push(dlg.animate([{ opacity: 1 }, { opacity: 0 }], { ...out, pseudoElement: '::backdrop' })); } catch (_) { /* the backdrop just goes */ }
    return closing;
  }

  // Overview polls refresh the header; the body is only rebuilt when the
  // machine's reachability or permission actually changed.
  function syncDrawer() {
    if (!dw.id) return;
    const before = dw.sig;
    renderDrawerHead();
    refreshVersionCard();
    refreshRebootCard();
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
    setPin($('.pin-drawer'), dw.id, name);
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
        osTag(os),
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
    const body = $('#dw-body');
    const was = body.firstElementChild;
    body.replaceChildren(view);
    // The skeleton crossfades into what replaces it; later rebuilds do not flicker.
    if (was && was.getAttribute('aria-busy') === 'true' && view.getAttribute('aria-busy') !== 'true') fadeIn(view);
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
    const orphans = [...dw.results.keys()].filter((k) => (k === 'add' ? !dw.add : k !== 'host' && k !== 'update' && k !== 'reboot' && !known.has(k)));
    return h('div', { class: 'dw-stack' },
      dw.error ? h('div', { class: 'result result-err', role: 'alert' },
        h('span', { class: 'result-icon', 'aria-hidden': 'true', text: '!' }),
        h('p', { class: 'result-msg', text: `Showing the last answer: the machine could not be read again. ${dw.error.hint || ''}` }),
        h('button', { type: 'button', class: 'btn-sm', 'data-fk': 'retry', text: 'Retry', onclick: () => loadConfig() }),
        dw.error.error ? h('pre', { class: 'result-pre', text: dw.error.error }) : null) : null,
      doc.schema_version !== 1 ? h('p', { class: 'notice notice-warn', text: `This machine describes its settings in format ${doc.schema_version}; this page reads format 1, so some details may be missing.` }) : null,
      versionCard(x),
      rebootCard(x),
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
      segThumb(seg);
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

  // ============================================================== settings
  // Every change goes through update(): normalized, kept in this browser at
  // once, sent to the coordinator a moment later, and applied to the page
  // with the usual animations (no reload).
  const clone = (v) => JSON.parse(JSON.stringify(v));
  const getPath = (o, path) => path.split('.').reduce((a, k) => (a == null ? a : a[k]), o);
  function setPath(o, path, v) {
    const ks = path.split('.'), last = ks.pop();
    ks.reduce((a, k) => a[k], o)[last] = clone(v);
  }

  function update(mutate) {
    const next = clone(cfg);
    mutate(next);
    replaceSettings(next);
  }
  // `remote`: the settings came from elsewhere (the coordinator, another
  // tab), so they are not sent back.
  function replaceSettings(next, remote) {
    const prev = cfg, n = RS.normalize(next);
    if (RS.same(n, prev)) return false;
    cfg = n;
    if (remote !== 'tab') storeLocal();
    if (!remote) saveSoon();
    applyAll(prev);
    return true;
  }

  // Brings the page in line with the settings: each render is a diff, so
  // what did not change stays put and what did moves.
  function applyAll(prev) {
    const changed = (k) => !RS.same(prev[k], cfg[k]);
    if (changed('general')) {
      applyGeneral();
      if (prev.general.refresh !== cfg.general.refresh && state.timers.ov) {
        clearTimeout(state.timers.ov);
        state.timers.ov = setTimeout(loadOverview, Math.min(overviewMs(), 1000));
      }
    }
    if (changed('layout')) applyLayout();
    syncRange();
    if (state.ov) renderOverview(state.ov);
    else if (changed('kpis')) renderSkeletons();
    if (state.metrics) renderCharts(); else renderChartFrames();
    if (changed('general')) { renderAudit(true); tick(); }
  }

  const darkScheme = matchMedia('(prefers-color-scheme: dark)');
  // Theme, motion, density and compact tables, as attributes the stylesheet reads.
  function applyGeneral() {
    const g = cfg.general, root = document.documentElement;
    const set = (k, v) => { if (v == null) delete root.dataset[k]; else root.dataset[k] = v; };
    set('theme', g.theme === 'system' ? null : g.theme);
    set('motion', g.motion === 'system' ? null : g.motion);
    set('density', g.density === 'compact' ? 'compact' : null);
    set('tables', g.compactTables ? 'compact' : null);
    const dark = g.theme === 'dark' || (g.theme === 'system' && darkScheme.matches);
    for (const m of $$('meta[name="theme-color"]')) {
      if (!m.dataset.color) m.dataset.color = m.content;
      m.content = g.theme === 'system' ? m.dataset.color : dark ? '#0a0b0d' : '#f6f7f9';
    }
    if (lessMotion()) settleMotion();
  }

  // The sections in their order, the hidden ones out, Queue and Running
  // side by side or stacked; the rest slide to their new places.
  function applyLayout() {
    const main = $('#main'), L = cfg.layout;
    const secs = L.order.map((k) => $(`:scope > [data-section="${k}"]`, main)).filter(Boolean);
    const split = $('[data-section="queue-running"]', main);
    const moving = [...secs, ...$$(':scope > .section', split)];
    const shown = [];
    flip(moving, () => {
      for (const el of secs) {
        main.append(el);
        const off = L.hidden.includes(el.dataset.section);
        if (!off && el.hasAttribute('data-off')) shown.push(el);
        el.toggleAttribute('data-off', off);
      }
      split.classList.toggle('is-stacked', L.split === 'stacked');
    });
    for (const el of shown) if (liveMotion()) el.animate([{ opacity: 0, transform: 'translateY(8px)' }, { opacity: 1, transform: 'none' }], { duration: DUR.slow, easing: EASE });
  }

  // ------------------------------------------------------------- syncing
  const SAVE_DELAY = 700;
  // `changes` counts this page's changes; `client` and `seq` order its
  // writes, so the coordinator keeps the newest of two on their way at once.
  const sync = {
    timer: 0, state: 'idle', note: '', dirty: false, inflight: false, again: false,
    changes: 0, client: Math.random().toString(36).slice(2, 12), seq: 0,
  };

  function saveSoon() {
    sync.dirty = true;
    sync.changes++;
    markUnsaved(JSON.stringify(cfg));
    setSync('pending');
    clearTimeout(sync.timer);
    sync.timer = setTimeout(pushSettings, SAVE_DELAY);
  }

  async function pushSettings(keepalive) {
    clearTimeout(sync.timer);
    // The page is going: send now even beside a request on its way; the
    // coordinator keeps whichever comes last, and both carry this copy.
    if (sync.inflight && keepalive !== true) { sync.again = true; return; }
    sync.inflight = true;
    sync.dirty = false;
    setSync('saving');
    const copy = JSON.stringify(cfg);
    const r = await call('/api/settings', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...cfg, client: sync.client, seq: ++sync.seq }), keepalive: keepalive === true,
    });
    sync.inflight = false;
    // 409: a newer write of this page got there first, which carries this change too.
    if (!r.ok && r.status !== 409) { sync.dirty = true; setSync('error', r.status === 401 ? '' : r.error || r.hint); }
    else {
      if (!sync.dirty) markUnsaved(null, copy);
      setSync(sync.dirty ? 'pending' : 'saved');
    }
    if (sync.again) { sync.again = false; if (sync.dirty) pushSettings(); }
  }

  // The coordinator's copy wins over this browser's, unless this browser
  // changed something meanwhile. With none there yet, this browser's
  // becomes the account's.
  async function loadServerSettings() {
    const changes = sync.changes;
    const r = await call('/api/settings');
    if (!r.ok) { if (r.status !== 401) setSync('error', 'Your saved settings could not be loaded; these are this browser’s.'); return; }
    // Changed here while the answer was on its way (perhaps saved already): this page's is newer.
    if (sync.dirty || sync.inflight || sync.changes !== changes) return;
    // A change this browser kept but never got confirmed: it is newer.
    if (unsaved()) { saveSoon(); return; }
    const remote = r.body && r.body.settings;
    if (remote) {
      replaceSettings(remote, 'server');
      setSync('saved');
      if (st.open) renderSettings();
    } else if (!RS.same(cfg, RS.defaults())) saveSoon();
  }

  function setSync(kind, note) {
    sync.state = kind;
    sync.note = note || '';
    $('#settings-btn').classList.toggle('has-error', kind === 'error');
    $('#settings-btn').title = kind === 'error' ? 'Settings · not saved' : 'Settings';
    renderStatus();
  }

  function renderStatus() {
    const box = $('#st-status');
    if (!box) return;
    let kids;
    if (st.undo) {
      kids = [h('span', { text: st.undo.text }), h('button', { type: 'button', class: 'link-btn', text: 'Undo', 'data-fk': 'undo', onclick: undoSettings })];
    } else if (st.msg) {
      kids = [h('span', { class: st.msg.kind === 'err' ? 'text-err' : null, text: st.msg.text })];
    } else {
      const text = {
        idle: 'Saved to your GitHub account as you go',
        pending: 'Saving…', saving: 'Saving…',
        saved: 'Saved to your account',
        error: 'Not saved',
      }[sync.state];
      kids = [
        h('i', { class: `st-dot st-dot-${sync.state}`, 'aria-hidden': 'true' }),
        h('span', { text }),
        sync.state === 'error' && sync.note ? h('span', { class: 'muted', text: ` · ${sync.note}` }) : null,
        sync.state === 'error' ? h('button', { type: 'button', class: 'link-btn', text: 'Retry', onclick: () => pushSettings() }) : null,
      ];
    }
    const sig = JSON.stringify([sync.state, sync.note, st.undo && st.undo.text, st.msg]);
    if (box.dataset.sig === sig) return;
    box.dataset.sig = sig;
    box.replaceChildren(...kids.filter(Boolean));
    fadeIn(box, DUR.fast);
  }

  // A message in the footer for a few seconds (an import that failed).
  function notify(text, kind) {
    clearTimeout(st.msgTimer);
    st.msg = { text, kind };
    renderStatus();
    st.msgTimer = setTimeout(() => { st.msg = null; renderStatus(); }, 6000);
  }

  // A reset or an import can be taken back for a while.
  function offerUndo(before, text) {
    clearTimeout(st.undoTimer);
    st.undo = { before, text };
    renderStatus();
    st.undoTimer = setTimeout(() => { st.undo = null; renderStatus(); }, 10000);
  }
  // After a reset the keyboard lands on its Undo.
  function focusUndo() {
    const b = $('#st-status [data-fk="undo"]');
    if (b) b.focus();
    return !!b;
  }
  function undoSettings() {
    if (!st.undo) return;
    const before = st.undo.before;
    st.undo = null;
    replaceSettings(before);
    renderSettings();
    $('#st-close').focus();
  }

  // ----------------------------------------------------------- the view
  const TABS = [['general', 'General'], ['layout', 'Layout'], ['machines', 'Machines'], ['charts', 'Charts'], ['kpis', 'Tiles']];
  const st = { open: false, tab: 'general', closing: null, expanded: new Set(), undo: null, msg: null, seq: 0 };

  function setupSettings() {
    const dlg = $('#settings');
    $('#settings-btn').addEventListener('click', openSettings);
    $('#st-close').addEventListener('click', () => closeSettings());
    dlg.addEventListener('cancel', (e) => { e.preventDefault(); closeSettings(); });
    dlg.addEventListener('click', (e) => { if (e.target === dlg) closeSettings(); });
    dlg.addEventListener('keydown', trapTab);
    const tabs = $('#st-tabs');
    tabs.replaceChildren(...TABS.map(([k, label]) => h('button', {
      type: 'button', role: 'tab', class: 'seg-btn', id: `st-tab-${k}`, 'aria-controls': 'st-body', 'data-tab': k, text: label,
      onclick: () => selectTab(k),
    })));
    tabs.addEventListener('keydown', (e) => {
      const i = TABS.findIndex((t) => t[0] === st.tab);
      const j = { ArrowLeft: i - 1, ArrowRight: i + 1, Home: 0, End: TABS.length - 1 }[e.key];
      if (j == null) return;
      e.preventDefault();
      const k = TABS[(j + TABS.length) % TABS.length][0];
      selectTab(k);
      $(`#st-tab-${k}`).focus();
    });
    $('#st-export').addEventListener('click', exportSettings);
    $('#st-import').addEventListener('click', () => $('#st-file').click());
    $('#st-file').addEventListener('change', importSettings);
    $('#st-reset').addEventListener('click', () => setConfirm(true));
    $('#st-reset-no').addEventListener('click', () => { setConfirm(false); $('#st-reset').focus(); });
    $('#st-reset-yes').addEventListener('click', () => {
      const before = cfg;
      setConfirm(false);
      if (replaceSettings(RS.defaults())) offerUndo(before, 'Every setting is back to its default.');
      renderSettings();
      if (!focusUndo()) $('#st-reset').focus();
    });
    // Another tab of this dashboard changed them: follow it.
    window.addEventListener('storage', (e) => {
      if (e.key !== SETTINGS_KEY || !e.newValue) return;
      try { if (replaceSettings(JSON.parse(e.newValue), 'tab') && st.open) renderSettings(); } catch (_) { /* not ours to read */ }
    });
    // Leaving with a change not yet sent: send it now.
    window.addEventListener('pagehide', () => { if (sync.dirty) pushSettings(true); });
    document.addEventListener('visibilitychange', () => { if (document.hidden && sync.dirty) pushSettings(true); });
  }

  function setConfirm(on) {
    $('#st-actions').hidden = on;
    $('#st-confirm').hidden = !on;
    if (on) { $('#st-reset-no').focus(); fadeIn($('#st-confirm'), DUR.fast); }
  }

  function openSettings() {
    const dlg = $('#settings');
    if (dlg.open && !st.closing) return;
    if (st.closing) { for (const a of st.closing) a.cancel(); st.closing = null; }
    st.open = true;
    setConfirm(false);
    if (!dlg.open) dlg.showModal();
    renderSettings(true);
    segThumb($('#st-tabs'));
    $('#st-close').focus();
  }

  // `handOff`: another panel takes over, so focus does not go back to the button.
  function closeSettings(handOff) {
    const dlg = $('#settings');
    if (!st.open) return;
    st.open = false;
    const done = () => {
      const anims = st.closing || [];
      st.closing = null;
      if (dlg.open) dlg.close();
      for (const a of anims) a.cancel();
      if (handOff !== true) $('#settings-btn').focus();
    };
    if (!motionOk()) { done(); return; }
    const closing = slideOut(dlg, () => { if (st.closing === closing) done(); });
    st.closing = closing;
  }

  function selectTab(k) {
    if (k === st.tab) return;
    st.tab = k;
    $('#st-body').scrollTop = 0;
    renderSettings(true);
  }

  const TAB_VIEW = { general: generalTab, layout: layoutTab, machines: machinesTab, charts: chartsTab, kpis: kpisTab };

  // Builds the open tab. `fresh`: a new tab, faded in at the top; otherwise
  // the same tab again (a reset, an import), keeping the scroll and focus.
  function renderSettings(fresh) {
    if (!st.open) return;
    for (const b of $$('[role="tab"]', $('#st-tabs'))) {
      const on = b.dataset.tab === st.tab;
      b.setAttribute('aria-selected', String(on));
      b.tabIndex = on ? 0 : -1;
    }
    segThumb($('#st-tabs'));
    const body = $('#st-body');
    const fk = document.activeElement && body.contains(document.activeElement) ? document.activeElement.dataset.fk : null;
    const top = body.scrollTop;
    st.seq = 0;
    const view = h('div', { class: 'st-stack' }, TAB_VIEW[st.tab]());
    body.replaceChildren(view);
    body.setAttribute('aria-labelledby', `st-tab-${st.tab}`);
    segThumbs(view);
    if (fresh) {
      if (motionOk()) view.animate([{ opacity: 0, transform: 'translateY(6px)' }, { opacity: 1, transform: 'none' }], { duration: DUR.base, easing: EASE });
      return;
    }
    body.scrollTop = top;
    if (!fk) return;
    // What had focus may be gone (an unpinned row): the panel keeps it.
    const again = $(`[data-fk="${CSS.escape(fk)}"]`, body);
    (again && !again.disabled ? again : body).focus({ preventScroll: true });
  }

  // ------------------------------------------------------------ controls
  const uid = (p) => `st-${p}-${++st.seq}`;

  // A card of related settings; `paths` are what its Reset puts back.
  function group(title, hint, paths, ...kids) {
    const isDefault = () => paths.every((p) => RS.same(getPath(cfg, p), getPath(RS.defaults(), p)));
    const reset = paths.length ? h('button', {
      type: 'button', class: 'link-btn st-reset', 'data-fk': `reset:${title}`, text: 'Reset', 'aria-label': `Reset ${title}`,
      disabled: isDefault() || null,
      onclick: () => {
        const before = cfg, d = RS.defaults();
        update((c) => { for (const p of paths) setPath(c, p, getPath(d, p)); });
        offerUndo(before, `${title} reset to defaults.`);
        renderSettings();
        focusUndo();
      },
    }) : null;
    const el = h('section', { class: 'card st-group' },
      h('header', { class: 'st-group-head' },
        h('div', { class: 'st-group-id' }, h('h3', { class: 'st-group-title', text: title }), hint ? h('p', { class: 'st-hint', text: hint }) : null),
        reset),
      ...kids);
    // A change in the card turns its Reset on or off.
    el._sync = () => { if (reset) reset.disabled = isDefault(); };
    el.addEventListener('st-change', () => el._sync());
    return el;
  }
  const touched = (from) => from.dispatchEvent(new Event('st-change', { bubbles: true }));

  // A setting: its name and hint, and its control (made by `make(labelId)`).
  function row(label, hint, make) {
    const id = uid('l');
    const ctl = make(id);
    // A switch or a stepper stays beside its name on a phone; wider controls go under it.
    const inline = ctl.classList.contains('switch') || ctl.classList.contains('stepper');
    return h('div', { class: `st-row${inline ? ' is-inline' : ''}` },
      h('div', { class: 'st-label' }, h('span', { class: 'st-name', id, text: label }), hint ? h('span', { class: 'st-hint', text: hint }) : null),
      h('div', { class: 'st-ctl' }, ctl));
  }

  function segCtl(path, options, labelId, after) {
    const box = h('div', { class: 'seg seg-sm', role: 'group', 'aria-labelledby': labelId });
    const press = () => { for (const b of $$('.seg-btn', box)) b.setAttribute('aria-pressed', String(b.dataset.v === String(getPath(cfg, path)))); };
    box.append(...options.map(([v, text]) => h('button', {
      type: 'button', class: 'seg-btn', 'data-v': String(v), 'data-fk': `${path}=${v}`, text,
      onclick: (e) => {
        update((c) => setPath(c, path, v));
        press();
        segThumb(box);
        touched(e.currentTarget);
        if (after) after();
      },
    })));
    press();
    return box;
  }

  // An on/off switch; `props` its label, state and data-fk.
  const switchBtn = (props) => h('button', { type: 'button', class: 'switch st-switch', role: 'switch', ...props },
    h('span', { class: 'switch-track', 'aria-hidden': 'true' }, h('i')));

  function switchCtl(path, labelId, after, opts = {}) {
    const get = () => (opts.invert ? !getPath(cfg, path) : !!getPath(cfg, path));
    const b = switchBtn({ 'aria-checked': String(get()), 'data-fk': path, 'aria-labelledby': labelId || null, 'aria-label': opts.label || null });
    b.addEventListener('click', () => {
      const v = !getPath(cfg, path);
      update((c) => setPath(c, path, v));
      b.setAttribute('aria-checked', String(get()));
      touched(b);
      if (after) after();
    });
    return b;
  }

  function stepperCtl(path, min, max, step, labelId) {
    const input = h('input', {
      class: 'num-input', type: 'number', inputmode: 'numeric', min, max, step, value: getPath(cfg, path),
      'aria-labelledby': labelId, 'data-fk': path,
    });
    const set = (v) => {
      const n = String(v).trim() === '' ? NaN : clamp(Math.round(Number(v)), min, max);
      if (!isFinite(n)) { input.value = getPath(cfg, path); return; }
      update((c) => setPath(c, path, n));
      input.value = getPath(cfg, path);
      dec.disabled = n <= min; inc.disabled = n >= max;
      touched(input);
    };
    const dec = h('button', { type: 'button', class: 'step-btn', 'aria-label': 'Fewer', text: '−', tabindex: -1, onclick: () => set(Number(input.value) - step) });
    const inc = h('button', { type: 'button', class: 'step-btn', 'aria-label': 'More', text: '+', tabindex: -1, onclick: () => set(Number(input.value) + step) });
    dec.disabled = getPath(cfg, path) <= min; inc.disabled = getPath(cfg, path) >= max;
    input.addEventListener('change', () => set(input.value));
    return h('div', { class: 'stepper' }, dec, input, inc);
  }

  function selectCtl(path, options, labelId) {
    const sel = h('select', { class: 'input st-select', 'aria-labelledby': labelId, 'data-fk': path },
      options.map(([v, text]) => h('option', { value: v, text, selected: v === getPath(cfg, path) || null })));
    sel.addEventListener('change', () => { update((c) => setPath(c, path, sel.value)); touched(sel); });
    return sel;
  }

  const gripIcon = () => s('svg', { viewBox: '0 0 20 20', width: 16, height: 16, 'aria-hidden': 'true' },
    ...[[7.5, 5], [12.5, 5], [7.5, 10], [12.5, 10], [7.5, 15], [12.5, 15]].map(([cx, cy]) => s('circle', { cx, cy, r: 1.4, fill: 'currentColor' })));
  const upIcon = () => icon('M6 12.5l4-4 4 4', 14);
  const downIcon = () => icon('M6 8l4 4 4-4', 14);

  function announce(text) {
    const live = $('#st-live');
    live.textContent = '';
    requestAnimationFrame(() => { live.textContent = text; });
  }

  // A list to put in order and, with `spec.hidden`, to switch items on and
  // off. A row moves by dragging its handle (mouse, pen or touch), by the
  // arrow keys on the handle, or by its up and down buttons; the others
  // slide out of its way. `spec`: { label, items: [{ key, label, sub, lead }],
  // order, hidden, onOrder(keys), onShow(key, on), actions(key), detail(key) }.
  function orderList(spec) {
    const ul = h('ul', { class: 'olist', 'aria-label': spec.label });
    const byKey = new Map(spec.items.map((it) => [it.key, it]));
    const rows = () => $$(':scope > li', ul);
    const keys = () => rows().map((li) => li.dataset.key);
    const syncMoves = () => rows().forEach((li, i, all) => { li._up.disabled = i === 0; li._down.disabled = i === all.length - 1; });
    const commit = () => { spec.onOrder(keys()); syncMoves(); touched(ul); };
    const labelOf = (li) => byKey.get(li.dataset.key).label;

    // `focus`: what keeps the keyboard focus (a move takes the row out of
    // the document for a moment); a move button that is now disabled hands
    // it to the other one.
    function moveBy(li, by, focus) {
      const all = rows(), i = all.indexOf(li), j = i + by;
      if (j < 0 || j >= all.length) return;
      flip(all, () => ul.insertBefore(li, by < 0 ? all[j] : all[j].nextSibling));
      commit();
      if (focus) (focus.disabled ? (focus === li._up ? li._down : li._up) : focus).focus({ preventScroll: false });
      announce(`${labelOf(li)}, position ${j + 1} of ${all.length}`);
    }

    function drag(e, li, handle) {
      if (e.button !== 0) return;
      e.preventDefault();
      // On the window, not the handle: the row moves in the document as it
      // passes others, which would drop a pointer capture.
      const id = e.pointerId;
      const scroller = ul.closest('.dw-body');
      const before = keys().join('\n');
      let y0 = e.clientY, dy = 0, moving = false, lastY = e.clientY;
      const place = () => { li.style.transform = `translateY(${dy}px)`; };
      const reorder = () => {
        const r = li.getBoundingClientRect(), mid = r.top + r.height / 2;
        const others = rows().filter((x) => x !== li);
        const next = others.find((o) => { const q = o.getBoundingClientRect(); return mid < q.top + q.height / 2; }) || null;
        if (li.nextElementSibling === next) return;
        const natural = r.top - dy;
        flip(others, () => ul.insertBefore(li, next));
        y0 += li.getBoundingClientRect().top - dy - natural;
        dy = lastY - y0;
        place();
      };
      const onMove = (ev) => {
        if (ev.pointerId !== id) return;
        lastY = ev.clientY;
        dy = ev.clientY - y0;
        if (!moving && Math.abs(dy) < 4) return;
        if (!moving) { moving = true; li.classList.add('is-dragging'); }
        // Near the panel's edges it scrolls, and the row stays under the pointer.
        if (scroller) {
          const b = scroller.getBoundingClientRect();
          const by = ev.clientY < b.top + 40 ? -12 : ev.clientY > b.bottom - 40 ? 12 : 0;
          if (by) { const t0 = scroller.scrollTop; scroller.scrollTop += by; y0 -= scroller.scrollTop - t0; dy = ev.clientY - y0; }
        }
        place();
        reorder();
      };
      const onUp = (ev) => {
        if (ev.pointerId !== id) return;
        window.removeEventListener('pointermove', onMove);
        window.removeEventListener('pointerup', onUp);
        window.removeEventListener('pointercancel', onUp);
        if (!moving) return;
        li.classList.remove('is-dragging');
        li.style.transform = '';
        handle.focus({ preventScroll: true });
        if (motionOk() && Math.abs(dy) > 0.5) li.animate([{ transform: `translateY(${dy}px)` }, { transform: 'none' }], { duration: DUR.base, easing: EASE });
        if (ul.isConnected && keys().join('\n') !== before) {
          commit();
          const all = rows();
          announce(`${labelOf(li)}, position ${all.indexOf(li) + 1} of ${all.length}`);
        }
      };
      window.addEventListener('pointermove', onMove);
      window.addEventListener('pointerup', onUp);
      window.addEventListener('pointercancel', onUp);
    }

    function item(it) {
      const off = spec.hidden ? spec.hidden.includes(it.key) : false;
      const name = uid('o');
      const handle = h('button', {
        type: 'button', class: 'ol-handle', 'aria-label': `Move ${it.label}`, 'aria-describedby': 'st-drag-help', 'data-fk': `${spec.fk}:${it.key}:grab`,
        title: 'Drag to reorder, or use the arrow keys',
      }, gripIcon());
      const li = h('li', { class: `ol-item${off ? ' is-off' : ''}`, 'data-key': it.key });
      li._up = h('button', { type: 'button', class: 'ol-move', 'aria-label': `Move ${it.label} up`, 'data-fk': `${spec.fk}:${it.key}:up`, onclick: () => moveBy(li, -1, li._up) }, upIcon());
      li._down = h('button', { type: 'button', class: 'ol-move', 'aria-label': `Move ${it.label} down`, 'data-fk': `${spec.fk}:${it.key}:down`, onclick: () => moveBy(li, 1, li._down) }, downIcon());
      handle.addEventListener('pointerdown', (e) => drag(e, li, handle));
      handle.addEventListener('keydown', (e) => {
        const by = { ArrowUp: -1, ArrowDown: 1 }[e.key];
        if (!by) return;
        e.preventDefault();
        moveBy(li, by, handle);
      });
      const open = spec.detail && st.expanded.has(`${spec.fk}:${it.key}`);
      const more = spec.detail ? h('button', {
        type: 'button', class: 'ol-more', 'aria-expanded': String(!!open), 'aria-label': `${it.label} options`, 'data-fk': `${spec.fk}:${it.key}:more`,
      }, h('span', { text: 'Options' }), downIcon()) : null;
      const show = spec.hidden ? switchBtn({ 'aria-checked': String(!off), 'aria-label': `Show ${it.label}`, 'data-fk': `${spec.fk}:${it.key}:show` }) : null;
      if (show) {
        show.addEventListener('click', () => {
          const on = show.getAttribute('aria-checked') !== 'true';
          spec.onShow(it.key, on);
          show.setAttribute('aria-checked', String(on));
          li.classList.toggle('is-off', !on);
          touched(show);
        });
      }
      append(li, [
        h('div', { class: 'ol-row' },
          handle,
          it.lead || null,
          h('div', { class: 'ol-text' }, h('span', { class: 'ol-name', id: name, text: it.label }), it.sub ? h('span', { class: 'ol-sub', text: it.sub }) : null),
          spec.actions ? spec.actions(it.key) : null,
          more, show,
          h('span', { class: 'ol-moves' }, li._up, li._down)),
      ]);
      if (spec.detail) {
        const box = h('div', { class: 'ol-detail', hidden: !open || null });
        if (open) box.append(spec.detail(it.key));
        li.append(box);
        more.addEventListener('click', () => {
          const k = `${spec.fk}:${it.key}`, on = !st.expanded.has(k);
          if (on) st.expanded.add(k); else st.expanded.delete(k);
          more.setAttribute('aria-expanded', String(on));
          if (on) { box.replaceChildren(spec.detail(it.key)); segThumbs(box); }
          collapse(box, on);
        });
      }
      return li;
    }

    for (const key of spec.order) if (byKey.has(key)) ul.append(item(byKey.get(key)));
    syncMoves();
    return rows().length ? ul : (spec.empty || null);
  }

  // A list's order and its hidden keys at `path` and `hiddenPath`.
  function listAt(path, hiddenPath) {
    return {
      order: getPath(cfg, path), hidden: hiddenPath ? getPath(cfg, hiddenPath) : null, fk: path,
      onOrder: (keys) => update((c) => setPath(c, path, keys)),
      onShow: (key, on) => update((c) => {
        const now = getPath(c, hiddenPath).filter((k) => k !== key);
        setPath(c, hiddenPath, on ? now : [...now, key]);
      }),
    };
  }

  // --------------------------------------------------------------- tabs
  function generalTab() {
    return [
      group('Appearance', null, ['general.theme', 'general.density', 'general.motion'],
        row('Theme', 'System follows your device’s light or dark mode.', (id) => segCtl('general.theme', [['system', 'System'], ['light', 'Light'], ['dark', 'Dark']], id)),
        row('Density', 'Spacing between and inside the sections.', (id) => segCtl('general.density', [['comfortable', 'Comfortable'], ['compact', 'Compact']], id)),
        row('Reduce motion', 'Off plays the dashboard’s animations even when your device asks for less motion.', (id) => segCtl('general.motion', [['system', 'System'], ['reduce', 'On'], ['full', 'Off']], id))),
      group('Data and units', null, ['general.refresh', 'general.time', 'general.clock', 'general.bytes'],
        row('Refresh every', 'How often the machines, queue and jobs are read again.', (id) => segCtl('general.refresh', RS.REFRESH.map((n) => [n, n < 60 ? `${n} s` : `${n / 60} min`]), id)),
        row('Times', 'When something happened: “3 min ago”, or the time of day.', (id) => segCtl('general.time', [['relative', 'Relative'], ['absolute', 'Time of day']], id)),
        row('Clock', null, (id) => segCtl('general.clock', [['24', '24-hour'], ['12', '12-hour']], id)),
        row('Sizes', 'Memory and disk in GiB (1024³ bytes) or GB (1000³).', (id) => segCtl('general.bytes', [['binary', 'GiB'], ['decimal', 'GB']], id))),
      group('Tables', null, ['general.compactTables', 'general.recentRows', 'general.auditRows', 'general.auditFilter'],
        row('Compact rows', 'Tighter rows in every table.', (id) => switchCtl('general.compactTables', id)),
        row('Recent jobs', 'Rows shown before “Show all”.', (id) => stepperCtl('general.recentRows', 5, 50, 1, id)),
        row('Remote commands', 'Rows shown before “Show all”.', (id) => stepperCtl('general.auditRows', 5, 100, 5, id)),
        row('Remote commands show', 'Changes only, or the panel’s reads too.', (id) => segCtl('general.auditFilter', [['changes', 'Changes'], ['all', 'All']], id))),
    ];
  }

  function layoutTab() {
    return [
      group('Sections', 'Drag a section by its handle, or use its arrows. Switch one off to hide it.', ['layout.order', 'layout.hidden'],
        orderList({ ...listAt('layout.order', 'layout.hidden'), label: 'Dashboard sections', items: RS.SECTIONS })),
      group('Queue and Running', null, ['layout.split'],
        row('Arrangement', 'On narrow screens they always stack.', (id) => segCtl('layout.split', [['side', 'Side by side'], ['stacked', 'Stacked']], id))),
    ];
  }

  // Every machine the page knows: the coordinator's list, then any only in
  // the charts' history, then pins of machines it does not know now.
  function knownHosts() {
    const seen = new Map();
    for (const x of (state.ov && state.ov.hosts) || []) seen.set(x.id, x);
    for (const x of (state.metrics && state.metrics.hosts) || []) if (!seen.has(x.id)) seen.set(x.id, { id: x.id, name: x.name, online: false, metricsOnly: true });
    return [...seen.values()].sort((a, b) => String(a.name || a.hostname || a.id).localeCompare(String(b.name || b.hostname || b.id)));
  }
  const hostLabel = (id) => { const x = knownHosts().find((y) => y.id === id); return x ? x.name || x.hostname || x.id : id; };
  function hostSub(x) {
    if (!x) return 'Not known to the coordinator now: kept for when it returns';
    const os = String(x.os || '').toLowerCase();
    return [OS_NAME[os] || null, x.metricsOnly ? 'in the history only' : RS.statusOf(x)].filter(Boolean).join(' · ');
  }

  function machinesTab() {
    const ms = cfg.machines;
    const hosts = knownHosts();
    const byId = new Map(hosts.map((x) => [x.id, x]));
    const pinned = orderList({
      ...listAt('machines.pinned'), label: 'Pinned machines',
      items: ms.pinned.map((id) => ({ key: id, label: hostLabel(id), sub: hostSub(byId.get(id)), lead: hostDot(id) })),
      actions: (id) => h('button', {
        type: 'button', class: 'btn-sm btn-quiet st-unpin', 'data-fk': `unpin:${id}`, 'aria-label': `Unpin ${hostLabel(id)}`,
        onclick: () => { togglePin(id); renderSettings(); },
      }, xIcon(12), 'Unpin'),
      empty: h('p', { class: 'st-empty', text: 'Nothing pinned. Pin a machine with the pin on its card, in its panel, or in the list below.' }),
    });
    return [
      group('Pinned', 'Pinned machines come first, in this order, offline or not.', ['machines.pinned'], pinned),
      group('Order', 'For the machines not pinned.', ['machines.sort', 'machines.reverse', 'machines.onlineFirst', 'machines.group', 'machines.showOffline'],
        row('Sort by', 'Loads and slots sort busiest first.', (id) => selectCtl('machines.sort', RS.SORTS, id)),
        row('Reverse', null, (id) => switchCtl('machines.reverse', id)),
        row('Online first', 'Offline machines after the connected ones.', (id) => switchCtl('machines.onlineFirst', id)),
        row('Group by', 'Headings over the cards; pinned ones get their own.', (id) => segCtl('machines.group', RS.GROUPS, id)),
        row('Show offline machines', 'A pinned machine shows anyway.', (id) => switchCtl('machines.showOffline', id))),
      group('Cards', 'What a card shows, top to bottom.', ['machines.density', 'machines.fields', 'machines.fieldsHidden'],
        row('Density', null, (id) => segCtl('machines.density', [['comfortable', 'Comfortable'], ['compact', 'Compact']], id)),
        orderList({ ...listAt('machines.fields', 'machines.fieldsHidden'), label: 'Card contents', items: RS.FIELDS })),
      group('All machines', 'Hidden machines leave the Machines section only; their jobs and history stay.', ['machines.hidden'],
        hosts.length ? h('ul', { class: 'olist st-hosts', 'aria-label': 'All machines' }, hosts.map((x) => hostRow(x))) : h('p', { class: 'st-empty', text: 'No machines yet.' })),
    ];
  }

  function hostRow(x) {
    const name = x.name || x.hostname || x.id;
    const pin = h('button', {
      type: 'button', class: 'pin-btn pin-list', 'aria-pressed': String(isPinned(x.id)), 'aria-label': `${isPinned(x.id) ? 'Unpin' : 'Pin'} ${name}`, 'data-fk': `pin:${x.id}`,
      onclick: () => { togglePin(x.id); renderSettings(); },
    }, pinIcon(15));
    const shown = !cfg.machines.hidden.includes(x.id);
    const show = switchBtn({
      'aria-checked': String(shown), 'aria-label': `Show ${name}`, 'data-fk': `show:${x.id}`,
      onclick: () => {
        update((c) => {
          const ms = c.machines;
          if (ms.hidden.includes(x.id)) ms.hidden = ms.hidden.filter((k) => k !== x.id);
          else { ms.hidden.push(x.id); ms.pinned = ms.pinned.filter((k) => k !== x.id); }
        });
        renderSettings();
      },
    });
    return h('li', { class: `ol-item${shown ? '' : ' is-off'}` },
      h('div', { class: 'ol-row' }, hostDot(x.id),
        h('div', { class: 'ol-text' }, h('span', { class: 'ol-name', text: name }), h('span', { class: 'ol-sub', text: hostSub(x) })),
        pin, show));
  }

  function chartsTab() {
    return [
      group('All charts', null, ['charts.range', 'charts.legend', 'charts.columns', 'charts.height'],
        row('Time range', 'The range the charts open with; the switch above them changes it too.', (id) => segCtl('charts.range', RANGES.map((r) => [r, r]), id)),
        row('Legends', 'The machine names over each chart (rows are named on their left).', (id) => switchCtl('charts.legend', id)),
        row('Columns', 'Narrow screens show one.', (id) => segCtl('charts.columns', [[1, '1'], [2, '2'], [3, '3']], id)),
        row('Height', null, (id) => segCtl('charts.height', [['s', 'Small'], ['m', 'Medium'], ['l', 'Large']], id))),
      group('Charts', 'Drag to reorder, switch off to hide; Options sets how each one draws.', ['charts.order', 'charts.hidden', 'charts.per'],
        orderList({
          ...listAt('charts.order', 'charts.hidden'), label: 'Charts', fk: 'charts',
          items: RS.CHARTS.map((d) => ({ key: d.key, label: d.label, sub: d.sub })),
          detail: chartOptionsView,
        })),
    ];
  }

  // One chart's options; redrawn when its style changes what applies.
  function chartOptionsView(key) {
    const d = RS.CHARTS.find((c) => c.key === key);
    const base = `charts.per.${key}`;
    const box = h('div', { class: 'st-sub' });
    const redo = () => {
      const o = cfg.charts.per[key];
      const fk = document.activeElement && box.contains(document.activeElement) ? document.activeElement.dataset.fk : null;
      box.replaceChildren(...[
        d.styles.length > 1 ? row('Style', null, (id) => segCtl(`${base}.style`, d.styles.map((x) => [x, RS.STYLE_LABEL[x]]), id, redo)) : null,
        o.style !== 'columns' ? row('Smooth lines', 'Curves through the points, or straight segments.', (id) => switchCtl(`${base}.smooth`, id)) : null,
        d.pct ? row('Scale', 'The full 0–100%, or fitted to the values.', (id) => segCtl(`${base}.scale`, [['full', '0–100%'], ['fit', 'Fit']], id)) : null,
        d.fleet ? null : row('Machines', null, (id) => segCtl(`${base}.hosts`, [['all', 'All'], ['top', 'Top'], ['pick', 'Chosen']], id, redo)),
        !d.fleet && o.hosts === 'top' ? row('How many', key === 'disk' ? 'The machines with the least free disk.' : 'The busiest machines over the range.', (id) => stepperCtl(`${base}.top`, 1, RS.MAX_TOP, 1, id)) : null,
        !d.fleet && o.hosts === 'pick' ? pickHosts(key) : null].filter(Boolean));
      segThumbs(box);
      const again = fk && $(`[data-fk="${CSS.escape(fk)}"]`, box);
      if (again) again.focus({ preventScroll: true });
    };
    redo();
    return box;
  }

  function pickHosts(key) {
    const hosts = knownHosts();
    const path = `charts.per.${key}.pick`;
    if (!hosts.length) return h('p', { class: 'st-empty', text: 'No machines yet.' });
    return h('div', { class: 'st-picks', role: 'group', 'aria-label': 'Machines this chart shows' }, hosts.map((x) => {
      const input = h('input', { type: 'checkbox', checked: cfg.charts.per[key].pick.includes(x.id) || null, 'data-fk': `${path}:${x.id}` });
      input.addEventListener('change', () => {
        update((c) => {
          const now = c.charts.per[key].pick.filter((k) => k !== x.id);
          c.charts.per[key].pick = input.checked ? [...now, x.id] : now;
        });
        touched(input);
      });
      return h('label', { class: 'check st-pick' }, input, hostDot(x.id), h('span', { text: x.name || x.hostname || x.id }));
    }));
  }

  function kpisTab() {
    return [
      group('Summary tiles', 'The tiles at the top of the page: drag to reorder, switch off to hide.', ['kpis.order', 'kpis.hidden'],
        orderList({ ...listAt('kpis.order', 'kpis.hidden'), label: 'Summary tiles', items: RS.KPIS })),
    ];
  }

  // --------------------------------------------------- export and import
  function exportSettings() {
    const blob = new Blob([`${JSON.stringify(cfg, null, 2)}\n`], { type: 'application/json' });
    const a = h('a', { href: URL.createObjectURL(blob), download: 'runner-manager-dashboard-settings.json', hidden: true });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    notify('Exported as runner-manager-dashboard-settings.json');
  }

  async function importSettings(e) {
    const file = e.target.files && e.target.files[0];
    e.target.value = '';
    if (!file) return;
    if (file.size > 64 * 1024) { notify('That file is too large to be dashboard settings.', 'err'); return; }
    let raw;
    try { raw = JSON.parse(await file.text()); } catch (_) { notify('That file is not JSON.', 'err'); return; }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw) || !Number.isInteger(raw.version) || raw.version < 1) {
      notify('That file does not hold dashboard settings.', 'err');
      return;
    }
    const before = cfg;
    if (replaceSettings(raw)) offerUndo(before, `Imported ${file.name}.`);
    else notify('Those are the settings already in use.');
    renderSettings();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
