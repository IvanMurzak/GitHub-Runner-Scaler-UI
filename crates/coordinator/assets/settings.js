// runner-manager dashboard settings: what can be set, the defaults, and the
// rules that turn anything stored (this browser's copy, the coordinator's,
// an imported file) into settings safe to use. Pure functions without the
// DOM, so they also run under plain node. app.js reads them as RMSettings.
'use strict';

(function (root) {
  // Raised when the shape changes in a way normalize() cannot read on its
  // own; it then migrates from the older version first.
  const VERSION = 1;

  // The dashboard's sections, in their default order.
  const SECTIONS = [
    { key: 'kpis', label: 'Summary tiles' },
    { key: 'machines', label: 'Machines' },
    { key: 'queue-running', label: 'Queue and Running' },
    { key: 'activity', label: 'Activity charts' },
    { key: 'recent', label: 'Recent jobs' },
    { key: 'audit', label: 'Remote commands', sub: 'Shown once a command was run' },
    { key: 'pools', label: 'Pools & leases', sub: 'Shown while a pool has work' },
  ];

  // The summary tiles; `off`: hidden until chosen.
  const KPIS = [
    { key: 'machines', label: 'Machines online' },
    { key: 'slots', label: 'Runner slots busy' },
    { key: 'jobs', label: 'Jobs running / queued' },
    { key: 'wait', label: 'Queue wait p50' },
    { key: 'cpu', label: 'Average CPU', sub: 'Across online machines', off: true },
    { key: 'memory', label: 'Memory in use', sub: 'Across online machines', off: true },
  ];

  // What a machine card shows, top to bottom. Disk and uptime sit in the
  // card's footer, in their order.
  const FIELDS = [
    { key: 'cpu', label: 'CPU meter' },
    { key: 'mem', label: 'Memory meter' },
    { key: 'slots', label: 'Slots meter' },
    { key: 'spark', label: 'CPU and memory history', sub: 'A sparkline over the chart range' },
    { key: 'ver', label: 'Versions', sub: 'runner-manager, its app and WSL' },
    { key: 'disk', label: 'Disk', sub: 'In the footer' },
    { key: 'up', label: 'Uptime / last seen', sub: 'In the footer' },
  ];

  // How a chart can be drawn:
  //   columns  stacked columns       stacked  stacked areas
  //   lines    a line per series     area     a filled line per series
  //   strips   a row per machine
  const STYLE_LABEL = { columns: 'Columns', stacked: 'Stacked area', lines: 'Lines', area: 'Area', strips: 'Rows' };

  // The Activity charts. `styles[0]` is the default; `pct`: a percentage,
  // which can fill 0–100% or fit its data; `fleet`: one series for the
  // whole fleet (no machine choice); `off`: hidden until chosen.
  const CHARTS = [
    { key: 'jobs', label: 'Jobs', sub: 'Running and queued', styles: ['columns', 'stacked', 'lines'], fleet: true },
    { key: 'cpu', label: 'CPU', sub: 'Per machine', styles: ['strips', 'lines', 'area'], pct: true },
    { key: 'busy', label: 'Busy slots', sub: 'Per machine', styles: ['columns', 'stacked', 'lines'] },
    { key: 'ram', label: 'Memory', sub: 'Used per machine', styles: ['lines', 'area', 'strips'], pct: true },
    { key: 'util', label: 'Slot use', sub: 'Busy share of all slots', styles: ['area', 'lines', 'columns'], fleet: true, pct: true, off: true },
    { key: 'disk', label: 'Disk free', sub: 'Per machine', styles: ['lines', 'area', 'strips'], off: true },
  ];

  // How the Balancing screen shows placement.
  const BALANCING_VIEWS = [
    ['flow', 'Flow map', 'Webhooks, queues, the coordinator and the machines on one map you can pan and zoom'],
    ['race', 'Decision theatre', 'One decision at a time: the machines race on their score parts'],
  ];

  const RANGES = ['1h', '6h', '24h', '7d'];
  const REFRESH = [2, 5, 10, 30, 60];
  const SORTS = [
    ['name', 'Name'], ['status', 'Status'], ['os', 'Operating system'], ['cpu', 'CPU load'],
    ['memory', 'Memory use'], ['busy', 'Busy slots'], ['free', 'Free slots'], ['uptime', 'Uptime'],
  ];
  const GROUPS = [['none', 'None'], ['os', 'OS'], ['status', 'Status']];
  const HEIGHTS = { s: 170, m: 210, l: 280 };
  // Far more than anyone pins; a list past it keeps its first entries.
  const MAX_IDS = 200, MAX_ID_LEN = 200, MAX_TOP = 20;

  const keys = (list) => list.map((x) => x.key);
  const offKeys = (list) => list.filter((x) => x.off).map((x) => x.key);

  function chartDefaults(c) {
    return { style: c.styles[0], smooth: true, scale: 'full', hosts: 'all', top: 5, pick: [] };
  }

  function defaults() {
    return {
      version: VERSION,
      general: {
        theme: 'system', motion: 'system', density: 'comfortable', refresh: 5,
        time: 'relative', clock: '24', bytes: 'binary',
        compactTables: false, recentRows: 12, auditRows: 15, auditFilter: 'changes',
      },
      layout: { order: keys(SECTIONS), hidden: [], split: 'side' },
      machines: {
        pinned: [], hidden: [], sort: 'name', reverse: false, onlineFirst: true, group: 'none',
        showOffline: true, density: 'comfortable', fields: keys(FIELDS), fieldsHidden: [],
      },
      charts: {
        order: keys(CHARTS), hidden: offKeys(CHARTS), range: '6h', legend: true, columns: 2, height: 'm',
        per: Object.fromEntries(CHARTS.map((c) => [c.key, chartDefaults(c)])),
      },
      kpis: { order: keys(KPIS), hidden: offKeys(KPIS) },
      balancing: { view: 'flow' },
    };
  }

  // ------------------------------------------------------------ the rules
  const isObj = (v) => v != null && typeof v === 'object' && !Array.isArray(v);
  const obj = (v) => (isObj(v) ? v : {});
  const oneOf = (v, allowed, d) => (allowed.includes(v) ? v : d);
  const bool = (v, d) => (typeof v === 'boolean' ? v : d);
  function intIn(v, lo, hi, d) {
    const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : v;
    return typeof n === 'number' && isFinite(n) ? Math.min(hi, Math.max(lo, Math.round(n))) : d;
  }
  // Distinct, non-empty strings of a sane length: machine ids. Unknown ones
  // are kept, since a machine away now may come back.
  function ids(v) {
    if (!Array.isArray(v)) return [];
    const out = [];
    for (const x of v) {
      if (typeof x !== 'string' || !x || x.length > MAX_ID_LEN || out.includes(x)) continue;
      out.push(x);
      if (out.length >= MAX_IDS) break;
    }
    return out;
  }
  // `known` in the order `v` gives, then any it left out (new ones) where
  // they are by default.
  function order(v, known) {
    const head = Array.isArray(v) ? v.filter((k, i) => known.includes(k) && v.indexOf(k) === i) : [];
    return [...head, ...known.filter((k) => !head.includes(k))];
  }
  const subset = (v, known, d) => (Array.isArray(v) ? known.filter((k) => v.includes(k)) : d);

  function chartOptions(c, raw) {
    const d = chartDefaults(c), r = obj(raw);
    return {
      style: oneOf(r.style, c.styles, d.style),
      smooth: bool(r.smooth, d.smooth),
      scale: oneOf(r.scale, ['full', 'fit'], d.scale),
      hosts: oneOf(r.hosts, ['all', 'top', 'pick'], d.hosts),
      top: intIn(r.top, 1, MAX_TOP, d.top),
      pick: ids(r.pick),
    };
  }

  // Anything to settings: every field the right type and in range, what is
  // missing or wrong at its default, what is unknown dropped.
  function normalize(raw) {
    const d = defaults(), r = obj(raw);
    const g = obj(r.general), l = obj(r.layout), m = obj(r.machines), c = obj(r.charts), k = obj(r.kpis), b = obj(r.balancing);
    const dg = d.general, dm = d.machines, dc = d.charts;
    const pinned = ids(m.pinned);
    return {
      version: VERSION,
      general: {
        theme: oneOf(g.theme, ['system', 'light', 'dark'], dg.theme),
        motion: oneOf(g.motion, ['system', 'reduce', 'full'], dg.motion),
        density: oneOf(g.density, ['comfortable', 'compact'], dg.density),
        refresh: oneOf(intIn(g.refresh, 1, 3600, dg.refresh), REFRESH, dg.refresh),
        time: oneOf(g.time, ['relative', 'absolute'], dg.time),
        clock: oneOf(g.clock, ['24', '12'], dg.clock),
        bytes: oneOf(g.bytes, ['binary', 'decimal'], dg.bytes),
        compactTables: bool(g.compactTables, dg.compactTables),
        recentRows: intIn(g.recentRows, 5, 50, dg.recentRows),
        auditRows: intIn(g.auditRows, 5, 100, dg.auditRows),
        auditFilter: oneOf(g.auditFilter, ['changes', 'all'], dg.auditFilter),
      },
      layout: {
        order: order(l.order, keys(SECTIONS)),
        hidden: subset(l.hidden, keys(SECTIONS), []),
        split: oneOf(l.split, ['side', 'stacked'], d.layout.split),
      },
      machines: {
        pinned,
        // A pinned machine is meant to be seen.
        hidden: ids(m.hidden).filter((id) => !pinned.includes(id)),
        sort: oneOf(m.sort, SORTS.map((x) => x[0]), dm.sort),
        reverse: bool(m.reverse, dm.reverse),
        onlineFirst: bool(m.onlineFirst, dm.onlineFirst),
        group: oneOf(m.group, GROUPS.map((x) => x[0]), dm.group),
        showOffline: bool(m.showOffline, dm.showOffline),
        density: oneOf(m.density, ['comfortable', 'compact'], dm.density),
        fields: order(m.fields, keys(FIELDS)),
        fieldsHidden: subset(m.fieldsHidden, keys(FIELDS), []),
      },
      charts: {
        order: order(c.order, keys(CHARTS)),
        hidden: subset(c.hidden, keys(CHARTS), dc.hidden),
        range: oneOf(c.range, RANGES, dc.range),
        legend: bool(c.legend, dc.legend),
        columns: intIn(c.columns, 1, 3, dc.columns),
        height: oneOf(c.height, Object.keys(HEIGHTS), dc.height),
        per: Object.fromEntries(CHARTS.map((x) => [x.key, chartOptions(x, obj(c.per)[x.key])])),
      },
      kpis: { order: order(k.order, keys(KPIS)), hidden: subset(k.hidden, keys(KPIS), d.kpis.hidden) },
      balancing: { view: oneOf(b.view, BALANCING_VIEWS.map((x) => x[0]), d.balancing.view) },
    };
  }

  // Settings from before there were any: what the page kept in this browser.
  function fromLegacy(range, auditAll) {
    return normalize({ charts: { range }, general: { auditFilter: auditAll ? 'all' : 'changes' } });
  }

  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

  // The keys of `list` in the order `order` gives, without the hidden ones.
  const shown = (order, hidden) => order.filter((k) => !hidden.includes(k));

  // ------------------------------------------------------- machine order
  const OS_ORDER = ['linux', 'windows', 'macos'];
  const OS_NAME = { linux: 'Linux', windows: 'Windows', macos: 'macOS' };
  const STATUS = [['online', 'Online'], ['draining', 'Draining'], ['unfit', 'Unfit'], ['offline', 'Offline']];

  function statusOf(x) {
    if (!x.online) return 'offline';
    if (x.unfit) return 'unfit';
    if (x.draining) return 'draining';
    return 'online';
  }
  const nameOf = (x) => String(x.name || x.hostname || x.id || '');
  const osOf = (x) => String(x.os || '').toLowerCase();
  const num = (v) => (typeof v === 'number' && isFinite(v) ? v : null);
  function memPct(x) {
    const total = num(x.ram_bytes), free = num(x.free_ram_bytes);
    return total && free != null ? ((total - free) / total) * 100 : null;
  }
  // A sort rule's value for a machine, higher first; null sorts last.
  const SORT_VALUE = {
    cpu: (x) => num(x.cpu_load_percent),
    memory: memPct,
    busy: (x) => num(x.busy_slots),
    free: (x) => num(x.free_slots),
    // Up the longest first.
    uptime: (x) => (x.online && num(x.connected_since) != null ? -x.connected_since : null),
  };
  function osRank(os) {
    const i = OS_ORDER.indexOf(os);
    return i >= 0 ? i : os ? OS_ORDER.length : OS_ORDER.length + 1;
  }
  // `dir` -1 reverses the rule; machines without its value stay last.
  function compareBy(rule, dir) {
    const byName = (a, b) => nameOf(a).localeCompare(nameOf(b));
    if (rule === 'name') return (a, b) => dir * byName(a, b);
    if (rule === 'status') {
      const rank = (x) => STATUS.findIndex((s) => s[0] === statusOf(x));
      return (a, b) => dir * (rank(a) - rank(b) || byName(a, b));
    }
    if (rule === 'os') return (a, b) => dir * (osRank(osOf(a)) - osRank(osOf(b)) || osOf(a).localeCompare(osOf(b)) || byName(a, b));
    const value = SORT_VALUE[rule];
    return (a, b) => {
      const x = value(a), y = value(b);
      if (x == null || y == null) return (x == null) - (y == null) || byName(a, b);
      return dir * (y - x || byName(a, b));
    };
  }

  // The machine cards to show, in groups: `[{ key, label, hosts }]`. Pinned
  // ones first, in their order (their own group when grouping); the rest by
  // the chosen rule. Hidden machines are left out, and offline ones unless
  // shown or pinned; pins of machines not in `hosts` are skipped.
  function arrangeHosts(hosts, ms) {
    const pinAt = new Map(ms.pinned.map((id, i) => [id, i]));
    const hidden = new Set(ms.hidden);
    const list = hosts.filter((x) => !hidden.has(x.id) && (ms.showOffline || x.online || pinAt.has(x.id)));
    const pinned = list.filter((x) => pinAt.has(x.id)).sort((a, b) => pinAt.get(a.id) - pinAt.get(b.id));
    const cmp = compareBy(ms.sort, ms.reverse ? -1 : 1);
    const rest = list.filter((x) => !pinAt.has(x.id)).sort((a, b) =>
      (ms.onlineFirst ? b.online - a.online : 0) || cmp(a, b));
    if (ms.group === 'none') return [{ key: 'all', label: null, hosts: [...pinned, ...rest] }];
    const groups = new Map();
    const keyOf = ms.group === 'os' ? (x) => osOf(x) || 'unknown' : statusOf;
    for (const x of rest) {
      const k = keyOf(x);
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(x);
    }
    const rank = ms.group === 'os' ? (k) => osRank(k === 'unknown' ? '' : k) : (k) => STATUS.findIndex((s) => s[0] === k);
    const label = ms.group === 'os'
      ? (k) => OS_NAME[k] || (k === 'unknown' ? 'Unknown OS' : k)
      : (k) => (STATUS.find((s) => s[0] === k) || [k, k])[1];
    const out = pinned.length ? [{ key: 'pinned', label: 'Pinned', hosts: pinned }] : [];
    for (const k of [...groups.keys()].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b))) {
      out.push({ key: `${ms.group}:${k}`, label: label(k), hosts: groups.get(k) });
    }
    return out;
  }

  const api = {
    VERSION, SECTIONS, KPIS, FIELDS, CHARTS, STYLE_LABEL, BALANCING_VIEWS, RANGES, REFRESH, SORTS, GROUPS, HEIGHTS, MAX_TOP,
    OS_NAME, STATUS, defaults, normalize, fromLegacy, same, shown, arrangeHosts, statusOf,
  };
  root.RMSettings = api;
  if (typeof module === 'object' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
