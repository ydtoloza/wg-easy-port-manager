'use strict';

// Lightweight traffic sampler inspired by ydtoloza/network-dashboard (Go)
// and the Plex bandwidth/CPU/RAM panels.
//
// Sources:
//  - per-peer WireGuard counters from `wg show wg0 dump` (same dump that
//    lib/WireGuard.js parses for transferRx/transferTx). Speeds are derived
//    server-side so every UI client sees identical values.
//  - host interface counters from /proc/net/dev (single read for all ifaces).
//  - CPU/RAM from /proc/stat + /proc/meminfo on linux, os/process fallback
//    elsewhere (Windows test server shows synthetic waves so the UI can be
//    evaluated without WireGuard).
//
// History is an in-memory ring (default 120 samples ≈ 2m at 1s, like Plex)
// plus a best-effort JSON sidecar in WG_PATH for peaks/totals across
// restarts. No new npm dependencies.

const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const Util = require('./Util');

const {
  WG_PATH,
  WG_DEVICE,
  TRAFFIC_POLL_MS,
  TRAFFIC_SAMPLES,
} = require('../config');

const RANGE_TO_POINTS = {
  '2m': 120,
  '1h': 120,
  '24h': 144,
  '30d': 180,
};

// Port of network-dashboard computeSpeeds: counter resets (reboots,
// interface restarts) never produce negative speeds.
function computeSpeeds(prevRx, prevTx, prevTs, curRx, curTx, now) {
  if (now <= prevTs) return { rxSpeed: 0, txSpeed: 0 };
  const dt = now - prevTs;
  let rxSpeed = 0;
  let txSpeed = 0;
  if (curRx >= prevRx) rxSpeed = ((curRx - prevRx) * 1000) / dt;
  if (curTx >= prevTx) txSpeed = ((curTx - prevTx) * 1000) / dt;
  return { rxSpeed, txSpeed };
}

function appendCapped(history, sample, cap) {
  history.push(sample);
  if (history.length > cap) history.splice(0, history.length - cap);
  return history;
}

async function readProcNetDev() {
  const raw = await fs.readFile('/proc/net/dev', 'utf8');
  const counters = {};
  for (const line of raw.split('\n')) {
    const sep = line.indexOf(':');
    if (sep < 0) continue;
    const fields = line.slice(sep + 1).trim().split(/\s+/);
    if (fields.length < 9) continue;
    const rx = Number(fields[0]);
    const tx = Number(fields[8]);
    if (!Number.isFinite(rx) || !Number.isFinite(tx)) continue;
    counters[line.slice(0, sep).trim()] = { rx, tx };
  }
  return counters;
}

async function readCpuMemLinux(prevCpu) {
  let cpuPercent = null;
  try {
    const stat = await fs.readFile('/proc/stat', 'utf8');
    const line = stat.split('\n').find((l) => l.startsWith('cpu '));
    if (line) {
      const parts = line.trim().split(/\s+/).slice(1).map(Number);
      const idle = (parts[3] || 0) + (parts[4] || 0);
      const total = parts.reduce((a, b) => a + (Number.isFinite(b) ? b : 0), 0);
      if (prevCpu && total > prevCpu.total) {
        const totalDelta = total - prevCpu.total;
        const idleDelta = idle - prevCpu.idle;
        cpuPercent = Math.max(0, Math.min(100, ((totalDelta - idleDelta) / totalDelta) * 100));
      }
      prevCpu.total = total;
      prevCpu.idle = idle;
    }
  } catch {
    // best-effort
  }
  let memPercent = null;
  let memUsed = null;
  let memTotal = null;
  try {
    const meminfo = await fs.readFile('/proc/meminfo', 'utf8');
    const get = (key) => {
      const m = meminfo.match(new RegExp(`^${key}:\\s+(\\d+)`, 'm'));
      return m ? Number(m[1]) * 1024 : null;
    };
    memTotal = get('MemTotal');
    const avail = get('MemAvailable');
    if (memTotal && avail !== null) {
      memUsed = memTotal - avail;
      memPercent = (memUsed / memTotal) * 100;
    }
  } catch {
    // best-effort
  }
  return {
    cpuPercent, memPercent, memUsed, memTotal, prevCpu,
  };
}

function synthWave(t, periodMs, base, amp, phase = 0) {
  // Deterministic waves so the local demo looks like the Plex screenshots:
  // mostly flat with periodic spikes.
  const s = Math.sin(((t / periodMs) * 2 * Math.PI) + phase);
  const spike = (Math.max(0, Math.sin((t / (periodMs * 7)) + phase))) ** 24;
  return Math.max(0, base + (s * amp * 0.15) + (spike * amp));
}

module.exports = class TrafficStats {

  constructor({
    pollMs = TRAFFIC_POLL_MS,
    samples = TRAFFIC_SAMPLES,
    wgDevice = WG_DEVICE,
    wgPath = WG_PATH,
    now = Date.now,
  } = {}) {
    this.pollMs = Math.min(10000, Math.max(500, Number(pollMs) || 1000));
    this.cap = Math.min(600, Math.max(30, Number(samples) || 120));
    this.wgDevice = wgDevice || 'eth0';
    this.wgPath = wgPath;
    this.now = now;
    this.timer = null;
    this.tickInFlight = false;
    this.lastTickAt = 0;
    this.prevPeerCounters = new Map(); // publicKey -> { rx, tx, ts }
    this.prevIfaceCounters = new Map(); // name -> { rx, tx, ts }
    this.prevCpu = { total: 0, idle: 0 };
    this.prevProcCpu = null;
    // Rolling realtime windows (Plex "Tiempo Real", 2m).
    this.ifaceHistory = new Map(); // name -> [{ t, rx, tx }]
    this.peerSpeeds = new Map(); // publicKey -> { rxSpeed, txSpeed, rx, tx }
    this.cpuHistory = [];
    this.memHistory = [];
    this.procCpuHistory = [];
    this.procMemHistory = [];
    this.peaks = {
      rxSpeed: 0, txSpeed: 0, cpu: 0, mem: 0,
    };
    // When each directional peak was seen (ms epoch, 0 = not seen yet).
    // Persisted with peaks so "historic peak" survives restarts.
    this.peakAt = { rxSpeed: 0, txSpeed: 0 };
    this.totals = { rxBytes: 0, txBytes: 0 };
    // Long-retention aggregates for the 1h/24h/30d views (the realtime
    // ring above only covers ~2m). Per-minute averages (cap 1440 = 24h)
    // roll up into per-hour averages (cap 720 = 30d). Bounded plain
    // arrays of {t, rx, tx, cpu, pcpu, mem, pmem}; persisted with the
    // sidecar so history survives restarts.
    this.minuteAcc = null;
    this.minutes = [];
    this.hourAcc = null;
    this.hours = [];
    this.startedAt = this.now();
    this.persistAt = 0;
  }

  start() {
    if (this.timer) return;
    // First tick ASAP so the dashboard paints instantly; failures are
    // swallowed (best-effort sampler must never take the panel down).
    this.tick().catch(() => {});
    this.timer = setInterval(() => {
      this.tick().catch(() => {});
    }, this.pollMs);
    if (typeof this.timer.unref === 'function') this.timer.unref();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async tick() {
    if (this.tickInFlight) return;
    this.tickInFlight = true;
    try {
      const now = this.now();
      if (process.platform !== 'linux') {
        this.tickSynthetic(now);
      } else {
        await this.tickLinux(now);
      }
      this.lastTickAt = now;
      // Persist peaks/totals at most every 30s (atomic write, best-effort).
      if (now - this.persistAt > 30000) {
        this.persistAt = now;
        await this.save().catch(() => {});
      }
    } finally {
      this.tickInFlight = false;
    }
  }

  tickSynthetic(now) {
    // Demo traffic so the UI can be evaluated on Windows/macOS without
    // WireGuard: one "wg0" aggregate + host device + 2 fake peers.
    const wgRx = synthWave(now, 20000, 2200, 9000);
    const wgTx = synthWave(now, 26000, 900, 4200, 1.3);
    this.recordIface('wg0', wgRx, wgTx, now);
    this.recordIface(this.wgDevice, wgRx * 1.12, wgTx * 1.08, now);
    this.peerSpeeds.set('demo-peer-1', {
      rxSpeed: wgRx * 0.6, txSpeed: wgTx * 0.6, rx: 0, tx: 0, name: 'demo-1',
    });
    this.peerSpeeds.set('demo-peer-2', {
      rxSpeed: wgRx * 0.4, txSpeed: wgTx * 0.4, rx: 0, tx: 0, name: 'demo-2',
    });
    const cpu = Math.min(100, synthWave(now, 45000, 2.4, 6, 0.5));
    const procCpu = Math.min(100, synthWave(now, 45000, 0.14, 0.6, 2.1));
    const mem = 14.99 + (Math.sin(now / 90000) * 0.05);
    const procMem = 5.4 + (Math.sin((now / 120000) + 1) * 0.05);
    this.recordSystem(cpu, procCpu, mem, procMem, now);
  }

  async tickLinux(now) {
    // 1) per-peer counters from wg dump (same source as getClients).
    try {
      const dump = await Util.exec('wg show wg0 dump', { log: false });
      const lines = String(dump || '').trim().split('\n').slice(1);
      let aggRx = 0;
      let aggTx = 0;
      for (const line of lines) {
        if (!line) continue;
        const parts = line.split('\t');
        if (parts.length < 7) continue;
        const [publicKey] = parts;
        const rx = Number(parts[5]);
        const tx = Number(parts[6]);
        if (!Number.isFinite(rx) || !Number.isFinite(tx)) continue;
        const prev = this.prevPeerCounters.get(publicKey);
        let rxSpeed = 0;
        let txSpeed = 0;
        if (prev) {
          ({ rxSpeed, txSpeed } = computeSpeeds(prev.rx, prev.tx, prev.ts, rx, tx, now));
        }
        this.prevPeerCounters.set(publicKey, { rx, tx, ts: now });
        this.peerSpeeds.set(publicKey, {
          rxSpeed, txSpeed, rx, tx,
        });
        aggRx += rxSpeed;
        aggTx += txSpeed;
      }
      this.recordIface('wg0', aggRx, aggTx, now);
    } catch {
      // wg0 may be down during tests; keep previous history.
    }

    // 2) host counters for WG_DEVICE (+ wg0 bytes as cross-check).
    try {
      const counters = await readProcNetDev();
      for (const name of [this.wgDevice, 'wg0']) {
        const cur = counters[name];
        if (!cur) continue;
        const prev = this.prevIfaceCounters.get(name);
        if (prev) {
          const { rxSpeed, txSpeed } = computeSpeeds(prev.rx, prev.tx, prev.ts, cur.rx, cur.tx, now);
          if (name !== 'wg0') this.recordIface(name, rxSpeed, txSpeed, now);
        }
        this.prevIfaceCounters.set(name, { rx: cur.rx, tx: cur.tx, ts: now });
      }
    } catch {
      // best-effort
    }

    // 3) CPU/RAM.
    try {
      const { cpuPercent, memPercent } = await readCpuMemLinux(this.prevCpu);
      const mem = os.totalmem() ? ((os.totalmem() - os.freemem()) / os.totalmem()) * 100 : memPercent;
      const procMemMb = process.memoryUsage().rss / 1024 / 1024;
      const procMemPct = os.totalmem() ? (process.memoryUsage().rss / os.totalmem()) * 100 : null;
      // process cpu% from cpuUsage deltas.
      let procCpu = null;
      const curProc = process.cpuUsage();
      if (this.prevProcCpu) {
        const userDelta = curProc.user - this.prevProcCpu.usage.user;
        const sysDelta = curProc.system - this.prevProcCpu.usage.system;
        const timeDelta = now - this.prevProcCpu.ts;
        if (timeDelta > 0) procCpu = Math.max(0, Math.min(100, (((userDelta + sysDelta) / 1000) / timeDelta) * 100));
      }
      this.prevProcCpu = { usage: curProc, ts: now };
      this.recordSystem(cpuPercent, procCpu, memPercent ?? mem, procMemPct ?? procMemMb, now);
    } catch {
      // best-effort
    }
  }

  recordIface(name, rxSpeed, txSpeed, now) {
    // recordIface always stores speeds (bytes/sec). Linux wg0 aggregate and
    // /proc paths already arrive as speeds; synthetic path too.
    const rx = Math.max(0, Number(rxSpeed) || 0);
    const tx = Math.max(0, Number(txSpeed) || 0);
    if (!this.ifaceHistory.has(name)) this.ifaceHistory.set(name, []);
    appendCapped(this.ifaceHistory.get(name), { t: now, rx, tx }, this.cap);
    if (name === 'wg0') {
      if (rx > this.peaks.rxSpeed) {
        this.peaks.rxSpeed = rx;
        this.peakAt.rxSpeed = now;
      }
      if (tx > this.peaks.txSpeed) {
        this.peaks.txSpeed = tx;
        this.peakAt.txSpeed = now;
      }
      // Totals accumulate bytes from speeds.
      const dt = this.lastTickAt ? (now - this.lastTickAt) / 1000 : this.pollMs / 1000;
      this.totals.rxBytes += rx * dt;
      this.totals.txBytes += tx * dt;
      // Long-retention rollups (n counts ticks so averages stay true).
      const acc = this.bucketFor(now);
      acc.rx += rx;
      acc.tx += tx;
      acc.n += 1;
    }
  }

  recordSystem(cpu, procCpu, mem, procMem, now) {
    const c = cpu === null || cpu === undefined ? 0 : Number(cpu);
    const pc = procCpu === null || procCpu === undefined ? 0 : Number(procCpu);
    const m = mem === null || mem === undefined ? 0 : Number(mem);
    const pm = procMem === null || procMem === undefined ? 0 : Number(procMem);
    appendCapped(this.cpuHistory, { t: now, v: c }, this.cap);
    appendCapped(this.procCpuHistory, { t: now, v: pc }, this.cap);
    appendCapped(this.memHistory, { t: now, v: m }, this.cap);
    appendCapped(this.procMemHistory, { t: now, v: pm }, this.cap);
    if (c > this.peaks.cpu) this.peaks.cpu = c;
    if (m > this.peaks.mem) this.peaks.mem = m;
    const acc = this.bucketFor(now);
    acc.cpu += c;
    acc.pcpu += pc;
    acc.mem += m;
    acc.pmem += pm;
  }

  // Current per-minute accumulator, closing and rolling up finished
  // minutes (and hours) as time advances. recordIface feeds rx/tx and
  // recordSystem feeds the rest; both run once per tick so dividing by n
  // yields true per-minute averages.
  bucketFor(now) {
    const minute = Math.floor(now / 60000) * 60000;
    if (!this.minuteAcc || this.minuteAcc.t !== minute) {
      if (this.minuteAcc) this.closeMinute(this.minuteAcc);
      this.minuteAcc = {
        t: minute, rx: 0, tx: 0, cpu: 0, pcpu: 0, mem: 0, pmem: 0, n: 0,
      };
    }
    return this.minuteAcc;
  }

  closeMinute(acc) {
    if (!acc.n) return;
    const avg = {
      t: acc.t,
      rx: acc.rx / acc.n,
      tx: acc.tx / acc.n,
      cpu: acc.cpu / acc.n,
      pcpu: acc.pcpu / acc.n,
      mem: acc.mem / acc.n,
      pmem: acc.pmem / acc.n,
    };
    appendCapped(this.minutes, avg, 1440);
    const hour = Math.floor(acc.t / 3600000) * 3600000;
    if (!this.hourAcc || this.hourAcc.t !== hour) {
      if (this.hourAcc) this.closeHour(this.hourAcc);
      this.hourAcc = {
        t: hour, rx: 0, tx: 0, cpu: 0, pcpu: 0, mem: 0, pmem: 0, n: 0,
      };
    }
    this.hourAcc.rx += avg.rx;
    this.hourAcc.tx += avg.tx;
    this.hourAcc.cpu += avg.cpu;
    this.hourAcc.pcpu += avg.pcpu;
    this.hourAcc.mem += avg.mem;
    this.hourAcc.pmem += avg.pmem;
    this.hourAcc.n += 1;
  }

  closeHour(acc) {
    if (!acc.n) return;
    appendCapped(this.hours, {
      t: acc.t,
      rx: acc.rx / acc.n,
      tx: acc.tx / acc.n,
      cpu: acc.cpu / acc.n,
      pcpu: acc.pcpu / acc.n,
      mem: acc.mem / acc.n,
      pmem: acc.pmem / acc.n,
    }, 720);
  }

  snapshotIface(name) {
    const hist = this.ifaceHistory.get(name) || [];
    const last = hist.length ? hist[hist.length - 1] : { rx: 0, tx: 0, t: this.now() };
    const avg = (key) => (hist.length ? hist.reduce((a, s) => a + s[key], 0) / hist.length : 0);
    const peak = (key) => (hist.length ? Math.max(...hist.map((s) => s[key])) : 0);
    return {
      name,
      rxSpeed: last.rx,
      txSpeed: last.tx,
      avgRx: avg('rx'),
      avgTx: avg('tx'),
      peakRx: peak('rx'),
      peakTx: peak('tx'),
      timestamp: last.t,
    };
  }

  getRealtime() {
    const ifaces = [];
    const names = new Set([...this.ifaceHistory.keys(), 'wg0', this.wgDevice]);
    for (const name of names) ifaces.push(this.snapshotIface(name));
    const peers = [...this.peerSpeeds.entries()].map(([id, s]) => ({
      id, rxSpeed: s.rxSpeed || 0, txSpeed: s.txSpeed || 0,
    }));
    const totalRx = peers.reduce((a, p) => a + p.rxSpeed, 0);
    const totalTx = peers.reduce((a, p) => a + p.txSpeed, 0);
    const lastCpu = this.cpuHistory.length ? this.cpuHistory[this.cpuHistory.length - 1].v : 0;
    const lastProcCpu = this.procCpuHistory.length ? this.procCpuHistory[this.procCpuHistory.length - 1].v : 0;
    const lastMem = this.memHistory.length ? this.memHistory[this.memHistory.length - 1].v : 0;
    const lastProcMem = this.procMemHistory.length ? this.procMemHistory[this.procMemHistory.length - 1].v : 0;
    return {
      generatedAt: this.now(),
      pollMs: this.pollMs,
      interfaces: ifaces,
      peers,
      totals: { rxSpeed: totalRx, txSpeed: totalTx },
      history: {
        wg0: this.ifaceHistory.get('wg0') || [],
        [this.wgDevice]: this.ifaceHistory.get(this.wgDevice) || [],
      },
      cpu: {
        system: lastCpu, process: lastProcCpu, history: this.cpuHistory, procHistory: this.procCpuHistory,
      },
      mem: {
        system: lastMem, process: lastProcMem, history: this.memHistory, procHistory: this.procMemHistory,
      },
      peaks: { ...this.peaks },
      peakAt: { ...this.peakAt },
    };
  }

  getHistory(range = '2m') {
    const points = RANGE_TO_POINTS[range] || this.cap;
    const slice = (arr) => (arr.length <= points ? [...arr] : arr.slice(arr.length - points));
    if (range === '1h' || range === '24h' || range === '30d') {
      const src = range === '30d' ? this.hours : this.minutes;
      const window = range === '1h' ? src.slice(-60) : [...src];
      return {
        range,
        wg0: window.map((s) => ({ t: s.t, rx: s.rx, tx: s.tx })),
        cpu: window.map((s) => ({ t: s.t, v: s.cpu })),
        procCpu: window.map((s) => ({ t: s.t, v: s.pcpu })),
        mem: window.map((s) => ({ t: s.t, v: s.mem })),
        procMem: window.map((s) => ({ t: s.t, v: s.pmem })),
      };
    }
    return {
      range,
      wg0: slice(this.ifaceHistory.get('wg0') || []),
      cpu: slice(this.cpuHistory),
      procCpu: slice(this.procCpuHistory),
      mem: slice(this.memHistory),
      procMem: slice(this.procMemHistory),
    };
  }

  getSummary() {
    const wg0 = this.ifaceHistory.get('wg0') || [];
    const avg = (key) => (wg0.length ? wg0.reduce((a, s) => a + s[key], 0) / wg0.length : 0);
    return {
      generatedAt: this.now(),
      uptimeMs: this.now() - this.startedAt,
      totals: { ...this.totals },
      avgRx: avg('rx'),
      avgTx: avg('tx'),
      peaks: { ...this.peaks },
      peakAt: { ...this.peakAt },
      samples: wg0.length,
    };
  }

  async save() {
    if (!this.wgPath) return;
    try {
      const target = path.join(this.wgPath, 'traffic-history.json');
      const payload = JSON.stringify({
        peaks: this.peaks,
        peakAt: this.peakAt,
        totals: this.totals,
        minutes: this.minutes.slice(-1440),
        hours: this.hours.slice(-720),
        savedAt: this.now(),
      });
      const tmp = `${target}.${Date.now()}.tmp`;
      await fs.writeFile(tmp, payload, { mode: 0o600 });
      await fs.rename(tmp, target);
    } catch {
      // best-effort: e.g. WG_PATH missing on Windows demo.
    }
  }

  async load() {
    if (!this.wgPath) return;
    try {
      const raw = await fs.readFile(path.join(this.wgPath, 'traffic-history.json'), 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        if (parsed.peaks) this.peaks = { ...this.peaks, ...parsed.peaks };
        if (parsed.peakAt) this.peakAt = { ...this.peakAt, ...parsed.peakAt };
        if (parsed.totals) this.totals = { ...this.totals, ...parsed.totals };
        if (Array.isArray(parsed.minutes)) this.minutes = parsed.minutes.slice(-1440);
        if (Array.isArray(parsed.hours)) this.hours = parsed.hours.slice(-720);
      }
    } catch {
      // missing file on first boot is normal.
    }
  }

};

module.exports.computeSpeeds = computeSpeeds;
module.exports.appendCapped = appendCapped;
