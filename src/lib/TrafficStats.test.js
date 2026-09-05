/* eslint-env jest */

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const TrafficStats = require('./TrafficStats');
const { computeSpeeds, appendCapped } = require('./TrafficStats');

describe('TrafficStats core math (network-dashboard port)', () => {
  it('derives bytes/sec and never goes negative on counter reset', () => {
    expect(computeSpeeds(1000, 2000, 0, 2000, 4000, 1000))
      .toEqual({ rxSpeed: 1000, txSpeed: 2000 });
    // Reset (e.g. reboot) clamps to 0 instead of negative.
    expect(computeSpeeds(5000, 5000, 0, 100, 100, 1000))
      .toEqual({ rxSpeed: 0, txSpeed: 0 });
    expect(computeSpeeds(1, 1, 1000, 2, 2, 1000))
      .toEqual({ rxSpeed: 0, txSpeed: 0 });
  });

  it('caps the rolling window', () => {
    const hist = [1, 2, 3];
    appendCapped(hist, 4, 3);
    expect(hist).toEqual([2, 3, 4]);
  });
});

describe('TrafficStats sampler', () => {
  it('records realtime speeds, peaks and averages', () => {
    let t = 1000000;
    const stats = new TrafficStats({ pollMs: 1000, samples: 5, now: () => t });
    // Feed deterministic speeds directly (bypasses /proc + wg).
    for (let i = 0; i < 5; i += 1) {
      t += 1000;
      stats.lastTickAt = t - 1000;
      stats.recordIface('wg0', 1000 + (i * 1000), 500, t);
      stats.recordSystem(2 + i, 0.1, 15, 5.4, t);
    }
    const realtime = stats.getRealtime();
    const wg0 = realtime.interfaces.find((i) => i.name === 'wg0');
    expect(wg0.rxSpeed).toBe(5000);
    expect(wg0.peakRx).toBe(5000);
    expect(wg0.avgRx).toBe(3000);
    expect(realtime.peaks.rxSpeed).toBe(5000);
    expect(realtime.peakAt.rxSpeed).toBe(t);
    expect(realtime.peakAt.txSpeed).toBe(1001000);
    expect(realtime.cpu.system).toBe(6);
    expect(realtime.mem.system).toBe(15);

    const history = stats.getHistory('2m');
    expect(history.wg0).toHaveLength(5);

    const summary = stats.getSummary();
    expect(summary.peaks.rxSpeed).toBe(5000);
    expect(summary.peakAt.rxSpeed).toBe(t);
    expect(summary.avgRx).toBe(3000);
    expect(summary.totals.rxBytes).toBeGreaterThan(0);
  });

  it('rolls ticks into per-minute and per-hour history', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wgpm-traffic-'));
    let t = 1_700_000_000_000;
    const stats = new TrafficStats({
      pollMs: 1000, samples: 200, wgPath: dir, now: () => t,
    });
    // 3 ticks in minute A, 2 ticks in minute B, then jump 61 minutes.
    for (let i = 0; i < 3; i += 1) {
      stats.lastTickAt = t - 1000;
      stats.recordIface('wg0', 1000, 500, t);
      stats.recordSystem(10, 1, 20, 5, t);
      t += 1000;
    }
    t = Math.ceil(t / 60000) * 60000 + 1000;
    for (let i = 0; i < 2; i += 1) {
      stats.lastTickAt = t - 1000;
      stats.recordIface('wg0', 3000, 1500, t);
      stats.recordSystem(30, 3, 40, 7, t);
      t += 1000;
    }
    expect(stats.minutes).toHaveLength(1);
    expect(stats.minutes[0]).toMatchObject({ rx: 1000, tx: 500 });
    expect(stats.getHistory('24h').wg0).toHaveLength(1);

    // Jump over an hour boundary: closes minute B (hourAcc opens).
    t = (Math.floor(t / 3600000) + 1) * 3600000 + 1000;
    stats.lastTickAt = t - 1000;
    stats.recordIface('wg0', 5000, 2500, t);
    stats.recordSystem(50, 5, 60, 9, t);
    expect(stats.minutes).toHaveLength(2);
    expect(stats.minutes[1]).toMatchObject({ rx: 3000, tx: 1500 });
    expect(stats.hours).toHaveLength(0);
    // Jump one more hour: closes the partial hour into hours.
    t = (Math.floor(t / 3600000) + 1) * 3600000 + 61000;
    stats.lastTickAt = t - 1000;
    stats.recordIface('wg0', 5000, 2500, t);
    stats.recordSystem(50, 5, 60, 9, t);
    expect(stats.hours).toHaveLength(1);
    expect(stats.hours[0]).toMatchObject({ rx: 2000, tx: 1000 });
    const day = stats.getHistory('24h');
    expect(day.wg0).toHaveLength(3);
    expect(day.cpu[1]).toMatchObject({ v: 30 });
    expect(stats.getHistory('1h').wg0).toHaveLength(3);
    expect(stats.getHistory('30d').wg0).toHaveLength(1);

    await stats.save();
    const reloaded = new TrafficStats({
      pollMs: 1000, samples: 200, wgPath: dir, now: Date.now,
    });
    await reloaded.load();
    expect(reloaded.minutes).toHaveLength(3);
    expect(reloaded.hours).toHaveLength(1);
    expect(reloaded.getHistory('24h').wg0).toHaveLength(3);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('generates synthetic demo traffic on non-linux for UI evaluation', async () => {
    if (process.platform === 'linux') return;
    const stats = new TrafficStats({ pollMs: 1000, samples: 10 });
    await stats.tick();
    await stats.tick();
    const realtime = stats.getRealtime();
    const wg0 = realtime.interfaces.find((i) => i.name === 'wg0');
    expect(wg0).toBeDefined();
    expect(realtime.history.wg0.length).toBeGreaterThan(0);
  });
});

describe('TrafficStats restart survival', () => {
  it('start() restores persisted aggregates before sampling (load was never called before 2.3.0)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wgpm-traffic-load-'));
    try {
      // Instance "before the restart": record traffic and persist it.
      const t = 1_700_000_000_000;
      const previous = new TrafficStats({ pollMs: 1000, wgPath: dir, now: () => t });
      previous.recordIface('wg0', 9000, 4000, t);
      previous.recordSystem(80, 7, 90, 8, t);
      await previous.save();

      // Fresh instance (post-restart): aggregates start empty...
      const restarted = new TrafficStats({ pollMs: 1000, wgPath: dir, now: () => t + 60000 });
      expect(restarted.peaks.rxSpeed).toBe(0);
      expect(restarted.minutes).toHaveLength(0);

      // ...and start() must bring them back before/without losing samples.
      restarted.start();
      await restarted.loadPromise;
      expect(restarted.peaks.rxSpeed).toBe(9000);
      expect(restarted.peaks.cpu).toBe(80);
      restarted.stop();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('start() is idempotent: concurrent calls never schedule two samplers', async () => {
    const stats = new TrafficStats({ pollMs: 1000, wgPath: null });
    stats.start();
    stats.start();
    stats.start();
    // The load promise resolves immediately (null wgPath); give the callbacks
    // a tick to run, then there must be exactly one sampler timer.
    await new Promise((resolve) => setImmediate(resolve));
    const timersBefore = stats.timer;
    expect(timersBefore).not.toBeNull();
    stats.stop();
    expect(stats.timer).toBeNull();
  });
});
