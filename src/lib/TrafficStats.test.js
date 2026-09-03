/* eslint-env jest */

'use strict';

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
