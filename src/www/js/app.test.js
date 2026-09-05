/* eslint-env jest */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const localStorageMock = {
  getItem: jest.fn(() => null),
  setItem: jest.fn(),
  theme: 'auto',
};

function loadAppOptions() {
  let options;
  const context = {
    API: function API() {},
    Vue: function Vue(value) {
      options = value;
    },
    VueApexCharts: {},
    VueI18n: function VueI18n(value) {
      return value;
    },
    clearTimeout,
    console,
    document: {},
    localStorage: localStorageMock,
    messages: {},
    setTimeout,
    timeago: {},
    window: {
      WgEasyAppTemplate: { render: jest.fn(), staticRenderFns: [] },
      matchMedia: jest.fn(() => ({ matches: false })),
    },
  };
  const source = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
  vm.runInNewContext(source, context);
  return options;
}

function client() {
  return {
    id: 'client1',
    name: 'client1',
    enabled: true,
    transferRx: 0,
    transferTx: 0,
    portForwards: [{
      id: 'rule1', proto: 'tcp', extPort: 8080, intPort: 80,
    }],
  };
}

describe('port-forward UI state', () => {
  afterEach(() => jest.useRealTimers());

  it('fails closed until server config explicitly enables forwarding', async () => {
    const options = loadAppOptions();
    expect(options.data.forwardingEnabled).toBe(false);

    const state = {
      ...options.data,
      authenticated: true,
      forwardingEnabled: true,
      api: {
        getClients: jest.fn().mockResolvedValue([]),
        getServerConfig: jest.fn().mockRejectedValue(new Error('unavailable')),
      },
      scheduleAutoProbe: jest.fn(),
    };

    await options.methods.refresh.call(state);

    expect(state.forwardingEnabled).toBe(false);
  });

  it('schedules a probe when forwarding transitions to enabled', async () => {
    const options = loadAppOptions();
    const currentClient = client();
    const signature = JSON.stringify([[
      currentClient.id,
      currentClient.enabled,
      currentClient.portForwards.map((rule) => [rule.id, rule.proto, rule.extPort, rule.intPort]),
    ]]);
    const state = {
      ...options.data,
      authenticated: true,
      clients: [currentClient],
      forwardingEnabled: false,
      lastPfSignature: signature,
      api: {
        getClients: jest.fn().mockResolvedValue([currentClient]),
        getServerConfig: jest.fn().mockResolvedValue({ forwardingEnabled: true }),
      },
      scheduleAutoProbe: jest.fn(),
      $set(target, key, value) {
        target[key] = value;
      },
    };

    await options.methods.refresh.call(state);

    expect(state.forwardingEnabled).toBe(true);
    expect(state.scheduleAutoProbe).toHaveBeenCalledTimes(1);
  });

  it('schedules only when a client section becomes expanded', () => {
    const options = loadAppOptions();
    const state = {
      expandedPfClients: {},
      scheduleAutoProbe: jest.fn(),
      persistPfExpanded: jest.fn(),
      $set(target, key, value) {
        target[key] = value;
      },
    };

    options.methods.togglePfExpanded.call(state, 'client1');
    options.methods.togglePfExpanded.call(state, 'client1');

    expect(state.scheduleAutoProbe).toHaveBeenCalledTimes(1);
    expect(state.persistPfExpanded).toHaveBeenCalledTimes(2);
  });

  it('re-arms one debounce timer instead of stacking probes', () => {
    jest.useFakeTimers();
    const options = loadAppOptions();
    const state = {
      forwardingEnabled: true,
      autoProbeTimer: null,
      runAutoProbe: jest.fn().mockResolvedValue(),
    };

    options.methods.scheduleAutoProbe.call(state);
    options.methods.scheduleAutoProbe.call(state);
    jest.advanceTimersByTime(2000);

    expect(state.runAutoProbe).toHaveBeenCalledTimes(1);
  });

  it('keeps the per-rule rate limit across repeated auto-probe runs', async () => {
    const options = loadAppOptions();
    const probePortForward = jest.fn().mockResolvedValue({ verdict: 'ok' });
    const state = {
      forwardingEnabled: true,
      clients: [client()],
      expandedPfClients: { client1: true },
      lastProbeAt: {},
      lastProbeVerdict: {},
      api: { probePortForward },
      isPfExpanded: options.methods.isPfExpanded,
      notify: jest.fn(),
      $t: jest.fn(),
      $set(target, key, value) {
        target[key] = value;
      },
    };

    await options.methods.runAutoProbe.call(state);
    await options.methods.runAutoProbe.call(state);

    expect(probePortForward).toHaveBeenCalledTimes(1);
    expect(state.lastProbeVerdict['client1:rule1']).toEqual(expect.objectContaining({ verdict: 'ok' }));
  });

  it('does not alert for protocol-indeterminate probe results', async () => {
    const options = loadAppOptions();
    const state = {
      forwardingEnabled: true,
      clients: [{
        ...client(),
        portForwards: [{
          id: 'rule1', proto: 'udp', extPort: 8080, intPort: 80,
        }],
      }],
      expandedPfClients: { client1: true },
      lastProbeAt: {},
      lastProbeVerdict: {},
      api: {
        probePortForward: jest.fn().mockResolvedValue({ verdict: 'indeterminate' }),
      },
      isPfExpanded: options.methods.isPfExpanded,
      notify: jest.fn(),
      $t: jest.fn(),
      $set(target, key, value) {
        target[key] = value;
      },
    };

    await options.methods.runAutoProbe.call(state);

    expect(state.notify).not.toHaveBeenCalled();
  });

  it('stays quiet for offline peers and notifies once per verdict change', async () => {
    const options = loadAppOptions();
    const api = { probePortForward: jest.fn().mockResolvedValue({ verdict: 'tunnel-down' }) };
    const state = {
      forwardingEnabled: true,
      clients: [client()],
      expandedPfClients: { client1: true },
      lastProbeAt: {},
      lastProbeVerdict: {},
      api,
      isPfExpanded: options.methods.isPfExpanded,
      notify: jest.fn(),
      $t: jest.fn((key) => key),
      $set(target, key, value) {
        target[key] = value;
      },
    };

    await options.methods.runAutoProbe.call(state);
    expect(state.notify).not.toHaveBeenCalled();

    api.probePortForward.mockResolvedValue({ verdict: 'unreachable' });
    state.lastProbeAt = {};
    await options.methods.runAutoProbe.call(state);
    expect(state.notify).toHaveBeenCalledTimes(1);

    state.lastProbeAt = {};
    await options.methods.runAutoProbe.call(state);
    expect(state.notify).toHaveBeenCalledTimes(1);

    api.probePortForward.mockResolvedValue({ verdict: 'ok' });
    state.lastProbeAt = {};
    await options.methods.runAutoProbe.call(state);
    expect(state.notify).toHaveBeenCalledTimes(1);
  });
});

describe('traffic side panel', () => {
  it('hides the panel by default and toggles with persistence', () => {
    const options = loadAppOptions();
    expect(options.data.uiShowTraffic).toBe(false);

    localStorageMock.setItem.mockClear();
    const state = {
      uiShowTraffic: false,
      refreshTraffic: jest.fn().mockResolvedValue(),
    };
    options.methods.toggleTraffic.call(state);
    expect(state.uiShowTraffic).toBe(true);
    expect(localStorageMock.setItem).toHaveBeenCalledWith('uiShowTraffic', '1');
    expect(state.refreshTraffic).toHaveBeenCalledTimes(1);
  });

  it('auto-shows the panel when UI_TRAFFIC_STATS is on and no pref stored', async () => {
    const options = loadAppOptions();
    const state = {
      ...options.data,
      api: {
        getSession: jest.fn().mockResolvedValue({ authenticated: false, requiresPassword: true }),
        getUiTrafficStats: jest.fn().mockResolvedValue(true),
        getChartType: jest.fn().mockResolvedValue(0),
        getLang: jest.fn().mockResolvedValue(null),
      },
      refresh: jest.fn().mockResolvedValue(),
      schedulePoll: jest.fn(),
    };
    await options.methods.initialize.call(state);
    expect(state.uiTrafficStats).toBe(true);
    expect(state.uiShowTraffic).toBe(true);
    expect(state.refresh).not.toHaveBeenCalled();
  });

  it('builds bandwidth series, peaks and totals text', () => {
    const options = loadAppOptions();
    const bw = [{ t: 1, rx: 1000, tx: 500 }, { t: 2, rx: 3000, tx: 1500 }];
    const state = {
      traffic: { history: { wg0: bw } },
      trafficBw: bw,
      trafficSummary: null,
    };
    expect(options.computed.trafficBw.call(state)).toHaveLength(2);
    expect(options.computed.trafficBwSeries.call(state)).toEqual([
      { name: 'REMOTO (RX)', data: [{ x: 1, y: 1000 }, { x: 2, y: 3000 }] },
      { name: 'LOCAL (TX)', data: [{ x: 1, y: 500 }, { x: 2, y: 1500 }] },
    ]);
    const peak = options.computed.trafficPeak.call(state);
    expect(peak).toEqual({ rx: 3000, tx: 1500 });
    expect(options.computed.trafficPeakMax.call({ ...state, trafficPeak: peak })).toBe(3000);
    expect(options.methods.fmtBytes()).toBe('-');
    expect(options.methods.fmtBytes(0)).toBe('0 B');
    expect(options.methods.fmtBytes(1536)).toBe('1.5 KB');
    expect(options.methods.fmtSpeed(1500)).toBe('1.5 KB/s');
  });

  it('prefers the range snapshot over realtime while a historic range is active', async () => {
    const options = loadAppOptions();
    const snapshot = {
      range: '24h',
      wg0: [{ t: 1, rx: 7000, tx: 700 }],
      cpu: [{ t: 1, v: 50 }],
      procCpu: [{ t: 1, v: 5 }],
      mem: [{ t: 1, v: 60 }],
      procMem: [{ t: 1, v: 6 }],
    };
    const state = {
      trafficRange: '24h',
      trafficRangeData: snapshot,
      trafficRangeAt: 0,
      traffic: { history: { wg0: [{ t: 2, rx: 100, tx: 10 }] } },
      api: { getTrafficHistory: jest.fn() },
    };
    expect(options.computed.trafficBw.call(state)).toEqual(snapshot.wg0);
    expect(options.computed.trafficAvg.call({ ...state, trafficBw: snapshot.wg0 })).toEqual({ rx: 7000, tx: 700 });
    expect(options.computed.trafficCpuSeries.call(state)[0].data).toEqual([{ x: 1, y: 50 }]);

    state.trafficRange = 'realtime';
    expect(options.computed.trafficBw.call(state)).toEqual([{ t: 2, rx: 100, tx: 10 }]);
  });
});

describe('notification center', () => {
  afterEach(() => {
    localStorageMock.getItem.mockReset();
    localStorageMock.getItem.mockImplementation(() => null);
    localStorageMock.setItem.mockClear();
  });

  function notificationState(options) {
    return {
      toasts: [],
      toastId: 0,
      notificationLogId: 0,
      notifications: [],
      notificationsReadAt: 0,
      showNotifications: false,
      dismissToast: options.methods.dismissToast,
      logNotification: options.methods.logNotification,
      persistNotifications: options.methods.persistNotifications,
      markNotificationsRead: options.methods.markNotificationsRead,
    };
  }

  it('logs every toast into the durable history and persists it', () => {
    const options = loadAppOptions();
    const state = notificationState(options);
    options.methods.notify.call(state, 'probe failed', 'error', 5);
    expect(state.notifications).toHaveLength(1);
    expect(state.notifications[0].msg).toBe('probe failed');
    expect(localStorageMock.setItem).toHaveBeenCalledWith('wgNotifications', expect.stringContaining('probe failed'));
  });

  it('caps the in-memory log and persists only the newest slice', () => {
    const options = loadAppOptions();
    const state = notificationState(options);
    for (let i = 0; i < 120; i += 1) options.methods.logNotification.call(state, `n${i}`, 'error');
    expect(state.notifications).toHaveLength(100);
    expect(JSON.parse(localStorageMock.setItem.mock.calls.at(-1)[1])).toHaveLength(50);
  });

  it('marks entries read when the panel opens and clears on demand', () => {
    const options = loadAppOptions();
    const state = notificationState(options);
    options.methods.logNotification.call(state, 'hello', 'info');
    expect(options.computed.unreadCount.call(state)).toBe(1);
    options.methods.toggleNotifications.call(state);
    expect(state.showNotifications).toBe(true);
    expect(options.computed.unreadCount.call(state)).toBe(0);
    options.methods.clearNotifications.call(state);
    expect(state.notifications).toHaveLength(0);
  });

  it('keeps newest notifications first in the panel slice', () => {
    const options = loadAppOptions();
    const state = {
      notifications: [
        {
          id: 1, msg: 'old', type: 'error', at: 1,
        },
        {
          id: 2, msg: 'new', type: 'error', at: 2,
        },
      ],
    };
    expect(options.computed.notificationsSlice.call(state).map((entry) => entry.id)).toEqual([2, 1]);
  });
});

describe('random port generator', () => {
  it('draws inside the configured window avoiding used and blocked ports', () => {
    const options = loadAppOptions();
    const state = {
      forwardingEnabled: true,
      clients: [{
        id: 'a',
        portForwards: [{
          id: 'r1', proto: 'tcp', extPort: 5000, intPort: 80,
        }],
      }],
      publicServerConfig: {
        portFwdMin: 4998, portFwdMax: 5002, port: 51820, configPort: 51821,
      },
      newPf: {},
      pfError: 'stale',
      getNewPf: options.methods.getNewPf,
      usedExternalPorts: options.methods.usedExternalPorts,
      notify: jest.fn(),
      $t: (key) => key,
      $set(target, key, value) {
        target[key] = value;
      },
    };
    options.methods.randomPortFor.call(state, { id: 'a' });
    const pf = state.newPf.a;
    expect(pf.extPort).not.toBe(5000); // already assigned to this peer
    expect(pf.extPort).toBeGreaterThanOrEqual(4998);
    expect(pf.extPort).toBeLessThanOrEqual(5002);
    expect(pf.intPort).toBe(pf.extPort); // seeding default mirrors the draw
    expect(state.pfError).toBeNull();
    expect(state.notify).not.toHaveBeenCalled();
  });

  it('notifies when the configured window has no free port left', () => {
    const options = loadAppOptions();
    const state = {
      forwardingEnabled: true,
      clients: [{
        id: 'a',
        portForwards: [{
          id: 'r1', proto: 'tcp', extPort: 5000, intPort: 80,
        }],
      }],
      publicServerConfig: {
        portFwdMin: 5000, portFwdMax: 5000, port: 51820, configPort: 51821,
      },
      newPf: {},
      pfError: null,
      getNewPf: options.methods.getNewPf,
      usedExternalPorts: options.methods.usedExternalPorts,
      notify: jest.fn(),
      $t: (key) => key,
      $set(target, key, value) {
        target[key] = value;
      },
    };
    options.methods.randomPortFor.call(state, { id: 'a' });
    expect(state.newPf.a.extPort).toBeNull(); // entry exists but was never filled
    expect(state.notify).toHaveBeenCalledWith('pf.randomPortNone', 'error');
  });

  it('prefers ports outside the ephemeral range, falling back when forced', () => {
    const options = loadAppOptions();
    // Full window: the draw must land outside 32768-60999 (project constraint).
    const wide = {
      forwardingEnabled: true,
      clients: [{ id: 'a', portForwards: [] }],
      publicServerConfig: {
        portFwdMin: 1024, portFwdMax: 65535, port: 51820, configPort: 51821,
      },
      newPf: {},
      pfError: null,
      getNewPf: options.methods.getNewPf,
      usedExternalPorts: options.methods.usedExternalPorts,
      notify: jest.fn(),
      $t: (key) => key,
      $set(target, key, value) {
        target[key] = value;
      },
    };
    for (let i = 0; i < 20; i += 1) {
      options.methods.randomPortFor.call(wide, { id: 'a' });
      const port = wide.newPf.a.extPort;
      expect(port).toBeGreaterThanOrEqual(1024);
      // Outside 32768-60999: below it or above it both count.
      const inEphemeral = port >= 32768 && port <= 60999;
      expect(inEphemeral).toBe(false);
    }
    // A window entirely inside the ephemeral range still yields a port.
    const forced = {
      ...wide,
      publicServerConfig: {
        portFwdMin: 40000, portFwdMax: 40100, port: 51820, configPort: 51821,
      },
    };
    options.methods.randomPortFor.call(forced, { id: 'a' });
    expect(forced.newPf.a.extPort).toBeGreaterThanOrEqual(40000);
    expect(forced.newPf.a.extPort).toBeLessThanOrEqual(40100);
  });

  it('does nothing while the forwarding kill switch is engaged', () => {
    const options = loadAppOptions();
    const state = {
      forwardingEnabled: false,
      clients: [],
      publicServerConfig: null,
      newPf: {},
      getNewPf: options.methods.getNewPf,
      usedExternalPorts: options.methods.usedExternalPorts,
      notify: jest.fn(),
      $t: (key) => key,
    };
    options.methods.randomPortFor.call(state, { id: 'a' });
    expect(state.newPf.a).toBeUndefined();
    expect(state.notify).not.toHaveBeenCalled();
  });
});

describe('port-forwarding panel persistence', () => {
  afterEach(() => {
    localStorageMock.getItem.mockReset();
    localStorageMock.getItem.mockImplementation(() => null);
    localStorageMock.setItem.mockClear();
  });

  it('hydrates expanded sections from localStorage, ignoring stale values', () => {
    const options = loadAppOptions();
    localStorageMock.getItem.mockImplementation((key) => (key === 'pfExpanded' ? '{"client1":true,"client2":false,"bad": "nope"}' : null));
    const state = { notifications: [], notificationsReadAt: 0, expandedPfClients: {} };
    options.methods.hydratePersistentState.call(state);
    expect(state.expandedPfClients).toEqual({ client1: true });
  });

  it('stores only expanded sections when toggling, collapsed by default', () => {
    const options = loadAppOptions();
    const state = {
      expandedPfClients: { client1: true },
      scheduleAutoProbe: jest.fn(),
      persistPfExpanded: options.methods.persistPfExpanded,
      $set(target, key, value) {
        target[key] = value;
      },
    };
    options.methods.togglePfExpanded.call(state, 'client1'); // collapse
    expect(localStorageMock.setItem).toHaveBeenLastCalledWith('pfExpanded', '{}');
    options.methods.togglePfExpanded.call(state, 'client3'); // expand
    expect(localStorageMock.setItem).toHaveBeenLastCalledWith('pfExpanded', '{"client3":true}');
    expect(state.scheduleAutoProbe).toHaveBeenCalledTimes(1);
  });

  it('loads sections collapsed even when the peer already has forwards', async () => {
    const options = loadAppOptions();
    const state = {
      ...options.data,
      authenticated: true,
      forwardingEnabled: true,
      clients: null,
      expandedPfClients: {},
      newPf: {},
      lastPfSignature: null,
      lastProbeAt: {},
      lastProbeVerdict: {},
      refreshGeneration: 0,
      chartsEnabled: false,
      api: {
        getClients: jest.fn().mockResolvedValue([client()]),
        getServerConfig: jest.fn().mockResolvedValue({ forwardingEnabled: true, portFwdMin: 1024, portFwdMax: 65535 }),
      },
      scheduleAutoProbe: jest.fn(),
      $set(target, key, value) {
        target[key] = value;
      },
    };
    await options.methods.refresh.call(state);
    expect(state.expandedPfClients).toEqual({});
    expect(state.publicServerConfig).toEqual(expect.objectContaining({ portFwdMin: 1024 }));
  });

  it('prunes probe bookkeeping when rules disappear', async () => {
    const options = loadAppOptions();
    const state = {
      ...options.data,
      authenticated: true,
      forwardingEnabled: true,
      clients: null,
      expandedPfClients: {},
      newPf: {},
      lastPfSignature: null,
      lastProbeAt: { 'gone:r1': 1 },
      lastProbeVerdict: { 'gone:r1': { verdict: 'ok', at: 1 } },
      refreshGeneration: 0,
      chartsEnabled: false,
      api: {
        getClients: jest.fn().mockResolvedValue([]),
        getServerConfig: jest.fn().mockResolvedValue({ forwardingEnabled: true }),
      },
      scheduleAutoProbe: jest.fn(),
      $set(target, key, value) {
        target[key] = value;
      },
    };
    await options.methods.refresh.call(state);
    expect(state.lastProbeAt).toEqual({});
    expect(state.lastProbeVerdict).toEqual({});
  });
});

describe('reachability dot', () => {
  it('maps probe verdicts to dot colors', () => {
    const options = loadAppOptions();
    const state = {
      lastProbeVerdict: {
        'c:r-ok': { verdict: 'ok', at: 1 },
        'c:r-bad': { verdict: 'unreachable', at: 1 },
        'c:r-miss': { verdict: 'rule-missing', at: 1 },
        'c:r-local': { verdict: 'dnat-local', at: 1 },
        'c:r-off': { verdict: 'tunnel-down', at: 1 },
        'c:r-udp': { verdict: 'indeterminate', at: 1 },
      },
      probeVerdictFor: options.methods.probeVerdictFor,
      $t: (key) => key,
    };
    expect(options.methods.probeDotClass.call(state, 'c', 'r-ok')).toBe('bg-green-500');
    expect(options.methods.probeDotClass.call(state, 'c', 'r-bad')).toBe('bg-red-500');
    expect(options.methods.probeDotClass.call(state, 'c', 'r-miss')).toBe('bg-red-500');
    expect(options.methods.probeDotClass.call(state, 'c', 'r-local')).toBe('bg-amber-400');
    expect(options.methods.probeDotClass.call(state, 'c', 'r-off')).toBe('bg-gray-300 dark:bg-neutral-500');
    expect(options.methods.probeDotClass.call(state, 'c', 'r-udp')).toBe('bg-gray-300 dark:bg-neutral-500');
    expect(options.methods.probeDotClass.call(state, 'c', 'r-none')).toBe('bg-gray-300 dark:bg-neutral-500');
    expect(options.methods.probeDotTitle.call(state, { id: 'c' }, { id: 'r-ok' })).toBe('networkPolicy.verdictTitle');
  });

  it('lists probe entries newest first for the notification panel', () => {
    const options = loadAppOptions();
    const state = {
      clients: [
        {
          id: 'c1',
          portForwards: [{
            id: 'r1', proto: 'tcp', extPort: 8080, intPort: 80,
          }],
        },
        {
          id: 'c2',
          portForwards: [{
            id: 'r2', proto: 'udp', extPort: 53, intPort: 53,
          }],
        },
      ],
      lastProbeVerdict: {
        'c1:r1': { verdict: 'ok', at: 10 },
        'c2:r2': { verdict: 'indeterminate', at: 20 },
      },
    };
    expect(options.methods.probeEntries.call(state).map((entry) => entry.rule.id)).toEqual(['r2', 'r1']);
  });
});

describe('all-ports consolidated view', () => {
  function portsState(options) {
    return {
      clients: [
        {
          id: 'a',
          name: 'alpha',
          portForwards: [{
            id: 'r1', proto: 'tcp', extPort: 8080, intPort: 80,
          }],
        },
        {
          id: 'b',
          name: 'beta',
          portForwards: [
            {
              id: 'r2', proto: 'udp', extPort: 27015, intPort: 27015,
            },
            {
              id: 'r3', proto: 'both', extPort: 51413, intPort: 51413,
            },
          ],
        },
      ],
      lastProbeVerdict: {
        'a:r1': { verdict: 'ok', at: 30 },
        'b:r2': { verdict: 'unreachable', at: 20 },
      },
      allPortsSearch: '',
      allPortsProto: 'all',
      allPortsStatus: 'all',
    };
  }

  it('aggregates every rule with its verdict, sorted by external port', () => {
    const options = loadAppOptions();
    const rows = options.computed.allPortsRows.call(portsState(options));
    expect(rows.map((row) => row.rule.extPort)).toEqual([8080, 27015, 51413].sort((x, y) => x - y));
    expect(rows[0].verdict).toBe('ok');
    expect(rows.find((row) => row.rule.id === 'r3').verdict).toBeNull();
    expect(options.computed.totalPortRules.call(portsState(options))).toBe(3);
  });

  it('filters by search text, protocol and probe status', () => {
    const options = loadAppOptions();
    const state = portsState(options);

    state.allPortsSearch = 'alp';
    expect(options.computed.allPortsRows.call(state)).toHaveLength(1);
    state.allPortsSearch = '27015';
    expect(options.computed.allPortsRows.call(state).map((row) => row.rule.id)).toEqual(['r2']);
    state.allPortsSearch = '';

    state.allPortsProto = 'udp';
    expect(options.computed.allPortsRows.call(state).map((row) => row.rule.id)).toEqual(['r2']);
    state.allPortsProto = 'all';

    state.allPortsStatus = 'ok';
    expect(options.computed.allPortsRows.call(state).map((row) => row.rule.id)).toEqual(['r1']);
    state.allPortsStatus = 'problems';
    expect(options.computed.allPortsRows.call(state).map((row) => row.rule.id)).toEqual(['r2']);
    state.allPortsStatus = 'unknown';
    expect(options.computed.allPortsRows.call(state).map((row) => row.rule.id)).toEqual(['r3']);
  });

  it('toggles with persistence', () => {
    const options = loadAppOptions();
    localStorageMock.setItem.mockClear();
    const state = { allPortsOpen: false };
    options.methods.toggleAllPorts.call(state);
    expect(state.allPortsOpen).toBe(true);
    expect(localStorageMock.setItem).toHaveBeenCalledWith('allPortsOpen', '1');
    options.methods.toggleAllPorts.call(state);
    expect(localStorageMock.setItem).toHaveBeenLastCalledWith('allPortsOpen', '0');
  });

  it('jumpToPeer expands the peer section, persists and schedules a probe', () => {
    const options = loadAppOptions();
    localStorageMock.setItem.mockClear();
    const state = {
      expandedPfClients: {},
      persistPfExpanded: options.methods.persistPfExpanded,
      scheduleAutoProbe: jest.fn(),
      $set(target, key, value) {
        target[key] = value;
      },
      // No DOM in the vm: record the tick instead of running it.
      $nextTick(callback) {
        state.__nextTick = callback;
      },
    };
    options.methods.jumpToPeer.call(state, 'client9');
    expect(state.expandedPfClients.client9).toBe(true);
    expect(localStorageMock.setItem).toHaveBeenCalledWith('pfExpanded', '{"client9":true}');
    expect(state.scheduleAutoProbe).toHaveBeenCalledTimes(1);
    // Already expanded: no double probe scheduling.
    options.methods.jumpToPeer.call(state, 'client9');
    expect(state.scheduleAutoProbe).toHaveBeenCalledTimes(1);
  });
});
