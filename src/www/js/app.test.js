/* eslint-env jest */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

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
    localStorage: {
      getItem: jest.fn(() => null),
      theme: 'auto',
    },
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
      $set(target, key, value) {
        target[key] = value;
      },
    };

    options.methods.togglePfExpanded.call(state, 'client1');
    options.methods.togglePfExpanded.call(state, 'client1');

    expect(state.scheduleAutoProbe).toHaveBeenCalledTimes(1);
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
      api: { probePortForward },
      isPfExpanded: options.methods.isPfExpanded,
      notify: jest.fn(),
      $t: jest.fn(),
    };

    await options.methods.runAutoProbe.call(state);
    await options.methods.runAutoProbe.call(state);

    expect(probePortForward).toHaveBeenCalledTimes(1);
  });
});
