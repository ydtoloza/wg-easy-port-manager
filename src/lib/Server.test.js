/* eslint-env jest */

'use strict';

const { once } = require('node:events');
const http = require('node:http');

jest.mock('bcryptjs', () => {
  const actual = jest.requireActual('bcryptjs');
  return {
    hashSync: actual.hashSync,
    compare: (password, hash) => {
      // Tests can freeze password checks to hold concurrency slots open.
      if (!globalThis.__deferPasswordCompares) return actual.compare(password, hash);
      return new Promise((resolve) => globalThis.__pendingPasswordCompares.push(resolve));
    },
  };
});

jest.mock('../config', () => ({
  PORT: 0,
  WEBUI_HOST: '127.0.0.1',
  RELEASE: '15',
  PASSWORD_HASH: require('bcryptjs').hashSync('correct-password', 10), // eslint-disable-line global-require
  SESSION_SECRET: '0123456789abcdef0123456789abcdef',
  SESSION_COOKIE_SECURE: false,
  TRUSTED_PROXY_IP: '127.0.0.1',
  LANG: 'es',
  UI_TRAFFIC_STATS: false,
  UI_CHART_TYPE: 0,
  validateEnvironment: jest.fn(),
}));

jest.mock('../services/WireGuard', () => ({
  getClients: jest.fn().mockResolvedValue([]),
  getNetworkPolicyOptions: jest.fn().mockReturnValue({ protocolPresets: [], maxCustomRules: 32 }),
  updateClientNetworkPolicy: jest.fn().mockResolvedValue({
    networkPolicy: { blockedProtocols: ['http'], customRules: [], peerAllowlist: [] },
    updatedAt: '2026-01-01T00:00:00.000Z',
  }),
}));

const WireGuard = require('../services/WireGuard');
const Server = require('./Server');

const postSession = (baseUrl, forwardedFor) => new Promise((resolve, reject) => {
  const request = http.request(`${baseUrl}/api/session`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(forwardedFor ? { 'X-Forwarded-For': forwardedFor } : {}),
    },
  }, (response) => {
    response.resume();
    resolve(response.statusCode);
  });
  request.on('error', reject);
  request.end(JSON.stringify({ password: 'wrong-password' }));
});

describe('HTTP server security', () => {
  let instance;
  let baseUrl;

  beforeAll(async () => {
    instance = new Server({ port: 0, host: '127.0.0.1' });
    await once(instance.server, 'listening');
    baseUrl = `http://127.0.0.1:${instance.server.address().port}`;
  });

  afterAll(async () => {
    await new Promise((resolve) => instance.server.close(resolve));
  });

  it('fails closed and sends security headers', async () => {
    const release = await fetch(`${baseUrl}/api/release`);
    expect(await release.json()).toBe('15');

    const session = await fetch(`${baseUrl}/api/session`);
    expect(session.status).toBe(200);
    expect(session.headers.get('cache-control')).toBe('no-store');
    expect(session.headers.get('content-security-policy')).toContain("script-src-attr 'none'");
    expect(await session.json()).toEqual({ requiresPassword: true, authenticated: false });

    const clients = await fetch(`${baseUrl}/api/wireguard/client`);
    expect(clients.status).toBe(401);
    expect(WireGuard.getClients).not.toHaveBeenCalled();
  });

  it('authenticates, authorizes and destroys sessions', async () => {
    const login = await fetch(`${baseUrl}/api/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'correct-password' }),
    });
    expect(login.status).toBe(200);
    const cookie = login.headers.get('set-cookie').split(';')[0];

    const clients = await fetch(`${baseUrl}/api/wireguard/client`, {
      headers: { Cookie: cookie },
    });
    expect(clients.status).toBe(200);
    expect(await clients.json()).toEqual([]);

    const options = await fetch(`${baseUrl}/api/wireguard/network-policy-options`, {
      headers: { Cookie: cookie },
    });
    expect(options.status).toBe(200);
    expect(await options.json()).toEqual({ protocolPresets: [], maxCustomRules: 32 });

    const policy = { blockedProtocols: ['http'], customRules: [], peerAllowlist: [] };
    const expectedUpdatedAt = '2026-01-01T00:00:00.000Z';
    const updatePolicy = await fetch(`${baseUrl}/api/wireguard/client/client1/network-policy`, {
      method: 'PUT',
      headers: { Cookie: cookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({ policy, expectedUpdatedAt }),
    });
    expect(updatePolicy.status).toBe(200);
    expect(WireGuard.updateClientNetworkPolicy).toHaveBeenCalledWith({
      clientId: 'client1', policy, expectedUpdatedAt,
    });

    const logout = await fetch(`${baseUrl}/api/session`, {
      method: 'DELETE',
      headers: { Cookie: cookie },
    });
    expect(logout.status).toBe(200);
    expect(logout.headers.get('set-cookie')).toMatch(/Max-Age=0/);

    const expired = await fetch(`${baseUrl}/api/wireguard/client`, {
      headers: { Cookie: cookie },
    });
    expect(expired.status).toBe(401);
  });

  it('rejects oversized bodies before parsing JSON', async () => {
    const response = await fetch(`${baseUrl}/api/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'a'.repeat(1024 * 1024) }),
    });
    expect(response.status).toBe(413);
    expect(response.headers.get('cache-control')).toBe('no-store');
  });

  it('reports a failed network rollback without exposing internal errors', async () => {
    const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});
    const failure = new Error('internal rollback details');
    failure.statusCode = 500;
    failure.data = { rollbackFailed: true };
    WireGuard.getClients.mockRejectedValueOnce(failure);

    try {
      const response = await fetch(`${baseUrl}/api/wireguard/client`, {
        headers: { Authorization: 'correct-password' },
      });
      expect(response.status).toBe(500);
      const body = await response.json();
      expect(body.data).toEqual({ rollbackFailed: true });
      expect(JSON.stringify(body)).not.toContain('internal rollback details');
    } finally {
      consoleError.mockRestore();
    }
  });

  it('does not let one IP lock out logins from another IP', async () => {
    // Hold every concurrent password-check slot the attacker IP can get by
    // freezing its bcrypt comparisons mid-flight.
    globalThis.__deferPasswordCompares = true;
    globalThis.__pendingPasswordCompares = [];
    const attackers = Array.from({ length: 8 }, () => postSession(baseUrl, '203.0.113.2'));
    const waitFor = async (predicate, what) => {
      for (let i = 0; i < 400 && !predicate(); i += 1) {
        // eslint-disable-next-line no-await-in-loop
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
      if (!predicate()) throw new Error(`timed out waiting for ${what}`);
    };

    try {
      await waitFor(() => globalThis.__pendingPasswordCompares.length === 8, 'attacker slots to be held');

      // A different IP must still be able to start a password check: its
      // comparison gets a slot instead of a global 429.
      const honest = postSession(baseUrl, '203.0.113.9');
      await waitFor(() => globalThis.__pendingPasswordCompares.length === 9, 'honest password check to start');
      globalThis.__pendingPasswordCompares[8](false);
      expect(await honest).toBe(401);
    } finally {
      for (const resolve of globalThis.__pendingPasswordCompares.splice(0)) resolve(false);
      await Promise.all(attackers);
      globalThis.__deferPasswordCompares = false;
    }
  });

  it('caps concurrent password checks', async () => {
    const responses = await Promise.all(Array.from({ length: 24 }, () => fetch(`${baseUrl}/api/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'wrong-password' }),
    })));
    const statuses = responses.map((response) => response.status);
    expect(statuses.filter((status) => status === 429).length).toBeGreaterThanOrEqual(4);
    expect(statuses.filter((status) => status === 401).length).toBeLessThanOrEqual(20);
  });
});
