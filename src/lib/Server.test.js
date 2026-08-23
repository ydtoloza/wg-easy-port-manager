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
  lookupPeerToken: jest.fn(),
  getPeerProfile: jest.fn().mockResolvedValue({
    id: 'client1',
    name: 'client1',
    address: '10.8.0.2',
    addressV6: 'fd42:42:42::2',
    portForwards: [],
    permissions: { selfManagePorts: true },
  }),
  addPortForward: jest.fn().mockResolvedValue(),
  updatePortForwardByRuleId: jest.fn().mockResolvedValue(),
  removePortForwardByRuleId: jest.fn().mockResolvedValue(),
  issueClientToken: jest.fn().mockResolvedValue({ token: `wgpt_${'a'.repeat(64)}`, tokenCreatedAt: new Date(0) }),
  revokeClientToken: jest.fn().mockResolvedValue({ success: true }),
  setClientSelfManagePorts: jest.fn().mockResolvedValue({ selfManagePorts: true }),
  getWebhookConfig: jest.fn().mockResolvedValue({ configured: true, url: 'https://example.test/hook' }),
  setWebhookConfig: jest.fn().mockResolvedValue({ configured: true, url: 'https://example.test/hook' }),
  probePortForward: jest.fn().mockResolvedValue({
    rule: {
      proto: 'tcp', extPort: 2000, intPort: 2000, peerIP: '10.8.0.2',
    },
    rulePresent: true,
    tunnelUp: true,
    tcpConnectable: true,
    verdict: 'ok',
  }),
  autoAssignPortForward: jest.fn().mockResolvedValue({
    id: '11111111-2222-3333-4444-555555555555', proto: 'tcp', extPort: 1024, intPort: 80,
  }),
  removePortForwardById: jest.fn().mockResolvedValue(),
  updatePortForwardById: jest.fn().mockResolvedValue(),
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
      expect(body).toEqual({ statusCode: 500, error: 'Internal server error' });
      expect(body.data).toBeUndefined();
      expect(JSON.stringify(body)).not.toContain('internal rollback details');
      expect(consoleError).toHaveBeenCalled();
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

  it('exposes validation error messages for sub-500 errors', async () => {
    const failure = new Error('Invalid client name: X');
    failure.statusCode = 400;
    WireGuard.getClients.mockRejectedValueOnce(failure);

    const response = await fetch(`${baseUrl}/api/wireguard/client`, {
      headers: { Authorization: 'correct-password' },
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ statusCode: 400, error: 'Invalid client name: X' });
  });

  it('propagates 409 conflict statuses with their message', async () => {
    const conflict = new Error('Port tcp/8080 is already assigned to another peer');
    conflict.statusCode = 409;
    WireGuard.getClients.mockRejectedValueOnce(conflict);

    const response = await fetch(`${baseUrl}/api/wireguard/client`, {
      headers: { Authorization: 'correct-password' },
    });
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      statusCode: 409,
      error: 'Port tcp/8080 is already assigned to another peer',
    });
  });

  describe('scoped peer tokens', () => {
    const peerToken = `Bearer wgpt_${'ab'.repeat(32)}`;

    it('serves the peer profile for a valid token', async () => {
      WireGuard.lookupPeerToken.mockResolvedValueOnce('client1');
      const response = await fetch(`${baseUrl}/api/peer/me`, { headers: { Authorization: peerToken } });
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ id: 'client1', permissions: { selfManagePorts: true } });
      expect(WireGuard.lookupPeerToken).toHaveBeenCalledWith(`wgpt_${'ab'.repeat(32)}`);
    });

    it('rejects missing, malformed and unknown tokens', async () => {
      const missing = await fetch(`${baseUrl}/api/peer/me`);
      expect(missing.status).toBe(401);

      const malformed = await fetch(`${baseUrl}/api/peer/me`, { headers: { Authorization: 'Bearer wgpt_nonsense' } });
      expect(malformed.status).toBe(401);

      WireGuard.lookupPeerToken.mockResolvedValueOnce(null);
      const unknown = await fetch(`${baseUrl}/api/peer/me`, { headers: { Authorization: peerToken } });
      expect(unknown.status).toBe(401);
      expect(await unknown.json()).toMatchObject({ error: 'Invalid peer token' });
    });

    it('never treats the admin password as a peer token', async () => {
      const response = await fetch(`${baseUrl}/api/peer/me`, { headers: { Authorization: 'correct-password' } });
      expect(response.status).toBe(401);
    });

    it('does not let peer tokens reach admin routes', async () => {
      WireGuard.getClients.mockClear();
      const response = await fetch(`${baseUrl}/api/wireguard/client`, { headers: { Authorization: peerToken } });
      expect(response.status).toBe(401);
      expect(WireGuard.getClients).not.toHaveBeenCalled();
    });

    it('mutates own forwards only with selfManagePorts', async () => {
      WireGuard.lookupPeerToken.mockResolvedValue('client1');

      WireGuard.getPeerProfile.mockResolvedValueOnce({
        id: 'client1', permissions: { selfManagePorts: false },
      });
      const forbidden = await fetch(`${baseUrl}/api/peer/me/port-forward`, {
        method: 'POST',
        headers: { Authorization: peerToken, 'Content-Type': 'application/json' },
        body: JSON.stringify({ proto: 'tcp', extPort: 3000, intPort: 3000 }),
      });
      expect(forbidden.status).toBe(403);

      const allowed = await fetch(`${baseUrl}/api/peer/me/port-forward`, {
        method: 'POST',
        headers: { Authorization: peerToken, 'Content-Type': 'application/json' },
        body: JSON.stringify({ proto: 'tcp', extPort: 3000, intPort: 3000 }),
      });
      expect(allowed.status).toBe(200);
      expect(WireGuard.addPortForward).toHaveBeenCalledWith('client1', 'tcp', 3000, 3000, { requireSelfManagePorts: true });
    });

    it('scopes byId mutations to the pinned peer', async () => {
      WireGuard.lookupPeerToken.mockResolvedValue('client1');
      const ruleId = '11111111-2222-3333-4444-555555555555';
      const updated = await fetch(`${baseUrl}/api/peer/me/port-forward/id/${ruleId}`, {
        method: 'PUT',
        headers: { Authorization: peerToken, 'Content-Type': 'application/json' },
        body: JSON.stringify({ proto: 'tcp', extPort: 3001, intPort: 3000 }),
      });
      expect(updated.status).toBe(200);
      expect(WireGuard.updatePortForwardByRuleId).toHaveBeenCalledWith('client1', ruleId, 'tcp', 3001, 3000, { requireSelfManagePorts: true });

      const removed = await fetch(`${baseUrl}/api/peer/me/port-forward/id/${ruleId}`, {
        method: 'DELETE',
        headers: { Authorization: peerToken },
      });
      expect(removed.status).toBe(200);
      expect(WireGuard.removePortForwardByRuleId).toHaveBeenCalledWith('client1', ruleId, { requireSelfManagePorts: true });
    });

    it('serves the peer probe route now that the probe feature merged', async () => {
      WireGuard.lookupPeerToken.mockResolvedValue('client1');
      const ruleId = '11111111-2222-3333-4444-555555555555';
      const response = await fetch(`${baseUrl}/api/peer/me/port-forward/${ruleId}/probe`, {
        headers: { Authorization: peerToken },
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ verdict: 'ok' });
      expect(WireGuard.probePortForward).toHaveBeenCalledWith({ clientId: 'client1', rule: ruleId });
    });

    it('rejects coercible-but-invalid ports strictly on peer routes', async () => {
      WireGuard.lookupPeerToken.mockResolvedValue('client1');
      for (const bad of [true, '0x10', '5e2', 0, 65536]) {
        const response = await fetch(`${baseUrl}/api/peer/me/port-forward`, {
          method: 'POST',
          headers: { Authorization: peerToken, 'Content-Type': 'application/json' },
          body: JSON.stringify({ proto: 'tcp', extPort: bad, intPort: 80 }),
        });
        expect(response.status).toBe(400);
        expect(await response.json()).toMatchObject({ statusCode: 400, error: 'Invalid ports' });
      }
      expect(WireGuard.addPortForward).not.toHaveBeenCalledWith('client1', 'tcp', 16, 80);
      expect(WireGuard.addPortForward).not.toHaveBeenCalledWith('client1', 'tcp', 1, 80);
    });

    it('rejects digit-string rule ids on the peer id routes instead of addressing by index', async () => {
      WireGuard.lookupPeerToken.mockResolvedValue('client1');
      WireGuard.updatePortForwardByRuleId.mockClear();
      WireGuard.removePortForwardByRuleId.mockClear();

      const updated = await fetch(`${baseUrl}/api/peer/me/port-forward/id/0`, {
        method: 'PUT',
        headers: { Authorization: peerToken, 'Content-Type': 'application/json' },
        body: JSON.stringify({ proto: 'tcp', extPort: 3000, intPort: 3000 }),
      });
      expect(updated.status).toBe(400);
      expect(WireGuard.updatePortForwardByRuleId).not.toHaveBeenCalled();

      const removed = await fetch(`${baseUrl}/api/peer/me/port-forward/id/1`, {
        method: 'DELETE',
        headers: { Authorization: peerToken },
      });
      expect(removed.status).toBe(400);
      expect(WireGuard.removePortForwardByRuleId).not.toHaveBeenCalled();
    });

    it('rejects numeric ids on the peer probe route', async () => {
      WireGuard.lookupPeerToken.mockResolvedValue('client1');
      WireGuard.probePortForward.mockClear();
      const response = await fetch(`${baseUrl}/api/peer/me/port-forward/0/probe`, {
        headers: { Authorization: peerToken },
      });
      expect(response.status).toBe(400);
      expect(WireGuard.probePortForward).not.toHaveBeenCalled();
    });

    it('accepts query strings on peer endpoints', async () => {
      WireGuard.lookupPeerToken.mockResolvedValue('client1');
      const profile = await fetch(`${baseUrl}/api/peer/me?x=1`, { headers: { Authorization: peerToken } });
      expect(profile.status).toBe(200);

      const added = await fetch(`${baseUrl}/api/peer/me/port-forward?src=cron`, {
        method: 'POST',
        headers: { Authorization: peerToken, 'Content-Type': 'application/json' },
        body: JSON.stringify({ proto: 'tcp', extPort: 3000, intPort: 3000 }),
      });
      expect(added.status).toBe(200);
    });

    it('rejects traversal-shaped peer paths explicitly', async () => {
      WireGuard.lookupPeerToken.mockResolvedValue('client1');
      const { port } = new URL(baseUrl);
      // fetch()/URL normalize dot segments client-side, so send raw paths.
      const rawStatus = (rawPath) => new Promise((resolve, reject) => {
        const request = http.request({
          host: '127.0.0.1',
          port,
          path: rawPath,
          method: 'GET',
          headers: { Authorization: peerToken },
        }, (response) => {
          response.resume();
          resolve(response.statusCode);
        });
        request.on('error', reject);
        request.end();
      });
      expect(await rawStatus('/api/peer/me/../me')).toBe(400);
      expect(await rawStatus('/api/peer/me//port-forward')).toBe(400);
      // sanity: the normal shape still authenticates
      expect(await rawStatus('/api/peer/me')).toBe(200);
    });

    it('isolates peer-token buckets from admin lockout counters', async () => {
      // 20 failed admin logins lock this IP out (the 21st is a 429).
      const adminIp = '198.51.100.77';
      for (let i = 0; i < 20; i += 1) {
        // eslint-disable-next-line no-await-in-loop
        expect(await postSession(baseUrl, adminIp)).toBe(401);
      }

      // Flood MORE buckets than the peer table cap with random tokens.
      WireGuard.lookupPeerToken.mockResolvedValue(null);
      const { port } = new URL(baseUrl);
      const agent = new http.Agent({ keepAlive: true, maxSockets: 32 });
      const peerStatus = (token) => new Promise((resolve, reject) => {
        const request = http.request({
          host: '127.0.0.1',
          port,
          path: '/api/peer/me',
          method: 'GET',
          agent,
          headers: { Authorization: `Bearer ${token}` },
        }, (response) => {
          response.resume();
          resolve(response.statusCode);
        });
        request.on('error', reject);
        request.end();
      });
      const flood = Array.from({ length: 10050 }, (_, i) => peerStatus(`${i.toString(16).padStart(64, '0')}`));
      const statuses = await Promise.all(flood);
      agent.destroy();
      expect(statuses.every((status) => status === 401 || status === 429)).toBe(true);

      WireGuard.lookupPeerToken.mockResolvedValue('client1');
      // The admin IP must STILL be locked out: its failure counter survived
      // the flood instead of being evicted from a shared table.
      expect(await postSession(baseUrl, adminIp)).toBe(429);
    }, 60000);
  });

  describe('token and webhook admin routes', () => {
    it('issues tokens once and revokes them', async () => {
      const issued = await fetch(`${baseUrl}/api/wireguard/client/client1/token`, {
        method: 'POST',
        headers: { Authorization: 'correct-password' },
      });
      expect(issued.status).toBe(200);
      expect(await issued.json()).toMatchObject({ token: expect.stringMatching(/^wgpt_[0-9a-f]{64}$/) });
      expect(WireGuard.issueClientToken).toHaveBeenCalledWith({ clientId: 'client1' });

      const revoked = await fetch(`${baseUrl}/api/wireguard/client/client1/token`, {
        method: 'DELETE',
        headers: { Authorization: 'correct-password' },
      });
      expect(revoked.status).toBe(200);
      expect(WireGuard.revokeClientToken).toHaveBeenCalledWith({ clientId: 'client1' });
    });

    it('toggles self-managed ports', async () => {
      const response = await fetch(`${baseUrl}/api/wireguard/client/client1/self-manage-ports`, {
        method: 'PUT',
        headers: { Authorization: 'correct-password', 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: true }),
      });
      expect(response.status).toBe(200);
      expect(WireGuard.setClientSelfManagePorts).toHaveBeenCalledWith({ clientId: 'client1', enabled: true });

      const invalid = await fetch(`${baseUrl}/api/wireguard/client/client1/self-manage-ports`, {
        method: 'PUT',
        headers: { Authorization: 'correct-password', 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: 'yes' }),
      });
      expect(invalid.status).toBe(400);
    });

    it('manages the webhook config without ever echoing the secret', async () => {
      const status = await fetch(`${baseUrl}/api/wireguard/webhook-config`, {
        headers: { Authorization: 'correct-password' },
      });
      expect(await status.json()).toEqual({ configured: true, url: 'https://example.test/hook' });

      const updated = await fetch(`${baseUrl}/api/wireguard/webhook-config`, {
        method: 'PUT',
        headers: { Authorization: 'correct-password', 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'https://example.test/hook', secret: 's' }),
      });
      expect(updated.status).toBe(200);
      expect(WireGuard.setWebhookConfig).toHaveBeenCalledWith({ url: 'https://example.test/hook', secret: 's' });
    });
  });

  it('exposes the probe endpoint for admins (rule id or index)', async () => {
    const response = await fetch(`${baseUrl}/api/wireguard/client/client1/port-forward/0/probe`, {
      headers: { Authorization: 'correct-password' },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ verdict: 'ok' });
    expect(WireGuard.probePortForward).toHaveBeenCalledWith({ clientId: 'client1', rule: '0' });

    const bad = await fetch(`${baseUrl}/api/wireguard/client/client1/port-forward/bogus/probe`, {
      headers: { Authorization: 'correct-password' },
    });
    expect(bad.status).toBe(400);
  });

  it('routes auto-assign through the service and returns the claimed rule', async () => {
    const response = await fetch(`${baseUrl}/api/wireguard/client/client1/port-forward/auto`, {
      method: 'POST',
      headers: { Authorization: 'correct-password', 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proto: 'tcp', intPort: 80, rangeStart: 1024, rangeEnd: 2048,
      }),
    });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.success).toBe(true);
    expect(body.rule.extPort).toBe(1024);
    expect(WireGuard.autoAssignPortForward).toHaveBeenCalledWith('client1', {
      proto: 'tcp', intPort: 80, rangeStart: 1024, rangeEnd: 2048,
    });
  });

  it('rejects coercible-but-invalid ports strictly (true, hex, exponent)', async () => {
    for (const bad of [true, '0x10', '5e2', 0, 65536]) {
      const response = await fetch(`${baseUrl}/api/wireguard/client/client1/port-forward`, {
        method: 'POST',
        headers: { Authorization: 'correct-password', 'Content-Type': 'application/json' },
        body: JSON.stringify({ proto: 'tcp', extPort: bad, intPort: 80 }),
      });
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ statusCode: 400, error: 'Invalid ports' });
    }
  });

  it('addresses rules by id on the id-based routes', async () => {
    const ruleId = '11111111-2222-3333-4444-555555555555';
    const removed = await fetch(`${baseUrl}/api/wireguard/client/client1/port-forward/id/${ruleId}`, {
      method: 'DELETE',
      headers: { Authorization: 'correct-password' },
    });
    expect(removed.status).toBe(200);
    expect(WireGuard.removePortForwardById).toHaveBeenCalledWith('client1', ruleId);

    const updated = await fetch(`${baseUrl}/api/wireguard/client/client1/port-forward/id/${ruleId}`, {
      method: 'PUT',
      headers: { Authorization: 'correct-password', 'Content-Type': 'application/json' },
      body: JSON.stringify({ proto: 'tcp', extPort: 3000, intPort: 3000 }),
    });
    expect(updated.status).toBe(200);
    expect(WireGuard.updatePortForwardById).toHaveBeenCalledWith('client1', ruleId, 'tcp', 3000, 3000);

    const malformed = await fetch(`${baseUrl}/api/wireguard/client/client1/port-forward/id/not-a-uuid`, {
      method: 'DELETE',
      headers: { Authorization: 'correct-password' },
    });
    expect(malformed.status).toBe(400);
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
