/* eslint-env jest */

'use strict';

const { once } = require('node:events');
const http = require('node:http');

// This suite configures a TRUSTED_PROXY_IP that the test client's loopback
// connection can never match, so every request here arrives from an
// UNTRUSTED peer. It proves forwarded headers cannot spoof identity, host
// or protocol on such connections.
jest.mock('../config', () => ({
  PORT: 0,
  WEBUI_HOST: '127.0.0.1',
  RELEASE: '15',
  PASSWORD_HASH: require('bcryptjs').hashSync('correct-password', 10), // eslint-disable-line global-require
  SESSION_SECRET: '0123456789abcdef0123456789abcdef',
  SESSION_COOKIE_SECURE: false,
  TRUSTED_PROXY_IP: '203.0.113.1',
  LANG: 'es',
  UI_TRAFFIC_STATS: false,
  UI_CHART_TYPE: 0,
  validateEnvironment: jest.fn(),
}));

jest.mock('../services/WireGuard', () => ({
  getClients: jest.fn().mockResolvedValue([]),
  lookupPeerToken: jest.fn(),
}));

const Server = require('./Server');

const postSession = (baseUrl, headers) => new Promise((resolve, reject) => {
  const request = http.request(`${baseUrl}/api/session`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  }, (response) => {
    response.resume();
    response.once('end', () => resolve(response.statusCode));
  });
  request.on('error', reject);
  request.end(JSON.stringify({ password: 'wrong-password' }));
});

describe('HTTP server behind an unmatched trusted proxy', () => {
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

  it('still authenticates direct connections', async () => {
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
  });

  it('stays fail-closed for cross-origin and malformed Origins', async () => {
    const crossOrigin = await fetch(`${baseUrl}/api/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: 'http://evil.example' },
      body: JSON.stringify({ password: 'correct-password' }),
    });
    expect(crossOrigin.status).toBe(403);

    const malformed = await fetch(`${baseUrl}/api/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: 'not-a-url' },
      body: JSON.stringify({ password: 'correct-password' }),
    });
    expect(malformed.status).toBe(403);
  });

  it('ignores X-Forwarded-Host from an untrusted peer', async () => {
    const response = await fetch(`${baseUrl}/api/session`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'http://vpn.example.test',
        'X-Forwarded-Host': 'vpn.example.test',
      },
      body: JSON.stringify({ password: 'correct-password' }),
    });
    // Even a CORRECT password must not pass: the claimed public host is
    // unvetted, so the request is cross-origin and rejected before auth.
    expect(response.status).toBe(403);
  });

  it('ignores X-Forwarded-Proto from an untrusted peer for cookie flags', async () => {
    const login = await fetch(`${baseUrl}/api/session`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-Proto': 'https',
      },
      body: JSON.stringify({ password: 'correct-password' }),
    });
    expect(login.status).toBe(200);
    // SESSION_COOKIE_SECURE is false; a spoofed proto header must not add
    // the Secure attribute (which would break non-TLS deployments).
    const setCookieHeader = login.headers.get('set-cookie');
    expect(setCookieHeader).toContain('connect.sid');
    expect(setCookieHeader).not.toContain('Secure');
  });

  it('ignores X-Forwarded-For from an untrusted peer for rate limiting', async () => {
    // Rotate a fresh spoofed client IP per attempt. If the header were
    // honored, each request would get its own bucket and none would lock;
    // because the peer is untrusted all requests share the real peer
    // bucket and the 21st is rejected.
    for (let i = 1; i <= 20; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      const status = await postSession(baseUrl, { 'X-Forwarded-For': `198.51.100.${i}` });
      expect(status).toBe(401);
    }
    const locked = await postSession(baseUrl, { 'X-Forwarded-For': '198.51.100.99' });
    expect(locked).toBe(429);
  });
});
