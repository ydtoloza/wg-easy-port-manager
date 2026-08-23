'use strict';

const crypto = require('node:crypto');
const dns = require('node:dns');
const http = require('node:http');
const https = require('node:https');
const { isIP } = require('node:net');
const debug = require('debug')('Webhook');

// At-least-once webhook delivery. Hard rules (all empirically verified in the
// v2.1 review): redirects are never followed (a 30x from https:// to
// http://127.0.0.1 must not succeed) and every request carries an explicit 5s
// abort, so delivery is made with node:http/https (which never follows
// redirects) and an overall request timer.

const RETRY_DELAYS_MS = [1000, 5000, 30000, 120000, 600000];
const REQUEST_TIMEOUT_MS = 5000;

const signPayload = (secret, timestamp, body) => {
  const mac = crypto.createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
  return `t=${timestamp},v1=${mac}`;
};

const isAllowedScheme = (url, allowInsecure) => {
  if (url.protocol === 'https:') return true;
  return allowInsecure && url.protocol === 'http:';
};

// ── Connect-time SSRF gate ────────────────────────────────────────────
// The URL scheme is checked at set time and per attempt, but that alone
// accepts any https:// host that resolves to loopback/link-local/private/
// metadata ranges (DNS rebinding included). The gate lives INSIDE the
// socket's lookup function: validation and connect use the same resolution,
// so DNS cannot rebind between check and connect, and the approved literal
// IP is what gets connected (the pin). Literal-IP hosts bypass lookup in
// net.connect and are pre-checked at the attempt level instead.

// 8 numeric groups for an IPv6 literal (embedded IPv4 tail expanded), or
// null when unparseable. Callers treat null as blocked (fail-closed).
const expandIPv6Groups = (address) => {
  let host = address;
  const lastColon = host.lastIndexOf(':');
  const tail = host.slice(lastColon + 1);
  if (tail.includes('.')) {
    const parts = tail.split('.').map(Number);
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
    host = `${host.slice(0, lastColon + 1)}${((parts[0] << 8) | parts[1]).toString(16)}:${((parts[2] << 8) | parts[3]).toString(16)}`;
  }
  const halves = host.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const groups = [...left, ...Array(missing).fill('0'), ...right].map((group) => parseInt(group, 16));
  return groups.length === 8 && groups.every((group) => Number.isInteger(group)) ? groups : null;
};

const isBlockedIPv4 = (address) => {
  const parts = address.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = parts;
  return a === 0 // 0.0.0.0/8 "this network"
    || a === 10 // RFC1918
    || a === 127 // loopback
    || (a === 169 && b === 254) // link-local, incl. 169.254.169.254 metadata
    || (a === 172 && b >= 16 && b <= 31) // RFC1918
    || (a === 192 && b === 168); // RFC1918
};

const isBlockedIPv6 = (address) => {
  const groups = expandIPv6Groups(address);
  if (!groups) return true;
  if (groups.every((group) => group === 0)) return true; // :: unspecified
  const [g0] = groups;
  if (g0 === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 && groups[4] === 0) {
    if (groups[5] === 0xffff) {
      // ::ffff:0:0/96 IPv4-mapped: judge the embedded v4 address.
      return isBlockedIPv4(`${(groups[6] >> 8) & 0xff}.${groups[6] & 0xff}.${(groups[7] >> 8) & 0xff}.${groups[7] & 0xff}`);
    }
    if (groups[5] === 0 && groups[6] === 0 && groups[7] === 1) return true; // ::1 loopback
  }
  if ((g0 & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((g0 & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
  return false;
};

const isBlockedAddress = (address) => {
  const family = isIP(address);
  if (family === 4) return isBlockedIPv4(address);
  if (family === 6) return isBlockedIPv6(address);
  return true; // not an IP literal: fail-closed (only literals reach here)
};

// Returns a net.connect-compatible lookup that resolves, drops blocked
// addresses and hands net the first approved literal IP.
const guardedLookup = (allowPrivate) => (hostname, options, callback) => {
  if (typeof options === 'function') {
    callback = options; // eslint-disable-line no-param-reassign
    options = {}; // eslint-disable-line no-param-reassign
  }
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    const list = Array.isArray(addresses) ? addresses : [{ address: addresses, family: 4 }];
    if (allowPrivate) {
      const first = list[0];
      return callback(null, first.address, first.family);
    }
    const allowed = list.filter((entry) => !isBlockedAddress(entry.address));
    if (!allowed.length) {
      return callback(new Error('webhook host resolves only to blocked address ranges'));
    }
    if (options.all) return callback(null, allowed);
    return callback(null, allowed[0].address, allowed[0].family);
  });
};

// fetch-compatible transport over node:http/https. Never follows redirects;
// pins the connection to the lookup-approved IP while keeping SNI/cert
// validation on the original hostname.
const requestViaNode = (url, init, { allowPrivate = false } = {}) => new Promise((resolve, reject) => {
  const target = new URL(url);
  const transport = target.protocol === 'https:' ? https : http;
  let settled = false;
  const request = transport.request(target, {
    method: init.method || 'POST',
    headers: init.headers,
    lookup: guardedLookup(allowPrivate),
    servername: target.hostname,
  });
  const timer = setTimeout(() => {
    request.destroy(new Error(`webhook request timed out after ${REQUEST_TIMEOUT_MS}ms`));
  }, REQUEST_TIMEOUT_MS);
  const finish = (fn) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    fn();
  };
  request.on('response', (response) => {
    response.resume(); // drain so the socket is released
    finish(() => resolve({ status: response.statusCode }));
  });
  request.on('error', (err) => finish(() => reject(err)));
  if (init.signal) {
    init.signal.addEventListener('abort', () => {
      request.destroy(new Error('webhook request aborted'));
    }, { once: true });
  }
  request.end(init.body);
});

// Attempts one delivery. 30x responses are failures (redirects are never
// followed), and only the host/status/attempt are ever logged.
const attemptOnce = async ({
  url, secret, body, allowInsecure, allowPrivate,
}, fetchImpl) => {
  const target = new URL(url);
  if (!isAllowedScheme(target, allowInsecure)) {
    throw new Error('webhook target must be https:// (or http:// with ALLOW_INSECURE_WEBHOOK=true)');
  }
  // Literal-IP hosts skip the socket lookup, so they are gated here. WHATWG
  // hostnames keep their brackets for IPv6 ([::1]); strip them first.
  const literalHost = target.hostname.replace(/^\[/, '').replace(/\]$/, '');
  if (!allowPrivate && isIP(literalHost) && isBlockedAddress(literalHost)) {
    throw new Error('webhook target address is in a blocked range (set ALLOW_PRIVATE_WEBHOOK=true to override)');
  }
  const timestamp = Math.floor(Date.now() / 1000);
  const response = await fetchImpl(target.toString(), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-WGPM-Signature': signPayload(secret, timestamp, body),
    },
    body,
    redirect: 'manual',
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (response.status >= 300 && response.status < 400) {
    throw new Error(`webhook redirect (${response.status}) not followed`);
  }
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`webhook endpoint answered ${response.status}`);
  }
  return response.status;
};

// Delivery is fire-and-forget: callers never await this. Retries use a fixed
// 1s/5s/30s/2m/10m backoff and then the event is DROPPED (at-least-once;
// receivers dedupe on eventId and reconcile seq gaps by polling client state).
const deliver = async (config, {
  fetchImpl,
  delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now = () => Date.now(),
} = {}) => {
  const startedAt = now();
  const doFetch = fetchImpl
    || ((url, init) => requestViaNode(url, init, { allowPrivate: !!config.allowPrivate }));
  const host = (() => {
    try {
      return new URL(config.url).host;
    } catch {
      return 'invalid-url';
    }
  })();

  for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt += 1) {
    try {
      const status = await attemptOnce(config, doFetch);
      debug(`webhook delivered host=${host} status=${status} attempt=${attempt} ms=${now() - startedAt}`);
      return true;
    } catch (err) {
      debug(`webhook attempt failed host=${host} attempt=${attempt} reason=${err.message}`);
      if (attempt === RETRY_DELAYS_MS.length) return false;
      // Only the delay is awaited; nothing here ever blocks a caller.
      await delay(RETRY_DELAYS_MS[attempt]);
    }
  }
  return false;
};

module.exports = {
  signPayload, deliver, isBlockedAddress, RETRY_DELAYS_MS, REQUEST_TIMEOUT_MS,
};
