'use strict';

const crypto = require('node:crypto');
const dns = require('node:dns');
const http = require('node:http');
const https = require('node:https');
const { isIP } = require('node:net');
const tls = require('node:tls');
const debug = require('debug')('Webhook');

// At-least-once webhook delivery. Hard rules (all empirically verified in the
// v2.1 review): redirects are never followed (a 30x from https:// to
// http://127.0.0.1 must not succeed) and every request carries an explicit 5s
// abort, so delivery is made with node:http/https (which never follows
// redirects) and an overall request timer.

const RETRY_DELAYS_MS = [1000, 5000, 30000, 120000, 600000];
const REQUEST_TIMEOUT_MS = 5000;

class WebhookError extends Error {

  constructor(message, retryable = false) {
    super(message);
    this.retryable = retryable;
  }

}

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
  const textGroups = [...left, ...Array(missing).fill('0'), ...right];
  if (textGroups.some((group) => !/^[0-9a-f]{1,4}$/i.test(group))) return null;
  return textGroups.map((group) => parseInt(group, 16));
};

const ipv4ToInt = (address) => {
  const parts = address.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return parts.reduce((value, part) => ((value << 8) | part) >>> 0, 0);
};

const inIPv4Cidr = (value, base, bits) => {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (value & mask) === (ipv4ToInt(base) & mask);
};

const isBlockedIPv4 = (address) => {
  const value = ipv4ToInt(address);
  if (value === null) return true;
  // IANA special-purpose ranges that are not globally reachable unicast.
  // The two PCP anycast addresses are the globally reachable exceptions in
  // 192.0.0.0/24.
  if (inIPv4Cidr(value, '192.0.0.0', 24)) {
    return value !== ipv4ToInt('192.0.0.9') && value !== ipv4ToInt('192.0.0.10');
  }
  return [
    ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10],
    ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
    ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
    ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
    ['224.0.0.0', 4], ['240.0.0.0', 4],
  ].some(([base, bits]) => inIPv4Cidr(value, base, bits));
};

const inIPv6Cidr = (groups, base, bits) => {
  const baseGroups = expandIPv6Groups(base);
  const whole = Math.floor(bits / 16);
  const remainder = bits % 16;
  for (let index = 0; index < whole; index += 1) {
    if (groups[index] !== baseGroups[index]) return false;
  }
  if (!remainder) return true;
  const mask = (0xffff << (16 - remainder)) & 0xffff;
  return (groups[whole] & mask) === (baseGroups[whole] & mask);
};

const isBlockedIPv6 = (address) => {
  const groups = expandIPv6Groups(address);
  if (!groups) return true;

  // Only global-unicast space is eligible. This rejects unspecified,
  // loopback, ULA, link-local, multicast, mapped/translated IPv4, NAT64 and
  // other special-purpose forms before considering exceptions inside 2000::/3.
  if (!inIPv6Cidr(groups, '2000::', 3)) return true;
  return inIPv6Cidr(groups, '2001::', 23) // protocol assignments and benchmark ranges
    || inIPv6Cidr(groups, '2001:db8::', 32) // documentation
    || inIPv6Cidr(groups, '2002::', 16) // deprecated 6to4 transition space
    || inIPv6Cidr(groups, '3fff::', 20); // documentation
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
      return callback(new WebhookError('webhook host resolves only to non-global address ranges'));
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
  const literalHost = target.hostname.replace(/^\[/, '').replace(/\]$/, '');
  const literalFamily = isIP(literalHost);
  let settled = false;
  const request = transport.request(target, {
    method: init.method || 'POST',
    headers: init.headers,
    lookup: guardedLookup(allowPrivate),
    servername: literalFamily ? '' : target.hostname,
    ...(literalFamily ? { checkServerIdentity: (_hostname, cert) => tls.checkServerIdentity(literalHost, cert) } : {}),
  });
  const timer = setTimeout(() => {
    request.destroy(new WebhookError(`webhook request timed out after ${REQUEST_TIMEOUT_MS}ms`, true));
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
      request.destroy(new WebhookError('webhook request timed out', true));
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
    throw new WebhookError('webhook target must be https:// (or http:// with ALLOW_INSECURE_WEBHOOK=true)');
  }
  // Literal-IP hosts skip the socket lookup, so they are gated here. WHATWG
  // hostnames keep their brackets for IPv6 ([::1]); strip them first.
  const literalHost = target.hostname.replace(/^\[/, '').replace(/\]$/, '');
  if (!allowPrivate && isIP(literalHost) && isBlockedAddress(literalHost)) {
    throw new WebhookError('webhook target address is not globally routable (set ALLOW_PRIVATE_WEBHOOK=true to override)');
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
    throw new WebhookError(`webhook redirect (${response.status}) not followed`);
  }
  if (response.status < 200 || response.status >= 300) {
    const retryable = response.status === 408 || response.status === 429
      || (response.status >= 500 && response.status <= 599);
    throw new WebhookError(`webhook endpoint answered ${response.status}`, retryable);
  }
  return response.status;
};

// Delivery is fire-and-forget: callers never await this. Transient failures
// use a jittered 1s/5s/30s/2m/10m backoff and then the event is dropped;
// receivers dedupe on eventId and reconcile seq gaps by polling client state.
const deliver = async (config, {
  fetchImpl,
  delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now = () => Date.now(),
  random = Math.random,
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
      const code = err.code || (err.cause && err.cause.code) || '';
      const transientNetworkError = [
        'EAI_AGAIN', 'ECONNABORTED', 'ECONNREFUSED', 'ECONNRESET',
        'EHOSTUNREACH', 'ENETDOWN', 'ENETUNREACH', 'EPIPE', 'ETIMEDOUT',
      ].includes(code);
      const tlsError = code.startsWith('CERT_')
        || code.startsWith('ERR_SSL_')
        || code.startsWith('ERR_TLS_')
        || ['DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN',
          'UNABLE_TO_GET_ISSUER_CERT', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
          'UNABLE_TO_VERIFY_LEAF_SIGNATURE'].includes(code);
      const retryable = !tlsError && (err.retryable === true || transientNetworkError);
      if (!retryable || attempt === RETRY_DELAYS_MS.length) return false;
      // Only the delay is awaited; nothing here ever blocks a caller.
      const jitter = 0.8 + (0.4 * random());
      await delay(Math.round(RETRY_DELAYS_MS[attempt] * jitter));
    }
  }
  return false;
};

module.exports = {
  signPayload, deliver, isBlockedAddress, RETRY_DELAYS_MS, REQUEST_TIMEOUT_MS,
};
