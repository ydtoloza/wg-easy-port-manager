'use strict';

const crypto = require('node:crypto');
const debug = require('debug')('Webhook');

// At-least-once webhook delivery. Hard rules (all empirically verified in the
// v2.1 review): fetch follows redirects ACROSS schemes (a 30x from https:// to
// http://127.0.0.1 succeeds with 200) and has NO usable default timeout, so
// every request is made with redirect:'manual' and an explicit 5s abort.

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

// Attempts one delivery. 30x responses are failures (redirects are never
// followed), and only the host/status/attempt are ever logged.
const attemptOnce = async ({
  url, secret, body, allowInsecure,
}, fetchImpl) => {
  const target = new URL(url);
  if (!isAllowedScheme(target, allowInsecure)) {
    throw new Error('webhook target must be https:// (or http:// with ALLOW_INSECURE_WEBHOOK=true)');
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
  fetchImpl = (...args) => globalThis.fetch(...args),
  delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now = () => Date.now(),
} = {}) => {
  const startedAt = now();
  const host = (() => {
    try {
      return new URL(config.url).host;
    } catch {
      return 'invalid-url';
    }
  })();

  for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt += 1) {
    try {
      const status = await attemptOnce(config, fetchImpl);
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
  signPayload, deliver, RETRY_DELAYS_MS, REQUEST_TIMEOUT_MS,
};
