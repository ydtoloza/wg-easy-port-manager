/* eslint-env jest */

'use strict';

const crypto = require('node:crypto');
const { signPayload, deliver, RETRY_DELAYS_MS } = require('./Webhook');

const okResponse = () => new Response('{}', { status: 200 });

describe('Webhook', () => {
  it('signs t.v1 payloads with HMAC-SHA256 over "<t>.<body>"', () => {
    const signature = signPayload('the-secret', 1700000000, '{"v":1}');
    const expected = crypto.createHmac('sha256', 'the-secret').update('1700000000.{"v":1}').digest('hex');
    expect(signature).toBe(`t=1700000000,v1=${expected}`);
  });

  it('sends the signature header, redirect:manual and an abort signal', async () => {
    const fetchImpl = jest.fn(async () => okResponse());
    const delivered = await deliver(
      { url: 'https://example.test/hook', secret: 's', body: '{"v":1}' },
      { fetchImpl, delay: async () => {} },
    );
    expect(delivered).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe('https://example.test/hook');
    expect(init.method).toBe('POST');
    expect(init.redirect).toBe('manual');
    expect(init.signal).toBeInstanceOf(AbortSignal);
    expect(init.headers['X-WGPM-Signature']).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
  });

  it('refuses http:// targets unless explicitly allowed', async () => {
    const fetchImpl = jest.fn(async () => okResponse());
    const denied = await deliver(
      { url: 'http://127.0.0.1:9000/hook', secret: 's', body: '{}' },
      { fetchImpl, delay: async () => {} },
    );
    expect(denied).toBe(false);
    expect(fetchImpl).not.toHaveBeenCalled();

    const allowed = await deliver(
      {
        url: 'http://127.0.0.1:9000/hook', secret: 's', body: '{}', allowInsecure: true,
      },
      { fetchImpl, delay: async () => {} },
    );
    expect(allowed).toBe(true);
  });

  it('treats a redirect to an internal http target as a failure', async () => {
    const fetchImpl = jest.fn(async () => new Response('', { status: 302, headers: { Location: 'http://127.0.0.1/x' } }));
    const delivered = await deliver(
      { url: 'https://example.test/hook', secret: 's', body: '{}' },
      { fetchImpl, delay: async () => {} },
    );
    expect(delivered).toBe(false);
    // one attempt per retry slot, then dropped
    expect(fetchImpl).toHaveBeenCalledTimes(RETRY_DELAYS_MS.length + 1);
  });

  it('retries with the 1s/5s/30s/2m/10m backoff and then drops', async () => {
    const delays = [];
    const fetchImpl = jest.fn(async () => {
      throw new Error('endpoint down');
    });
    const delivered = await deliver(
      { url: 'https://example.test/hook', secret: 's', body: '{}' },
      { fetchImpl, delay: async (ms) => delays.push(ms) },
    );
    expect(delivered).toBe(false);
    expect(delays).toEqual(RETRY_DELAYS_MS);
    expect(fetchImpl).toHaveBeenCalledTimes(RETRY_DELAYS_MS.length + 1);
  });

  it('succeeds on a later attempt after early failures', async () => {
    let calls = 0;
    const fetchImpl = jest.fn(async () => {
      calls += 1;
      if (calls < 3) throw new Error('flaky');
      return okResponse();
    });
    const delivered = await deliver(
      { url: 'https://example.test/hook', secret: 's', body: '{}' },
      { fetchImpl, delay: async () => {} },
    );
    expect(delivered).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });
});
