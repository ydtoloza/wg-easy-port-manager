/* eslint-env jest */

'use strict';

const crypto = require('node:crypto');
const dns = require('node:dns');
const EventEmitter = require('node:events');
const https = require('node:https');
const {
  signPayload, deliver, isBlockedAddress, RETRY_DELAYS_MS,
} = require('./Webhook');

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
      { url: 'http://example.test:9000/hook', secret: 's', body: '{}' },
      { fetchImpl, delay: async () => {} },
    );
    expect(denied).toBe(false);
    expect(fetchImpl).not.toHaveBeenCalled();

    const allowed = await deliver(
      {
        url: 'http://example.test:9000/hook', secret: 's', body: '{}', allowInsecure: true,
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

  describe('connect-time SSRF gate', () => {
    it.each([
      ['127.0.0.1', true], ['127.200.1.1', true],
      ['0.0.0.0', true], ['0.1.2.3', true],
      ['10.0.0.5', true], ['172.16.0.1', true], ['172.31.255.255', true],
      ['192.168.1.1', true],
      ['169.254.169.254', true], ['169.254.0.1', true],
      ['::1', true], ['fe80::1', true], ['fc00::1', true], ['fd42:42:42::2', true],
      ['::ffff:127.0.0.1', true], ['::ffff:10.0.0.5', true],
      ['203.0.113.9', false], ['8.8.8.8', false],
      ['172.32.0.1', false], ['172.15.255.255', false],
      ['2606:4700::1111', false], ['2001:db8::1', false],
    ])('classifies %s as blocked=%s', (address, expected) => {
      expect(isBlockedAddress(address)).toBe(expected);
    });

    it('rejects literal loopback/link-local/metadata targets before any request', async () => {
      const fetchImpl = jest.fn(async () => okResponse());
      for (const url of [
        'https://127.0.0.1/hook',
        'https://169.254.169.254/hook',
        'https://[::1]/hook',
        'https://[::ffff:127.0.0.1]/hook',
      ]) {
        const delivered = await deliver({ url, secret: 's', body: '{}' }, { fetchImpl, delay: async () => {} });
        expect(delivered).toBe(false);
      }
      expect(fetchImpl).not.toHaveBeenCalled();
    });

    it('allows literal private targets only with the explicit opt-in', async () => {
      const fetchImpl = jest.fn(async () => okResponse());
      const allowed = await deliver(
        {
          url: 'https://10.0.0.5/hook', secret: 's', body: '{}', allowPrivate: true,
        },
        { fetchImpl, delay: async () => {} },
      );
      expect(allowed).toBe(true);
      expect(fetchImpl).toHaveBeenCalledTimes(1);
    });

    it('rejects hostnames that resolve into private ranges at connect time', async () => {
      const lookupSpy = jest.spyOn(dns, 'lookup').mockImplementation((hostname, options, callback) => {
        callback(null, [{ address: '10.0.0.5', family: 4 }]);
      });
      try {
        // No fetchImpl injected: the default transport runs with the guarded
        // lookup, which must fail the socket before any connect succeeds.
        const delivered = await deliver(
          { url: 'https://internal.example/hook', secret: 's', body: '{}' },
          { delay: async () => {} },
        );
        expect(delivered).toBe(false);
      } finally {
        lookupSpy.mockRestore();
      }
    });

    it('pins a public resolution for the connect', async () => {
      const lookupSpy = jest.spyOn(dns, 'lookup').mockImplementation((hostname, options, callback) => {
        callback(null, [{ address: '203.0.113.10', family: 4 }]);
      });
      const requestSpy = jest.spyOn(https, 'request').mockImplementation(() => {
        const fake = new EventEmitter();
        fake.end = () => {
          process.nextTick(() => fake.emit('response', { statusCode: 200, resume: () => {} }));
        };
        fake.destroy = () => {};
        return fake;
      });
      try {
        const delivered = await deliver(
          { url: 'https://receiver.example/hook', secret: 's', body: '{}' },
          { delay: async () => {} },
        );
        expect(delivered).toBe(true);
        expect(requestSpy).toHaveBeenCalledTimes(1);
        const [target, options] = requestSpy.mock.calls[0];
        expect(String(target)).toBe('https://receiver.example/hook');
        // the pin lives inside the connect path, and TLS still sees the hostname
        expect(typeof options.lookup).toBe('function');
        expect(options.servername).toBe('receiver.example');
      } finally {
        lookupSpy.mockRestore();
        requestSpy.mockRestore();
      }
    });
  });
});
