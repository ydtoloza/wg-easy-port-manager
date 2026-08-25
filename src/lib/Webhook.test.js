/* eslint-env jest */

'use strict';

const crypto = require('node:crypto');
const dns = require('node:dns');
const EventEmitter = require('node:events');
const https = require('node:https');
const tls = require('node:tls');
const {
  signPayload, deliver, isBlockedAddress, RETRY_DELAYS_MS, REQUEST_TIMEOUT_MS,
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

  it('rejects embedded URL credentials before transport', async () => {
    const fetchImpl = jest.fn(async () => okResponse());
    expect(await deliver(
      { url: 'https://user:password@example.test/hook', secret: 's', body: '{}' },
      { fetchImpl, delay: async () => {} },
    )).toBe(false);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('does not retry redirects', async () => {
    const fetchImpl = jest.fn(async () => new Response('', { status: 302, headers: { Location: 'http://127.0.0.1/x' } }));
    const delivered = await deliver(
      { url: 'https://example.test/hook', secret: 's', body: '{}' },
      { fetchImpl, delay: async () => {} },
    );
    expect(delivered).toBe(false);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('retries transient network failures with deterministic jitter and then drops', async () => {
    const delays = [];
    const fetchImpl = jest.fn(async () => {
      const error = new Error('endpoint down');
      error.code = 'ECONNRESET';
      throw error;
    });
    const delivered = await deliver(
      { url: 'https://example.test/hook', secret: 's', body: '{}' },
      { fetchImpl, delay: async (ms) => delays.push(ms), random: () => 0.5 },
    );
    expect(delivered).toBe(false);
    expect(delays).toEqual(RETRY_DELAYS_MS);
    expect(fetchImpl).toHaveBeenCalledTimes(RETRY_DELAYS_MS.length + 1);
  });

  it('succeeds on a later attempt after early failures', async () => {
    let calls = 0;
    const fetchImpl = jest.fn(async () => {
      calls += 1;
      if (calls < 3) {
        const error = new Error('flaky');
        error.code = 'EAI_AGAIN';
        throw error;
      }
      return okResponse();
    });
    const delivered = await deliver(
      { url: 'https://example.test/hook', secret: 's', body: '{}' },
      { fetchImpl, delay: async () => {} },
    );
    expect(delivered).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it.each([400, 401, 403, 404, 409, 422])('does not retry permanent HTTP %s responses', async (status) => {
    const fetchImpl = jest.fn(async () => new Response('', { status }));
    expect(await deliver(
      { url: 'https://example.test/hook', secret: 's', body: '{}' },
      { fetchImpl, delay: async () => {} },
    )).toBe(false);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it.each([408, 429, 500, 502, 503, 599])('retries transient HTTP %s responses', async (status) => {
    const fetchImpl = jest.fn(async () => new Response('', { status }));
    expect(await deliver(
      { url: 'https://example.test/hook', secret: 's', body: '{}' },
      { fetchImpl, delay: async () => {}, random: () => 0.5 },
    )).toBe(false);
    expect(fetchImpl).toHaveBeenCalledTimes(RETRY_DELAYS_MS.length + 1);
  });

  it.each(['CERT_HAS_EXPIRED', 'ERR_TLS_CERT_ALTNAME_INVALID', 'DEPTH_ZERO_SELF_SIGNED_CERT'])('does not retry TLS failure %s', async (code) => {
    const fetchImpl = jest.fn(async () => {
      const error = new Error('TLS validation failed');
      error.code = code;
      throw error;
    });
    expect(await deliver(
      { url: 'https://example.test/hook', secret: 's', body: '{}' },
      { fetchImpl, delay: async () => {} },
    )).toBe(false);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('does not retry policy, malformed-target or unknown failures', async () => {
    const fetchImpl = jest.fn(async () => {
      throw new Error('unexpected');
    });
    expect(await deliver(
      { url: 'http://example.test/hook', secret: 's', body: '{}' },
      { fetchImpl, delay: async () => {} },
    )).toBe(false);
    expect(await deliver(
      { url: 'not a URL', secret: 's', body: '{}' },
      { fetchImpl, delay: async () => {} },
    )).toBe(false);
    expect(await deliver(
      { url: 'https://example.test/hook', secret: 's', body: '{}' },
      { fetchImpl, delay: async () => {} },
    )).toBe(false);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('keeps retry jitter within plus or minus twenty percent', async () => {
    const fetchImpl = jest.fn(async () => {
      const error = new Error('timeout');
      error.code = 'ETIMEDOUT';
      throw error;
    });
    const low = [];
    const high = [];
    await deliver(
      { url: 'https://example.test/hook', secret: 's', body: '{}' },
      { fetchImpl, delay: async (ms) => low.push(ms), random: () => 0 },
    );
    await deliver(
      { url: 'https://example.test/hook', secret: 's', body: '{}' },
      { fetchImpl, delay: async (ms) => high.push(ms), random: () => 1 },
    );
    expect(low).toEqual(RETRY_DELAYS_MS.map((ms) => Math.round(ms * 0.8)));
    expect(high).toEqual(RETRY_DELAYS_MS.map((ms) => Math.round(ms * 1.2)));
  });

  it('destroys a response whose body never ends before retrying', async () => {
    jest.useFakeTimers();
    let calls = 0;
    const requests = [];
    const requestSpy = jest.spyOn(https, 'request').mockImplementation(() => {
      calls += 1;
      const request = new EventEmitter();
      request.destroy = jest.fn((err) => request.emit('error', err));
      request.end = () => {
        const response = new EventEmitter();
        response.statusCode = 200;
        response.resume = () => {
          if (calls > 1) response.emit('end');
        };
        request.emit('response', response);
      };
      requests.push(request);
      return request;
    });
    try {
      const delivery = deliver(
        {
          url: 'https://8.8.8.8/hook', secret: 's', body: '{}', allowPrivate: true,
        },
        { delay: async () => {} },
      );
      await jest.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS);

      await expect(delivery).resolves.toBe(true);
      expect(requestSpy).toHaveBeenCalledTimes(2);
      expect(requests[0].destroy).toHaveBeenCalledWith(expect.objectContaining({ retryable: true }));
    } finally {
      requestSpy.mockRestore();
      jest.useRealTimers();
    }
  });

  describe('connect-time SSRF gate', () => {
    it.each([
      ['127.0.0.1', true], ['127.200.1.1', true],
      ['0.0.0.0', true], ['0.1.2.3', true],
      ['10.0.0.5', true], ['172.16.0.1', true], ['172.31.255.255', true],
      ['192.168.1.1', true],
      ['100.64.0.1', true], ['100.127.255.254', true],
      ['192.0.2.1', true], ['198.18.0.1', true], ['198.51.100.1', true],
      ['203.0.113.9', true], ['224.0.0.1', true], ['255.255.255.255', true],
      ['169.254.169.254', true], ['169.254.0.1', true],
      ['::1', true], ['fe80::1', true], ['fc00::1', true], ['fd42:42:42::2', true],
      ['::ffff:127.0.0.1', true], ['::ffff:10.0.0.5', true],
      ['::ffff:8.8.8.8', true], ['::ffff:0:8.8.8.8', true],
      ['64:ff9b::808:808', true], ['64:ff9b:1::808:808', true],
      ['100::1', true], ['2001:2::1', true], ['2001:db8::1', true],
      ['2002:0808:0808::1', true], ['3fff::1', true], ['ff02::1', true],
      ['8.8.8.8', false], ['192.0.0.9', false], ['192.0.0.10', false],
      ['172.32.0.1', false], ['172.15.255.255', false],
      ['2606:4700::1111', false], ['2001:4860:4860::8888', false],
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

    it('rejects literal non-global targets without retrying', async () => {
      const fetchImpl = jest.fn(async () => okResponse());
      const delays = [];
      expect(await deliver(
        { url: 'https://203.0.113.9/hook', secret: 's', body: '{}' },
        { fetchImpl, delay: async (ms) => delays.push(ms) },
      )).toBe(false);
      expect(fetchImpl).not.toHaveBeenCalled();
      expect(delays).toEqual([]);
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
        expect(lookupSpy).toHaveBeenCalledTimes(1);
      } finally {
        lookupSpy.mockRestore();
      }
    });

    it('pins a public resolution for the connect', async () => {
      const lookupSpy = jest.spyOn(dns, 'lookup').mockImplementation((hostname, options, callback) => {
        callback(null, [{ address: '8.8.8.8', family: 4 }]);
      });
      const requestSpy = jest.spyOn(https, 'request').mockImplementation((target, options) => {
        const fake = new EventEmitter();
        fake.end = () => {
          options.lookup(target.hostname, {}, (err, address, family) => {
            if (err) return fake.emit('error', err);
            fake.connectedAddress = address;
            fake.connectedFamily = family;
            const response = new EventEmitter();
            response.statusCode = 200;
            response.resume = () => response.emit('end');
            return fake.emit('response', response);
          });
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
        expect(lookupSpy).toHaveBeenCalledTimes(1);
        const request = requestSpy.mock.results[0].value;
        expect(request.connectedAddress).toBe('8.8.8.8');
        expect(request.connectedFamily).toBe(4);
      } finally {
        lookupSpy.mockRestore();
        requestSpy.mockRestore();
      }
    });

    it('suppresses SNI for HTTPS IPv6 literals and checks the unbracketed certificate IP', async () => {
      const requestSpy = jest.spyOn(https, 'request').mockImplementation(() => {
        const fake = new EventEmitter();
        fake.end = () => process.nextTick(() => {
          const response = new EventEmitter();
          response.statusCode = 200;
          response.resume = () => response.emit('end');
          fake.emit('response', response);
        });
        fake.destroy = () => {};
        return fake;
      });
      const identitySpy = jest.spyOn(tls, 'checkServerIdentity').mockReturnValue(undefined);
      try {
        expect(await deliver(
          { url: 'https://[2606:4700::1111]/hook', secret: 's', body: '{}' },
          { delay: async () => {} },
        )).toBe(true);
        const options = requestSpy.mock.calls[0][1];
        expect(options.servername).toBe('');
        options.checkServerIdentity('[2606:4700::1111]', {});
        expect(identitySpy).toHaveBeenCalledWith('2606:4700::1111', {});
      } finally {
        identitySpy.mockRestore();
        requestSpy.mockRestore();
      }
    });
  });
});
