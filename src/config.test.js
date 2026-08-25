/* eslint-env jest */

'use strict';

const bcrypt = require('bcryptjs');

const managedVariables = [
  'PASSWORD',
  'PASSWORD_HASH',
  'SESSION_SECRET',
  'ALLOW_INSECURE_NO_AUTH',
  'WEBUI_HOST',
  'TRUSTED_PROXY_IP',
  'UI_TRAFFIC_STATS',
  'UI_CHART_TYPE',
  'WG_HOST',
  'WG_DEFAULT_DNS',
  'WG_ALLOWED_IPS',
];
const originalEnvironment = { ...process.env };

const loadConfig = (environment = {}) => {
  for (const key of managedVariables) delete process.env[key];
  Object.assign(process.env, environment);
  jest.resetModules();
  return require('./config'); // eslint-disable-line global-require
};

afterAll(() => {
  process.env = originalEnvironment;
});

describe('environment validation', () => {
  const secret = '0123456789abcdef0123456789abcdef';

  it('fails closed without a password hash', () => {
    const config = loadConfig({ SESSION_SECRET: secret });
    expect(() => config.validateEnvironment()).toThrow(/PASSWORD_HASH is required/);
  });

  it('only permits explicit passwordless mode on loopback', () => {
    const local = loadConfig({
      SESSION_SECRET: secret,
      ALLOW_INSECURE_NO_AUTH: 'true',
      WEBUI_HOST: '127.0.0.1',
    });
    expect(() => local.validateEnvironment()).not.toThrow();

    const exposed = loadConfig({
      SESSION_SECRET: secret,
      ALLOW_INSECURE_NO_AUTH: 'true',
      WEBUI_HOST: '0.0.0.0',
    });
    expect(() => exposed.validateEnvironment()).toThrow(/PASSWORD_HASH is required/);
  });

  it('requires a valid bcrypt cost and persistent session secret', () => {
    const weakHash = loadConfig({
      SESSION_SECRET: secret,
      PASSWORD_HASH: bcrypt.hashSync('secret', 4),
    });
    expect(() => weakHash.validateEnvironment()).toThrow(/cost 10-15/);

    const shortSecret = loadConfig({
      SESSION_SECRET: 'short',
      PASSWORD_HASH: bcrypt.hashSync('secret', 10),
    });
    expect(() => shortSecret.validateEnvironment()).toThrow(/at least 32 bytes/);
  });

  it('normalizes UI settings to safe types', () => {
    const config = loadConfig({ UI_TRAFFIC_STATS: 'false', UI_CHART_TYPE: '99' });
    expect(config.UI_TRAFFIC_STATS).toBe(false);
    expect(config.UI_CHART_TYPE).toBe(0);
  });

  it('rejects control characters in settings that reach generated config', () => {
    const settings = [
      ['WG_HOST', 'vpn.example.test\t'],
      ['WG_DEFAULT_DNS', '1.1.1.1\x00'],
      ['WG_ALLOWED_IPS', '0.0.0.0/0\r, ::/0'],
    ];
    for (const [name, value] of settings) {
      const config = loadConfig({
        SESSION_SECRET: secret,
        PASSWORD_HASH: bcrypt.hashSync('secret', 10),
        [name]: value,
      });
      // eslint-disable-next-line no-loop-func
      expect(() => config.validateEnvironment()).toThrow(`${name} must not contain control characters`);
    }
  });

  it('accepts ordinary, Unicode and hook-style values at startup', () => {
    const config = loadConfig({
      SESSION_SECRET: secret,
      PASSWORD_HASH: bcrypt.hashSync('secret', 10),
      WG_HOST: 'vpn.ünicöde-ejemplo.test',
      WG_DEFAULT_DNS: '1.1.1.1, 1.0.0.1',
      WG_ALLOWED_IPS: '0.0.0.0/0, ::/0',
      WG_PRE_UP: 'echo "pre-up\twith controls"; true',
      WG_POST_UP: 'iptables -A FORWARD -j ACCEPT\nip6tables -A FORWARD -j ACCEPT',
    });
    expect(() => config.validateEnvironment()).not.toThrow();
  });
});
