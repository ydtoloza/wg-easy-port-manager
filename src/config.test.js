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
  'TRAFFIC_POLL_MS',
  'TRAFFIC_SAMPLES',
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
});
