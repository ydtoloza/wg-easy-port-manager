'use strict';

const fs = require('node:fs/promises');
const path = require('path');
const debug = require('debug')('WireGuard');
const crypto = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');
const net = require('node:net');
const QRCode = require('qrcode');
const Webhook = require('./Webhook');
const { parseDnatRules, rulePresent: dnatRulePresent } = require('./NftRules');

const Util = require('./Util');
const ServerError = require('./ServerError');
const {
  MAX_CUSTOM_RULES,
  PROTOCOL_PRESETS,
  PROTOCOL_PRESET_IDS,
  createDefaultNetworkPolicy,
  getProtocolPresets,
} = require('./NetworkPolicy');

const {
  WG_PATH,
  WG_HOST,
  WG_PORT,
  WG_CONFIG_PORT,
  WG_DEVICE,
  WG_MTU,
  WG_DEFAULT_DNS,
  WG_DEFAULT_ADDRESS,
  WG_DEFAULT_ADDRESS_V6,
  WG_PERSISTENT_KEEPALIVE,
  WG_ALLOWED_IPS,
  WG_PRE_UP,
  WG_POST_UP,
  WG_PRE_DOWN,
  WG_POST_DOWN,
  WG_PORT_FWD_MIN,
  WG_PORT_FWD_MAX,
  WG_NFT_MASQUERADE,
  WG_SEED_TUNING,
  ALLOW_INSECURE_WEBHOOK,
} = require('../config');

const WIREGUARD_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;
const TOKEN_HASH_RE = /^[0-9a-f]{64}$/;
const sha256Hex = (value) => crypto.createHash('sha256').update(value).digest('hex');
const CLIENT_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const RESERVED_CLIENT_IDS = new Set(['__proto__', 'constructor', 'prototype']);
const SERVER_SETTING_KEYS = ['host', 'port', 'configPort', 'device', 'defaultDns',
  'defaultAddress', 'defaultAddressV6', 'enableIpv6', 'mtu', 'allowedIps',
  'persistentKeepalive', 'portFwdMin', 'portFwdMax', 'forwardingEnabled'];
// Settings that must never be echoed by the server-config API. None of the
// current settings are secret, but when new secret-bearing settings are added
// to SERVER_SETTING_KEYS (e.g. v2.1 webhook/Bearer secrets) they MUST be
// listed here so GET/PUT responses cannot leak them.
const HIDDEN_SERVER_SETTING_KEYS = new Set(['webhookSecret', 'webhookUrl', 'tokenHash', 'tokenCreatedAt']);

const serializeServerSettingsPublic = (settings) => Object.fromEntries(
  Object.entries(settings).filter(([key]) => SERVER_SETTING_KEYS.includes(key)
    && !HIDDEN_SERVER_SETTING_KEYS.has(key)),
);

const isPlainObject = (value) => value !== null
  && typeof value === 'object'
  && !Array.isArray(value);

const isValidDate = (value) => (value instanceof Date && !Number.isNaN(value.getTime()))
  || (typeof value === 'string' && !Number.isNaN(Date.parse(value)));

const expandIPv6 = (address) => {
  if (typeof address !== 'string' || address.includes('.')) return null;
  const halves = address.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const expanded = [...left, ...Array(missing).fill('0'), ...right];
  return expanded.length === 8 ? expanded.map((part) => part.padStart(4, '0').toLowerCase()) : null;
};

const isSameIPv6Subnet64 = (first, second) => {
  const firstParts = expandIPv6(first);
  const secondParts = expandIPv6(second);
  return !!firstParts && !!secondParts
    && firstParts.slice(0, 4).join(':') === secondParts.slice(0, 4).join(':');
};

const DUMMY_CLIENT_PREVIEW = {
  id: 'dummy-client-preview',
  name: 'Preview Client (Local)',
  address: '10.8.0.2',
  addressV6: 'fd42:42:42::2',
  enabled: true,
  createdAt: new Date(),
  updatedAt: new Date(),
  transferRx: 1024 * 1024 * 500,
  transferTx: 1024 * 1024 * 120,
  allowedIPs: ['10.8.0.2/32', 'fd42:42:42::2/128'],
  publicKey: 'mockPublicKey=',
  downloadableConfig: false,
  persistentKeepalive: null,
  latestHandshakeAt: new Date(),
  portForwards: [
    { proto: 'tcp', extPort: 8080, intPort: 80 },
    { proto: 'udp', extPort: 27015, intPort: 27015 },
  ],
  networkPolicy: createDefaultNetworkPolicy(),
};

// Tracks which WireGuard instance's mutation is currently executing so that
// re-entrant __withMutation calls (the deadlock pattern) can be told apart
// from unrelated callers enqueueing work while a mutation runs.
const mutationContext = new AsyncLocalStorage();

module.exports = class WireGuard {

  constructor() {
    // Runtime-mutable server settings (seeded from env vars)
    this.__serverSettings = {
      host: WG_HOST,
      port: Number(WG_PORT),
      configPort: Number(WG_CONFIG_PORT),
      device: WG_DEVICE,
      defaultDns: WG_DEFAULT_DNS,
      defaultAddress: WG_DEFAULT_ADDRESS,
      defaultAddressV6: WG_DEFAULT_ADDRESS_V6,
      enableIpv6: true,
      mtu: WG_MTU,
      allowedIps: WG_ALLOWED_IPS,
      persistentKeepalive: Number(WG_PERSISTENT_KEEPALIVE),
      portFwdMin: Number(WG_PORT_FWD_MIN),
      portFwdMax: Number(WG_PORT_FWD_MAX),
      // Kill-switch: when false, no DNAT rules are emitted at all (the
      // forwarding config itself is preserved). Tolerant migration: settings
      // files written before this key existed keep the default.
      forwardingEnabled: true,
    };
    this.__config = null;
    this.__initPromise = null;
    this.__buildPromise = null;
    this.__mutationQueue = Promise.resolve();
    this.__activeMutation = false;
    this.__settingsRecoveryPending = false;
    this.__settingsRecoveryConfig = null;
    this.__webhookConfig = null;
    this.__eventSeq = null;
    this.__probeState = new Map(); // key: `${clientId}:${ruleKey}` -> { lastAt, inFlight }
  }

  // Serializes every state change (and read snapshots, see the public read
  // methods) behind a single promise chain. A queued operation that re-enters
  // this method would await its own tail and hang every future mutation, so
  // re-entrancy from inside a running operation is rejected (external callers
  // may keep enqueueing while an operation runs).
  __withMutation(operation) {
    if (mutationContext.getStore() === this) {
      return Promise.reject(new ServerError(
        'Concurrent mutation re-entrancy detected: use the internal (__-prefixed) variant inside queued operations',
        500,
      ));
    }
    const run = this.__mutationQueue.then(async () => mutationContext.run(this, operation));
    this.__mutationQueue = run.catch(() => {});
    return run;
  }

  async waitForMutations() {
    // Drain to quiescence: operations enqueued while we are awaiting must also
    // settle (Shutdown downs the interface right after this resolves).
    let tail = this.__mutationQueue;
    for (;;) {
      await tail;
      if (this.__mutationQueue === tail) return;
      tail = this.__mutationQueue;
    }
  }

  __normalizeServerSettings(settings, base = this.__serverSettings, strict = false) {
    if (!isPlainObject(settings)) {
      throw new ServerError('Invalid server settings: expected an object', 400);
    }
    if (strict) {
      const unknown = Object.keys(settings).filter((key) => !SERVER_SETTING_KEYS.includes(key));
      if (unknown.length) throw new ServerError(`Invalid server settings: unknown field ${unknown[0]}`, 400);
    }

    const isPort = (value) => Number.isInteger(Number(value)) && Number(value) >= 1 && Number(value) <= 65535;
    const isPlainString = (value) => typeof value === 'string' && !/[\r\n]/.test(value);
    const isIPv4Template = (value) => typeof value === 'string'
      && value.split('.').length === 4
      && value.split('.')[3] === 'x'
      && Util.isValidIPv4(value.replace('x', '1'));
    const isIPv6Template = (value) => typeof value === 'string'
      && (value.match(/x/g) || []).length === 1
      && Util.isValidIPv6(value.replace('x', '1'))
      && Util.isValidIPv6(value.replace('x', '2'))
      && isSameIPv6Subnet64(value.replace('x', '1'), value.replace('x', '2'));
    const validators = {
      host: (value) => isPlainString(value) && value.length > 0 && value.length <= 255,
      port: isPort,
      configPort: isPort,
      device: (value) => typeof value === 'string' && /^[A-Za-z0-9_.-]+$/.test(value),
      defaultDns: (value) => isPlainString(value) && value.length <= 255,
      defaultAddress: isIPv4Template,
      defaultAddressV6: isIPv6Template,
      enableIpv6: (value) => typeof value === 'boolean',
      mtu: (value) => value === null || (Number.isInteger(Number(value)) && Number(value) >= 576 && Number(value) <= 65535),
      allowedIps: (value) => isPlainString(value) && value.length > 0 && value.length <= 255,
      persistentKeepalive: (value) => value === null
        || (Number.isInteger(Number(value)) && Number(value) >= 0 && Number(value) <= 65535),
      portFwdMin: isPort,
      portFwdMax: isPort,
      forwardingEnabled: (value) => typeof value === 'boolean',
    };
    const normalized = { ...base };

    for (const key of SERVER_SETTING_KEYS) {
      if (settings[key] === undefined) continue;
      if (!validators[key](settings[key])) {
        throw new ServerError(`Invalid value for ${key}`, 400);
      }
      normalized[key] = settings[key];
    }
    for (const key of ['port', 'configPort', 'mtu', 'persistentKeepalive', 'portFwdMin', 'portFwdMax']) {
      if (normalized[key] !== null && normalized[key] !== undefined) {
        normalized[key] = Number(normalized[key]);
      }
    }
    if (normalized.portFwdMin > normalized.portFwdMax) {
      throw new ServerError('portFwdMin cannot be greater than portFwdMax', 400);
    }
    return normalized;
  }

  async __loadServerSettings() {
    let raw;
    try {
      raw = await fs.readFile(path.join(WG_PATH, 'server-settings.json'), 'utf8');
    } catch (err) {
      if (err.code !== 'ENOENT') {
        throw new Error(`Failed to read server-settings.json: ${err.message}`);
      }
    }

    let saved = null;
    if (raw !== undefined) {
      try {
        saved = JSON.parse(raw);
      } catch (err) {
        throw new Error(`server-settings.json is invalid JSON: ${err.message}`);
      }
      this.__serverSettings = this.__normalizeServerSettings(saved, this.__serverSettings, true);
      saved = this.__serverSettings;
      debug('Server settings loaded from disk.');
    }

    let transactionRaw;
    try {
      transactionRaw = await fs.readFile(path.join(WG_PATH, 'server-settings.transaction.json'), 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') return;
      throw new Error(`Failed to read server settings transaction: ${err.message}`);
    }
    let transaction;
    try {
      transaction = JSON.parse(transactionRaw);
    } catch (err) {
      throw new Error(`server settings transaction is invalid JSON: ${err.message}`);
    }
    if (!isPlainObject(transaction)
      || Object.keys(transaction).some((key) => !['previous', 'candidate', 'previousConfig', 'candidateConfig'].includes(key))
      || !isPlainObject(transaction.previousConfig)
      || !isPlainObject(transaction.candidateConfig)) {
      throw new Error('server settings transaction has an invalid structure');
    }
    const previous = this.__normalizeServerSettings(transaction.previous, this.__serverSettings, true);
    const candidate = this.__normalizeServerSettings(transaction.candidate, this.__serverSettings, true);
    const candidateWasCommitted = saved && SERVER_SETTING_KEYS
      .every((key) => saved[key] === candidate[key]);
    this.__serverSettings = candidateWasCommitted ? candidate : previous;
    this.__settingsRecoveryConfig = candidateWasCommitted
      ? transaction.candidateConfig
      : transaction.previousConfig;
    this.__settingsRecoveryPending = true;
    debug(`Recovering ${candidateWasCommitted ? 'committed' : 'rolled back'} server settings transaction.`);
  }

  async __syncDirectory() {
    const directory = await fs.open(WG_PATH, 'r');
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  }

  async __writeAtomic(filename, contents, mode) {
    const target = path.join(WG_PATH, filename);
    const temporary = `${target}.${crypto.randomUUID()}.tmp`;
    let handle;
    try {
      handle = await fs.open(temporary, 'w', mode);
      await handle.writeFile(contents);
      await handle.sync();
      await handle.close();
      handle = null;
      await fs.rename(temporary, target);
      await this.__syncDirectory();
    } catch (err) {
      if (handle) await handle.close().catch(() => {});
      await fs.unlink(temporary).catch(() => {});
      throw err;
    }
  }

  async __saveServerSettings(settings = this.__serverSettings) {
    await this.__writeAtomic('server-settings.json', JSON.stringify(settings, null, 2), 0o600);
  }

  async __saveSettingsTransaction(previous, candidate, previousConfig, candidateConfig) {
    await this.__writeAtomic(
      'server-settings.transaction.json',
      JSON.stringify({
        previous, candidate, previousConfig, candidateConfig,
      }, null, 2),
      0o600,
    );
  }

  async __completeSettingsTransaction() {
    await this.__saveServerSettings();
    await fs.unlink(path.join(WG_PATH, 'server-settings.transaction.json')).catch((err) => {
      if (err.code !== 'ENOENT') throw err;
    });
    await this.__syncDirectory();
    this.__settingsRecoveryPending = false;
    this.__settingsRecoveryConfig = null;
    this.__webhookConfig = null;
    this.__eventSeq = null;
    this.__probeState = new Map(); // key: `${clientId}:${ruleKey}` -> { lastAt, inFlight }
  }

  async __buildConfig() {
    if (this.__config) return this.__config;

    await this.__loadServerSettings();
    await this.__loadWebhookConfig();

    if (!this.__serverSettings.host) {
      throw new Error('WG_HOST Environment Variable Not Set!');
    }

    debug('Loading configuration...');
    let raw;
    try {
      raw = await fs.readFile(path.join(WG_PATH, 'wg0.json'), 'utf8');
    } catch (err) {
      if (err.code !== 'ENOENT') {
        throw new Error(`Failed to read wg0.json: ${err.message}`);
      }
    }

    let config;
    if (raw === undefined) {
      let privateKey;
      let publicKey;
      if (process.platform !== 'linux') {
        privateKey = crypto.randomBytes(32).toString('base64');
        publicKey = crypto.randomBytes(32).toString('base64');
      } else {
        privateKey = await Util.exec('wg genkey');
        publicKey = await Util.execFile('wg', ['pubkey'], { input: `${privateKey}\n`, log: 'wg pubkey' });
      }
      const address = this.__serverSettings.defaultAddress.replace('x', '1');
      const addressV6 = this.__serverSettings.enableIpv6 ? this.__serverSettings.defaultAddressV6.replace('x', '1') : null;

      config = {
        server: {
          privateKey,
          publicKey,
          address,
          addressV6,
        },
        clients: {},
      };
      debug('Configuration generated.');
    } else {
      try {
        config = JSON.parse(raw);
      } catch (err) {
        throw new Error(`wg0.json is invalid JSON and was not overwritten: ${err.message}`);
      }
      debug('Configuration loaded.');
    }

    if (this.__settingsRecoveryConfig) {
      config = this.__settingsRecoveryConfig;
    }

    if (!isPlainObject(config) || !isPlainObject(config.server) || !isPlainObject(config.clients)) {
      throw new Error('wg0.json has an invalid structure and was not overwritten.');
    }

    // Migrate fields introduced after the initial configuration format.
    for (const [clientId, client] of Object.entries(config.clients)) {
      if (!isPlainObject(client)) throw new Error(`Invalid client entry: ${clientId}`);
      if (client.id === undefined || client.id === null) client.id = clientId;
      if (client.enabled === undefined || client.enabled === null) client.enabled = true;
      if (client.preSharedKey === '' || client.preSharedKey === undefined) client.preSharedKey = null;
      if (client.privateKey === '' || client.privateKey === undefined) delete client.privateKey;
      if (client.createdAt === undefined || client.createdAt === null || !isValidDate(client.createdAt)) {
        client.createdAt = new Date().toISOString();
      }
      if (client.updatedAt === undefined || client.updatedAt === null || !isValidDate(client.updatedAt)) {
        client.updatedAt = new Date().toISOString();
      }
      if (!Array.isArray(client.portForwards)) {
        client.portForwards = [];
      }
      // Stable rule ids: every rule gets one at creation; migrate old configs
      // by healing MISSING ids. A present-but-malformed id is corruption and
      // fails validation below rather than being silently re-addressed.
      for (const rule of client.portForwards) {
        if (isPlainObject(rule) && (rule.id === undefined || rule.id === null)) rule.id = crypto.randomUUID();
      }
      if (client.networkPolicy === undefined || client.networkPolicy === null) {
        client.networkPolicy = createDefaultNetworkPolicy();
      }
      client.networkPolicy = this.__normalizeNetworkPolicy(client.networkPolicy, { strict: false });

      if (client.name === undefined || client.name === null) {
        client.name = clientId;
      }
      if (!WIREGUARD_KEY_RE.test(client.publicKey || '') && WIREGUARD_KEY_RE.test(client.privateKey || '')) {
        // publicKey is deterministically derivable from privateKey.
        const derived = await Util.execFile('wg', ['pubkey'], { input: `${client.privateKey}\n`, log: 'wg pubkey' });
        if (WIREGUARD_KEY_RE.test(derived)) client.publicKey = derived;
      }
      if (client.address === undefined || client.address === null || !Util.isValidIPv4(client.address)) {
        const usedAddresses = new Set(Object.values(config.clients)
          .map((candidate) => candidate.address)
          .filter(Boolean));
        const host = Array.from({ length: 253 }, (_, offset) => offset + 2)
          .find((value) => !usedAddresses.has(this.__serverSettings.defaultAddress.replace('x', value)));
        if (host === undefined) throw new Error('Maximum number of clients reached.');
        client.address = this.__serverSettings.defaultAddress.replace('x', host);
      }
      if (client.selfManagePorts === undefined || client.selfManagePorts === null) {
        client.selfManagePorts = false;
      }
      if (client.persistentKeepalive === undefined) client.persistentKeepalive = null;
    }

    if (this.__serverSettings.enableIpv6 && !config.server.addressV6) {
      config.server.addressV6 = this.__serverSettings.defaultAddressV6.replace('x', '1');
    }
    if (this.__serverSettings.enableIpv6) {
      const usedV6 = new Set([
        config.server.addressV6,
        ...Object.values(config.clients).map((client) => client.addressV6),
      ].filter(Boolean));
      for (const client of Object.values(config.clients)) {
        if (client.addressV6) continue;
        const ipv4Host = Util.isValidIPv4(client.address) ? Number(client.address.split('.')[3]) : null;
        const candidates = ipv4Host >= 2 && ipv4Host <= 254
          ? [ipv4Host, ...Array.from({ length: 253 }, (_, index) => index + 2)]
          : Array.from({ length: 253 }, (_, index) => index + 2);
        const host = candidates.find((value) => !usedV6.has(this.__serverSettings.defaultAddressV6.replace('x', value)));
        if (host === undefined) throw new Error('Maximum number of IPv6 clients reached.');
        client.addressV6 = this.__serverSettings.defaultAddressV6.replace('x', host);
        usedV6.add(client.addressV6);
      }
    }

    this.__validateConfig(config);
    this.__config = config;
    return config;
  }

  __validateConfig(config, { strict = false } = {}) {
    if (!isPlainObject(config) || !isPlainObject(config.server) || !isPlainObject(config.clients)) {
      throw new ServerError('Invalid configuration structure', 400);
    }
    if (strict) {
      const rootUnknown = Object.keys(config).filter((key) => !['server', 'clients'].includes(key));
      const serverUnknown = Object.keys(config.server)
        .filter((key) => !['privateKey', 'publicKey', 'address', 'addressV6'].includes(key));
      if (rootUnknown.length) throw new ServerError(`Invalid configuration field: ${rootUnknown[0]}`, 400);
      if (serverUnknown.length) throw new ServerError(`Invalid server field: ${serverUnknown[0]}`, 400);
    }

    for (const key of ['privateKey', 'publicKey']) {
      if (typeof config.server[key] !== 'string' || !WIREGUARD_KEY_RE.test(config.server[key])) {
        throw new ServerError(`Invalid server.${key}`, 400);
      }
    }
    if (!Util.isValidIPv4(config.server.address)) {
      throw new ServerError(`Invalid server.address: ${config.server.address}`, 400);
    }
    if (config.server.addressV6 != null && !Util.isValidIPv6(config.server.addressV6)) {
      throw new ServerError(`Invalid server.addressV6: ${config.server.addressV6}`, 400);
    }

    const addresses = new Set([config.server.address]);
    const addressesV6 = new Set(config.server.addressV6 ? [config.server.addressV6] : []);
    const publicKeys = new Set([config.server.publicKey]);
    const forwardedPorts = new Set();
    const networkPolicies = new Map();
    const allowedClientKeys = ['id', 'name', 'address', 'addressV6', 'privateKey', 'publicKey',
      'preSharedKey', 'createdAt', 'updatedAt', 'enabled', 'portForwards', 'allowedIPs', 'networkPolicy',
      'tokenHash', 'tokenCreatedAt', 'selfManagePorts', 'persistentKeepalive'];

    for (const [clientId, client] of Object.entries(config.clients)) {
      if (!CLIENT_ID_RE.test(clientId) || RESERVED_CLIENT_IDS.has(clientId) || !isPlainObject(client)) {
        throw new ServerError(`Invalid client entry: ${clientId}`, 400);
      }
      if (strict) {
        const unknown = Object.keys(client).filter((key) => !allowedClientKeys.includes(key));
        if (unknown.length) throw new ServerError(`Invalid client field: ${unknown[0]}`, 400);
      }
      if (client.id !== clientId) throw new ServerError(`Invalid client id: ${clientId}`, 400);
      if (!Util.isValidName(client.name)) throw new ServerError(`Invalid client name: ${client.name}`, 400);
      if (typeof client.enabled !== 'boolean') throw new ServerError(`Invalid client.enabled: ${clientId}`, 400);
      if (!Util.isValidIPv4(client.address) || addresses.has(client.address)) {
        throw new ServerError(`Invalid or duplicate IPv4 address: ${client.address}`, 400);
      }
      addresses.add(client.address);
      if (client.addressV6 != null) {
        if (!Util.isValidIPv6(client.addressV6) || addressesV6.has(client.addressV6)) {
          throw new ServerError(`Invalid or duplicate IPv6 address: ${client.addressV6}`, 400);
        }
        addressesV6.add(client.addressV6);
      }
      if (typeof client.publicKey !== 'string' || !WIREGUARD_KEY_RE.test(client.publicKey)
        || publicKeys.has(client.publicKey)) {
        throw new ServerError(`Invalid or duplicate client.publicKey: ${clientId}`, 400);
      }
      publicKeys.add(client.publicKey);
      for (const key of ['privateKey', 'preSharedKey']) {
        if (client[key] != null && (typeof client[key] !== 'string' || !WIREGUARD_KEY_RE.test(client[key]))) {
          throw new ServerError(`Invalid client.${key}: ${clientId}`, 400);
        }
      }
      if (strict && (!isValidDate(client.createdAt) || !isValidDate(client.updatedAt))) {
        throw new ServerError(`Invalid client timestamps: ${clientId}`, 400);
      }
      if (client.allowedIPs !== undefined
        && (!Array.isArray(client.allowedIPs) || client.allowedIPs.some((value) => typeof value !== 'string' || /[\r\n]/.test(value)))) {
        throw new ServerError(`Invalid client.allowedIPs: ${clientId}`, 400);
      }
      if (client.tokenHash !== undefined && client.tokenHash !== null && !TOKEN_HASH_RE.test(client.tokenHash)) {
        throw new ServerError(`Invalid client.tokenHash: ${clientId}`, 400);
      }
      if (client.tokenCreatedAt !== undefined && client.tokenCreatedAt !== null && !isValidDate(client.tokenCreatedAt)) {
        throw new ServerError(`Invalid client.tokenCreatedAt: ${clientId}`, 400);
      }
      if (client.selfManagePorts !== undefined && client.selfManagePorts !== null
        && typeof client.selfManagePorts !== 'boolean') {
        throw new ServerError(`Invalid client.selfManagePorts: ${clientId}`, 400);
      }
      if (client.persistentKeepalive !== undefined && client.persistentKeepalive !== null
        && (!Number.isInteger(client.persistentKeepalive)
          || client.persistentKeepalive < 0 || client.persistentKeepalive > 65535)) {
        throw new ServerError(`Invalid client.persistentKeepalive: ${clientId}`, 400);
      }
      if (!Array.isArray(client.portForwards)) {
        throw new ServerError(`Invalid client.portForwards: ${clientId}`, 400);
      }
      networkPolicies.set(clientId, this.__normalizeNetworkPolicy(client.networkPolicy, { strict }));

      for (const rule of client.portForwards) {
        if (!isPlainObject(rule)) throw new ServerError(`Invalid port forward for ${clientId}`, 400);
        if (!Util.isValidRuleId(rule.id)) {
          throw new ServerError(`Invalid port forward id for ${clientId}`, 400);
        }
        if (strict && Object.keys(rule).some((key) => !['id', 'proto', 'extPort', 'intPort'].includes(key))) {
          throw new ServerError(`Invalid port forward field for ${clientId}`, 400);
        }
        if (!['tcp', 'udp', 'both'].includes(rule.proto)
          || !Number.isInteger(rule.extPort) || !Number.isInteger(rule.intPort)
          || rule.extPort < 1 || rule.extPort > 65535
          || rule.intPort < 1 || rule.intPort > 65535
          || !this.__isPortAllowed(rule.extPort)) {
          throw new ServerError(`Invalid port forward for ${clientId}`, 400);
        }
        const protocols = rule.proto === 'both' ? ['tcp', 'udp'] : [rule.proto];
        for (const protocol of protocols) {
          const key = `${protocol}:${rule.extPort}`;
          if (forwardedPorts.has(key)) throw new ServerError(`Duplicate forwarded port: ${key}`, 409);
          forwardedPorts.add(key);
        }
      }
    }

    for (const [clientId, policy] of networkPolicies) {
      for (const allowedId of policy.peerAllowlist) {
        if (allowedId === clientId || !Object.hasOwn(config.clients, allowedId)) {
          throw new ServerError(`Invalid peer allowlist entry for ${clientId}: ${allowedId}`, 400);
        }
        if (!networkPolicies.get(allowedId).peerAllowlist.includes(clientId)) {
          throw new ServerError(`Peer allowlist must be symmetric: ${clientId} and ${allowedId}`, 400);
        }
      }
    }
  }

  __normalizeNetworkPolicy(policy, { strict = true } = {}) {
    if (!isPlainObject(policy)) throw new ServerError('Invalid network policy: expected an object', 400);
    const allowedKeys = ['blockedProtocols', 'customRules', 'peerAllowlist'];
    if (strict) {
      const unknown = Object.keys(policy).find((key) => !allowedKeys.includes(key));
      if (unknown) throw new ServerError(`Invalid network policy field: ${unknown}`, 400);
      const missing = allowedKeys.find((key) => policy[key] === undefined);
      if (missing) throw new ServerError(`Missing network policy field: ${missing}`, 400);
    }

    const blockedProtocols = policy.blockedProtocols ?? [];
    const customRules = policy.customRules ?? [];
    const peerAllowlist = policy.peerAllowlist ?? [];
    if (!Array.isArray(blockedProtocols)
      || blockedProtocols.some((id) => typeof id !== 'string' || !PROTOCOL_PRESET_IDS.has(id))
      || new Set(blockedProtocols).size !== blockedProtocols.length) {
      throw new ServerError('Invalid blocked protocol selection', 400);
    }
    if (!Array.isArray(peerAllowlist)
      || peerAllowlist.some((id) => typeof id !== 'string' || !CLIENT_ID_RE.test(id))
      || new Set(peerAllowlist).size !== peerAllowlist.length) {
      throw new ServerError('Invalid peer allowlist', 400);
    }
    if (!Array.isArray(customRules) || customRules.length > MAX_CUSTOM_RULES) {
      throw new ServerError(`A maximum of ${MAX_CUSTOM_RULES} custom rules is allowed`, 400);
    }

    const normalizedRules = customRules.map((rule) => {
      if (!isPlainObject(rule)) throw new ServerError('Invalid custom network rule', 400);
      if (strict) {
        const unknown = Object.keys(rule).find((key) => !['proto', 'startPort', 'endPort', 'label'].includes(key));
        if (unknown) throw new ServerError(`Invalid custom network rule field: ${unknown}`, 400);
      }
      const label = rule.label ?? '';
      if (!['tcp', 'udp'].includes(rule.proto)
        || !Number.isInteger(rule.startPort) || !Number.isInteger(rule.endPort)
        || rule.startPort < 1 || rule.endPort > 65535 || rule.startPort > rule.endPort
        || typeof label !== 'string' || label.length > 64 || /[\r\n]/.test(label)) {
        throw new ServerError('Invalid custom network rule', 400);
      }
      return {
        proto: rule.proto,
        startPort: rule.startPort,
        endPort: rule.endPort,
        label,
      };
    });

    return {
      blockedProtocols: [...blockedProtocols],
      customRules: normalizedRules,
      peerAllowlist: [...peerAllowlist],
    };
  }

  async getConfig() {
    if (!this.__config) {
      // Memoize the build so concurrent first calls cannot each generate a
      // (different) server keypair on a fresh install.
      if (!this.__buildPromise) {
        this.__buildPromise = this.__buildConfig().finally(() => {
          this.__buildPromise = null;
        });
      }
      await this.__buildPromise;
    }
    return this.__config;
  }

  async init() {
    if (this.__initPromise) return this.__initPromise;

    this.__initPromise = (async () => {
      const config = await this.getConfig();

      // Down reads the currently active wg0.conf. Replace it only afterwards.
      await this.__bringWireGuardDown();
      await this.__saveConfig(config);
      await this.__ensureNftablesSetup();
      await this.__applyAllNetworkRules();
      await this.__bringWireGuardUp();
      await this.__syncConfig();
      if (this.__settingsRecoveryPending) await this.__completeSettingsTransaction();

      debug('WireGuard initialization completed.');
    })();

    return this.__initPromise;
  }

  async __bringWireGuardDown() {
    try {
      await Util.exec('wg-quick down wg0');
    } catch (err) {
      if (/not a WireGuard interface|Cannot find device|does not exist/i.test(err.message || '')) return;
      throw err;
    }
  }

  async __bringWireGuardUp() {
    await Util.exec('wg-quick up wg0').catch((err) => {
      if (err && err.message && err.message.includes('Cannot find device "wg0"')) {
        throw new Error('WireGuard exited with the error: Cannot find device "wg0"\nThis usually means that your host\'s kernel does not support WireGuard!');
      }
      throw err;
    });
    // Performance: increase txqueuelen and apply lightweight sysctl tuning for seeding workloads (best-effort, never fails boot).
    // Host sysctls are authoritative; container attempts are non-privileged safe fallback when running with host network_mode + NET_ADMIN.
    await Util.exec('ip link set wg0 txqueuelen 5000 2>/dev/null || ip link set dev wg0 txqueuelen 5000 2>/dev/null || true').catch(() => {});
    await Util.exec(
      'sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216 net.core.rmem_default=262144 net.core.wmem_default=262144 net.ipv4.udp_mem="102400 524288 16777216" net.core.netdev_max_backlog=5000 2>/dev/null || true',
    ).catch(() => {});
    await Util.exec(
      'sysctl -w net.netfilter.nf_conntrack_max=262144 2>/dev/null || echo 262144 > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true',
    ).catch(() => {});
  }

  async saveConfig() {
    const config = await this.getConfig();
    await this.__saveConfig(config);
    await this.__syncConfig();
  }

  __getPostUp() {
    if (process.env.WG_POST_UP) return WG_POST_UP;
    // When WG_NFT_MASQUERADE=true the masquerade is handled atomically via nft wgeasy_dnat postrouting.
    // Keep iptables FORWARD/INPUT for compatibility; skip duplicate MASQUERADE to reduce rule duplication.
    const commands = [
      ...(WG_NFT_MASQUERADE ? [] : [`iptables -t nat -I POSTROUTING 1 -s ${this.__serverSettings.defaultAddress.replace('x', '0')}/24 -o ${this.__serverSettings.device} -j MASQUERADE;`]),
      `iptables -I INPUT 1 -p udp -m udp --dport ${this.__serverSettings.port} -j ACCEPT;`,
      'iptables -I FORWARD 1 -i wg0 -j ACCEPT;',
      'iptables -I FORWARD 1 -o wg0 -j ACCEPT;',
    ];
    if (this.__serverSettings.enableIpv6) {
      commands.push(
        ...(WG_NFT_MASQUERADE ? [] : [`ip6tables -t nat -I POSTROUTING 1 -s ${this.__serverSettings.defaultAddressV6.replace('x', '0')}/64 -o ${this.__serverSettings.device} -j MASQUERADE;`]),
        'ip6tables -I FORWARD 1 -i wg0 -j ACCEPT;',
        'ip6tables -I FORWARD 1 -o wg0 -j ACCEPT;',
      );
    }
    // Lightweight seed tuning: ensure forwarding and conntrack are sane (best-effort, idempotent).
    if (WG_SEED_TUNING) {
      commands.push(
        'sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 2>/dev/null || true;',
        'sysctl -w net.core.default_qdisc=fq net.ipv4.tcp_congestion_control=bbr 2>/dev/null || true;',
      );
    }
    return commands.join(' ');
  }

  __getPostDown() {
    if (process.env.WG_POST_DOWN) return WG_POST_DOWN;
    const commands = [
      ...(WG_NFT_MASQUERADE ? [] : [`iptables -t nat -D POSTROUTING -s ${this.__serverSettings.defaultAddress.replace('x', '0')}/24 -o ${this.__serverSettings.device} -j MASQUERADE;`]),
      `iptables -D INPUT -p udp -m udp --dport ${this.__serverSettings.port} -j ACCEPT;`,
      'iptables -D FORWARD -i wg0 -j ACCEPT;',
      'iptables -D FORWARD -o wg0 -j ACCEPT;',
    ];
    if (this.__serverSettings.enableIpv6) {
      commands.push(
        ...(WG_NFT_MASQUERADE ? [] : [`ip6tables -t nat -D POSTROUTING -s ${this.__serverSettings.defaultAddressV6.replace('x', '0')}/64 -o ${this.__serverSettings.device} -j MASQUERADE;`]),
        'ip6tables -D FORWARD -i wg0 -j ACCEPT;',
        'ip6tables -D FORWARD -o wg0 -j ACCEPT;',
      );
    }
    return commands.join(' ');
  }

  async __saveConfig(config) {
    this.__validateConfig(config);
    const mtuLine = this.__serverSettings.mtu ? `MTU = ${this.__serverSettings.mtu}\n` : '';
    let result = `
# Note: Do not edit this file directly.
# Your changes will be overwritten!

# Server
[Interface]
PrivateKey = ${config.server.privateKey}
Address = ${config.server.address}/24${this.__serverSettings.enableIpv6 && config.server.addressV6 ? `, ${config.server.addressV6}/64` : ''}
ListenPort = ${this.__serverSettings.port}
${mtuLine}PreUp = ${WG_PRE_UP}
PostUp = ${this.__getPostUp()}
PreDown = ${WG_PRE_DOWN}
PostDown = ${this.__getPostDown()}
`;

    for (const [clientId, client] of Object.entries(config.clients)) {
      if (!client.enabled) continue;

      result += `

# Client: ${client.name} (${clientId})
[Peer]
PublicKey = ${client.publicKey}
${client.preSharedKey ? `PresharedKey = ${client.preSharedKey}\n` : ''
}AllowedIPs = ${client.address}/32${this.__serverSettings.enableIpv6 && client.addressV6 ? `, ${client.addressV6}/128` : ''}`;
    }

    debug('Config saving...');
    const jsonFile = path.join(WG_PATH, 'wg0.json');

    try {
      try {
        const previousJson = await fs.readFile(jsonFile, 'utf8');
        await this.__writeAtomic('wg0.json.bak', previousJson, 0o600);
      } catch (err) {
        if (err.code !== 'ENOENT') throw err;
      }
      // wg0.json is canonical, so publish it only after the generated config.
      await this.__writeAtomic('wg0.conf', result, 0o600);
      await this.__writeAtomic('wg0.json', JSON.stringify(config, false, 2), 0o600);

      debug('Config saved.');
    } catch (err) {
      debug(`Error saving config: ${err.message}`);
      throw err;
    }
  }

  async __syncConfig() {
    debug('Config syncing...');
    await Util.exec('wg syncconf wg0 <(wg-quick strip wg0)');
    debug('Config synced.');
  }

  async getClients() {
    if (process.platform !== 'linux') {
      return [DUMMY_CLIENT_PREVIEW];
    }

    // Serialized behind the mutation queue so clients can never observe
    // half-applied (or later rolled-back) in-memory state.
    return this.__withMutation(async () => {
      const config = await this.getConfig();
      const clients = Object.entries(config.clients).map(([clientId, client]) => ({
        id: clientId,
        name: client.name,
        enabled: client.enabled,
        address: client.address,
        publicKey: client.publicKey,
        createdAt: new Date(client.createdAt),
        updatedAt: new Date(client.updatedAt),
        allowedIPs: client.allowedIPs || [`${client.address}/32`, (this.__serverSettings.enableIpv6 && client.addressV6 ? `${client.addressV6}/128` : null)].filter(Boolean),
        addressV6: client.addressV6,
        portForwards: Array.isArray(client.portForwards)
          ? client.portForwards.map((rule) => ({ ...rule }))
          : [],
        networkPolicy: this.__normalizeNetworkPolicy(client.networkPolicy, { strict: false }),
        downloadableConfig: 'privateKey' in client && client.privateKey != null,
        persistentKeepalive: null,
        latestHandshakeAt: null,
        endpoint: null,
        // A handshake within 3x the effective keepalive (or 3x 180s when no
        // keepalive is configured) means the peer is reachable right now.
        online: false,
        transferRx: null,
        transferTx: null,
      }));

      // Loop WireGuard status
      try {
        const dump = await Util.exec('wg show wg0 dump', {
          log: false,
        });
        dump
          .trim()
          .split('\n')
          .slice(1)
          .forEach((line) => {
            const [
              publicKey,
              preSharedKey, // eslint-disable-line no-unused-vars
              endpoint,
              allowedIps, // eslint-disable-line no-unused-vars
              latestHandshakeAt,
              transferRx,
              transferTx,
              persistentKeepalive,
            ] = line.split('\t');

            const client = clients.find((c) => c.publicKey === publicKey);
            if (!client) return;

            client.latestHandshakeAt = latestHandshakeAt === '0'
              ? null
              : new Date(Number(`${latestHandshakeAt}000`));
            client.endpoint = endpoint && endpoint !== '(none)' ? endpoint : null;
            client.transferRx = Number(transferRx);
            client.transferTx = Number(transferTx);
            client.persistentKeepalive = persistentKeepalive;
          });
      } catch (err) {
        debug(`Warning: Could not fetch wireguard dump: ${err.message}`);
      }

      const now = Date.now();
      for (const client of clients) {
        if (!client.latestHandshakeAt) continue;
        const effectiveKeepalive = Number(this.__serverSettings.persistentKeepalive) || 180;
        const onlineWindowMs = 3 * effectiveKeepalive * 1000;
        client.online = (now - client.latestHandshakeAt.getTime()) < onlineWindowMs;
      }

      return clients;
    });
  }

  async getClient({ clientId }) {
    if (RESERVED_CLIENT_IDS.has(clientId)) {
      throw new ServerError(`Client Not Found: ${clientId}`, 404);
    }

    const config = await this.getConfig();
    if (!Object.hasOwn(config.clients, clientId)) {
      throw new ServerError(`Client Not Found: ${clientId}`, 404);
    }
    const client = config.clients[clientId];

    return client;
  }

  async getClientConfiguration({ clientId }) {
    // Serialized behind the mutation queue: a .conf handed to a device must
    // reflect fully committed state, never a mid-mutation mix.
    return this.__withMutation(async () => {
      const config = await this.getConfig();
      const client = await this.getClient({ clientId });

      return `
[Interface]
PrivateKey = ${client.privateKey ? `${client.privateKey}` : 'REPLACE_ME'}
Address = ${client.address}/24${this.__serverSettings.enableIpv6 && client.addressV6 ? `, ${client.addressV6}/128` : ''}
${this.__serverSettings.defaultDns ? `DNS = ${this.__serverSettings.defaultDns}\n` : ''}\
${this.__serverSettings.mtu ? `MTU = ${this.__serverSettings.mtu}\n` : ''}\

[Peer]
PublicKey = ${config.server.publicKey}
${client.preSharedKey ? `PresharedKey = ${client.preSharedKey}\n` : ''
}AllowedIPs = ${this.__serverSettings.allowedIps}
PersistentKeepalive = ${client.persistentKeepalive ?? this.__serverSettings.persistentKeepalive}
Endpoint = ${this.__serverSettings.host}:${this.__serverSettings.configPort}`;
    });
  }

  async getClientQRCodeSVG({ clientId }) {
    const config = await this.getClientConfiguration({ clientId });
    return QRCode.toString(config, {
      type: 'svg',
      width: 512,
    });
  }

  async createClient({ name }) {
    return this.__withMutation(async () => {
      if (!Util.isValidName(name)) {
        throw new ServerError('Invalid name: 1-128 chars, no control characters', 400);
      }

      const config = await this.getConfig();
      const privateKey = await Util.exec('wg genkey');
      const publicKey = await Util.execFile('wg', ['pubkey'], { input: `${privateKey}\n`, log: 'wg pubkey' });
      const preSharedKey = await Util.exec('wg genpsk');

      let address;
      let addressV6;
      for (let i = 2; i < 255; i++) {
        const existingClient = Object.values(config.clients).find((candidate) => {
          return candidate.address === this.__serverSettings.defaultAddress.replace('x', i)
            || (this.__serverSettings.enableIpv6 && candidate.addressV6 === this.__serverSettings.defaultAddressV6.replace('x', i));
        });
        if (!existingClient) {
          address = this.__serverSettings.defaultAddress.replace('x', i);
          addressV6 = this.__serverSettings.enableIpv6 ? this.__serverSettings.defaultAddressV6.replace('x', i) : null;
          break;
        }
      }
      if (!address) throw new Error('Maximum number of clients reached.');

      const id = crypto.randomUUID();
      const client = {
        id,
        name,
        address,
        addressV6,
        privateKey,
        publicKey,
        preSharedKey,
        createdAt: new Date(),
        updatedAt: new Date(),
        enabled: true,
        portForwards: [],
        networkPolicy: createDefaultNetworkPolicy(),
      };
      await this.__transactionalDnatChange(
        () => {
          config.clients[id] = client;
        },
        () => {
          delete config.clients[id];
        },
        'create-client',
      );
      return client;
    });
  }

  async deleteClient({ clientId }) {
    return this.__withMutation(async () => {
      const config = await this.getConfig();
      if (RESERVED_CLIENT_IDS.has(clientId)) {
        throw new ServerError(`Client Not Found: ${clientId}`, 404);
      }
      if (Object.hasOwn(config.clients, clientId)) {
        const removedClient = config.clients[clientId];
        const previousPolicies = Object.fromEntries(Object.entries(config.clients).map(([id, client]) => [id, {
          networkPolicy: this.__normalizeNetworkPolicy(client.networkPolicy),
          updatedAt: client.updatedAt,
        }]));
        await this.__transactionalDnatChange(
          () => {
            delete config.clients[clientId];
            for (const client of Object.values(config.clients)) {
              if (client.networkPolicy.peerAllowlist.includes(clientId)) {
                client.networkPolicy.peerAllowlist = client.networkPolicy.peerAllowlist
                  .filter((allowedId) => allowedId !== clientId);
                client.updatedAt = new Date();
              }
            }
          },
          () => {
            config.clients[clientId] = removedClient;
            for (const [id, snapshot] of Object.entries(previousPolicies)) {
              config.clients[id].networkPolicy = snapshot.networkPolicy;
              config.clients[id].updatedAt = snapshot.updatedAt;
            }
          },
          'delete-client',
          { reloadWireGuard: true },
        );
      }
    });
  }

  async enableClient({ clientId }) {
    return this.__withMutation(async () => {
      const client = await this.getClient({ clientId });
      const previous = { enabled: client.enabled, updatedAt: client.updatedAt };
      await this.__transactionalDnatChange(
        () => {
          client.enabled = true; client.updatedAt = new Date();
        },
        () => {
          Object.assign(client, previous);
        },
        'enable-client',
      );
    });
  }

  async disableClient({ clientId }) {
    return this.__withMutation(async () => {
      const client = await this.getClient({ clientId });
      const previous = { enabled: client.enabled, updatedAt: client.updatedAt };
      await this.__transactionalDnatChange(
        () => {
          client.enabled = false; client.updatedAt = new Date();
        },
        () => {
          Object.assign(client, previous);
        },
        'disable-client',
        { reloadWireGuard: true },
      );
    });
  }

  async updateClientName({ clientId, name }) {
    return this.__withMutation(async () => {
      const client = await this.getClient({ clientId });
      if (!Util.isValidName(name)) {
        throw new ServerError('Invalid name: 1-128 chars, no control characters', 400);
      }
      const previous = { name: client.name, updatedAt: client.updatedAt };
      await this.__transactionalConfigChange(
        () => {
          client.name = name; client.updatedAt = new Date();
        },
        () => {
          Object.assign(client, previous);
        },
        { context: 'update-client-name' },
      );
    });
  }

  async updateClientKeepalive({ clientId, persistentKeepalive }) {
    return this.__withMutation(async () => {
      const client = await this.getClient({ clientId });
      if (persistentKeepalive !== null
        && (!Number.isInteger(persistentKeepalive) || persistentKeepalive < 0 || persistentKeepalive > 65535)) {
        throw new ServerError('persistentKeepalive must be null or an integer between 0 and 65535', 400);
      }
      const previous = { persistentKeepalive: client.persistentKeepalive ?? null, updatedAt: client.updatedAt };
      await this.__transactionalConfigChange(
        () => {
          client.persistentKeepalive = persistentKeepalive;
          client.updatedAt = new Date();
        },
        () => {
          Object.assign(client, previous);
        },
        { context: 'update-client-keepalive' },
      );
      return { persistentKeepalive, updatedAt: client.updatedAt };
    });
  }

  // ── Peer tokens (self-service port management) ──────────────────

  // Issue (or rotate) a peer token. The plaintext token exists exactly once
  // in the HTTP response; only its sha256 is persisted.
  async issueClientToken({ clientId }) {
    return this.__withMutation(async () => {
      const client = await this.getClient({ clientId });
      const token = `wgpt_${crypto.randomBytes(32).toString('hex')}`;
      const previous = {
        tokenHash: client.tokenHash ?? null,
        tokenCreatedAt: client.tokenCreatedAt ?? null,
        updatedAt: client.updatedAt,
      };
      const issued = { tokenHash: sha256Hex(token), tokenCreatedAt: new Date() };
      await this.__transactionalConfigChange(
        () => {
          Object.assign(client, issued, { updatedAt: new Date() });
        },
        () => {
          Object.assign(client, previous);
        },
        { context: 'issue-client-token' },
      );
      return { token, tokenCreatedAt: issued.tokenCreatedAt };
    });
  }

  async revokeClientToken({ clientId }) {
    return this.__withMutation(async () => {
      const client = await this.getClient({ clientId });
      const previous = {
        tokenHash: client.tokenHash ?? null,
        tokenCreatedAt: client.tokenCreatedAt ?? null,
        updatedAt: client.updatedAt,
      };
      await this.__transactionalConfigChange(
        () => {
          client.tokenHash = null;
          client.tokenCreatedAt = null;
          client.updatedAt = new Date();
        },
        () => {
          Object.assign(client, previous);
        },
        { context: 'revoke-client-token' },
      );
      return { success: true };
    });
  }

  // Constant-time lookup: every client's stored hash is compared (no early
  // exit), with timingSafeEqual over equal-length buffers. Returns the owning
  // clientId or null. Snapshot read behind the mutation queue (same family as
  // getClients): a lookup must never observe half-applied or rolled-back
  // state — e.g. a revoke racing this very check.
  async lookupPeerToken(token) {
    if (typeof token !== 'string' || !/^wgpt_[0-9a-f]{64}$/.test(token)) return null;
    const presented = Buffer.from(sha256Hex(token), 'hex');
    return this.__withMutation(async () => {
      const config = await this.getConfig();
      let match = null;
      for (const client of Object.values(config.clients)) {
        if (!TOKEN_HASH_RE.test(client.tokenHash || '')) continue;
        const stored = Buffer.from(client.tokenHash, 'hex');
        if (presented.length === stored.length && crypto.timingSafeEqual(presented, stored)) {
          match = client.id;
        }
      }
      return match;
    });
  }

  // Dedicated serializer for /api/peer/me — NEVER spread the raw client
  // (privateKey/preSharedKey/tokenHash must not leak to token holders).
  // Snapshot read behind the mutation queue, like getClients.
  async getPeerProfile({ clientId }) {
    return this.__withMutation(async () => {
      const config = await this.getConfig();
      const client = config.clients[clientId];
      if (!client) throw new ServerError(`Client Not Found: ${clientId}`, 404);
      return {
        id: client.id,
        name: client.name,
        address: client.address,
        addressV6: client.addressV6,
        portForwards: (Array.isArray(client.portForwards) ? client.portForwards : [])
          .map((rule) => ({ ...rule })),
        permissions: {
          selfManagePorts: client.selfManagePorts === true,
        },
      };
    });
  }

  async setClientSelfManagePorts({ clientId, enabled }) {
    return this.__withMutation(async () => {
      const client = await this.getClient({ clientId });
      if (typeof enabled !== 'boolean') {
        throw new ServerError('enabled must be a boolean', 400);
      }
      const previous = { selfManagePorts: client.selfManagePorts ?? false, updatedAt: client.updatedAt };
      await this.__transactionalConfigChange(
        () => {
          client.selfManagePorts = enabled;
          client.updatedAt = new Date();
        },
        () => {
          Object.assign(client, previous);
        },
        { context: 'set-client-self-manage-ports' },
      );
      return { selfManagePorts: enabled };
    });
  }

  // ── Webhook configuration (sidecar file, secret never echoed) ──

  async __loadWebhookConfig() {
    // Webhooks are auxiliary: any problem with the config file disables them
    // with a warning rather than taking the panel down at boot.
    try {
      const raw = await fs.readFile(path.join(WG_PATH, 'webhook.json'), 'utf8');
      const parsed = JSON.parse(raw);
      this.__webhookConfig = isPlainObject(parsed)
        && typeof parsed.url === 'string'
        && (parsed.secret === undefined || typeof parsed.secret === 'string')
        ? { url: parsed.url, secret: parsed.secret ?? '' }
        : null;
    } catch (err) {
      if (err.code !== 'ENOENT') {
        debug(`Warning: webhook config unavailable: ${err.message}`);
      }
      this.__webhookConfig = null;
    }
  }

  async getWebhookConfig() {
    await this.getConfig();
    return {
      configured: !!(this.__webhookConfig && this.__webhookConfig.url),
      url: (this.__webhookConfig && this.__webhookConfig.url) || null,
    };
  }

  async setWebhookConfig({ url, secret }) {
    return this.__withMutation(async () => {
      if (url !== null) {
        if (typeof url !== 'string' || url.length === 0 || url.length > 2048 || /[\r\n]/.test(url)) {
          throw new ServerError('Invalid webhook url', 400);
        }
        let parsed;
        try {
          parsed = new URL(url);
        } catch {
          throw new ServerError('Invalid webhook url', 400);
        }
        if (parsed.protocol !== 'https:' && !(ALLOW_INSECURE_WEBHOOK && parsed.protocol === 'http:')) {
          throw new ServerError('Webhook url must be https:// (or http:// with ALLOW_INSECURE_WEBHOOK=true)', 400);
        }
        if (typeof secret !== 'string' || secret.length === 0 || secret.length > 255 || /[\r\n]/.test(secret)) {
          throw new ServerError('A webhook secret (1-255 chars, no line breaks) is required', 400);
        }
      }
      const next = url === null ? null : { url, secret };
      await this.__writeAtomic('webhook.json', JSON.stringify(next ?? {}), 0o600);
      this.__webhookConfig = next;
      return { configured: !!next, url: next ? next.url : null };
    });
  }

  // ── Port events (seq + delivery) ────────────────────────────────

  // Strictly increasing per-peer sequence numbers, persisted in the
  // wg0-events.json sidecar so receivers can detect gaps across restarts.
  async __nextEventSeq(peerId) {
    if (this.__eventSeq === null) {
      try {
        const raw = await fs.readFile(path.join(WG_PATH, 'wg0-events.json'), 'utf8');
        const parsed = JSON.parse(raw);
        this.__eventSeq = isPlainObject(parsed) ? parsed : {};
      } catch (err) {
        if (err.code !== 'ENOENT') throw err;
        this.__eventSeq = {};
      }
    }
    const next = Number(this.__eventSeq[peerId] || 0) + 1;
    this.__eventSeq[peerId] = next;
    await this.__writeAtomic('wg0-events.json', JSON.stringify(this.__eventSeq), 0o600);
    return next;
  }

  // Called from the single success path of __transactionalConfigChange (inside
  // the queue: seq allocation and the sidecar write are part of the commit).
  // Delivery itself is detached — webhook I/O must never block mutations.
  async __emitPortEvent(event) {
    const webhook = this.__webhookConfig;
    if (!webhook || !webhook.url) return;
    const seq = await this.__nextEventSeq(event.clientId);
    const payload = {
      v: 1,
      event: event.type,
      eventId: crypto.randomUUID(),
      peerId: event.clientId,
      seq,
      proto: event.proto,
      extPort: event.extPort,
      previousExtPort: event.previousExtPort ?? null,
      intPort: event.intPort,
      ts: new Date().toISOString(),
    };
    Webhook.deliver(
      {
        url: webhook.url, secret: webhook.secret, body: JSON.stringify(payload), allowInsecure: !!ALLOW_INSECURE_WEBHOOK,
      },
    ).then((delivered) => {
      if (!delivered) debug(`webhook event ${payload.event} seq=${seq} dropped after retries`);
    });
  }

  async updateClientAddress({ clientId, address, addressV6 }) {
    return this.__withMutation(async () => {
      const config = await this.getConfig();
      const client = await this.getClient({ clientId });
      if (address && !Util.isValidIPv4(address)) throw new ServerError(`Invalid IPv4 Address: ${address}`, 400);
      if (addressV6 && !Util.isValidIPv6(addressV6)) throw new ServerError(`Invalid IPv6 Address: ${addressV6}`, 400);
      if (address && (address === config.server.address
        || Object.values(config.clients).some((candidate) => candidate !== client && candidate.address === address))) {
        throw new ServerError(`IPv4 address already in use: ${address}`, 409);
      }
      if (addressV6 && (addressV6 === config.server.addressV6
        || Object.values(config.clients).some((candidate) => candidate !== client && candidate.addressV6 === addressV6))) {
        throw new ServerError(`IPv6 address already in use: ${addressV6}`, 409);
      }
      if (addressV6 && config.server.addressV6 && !isSameIPv6Subnet64(config.server.addressV6, addressV6)) {
        throw new ServerError('IPv6 address must be in the server /64', 400);
      }
      if (address) {
        const serverPrefix = config.server.address.split('.').slice(0, 3).join('.');
        const parts = address.split('.');
        const host = Number(parts[3]);
        if (parts.slice(0, 3).join('.') !== serverPrefix || host < 2 || host > 254) {
          throw new ServerError(`IPv4 address must be a usable host in ${serverPrefix}.0/24`, 400);
        }
      }

      const previous = { address: client.address, addressV6: client.addressV6, updatedAt: client.updatedAt };
      await this.__transactionalDnatChange(
        () => {
          if (address) client.address = address;
          if (addressV6) client.addressV6 = addressV6;
          client.updatedAt = new Date();
        },
        () => {
          Object.assign(client, previous);
        },
        'update-client-address',
        { reloadWireGuard: true },
      );
    });
  }

  getNetworkPolicyOptions() {
    return {
      protocolPresets: getProtocolPresets(),
      maxCustomRules: MAX_CUSTOM_RULES,
    };
  }

  async updateClientNetworkPolicy({ clientId, policy, expectedUpdatedAt }) {
    if (process.platform !== 'linux') {
      DUMMY_CLIENT_PREVIEW.networkPolicy = this.__normalizeNetworkPolicy(policy);
      DUMMY_CLIENT_PREVIEW.updatedAt = new Date();
      return {
        networkPolicy: DUMMY_CLIENT_PREVIEW.networkPolicy,
        updatedAt: DUMMY_CLIENT_PREVIEW.updatedAt,
      };
    }

    return this.__withMutation(async () => {
      const config = await this.getConfig();
      const client = await this.getClient({ clientId });
      if (expectedUpdatedAt !== undefined) {
        const expectedTime = Date.parse(expectedUpdatedAt);
        if (Number.isNaN(expectedTime)) throw new ServerError('Invalid policy version', 400);
        if (new Date(client.updatedAt).getTime() !== expectedTime) {
          throw new ServerError('The client changed since this policy was opened', 409);
        }
      }
      const nextPolicy = this.__normalizeNetworkPolicy(policy);
      if (nextPolicy.peerAllowlist.includes(clientId)) {
        throw new ServerError('A client cannot allow itself', 400);
      }
      for (const allowedId of nextPolicy.peerAllowlist) {
        if (!Object.hasOwn(config.clients, allowedId)) {
          throw new ServerError(`Client Not Found: ${allowedId}`, 404);
        }
      }

      const previous = Object.fromEntries(Object.entries(config.clients).map(([id, candidate]) => [id, {
        networkPolicy: this.__normalizeNetworkPolicy(candidate.networkPolicy),
        updatedAt: candidate.updatedAt,
      }]));
      const allowedIds = new Set(nextPolicy.peerAllowlist);
      await this.__transactionalDnatChange(
        () => {
          const updatedAt = new Date();
          client.networkPolicy = nextPolicy;
          client.updatedAt = updatedAt;
          for (const [id, candidate] of Object.entries(config.clients)) {
            if (id === clientId) continue;
            const reverse = new Set(candidate.networkPolicy.peerAllowlist);
            const previouslyAllowed = reverse.has(clientId);
            if (allowedIds.has(id)) reverse.add(clientId);
            else reverse.delete(clientId);
            if (previouslyAllowed !== reverse.has(clientId)) {
              candidate.networkPolicy.peerAllowlist = [...reverse];
              candidate.updatedAt = updatedAt;
            }
          }
        },
        () => {
          for (const [id, snapshot] of Object.entries(previous)) {
            config.clients[id].networkPolicy = snapshot.networkPolicy;
            config.clients[id].updatedAt = snapshot.updatedAt;
          }
        },
        'update-client-network-policy',
      );
      return {
        networkPolicy: this.__normalizeNetworkPolicy(client.networkPolicy),
        updatedAt: client.updatedAt,
      };
    });
  }

  async restoreConfiguration(config) {
    return this.__withMutation(async () => {
      debug('Starting configuration restore process.');
      let restored;
      try {
        restored = JSON.parse(config);
      } catch {
        throw new ServerError('Invalid backup: not valid JSON', 400);
      }
      if (isPlainObject(restored) && isPlainObject(restored.clients)) {
        for (const [clientId, client] of Object.entries(restored.clients)) {
          if (isPlainObject(client)) {
            if (client.id === undefined || client.id === null) client.id = clientId;
            if (client.enabled === undefined || client.enabled === null) client.enabled = true;
            if (client.preSharedKey === '' || client.preSharedKey === undefined) client.preSharedKey = null;
            if (client.privateKey === '' || client.privateKey === undefined) delete client.privateKey;
            if (client.createdAt === undefined || client.createdAt === null || !isValidDate(client.createdAt)) {
              client.createdAt = new Date().toISOString();
            }
            if (client.updatedAt === undefined || client.updatedAt === null || !isValidDate(client.updatedAt)) {
              client.updatedAt = new Date().toISOString();
            } else {
              // Restoring is itself a change: bump updatedAt (never roll it
              // backwards) so open editors' expectedUpdatedAt checks fail
              // loudly instead of silently diverging from the restored state.
              client.updatedAt = new Date(Math.max(Date.parse(client.updatedAt), Date.now())).toISOString();
            }
            if (!Array.isArray(client.portForwards)) client.portForwards = [];
            for (const rule of client.portForwards) {
              if (isPlainObject(rule) && (rule.id === undefined || rule.id === null)) rule.id = crypto.randomUUID();
            }
            if (client.networkPolicy === undefined || client.networkPolicy === null) {
              client.networkPolicy = createDefaultNetworkPolicy();
            }
            client.networkPolicy = this.__normalizeNetworkPolicy(client.networkPolicy, { strict: false });
            if (client.selfManagePorts === undefined || client.selfManagePorts === null) {
              client.selfManagePorts = false;
            }
            if (client.persistentKeepalive === undefined) client.persistentKeepalive = null;
          }
        }
      }
      this.__validateConfig(restored, { strict: true });

      const oldConfig = this.__config;
      await this.__transactionalDnatChange(
        () => {
          this.__config = restored;
        },
        () => {
          this.__config = oldConfig;
        },
        'restore',
        { reloadWireGuard: true },
      );
      debug('Configuration restore process completed.');
    });
  }

  async __transactionalConfigChange(mutate, rollback, {
    applyDnat = false,
    context = 'config-change',
    reloadWireGuard = false,
    event = null,
  } = {}) {
    await mutate();
    let interfaceDown = false;
    try {
      if (reloadWireGuard) {
        await this.__bringWireGuardDown();
        interfaceDown = true;
        if (applyDnat) await this.__applyAllDnatRules();
        await this.__saveConfig(this.__config);
        await this.__bringWireGuardUp();
        interfaceDown = false;
      } else {
        if (applyDnat) await this.__applyAllDnatRules();
        await this.saveConfig();
      }
    } catch (err) {
      await rollback();
      const rollbackErrors = [];
      if (reloadWireGuard) {
        interfaceDown = false;
        await this.__bringWireGuardDown().then(() => {
          interfaceDown = true;
        }).catch((downErr) => {
          const msg = `WireGuard shutdown rollback failed in ${context}: ${downErr.message}`;
          debug(msg);
          rollbackErrors.push(msg);
        });
      }
      if (applyDnat) {
        await this.__applyAllDnatRules().catch((rollbackErr) => {
          const msg = `Host rollback failed in ${context}: ${rollbackErr.message}`;
          debug(msg);
          rollbackErrors.push(msg);
        });
      }
      await this.__saveConfig(this.__config).catch((diskErr) => {
        const msg = `Disk rollback failed in ${context}: ${diskErr.message}`;
        debug(msg);
        rollbackErrors.push(msg);
      });
      if (reloadWireGuard && interfaceDown) {
        await this.__bringWireGuardUp().catch((upErr) => {
          const msg = `WireGuard startup rollback failed in ${context}: ${upErr.message}`;
          debug(msg);
          rollbackErrors.push(msg);
        });
      } else {
        await this.__syncConfig().catch((syncErr) => {
          const msg = `WG sync rollback failed in ${context}: ${syncErr.message}`;
          debug(msg);
          rollbackErrors.push(msg);
        });
      }
      err.rollbackErrors = rollbackErrors;
      if (rollbackErrors.length) err.data = { rollbackFailed: true };
      throw err;
    }

    // Single funnel for port events: only reached on the success path.
    if (event) await this.__emitPortEvent(event);
  }

  async __transactionalDnatChange(mutate, rollback, context = 'dnat-change', options = {}) {
    return this.__transactionalConfigChange(mutate, rollback, {
      applyDnat: true,
      context,
      ...options,
    });
  }

  async backupConfiguration() {
    debug('Starting configuration backup.');
    // Serialized behind the mutation queue so the backup is a consistent
    // snapshot of committed state.
    const backup = await this.__withMutation(async () => {
      const config = await this.getConfig();
      return JSON.stringify(config, null, 2);
    });
    debug('Configuration backup completed.');
    return backup;
  }

  // Shutdown wireguard
  async Shutdown() {
    await this.__bringWireGuardDown();
    // Remove owned tables so no host rules survive the service.
    await Util.exec('nft delete table ip wgeasy_dnat').catch(() => {});
    await Util.exec('nft delete table ip6 wgeasy_dnat').catch(() => {});
    await Util.exec('nft delete table inet wgeasy_filter').catch(() => {});
  }

  // ── Server Settings (Global IP Config) ──────────────────────────

  async getServerConfig() {
    // Serialized behind the mutation queue so settings are read from a fully
    // committed state (which also loads them from disk on first call).
    return this.__withMutation(async () => {
      await this.getConfig();
      return serializeServerSettingsPublic(this.__serverSettings);
    });
  }

  async updateServerConfig(settings) {
    return this.__withMutation(async () => {
      const config = await this.getConfig();
      const previousConfig = JSON.parse(JSON.stringify(config));
      const previous = { ...this.__serverSettings };
      const candidate = this.__normalizeServerSettings(settings, previous, true);
      this.__serverSettings = candidate;

      if (candidate.defaultAddress !== previous.defaultAddress) {
        config.server.address = candidate.defaultAddress.replace('x', '1');
        for (const client of Object.values(config.clients)) {
          const host = client.address.split('.')[3];
          client.address = candidate.defaultAddress.replace('x', host);
        }
      }
      if (candidate.enableIpv6
        && (candidate.defaultAddressV6 !== previous.defaultAddressV6 || !previous.enableIpv6)) {
        config.server.addressV6 = candidate.defaultAddressV6.replace('x', '1');
        for (const client of Object.values(config.clients)) {
          const host = client.address.split('.')[3];
          client.addressV6 = candidate.defaultAddressV6.replace('x', host);
        }
      }

      try {
        this.__validateConfig(config);
      } catch (err) {
        this.__serverSettings = previous;
        this.__config = previousConfig;
        throw err;
      }

      try {
        await this.__saveSettingsTransaction(
          previous,
          candidate,
          previousConfig,
          JSON.parse(JSON.stringify(config)),
        );
        await this.__bringWireGuardDown();
        await this.__saveConfig(config);
        await this.__ensureNftablesSetup();
        await this.__applyAllDnatRules();
        await this.__bringWireGuardUp();
        await this.__completeSettingsTransaction();
      } catch (err) {
        const rollbackErrors = [];
        await this.__bringWireGuardDown().catch((rollbackErr) => {
          rollbackErrors.push(`WireGuard shutdown rollback failed: ${rollbackErr.message}`);
        });
        this.__serverSettings = previous;
        this.__config = previousConfig;
        let configRollbackFailed = false;
        await this.__saveConfig(previousConfig).catch((rollbackErr) => {
          configRollbackFailed = true;
          rollbackErrors.push(`Settings config rollback failed: ${rollbackErr.message}`);
        });
        await this.__ensureNftablesSetup()
          .then(() => this.__applyAllDnatRules())
          .catch((rollbackErr) => {
            rollbackErrors.push(`DNAT settings rollback failed: ${rollbackErr.message}`);
          });
        await this.__bringWireGuardUp().catch((rollbackErr) => {
          rollbackErrors.push(`WireGuard settings rollback failed: ${rollbackErr.message}`);
        });
        if (configRollbackFailed) {
          // The disk still holds the candidate config. Keep the journal: boot
          // recovery rewrites wg0.json from previousConfig, which is the only
          // remaining way to converge disk, settings and live state.
          debug('Settings journal kept after a failed config rollback.');
        } else {
          await this.__completeSettingsTransaction().catch((rollbackErr) => {
            rollbackErrors.push(`Settings journal rollback failed: ${rollbackErr.message}`);
          });
        }
        err.rollbackErrors = rollbackErrors;
        if (rollbackErrors.length) err.data = { rollbackFailed: true };
        throw err;
      }

      debug('Server settings updated, applied and persisted.');
      return serializeServerSettingsPublic(this.__serverSettings);
    });
  }

  // ── NFTables / DNAT ─────────────────────────────────────────────

  __isPortAllowed(port) {
    const p = Number(port);
    if (!Number.isInteger(p)) return false;
    if (p === Number(this.__serverSettings.port) || p === Number(this.__serverSettings.configPort)) return false;

    const min = this.__serverSettings.portFwdMin;
    const max = this.__serverSettings.portFwdMax;
    return p >= min && p <= max;
  }

  async __ensureNftablesSetup() {
    const ensure = async (listCommand, addCommand) => {
      try {
        await Util.exec(listCommand, { log: false });
      } catch {
        try {
          await Util.exec(addCommand);
        } catch (err) {
          // A concurrent creator may have won the race; verify the resource.
          await Util.exec(listCommand, { log: false }).catch(() => {
            throw err;
          });
        }
      }
    };

    const families = this.__serverSettings.enableIpv6 ? ['ip', 'ip6'] : ['ip'];
    for (const family of families) {
      await ensure(
        `nft list table ${family} wgeasy_dnat`,
        `nft add table ${family} wgeasy_dnat`,
      );
      await ensure(
        `nft list chain ${family} wgeasy_dnat prerouting`,
        `nft add chain ${family} wgeasy_dnat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'`,
      );
    }
    await ensure(
      'nft list table inet wgeasy_filter',
      'nft add table inet wgeasy_filter',
    );
    await ensure(
      'nft list chain inet wgeasy_filter input',
      "nft add chain inet wgeasy_filter input '{ type filter hook input priority filter; policy accept; }'",
    );
    await ensure(
      'nft list chain inet wgeasy_filter forward',
      "nft add chain inet wgeasy_filter forward '{ type filter hook forward priority filter; policy accept; }'",
    );
    debug('nftables tables and chains ensured.');
  }

  async __removeIpv6DnatTable() {
    try {
      await Util.exec('nft list table ip6 wgeasy_dnat', { log: false });
    } catch {
      return;
    }
    await Util.exec('nft delete table ip6 wgeasy_dnat');
  }

  async __applyAllNetworkRules() {
    const config = await this.getConfig();
    this.__validateConfig(config);
    if (!this.__serverSettings.enableIpv6) await this.__removeIpv6DnatTable();
    await this.__ensureNftablesSetup();
    const vpnNet4 = `${this.__serverSettings.defaultAddress.replace('x', '0')}/24`;
    const vpnNet6 = this.__serverSettings.enableIpv6 ? `${this.__serverSettings.defaultAddressV6.replace('x', '0')}/64` : null;
    const commands = [
      'delete table ip wgeasy_dnat',
      'add table ip wgeasy_dnat',
      'add chain ip wgeasy_dnat prerouting { type nat hook prerouting priority dstnat; policy accept; }',
    ];
    if (WG_NFT_MASQUERADE) {
      commands.push(
        'add chain ip wgeasy_dnat postrouting { type nat hook postrouting priority srcnat; policy accept; }',
        `add rule ip wgeasy_dnat postrouting ip saddr ${vpnNet4} oifname "${this.__serverSettings.device}" masquerade`,
      );
    }
    if (this.__serverSettings.enableIpv6) {
      commands.push(
        'delete table ip6 wgeasy_dnat',
        'add table ip6 wgeasy_dnat',
        'add chain ip6 wgeasy_dnat prerouting { type nat hook prerouting priority dstnat; policy accept; }',
      );
      if (WG_NFT_MASQUERADE) {
        commands.push(
          'add chain ip6 wgeasy_dnat postrouting { type nat hook postrouting priority srcnat; policy accept; }',
          `add rule ip6 wgeasy_dnat postrouting ip6 saddr ${vpnNet6} oifname "${this.__serverSettings.device}" masquerade`,
        );
      }
    }
    commands.push(
      'delete table inet wgeasy_filter',
      'add table inet wgeasy_filter',
      'add chain inet wgeasy_filter input { type filter hook input priority filter; policy accept; }',
      'add chain inet wgeasy_filter forward { type filter hook forward priority filter; policy accept; }',
      'add set inet wgeasy_filter peer_ipv4 { type ipv4_addr; }',
    );
    const clients = Object.values(config.clients);
    if (clients.length) {
      commands.push(`add element inet wgeasy_filter peer_ipv4 { ${clients.map((client) => client.address).join(', ')} }`);
    }
    if (this.__serverSettings.enableIpv6) {
      commands.push('add set inet wgeasy_filter peer_ipv6 { type ipv6_addr; }');
      const ipv6Addresses = clients.map((client) => client.addressV6).filter(Boolean);
      if (ipv6Addresses.length) {
        commands.push(`add element inet wgeasy_filter peer_ipv6 { ${ipv6Addresses.join(', ')} }`);
      }
    }

    for (const client of clients) {
      if (!client.enabled || !client.portForwards || !client.portForwards.length) continue;
      // Kill-switch: stop emitting DNAT (external reachability) while keeping
      // the WireGuard filter rules and the stored forwarding config intact.
      if (!this.__serverSettings.forwardingEnabled) break;

      const peerIP = client.address;
      const peerIPv6 = this.__serverSettings.enableIpv6 ? client.addressV6 : null;

      for (const rule of client.portForwards) {
        const protocols = rule.proto === 'both' ? ['tcp', 'udp'] : [rule.proto];
        for (const protocol of protocols) {
          commands.push(`add rule ip wgeasy_dnat prerouting ${protocol} dport ${rule.extPort} dnat to ${peerIP}:${rule.intPort}`);
          if (peerIPv6) {
            commands.push(`add rule ip6 wgeasy_dnat prerouting ${protocol} dport ${rule.extPort} dnat to [${peerIPv6}]:${rule.intPort}`);
          }
        }
      }
    }

    const addBlockedRule = (client, family, address, rule) => {
      const destinationPort = rule.startPort === rule.endPort
        ? rule.startPort
        : `${rule.startPort}-${rule.endPort}`;
      commands.push(`add rule inet wgeasy_filter input iifname "wg0" ${family} saddr ${address} ${rule.proto} dport ${destinationPort} drop`);
      commands.push(`add rule inet wgeasy_filter forward iifname "wg0" ${family} saddr ${address} ${rule.proto} dport ${destinationPort} drop`);
    };
    const enabledClients = clients.filter((client) => client.enabled);
    for (const client of enabledClients) {
      const policy = this.__normalizeNetworkPolicy(client.networkPolicy);
      const presetRules = PROTOCOL_PRESETS
        .filter((preset) => policy.blockedProtocols.includes(preset.id))
        .flatMap((preset) => preset.rules);
      for (const rule of [...presetRules, ...policy.customRules]) {
        addBlockedRule(client, 'ip', client.address, rule);
        if (this.__serverSettings.enableIpv6 && client.addressV6) {
          addBlockedRule(client, 'ip6', client.addressV6, rule);
        }
      }
    }

    for (const client of enabledClients) {
      for (const allowedId of client.networkPolicy.peerAllowlist) {
        const peer = config.clients[allowedId];
        if (!peer.enabled) continue;
        commands.push(`add rule inet wgeasy_filter forward iifname "wg0" oifname "wg0" ip saddr ${client.address} ip daddr ${peer.address} accept`);
        if (this.__serverSettings.enableIpv6 && client.addressV6 && peer.addressV6) {
          commands.push(`add rule inet wgeasy_filter forward iifname "wg0" oifname "wg0" ip6 saddr ${client.addressV6} ip6 daddr ${peer.addressV6} accept`);
        }
      }
      commands.push(`add rule inet wgeasy_filter forward iifname "wg0" oifname "wg0" ip saddr ${client.address} ip daddr @peer_ipv4 drop`);
      if (this.__serverSettings.enableIpv6 && client.addressV6) {
        commands.push(`add rule inet wgeasy_filter forward iifname "wg0" oifname "wg0" ip6 saddr ${client.addressV6} ip6 daddr @peer_ipv6 drop`);
      }
    }

    try {
      await Util.execFile('nft', ['-f', '-'], {
        input: `${commands.join('\n')}\n`,
        log: 'nft -f -',
      });
    } catch (err) {
      throw new ServerError(`Failed to apply network rules atomically: ${err.message}`, 500);
    }
    debug('All DNAT and client policy rules applied atomically.');
  }

  async __applyAllDnatRules() {
    return this.__applyAllNetworkRules();
  }

  // Best-effort TCP connect. Locally originated traffic may take a hairpin
  // path instead of traversing prerouting DNAT, which the verdict labels
  // honestly as 'dnat-local'.
  __tcpConnect(host, port, timeoutMs = 2000) {
    return new Promise((resolve) => {
      const socket = net.connect({ host, port });
      const finish = (result) => {
        socket.removeAllListeners();
        socket.destroy();
        resolve(result);
      };
      socket.setTimeout(timeoutMs, () => finish(false));
      socket.once('connect', () => finish(true));
      socket.once('error', () => finish(false));
    });
  }

  __peerTunnelUp(client) {
    const now = Date.now();
    const effectiveKeepalive = Number(this.__serverSettings.persistentKeepalive) || 180;
    const onlineWindowMs = 3 * effectiveKeepalive * 1000;
    return now - client.latestHandshakeAt.getTime() < onlineWindowMs;
  }

  // Three-level reachability verdict for one forwarding rule. Runs OUTSIDE the
  // mutation queue (it performs network I/O with a 2s budget); the rule is
  // snapshotted synchronously up front so concurrent mutations cannot change
  // what is being probed mid-flight.
  async probePortForward({ clientId, rule }) {
    const config = await this.getConfig();
    const client = config.clients[clientId];
    if (!client) throw new ServerError(`Client not found: ${clientId}`, 404);
    const rules = Array.isArray(client.portForwards) ? client.portForwards : [];
    const resolved = typeof rule === 'string' && /^[0-9]+$/.test(rule)
      ? rules[Number(rule)]
      : rules.find((entry) => entry && entry.id === rule);
    if (!resolved || !Number.isInteger(resolved.extPort) || !Number.isInteger(resolved.intPort)) {
      throw new ServerError('Port forward rule not found', 404);
    }
    const snapshot = {
      proto: resolved.proto,
      extPort: Number(resolved.extPort),
      intPort: Number(resolved.intPort),
      peerIP: client.address,
    };

    const probeKey = `${clientId}:${resolved.id ?? `${snapshot.proto}/${snapshot.extPort}`}`;
    const state = this.__probeState.get(probeKey);
    if (state && state.inFlight) return state.inFlight;
    if (state && Date.now() - state.lastAt < 30_000) {
      throw new ServerError('Probe rate limit: try again in less than 30s', 429);
    }

    const execution = (async () => {
      let liveRules = [];
      try {
        const tableJson = await Util.exec('nft -j list table ip wgeasy_dnat', { log: false });
        liveRules = parseDnatRules(tableJson);
      } catch (err) {
        debug(`Probe: could not list nft rules: ${err.message}`);
      }
      const isPresent = dnatRulePresent(liveRules, snapshot);

      let tunnelUp = false;
      try {
        const dump = await Util.exec('wg show wg0 dump', { log: false });
        const peerLine = String(dump).trim().split('\n').slice(1)
          .find((line) => line.split('\t')[0] === client.publicKey);
        const handshake = peerLine ? Number(peerLine.split('\t')[4]) : 0;
        if (handshake > 0) {
          tunnelUp = this.__peerTunnelUp({ latestHandshakeAt: new Date(handshake * 1000) });
        }
      } catch (err) {
        debug(`Probe: could not read wg dump: ${err.message}`);
      }

      const tcpConnectable = await this.__tcpConnect(this.__serverSettings.host, snapshot.extPort);

      let verdict;
      if (!isPresent) {
        verdict = tcpConnectable ? 'dnat-local' : 'rule-missing';
      } else if (!tunnelUp) {
        verdict = tcpConnectable ? 'dnat-local' : 'tunnel-down';
      } else {
        verdict = tcpConnectable ? 'ok' : 'unreachable';
      }
      return {
        rule: { ...snapshot },
        rulePresent: isPresent,
        tunnelUp,
        tcpConnectable,
        verdict,
      };
    })();

    this.__probeState.set(probeKey, { lastAt: Date.now(), inFlight: execution });
    try {
      return await execution;
    } finally {
      const current = this.__probeState.get(probeKey);
      if (current && current.inFlight === execution) {
        this.__probeState.set(probeKey, { lastAt: Date.now(), inFlight: null });
      }
    }
  }

  // Internal, queue-context-only guard: enforces selfManagePorts from the
  // state the queued operation is about to mutate. The route-level pre-check
  // happens outside the queue; a revoke landing between that check and this
  // execution must still reject (TOCTOU closure). Never call the public
  // getPeerProfile here — wrappers re-entering __withMutation are rejected.
  __assertSelfManagePorts(clientId) {
    const client = this.__config ? this.__config.clients[clientId] : null;
    if (!client || client.selfManagePorts !== true) {
      throw new ServerError('Self port management is disabled for this peer', 403);
    }
  }

  async addPortForward(clientId, proto, extPort, intPort, { requireSelfManagePorts = false } = {}) {
    return this.__withMutation(async () => {
      if (requireSelfManagePorts) {
        await this.getConfig();
        this.__assertSelfManagePorts(clientId);
      }
      return this.__addPortForward(clientId, proto, extPort, intPort);
    });
  }

  // Stable-id addressing: resolve the rule id to its index INSIDE the queued
  // operation so sibling mutations cannot shift the resolution underneath us.
  async removePortForwardById(clientId, ruleId) {
    if (!Util.isValidRuleId(ruleId)) throw new ServerError('Invalid rule id', 400);
    return this.__withMutation(async () => {
      const index = this.__findPortForwardIndex(clientId, ruleId);
      return this.__removePortForward(clientId, index);
    });
  }

  async updatePortForwardById(clientId, ruleId, proto, extPort, intPort) {
    if (!Util.isValidRuleId(ruleId)) throw new ServerError('Invalid rule id', 400);
    return this.__withMutation(async () => {
      const index = this.__findPortForwardIndex(clientId, ruleId);
      return this.__updatePortForward(clientId, index, proto, extPort, intPort);
    });
  }

  __findPortForwardIndex(clientId, ruleId) {
    const client = this.__config ? this.__config.clients[clientId] : null;
    const rules = client && Array.isArray(client.portForwards) ? client.portForwards : [];
    const index = rules.findIndex((rule) => rule && rule.id === ruleId);
    if (index === -1) throw new ServerError('Port forward rule not found', 404);
    return index;
  }

  // Sticky auto-assign: prefer ports this peer already holds (so a tracker
  // keyed on the external port keeps working across re-adds), then the
  // deterministic lowest-free scan. Scan and claim happen in ONE queued
  // operation — scanning from a route would let parallel requests race for
  // the same port.
  async autoAssignPortForward(clientId, {
    proto, intPort, rangeStart, rangeEnd,
  } = {}) {
    return this.__withMutation(async () => {
      if (!['tcp', 'udp', 'both'].includes(proto)) {
        throw new ServerError('proto must be tcp, udp or both', 400);
      }
      const internalPort = Util.parsePort(intPort);
      if (!Number.isInteger(internalPort) || internalPort < 1 || internalPort > 65535) {
        throw new ServerError('Invalid internal port (must be 1-65535)', 400);
      }
      let min = null;
      let max = null;
      if (rangeStart !== undefined && rangeStart !== null) {
        min = Util.parsePort(rangeStart);
        if (!Number.isInteger(min) || min < 1 || min > 65535) {
          throw new ServerError('Invalid rangeStart (must be 1-65535)', 400);
        }
      }
      if (rangeEnd !== undefined && rangeEnd !== null) {
        max = Util.parsePort(rangeEnd);
        if (!Number.isInteger(max) || max < 1 || max > 65535) {
          throw new ServerError('Invalid rangeEnd (must be 1-65535)', 400);
        }
      }
      if (min !== null && max !== null && min > max) {
        throw new ServerError('rangeStart cannot be greater than rangeEnd', 400);
      }

      const config = await this.getConfig();
      const client = config.clients[clientId];
      if (!client) throw new ServerError(`Client not found: ${clientId}`, 404);
      const rules = Array.isArray(client.portForwards) ? client.portForwards : [];

      const windowMin = Math.max(Number(this.__serverSettings.portFwdMin), min ?? 1);
      const windowMax = Math.min(Number(this.__serverSettings.portFwdMax), max ?? 65535);

      // Sticky candidates first (ascending), then the deterministic scan.
      const sticky = [...new Set(rules.map((rule) => rule.extPort))].sort((a, b) => a - b);
      const candidates = [...sticky, ...Array.from(
        { length: Math.max(0, windowMax - windowMin + 1) },
        (_, offset) => windowMin + offset,
      )];

      const inUse = (port) => Object.values(config.clients).some((peer) => Array.isArray(peer.portForwards)
        && peer.portForwards.some((rule) => (rule.proto === proto || rule.proto === 'both' || proto === 'both')
          && rule.extPort === port));

      for (const port of candidates) {
        if (port < windowMin || port > windowMax) continue; // sticky ports may fall outside the requested window
        // __isPortAllowed enforces the policy window and the reserved ports
        // (server port, config port).
        if (!this.__isPortAllowed(port)) continue;
        if (inUse(port)) continue;
        return this.__addPortForward(clientId, proto, port, internalPort);
      }
      throw new ServerError('No free port available in the configured range', 409);
    });
  }

  async __addPortForward(clientId, proto, extPort, intPort) {
    if (process.platform !== 'linux') {
      debug('Preview: Simulated adding port forward');
      DUMMY_CLIENT_PREVIEW.portForwards.push({ proto, extPort: Number(extPort), intPort: Number(intPort) });
      return;
    }
    const config = await this.getConfig();
    const client = config.clients[clientId];
    if (!client) throw new ServerError(`Client not found: ${clientId}`, 404);

    if (!Array.isArray(client.portForwards)) client.portForwards = [];

    const port = Number(extPort);
    const internalPort = Number(intPort);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new ServerError('Invalid external port (must be 1-65535)', 400);
    }
    if (!Number.isInteger(internalPort) || internalPort < 1 || internalPort > 65535) {
      throw new ServerError('Invalid internal port (must be 1-65535)', 400);
    }

    // Block unallowed ports
    if (!this.__isPortAllowed(port)) {
      throw new ServerError(`Port ${port} is not allowed by policy or is reserved`, 400);
    }

    // Validate extPort not already used by the same peer
    const selfConflict = client.portForwards.some((r) => (r.proto === proto || r.proto === 'both' || proto === 'both')
      && r.extPort === port);
    if (selfConflict) throw new ServerError(`Port ${proto}/${port} is already configured on this peer`, 409);

    // Validate extPort not already used by another peer
    const crossConflict = Object.values(config.clients).some((c) => c.id !== clientId
      && Array.isArray(c.portForwards)
      && c.portForwards.some((r) => (r.proto === proto || r.proto === 'both' || proto === 'both')
        && r.extPort === port));
    if (crossConflict) throw new ServerError(`Port ${proto}/${port} is already assigned to another peer`, 409);

    const created = {
      id: crypto.randomUUID(), proto, extPort: port, intPort: internalPort,
    };
    await this.__transactionalDnatChange(
      () => {
        client.portForwards.push(created);
      },
      () => {
        client.portForwards.pop();
      },
      'add-port-forward',
      {
        event: {
          type: 'port.confirmed',
          clientId,
          proto,
          extPort: port,
          intPort: internalPort,
        },
      },
    );
    return { ...created };
  }

  async removePortForward(clientId, index) {
    return this.__withMutation(() => this.__removePortForward(clientId, index));
  }

  async __removePortForward(clientId, index) {
    if (!Number.isInteger(index) || index < 0) {
      throw new ServerError('Invalid index', 400);
    }
    if (process.platform !== 'linux') {
      if (!Array.isArray(DUMMY_CLIENT_PREVIEW.portForwards) || DUMMY_CLIENT_PREVIEW.portForwards.length <= index) {
        throw new ServerError('Port forward rule not found', 404);
      }
      debug('Preview: Simulated removing port forward');
      DUMMY_CLIENT_PREVIEW.portForwards.splice(index, 1);
      return;
    }
    const config = await this.getConfig();
    const client = config.clients[clientId];
    if (!client) throw new ServerError(`Client not found: ${clientId}`, 404);

    // An out-of-range index must fail like updatePortForward does: returning
    // success for a no-op masks drift and breaks retry/idempotency assumptions.
    if (!Array.isArray(client.portForwards) || client.portForwards.length <= index) {
      throw new ServerError('Port forward rule not found', 404);
    }
    const ruleToRemove = client.portForwards[index];
    await this.__transactionalDnatChange(
      () => {
        client.portForwards.splice(index, 1);
      },
      () => {
        client.portForwards.splice(index, 0, ruleToRemove);
      },
      'remove-port-forward',
    );
  }

  // Resolve a rule reference (stable id or legacy numeric index) to its index
  // INSIDE the queued operation, so sibling mutations cannot shift it.
  async removePortForwardByRuleId(clientId, ruleId, { requireSelfManagePorts = false } = {}) {
    return this.__withMutation(async () => {
      if (requireSelfManagePorts) {
        await this.getConfig();
        this.__assertSelfManagePorts(clientId);
      }
      return this.__removePortForward(clientId, this.__resolveRuleIndex(clientId, ruleId));
    });
  }

  async updatePortForwardByRuleId(clientId, ruleId, proto, extPort, intPort, { requireSelfManagePorts = false } = {}) {
    return this.__withMutation(async () => {
      if (requireSelfManagePorts) {
        await this.getConfig();
        this.__assertSelfManagePorts(clientId);
      }
      return this.__updatePortForward(
        clientId,
        this.__resolveRuleIndex(clientId, ruleId),
        proto,
        extPort,
        intPort,
      );
    });
  }

  __resolveRuleIndex(clientId, ruleId) {
    const client = this.__config ? this.__config.clients[clientId] : null;
    const rules = client && Array.isArray(client.portForwards) ? client.portForwards : [];
    if (/^\d+$/.test(String(ruleId))) {
      return Number(ruleId);
    }
    const index = rules.findIndex((rule) => rule && rule.id === ruleId);
    if (index === -1) throw new ServerError('Port forward rule not found', 404);
    return index;
  }

  async updatePortForward(clientId, index, proto, extPort, intPort) {
    return this.__withMutation(() => this.__updatePortForward(clientId, index, proto, extPort, intPort));
  }

  async __updatePortForward(clientId, index, proto, extPort, intPort) {
    if (process.platform !== 'linux') {
      debug('Preview: Simulated updating port forward');
      DUMMY_CLIENT_PREVIEW.portForwards[index] = { proto, extPort: Number(extPort), intPort: Number(intPort) };
      return;
    }
    const config = await this.getConfig();
    const client = config.clients[clientId];
    if (!client) throw new ServerError(`Client not found: ${clientId}`, 404);

    const idx = Number(index);
    if (!Number.isInteger(idx) || idx < 0) {
      throw new ServerError('Invalid index', 400);
    }
    if (!Array.isArray(client.portForwards) || client.portForwards.length <= idx) {
      throw new ServerError('Port forward rule not found', 404);
    }

    const port = Number(extPort);
    const internalPort = Number(intPort);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new ServerError('Invalid external port (must be 1-65535)', 400);
    }
    if (!Number.isInteger(internalPort) || internalPort < 1 || internalPort > 65535) {
      throw new ServerError('Invalid internal port (must be 1-65535)', 400);
    }

    // Block unallowed ports
    if (!this.__isPortAllowed(port)) {
      throw new ServerError(`Port ${port} is not allowed by policy or is reserved`, 400);
    }

    // Validate extPort not already used by the same peer (excluding the rule being updated)
    const selfConflict = client.portForwards.some((r, i) => i !== idx
      && (r.proto === proto || r.proto === 'both' || proto === 'both')
      && r.extPort === port);
    if (selfConflict) throw new ServerError(`Port ${proto}/${port} is already configured on this peer`, 409);

    // Validate extPort not already used by another peer, ignoring current rule
    const crossConflict = Object.values(config.clients).some((c) => {
      if (!Array.isArray(c.portForwards)) return false;
      return c.portForwards.some((r, i) => {
        if (c.id === clientId && i === idx) return false;
        return (r.proto === proto || r.proto === 'both' || proto === 'both') && r.extPort === port;
      });
    });
    if (crossConflict) throw new ServerError(`Port ${proto}/${port} is already assigned to another peer`, 409);

    const oldRule = client.portForwards[idx];
    const updated = {
      id: Util.isValidRuleId(oldRule.id) ? oldRule.id : crypto.randomUUID(),
      proto,
      extPort: port,
      intPort: internalPort,
    };
    await this.__transactionalDnatChange(
      () => {
        client.portForwards[idx] = updated;
      },
      () => {
        client.portForwards[idx] = oldRule;
      },
      'update-port-forward',
      {
        event: {
          type: 'port.changed',
          clientId,
          proto,
          extPort: port,
          previousExtPort: oldRule.extPort,
          intPort: internalPort,
        },
      },
    );
    return { ...updated };
  }

};
