'use strict';

const fs = require('node:fs/promises');
const path = require('path');
const debug = require('debug')('WireGuard');
const crypto = require('node:crypto');
const QRCode = require('qrcode');

const Util = require('./Util');
const ServerError = require('./ServerError');

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
} = require('../config');

const WIREGUARD_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;
const CLIENT_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const SERVER_SETTING_KEYS = ['host', 'port', 'configPort', 'device', 'defaultDns',
  'defaultAddress', 'defaultAddressV6', 'enableIpv6', 'mtu', 'allowedIps',
  'persistentKeepalive', 'portFwdMin', 'portFwdMax'];

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
};

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
    };
    this.__config = null;
    this.__initPromise = null;
    this.__mutationQueue = Promise.resolve();
    this.__settingsRecoveryPending = false;
    this.__settingsRecoveryConfig = null;
  }

  __withMutation(operation) {
    const run = this.__mutationQueue.then(operation, operation);
    this.__mutationQueue = run.catch(() => {});
    return run;
  }

  async waitForMutations() {
    await this.__mutationQueue;
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
  }

  async __buildConfig() {
    if (this.__config) return this.__config;

    await this.__loadServerSettings();

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
      const privateKey = await Util.exec('wg genkey');
      const publicKey = await Util.execFile('wg', ['pubkey'], { input: `${privateKey}\n`, log: 'wg pubkey' });
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

    // Ensure all clients have portForwards array
    for (const [clientId, client] of Object.entries(config.clients)) {
      if (!isPlainObject(client)) throw new Error(`Invalid client entry: ${clientId}`);
      if (client.id === undefined) client.id = clientId;
      if (client.enabled === undefined) client.enabled = true;
      if (!Array.isArray(client.portForwards)) {
        client.portForwards = [];
      }
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
    const allowedClientKeys = ['id', 'name', 'address', 'addressV6', 'privateKey', 'publicKey',
      'preSharedKey', 'createdAt', 'updatedAt', 'enabled', 'portForwards', 'allowedIPs'];

    for (const [clientId, client] of Object.entries(config.clients)) {
      if (!CLIENT_ID_RE.test(clientId) || !isPlainObject(client)) {
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
      if (!Array.isArray(client.portForwards)) {
        throw new ServerError(`Invalid client.portForwards: ${clientId}`, 400);
      }

      for (const rule of client.portForwards) {
        if (!isPlainObject(rule)) throw new ServerError(`Invalid port forward for ${clientId}`, 400);
        if (strict && Object.keys(rule).some((key) => !['proto', 'extPort', 'intPort'].includes(key))) {
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
          if (forwardedPorts.has(key)) throw new ServerError(`Duplicate forwarded port: ${key}`, 400);
          forwardedPorts.add(key);
        }
      }
    }
  }

  async getConfig() {
    if (!this.__config) {
      await this.__buildConfig();
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
      await this.__bringWireGuardUp();

      await this.__syncConfig();
      await this.__ensureNftablesSetup();
      await this.__applyAllDnatRules();
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
  }

  async saveConfig() {
    const config = await this.getConfig();
    await this.__saveConfig(config);
    await this.__syncConfig();
  }

  __getPostUp() {
    if (process.env.WG_POST_UP) return WG_POST_UP;
    const commands = [
      `iptables -t nat -I POSTROUTING 1 -s ${this.__serverSettings.defaultAddress.replace('x', '0')}/24 -o ${this.__serverSettings.device} -j MASQUERADE;`,
      `iptables -I INPUT 1 -p udp -m udp --dport ${this.__serverSettings.port} -j ACCEPT;`,
      'iptables -I FORWARD 1 -i wg0 -j ACCEPT;',
      'iptables -I FORWARD 1 -o wg0 -j ACCEPT;',
    ];
    if (this.__serverSettings.enableIpv6) {
      commands.push(
        `ip6tables -t nat -I POSTROUTING 1 -s ${this.__serverSettings.defaultAddressV6.replace('x', '0')}/64 -o ${this.__serverSettings.device} -j MASQUERADE;`,
        'ip6tables -I FORWARD 1 -i wg0 -j ACCEPT;',
        'ip6tables -I FORWARD 1 -o wg0 -j ACCEPT;',
      );
    }
    return commands.join(' ');
  }

  __getPostDown() {
    if (process.env.WG_POST_DOWN) return WG_POST_DOWN;
    const commands = [
      `iptables -t nat -D POSTROUTING -s ${this.__serverSettings.defaultAddress.replace('x', '0')}/24 -o ${this.__serverSettings.device} -j MASQUERADE;`,
      `iptables -D INPUT -p udp -m udp --dport ${this.__serverSettings.port} -j ACCEPT;`,
      'iptables -D FORWARD -i wg0 -j ACCEPT;',
      'iptables -D FORWARD -o wg0 -j ACCEPT;',
    ];
    if (this.__serverSettings.enableIpv6) {
      commands.push(
        `ip6tables -t nat -D POSTROUTING -s ${this.__serverSettings.defaultAddressV6.replace('x', '0')}/64 -o ${this.__serverSettings.device} -j MASQUERADE;`,
        'ip6tables -D FORWARD -i wg0 -j ACCEPT;',
        'ip6tables -D FORWARD -o wg0 -j ACCEPT;',
      );
    }
    return commands.join(' ');
  }

  async __saveConfig(config) {
    this.__validateConfig(config);
    let result = `
# Note: Do not edit this file directly.
# Your changes will be overwritten!

# Server
[Interface]
PrivateKey = ${config.server.privateKey}
Address = ${config.server.address}/24${this.__serverSettings.enableIpv6 && config.server.addressV6 ? `, ${config.server.addressV6}/64` : ''}
ListenPort = ${this.__serverSettings.port}
PreUp = ${WG_PRE_UP}
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
      portForwards: Array.isArray(client.portForwards) ? client.portForwards : [],
      downloadableConfig: 'privateKey' in client,
      persistentKeepalive: null,
      latestHandshakeAt: null,
      transferRx: null,
      transferTx: null,
    }));

    // Loop WireGuard status
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
          endpoint, // eslint-disable-line no-unused-vars
          allowedIps, // eslint-disable-line no-unused-vars
          latestHandshakeAt,
          transferRx,
          transferTx,
          persistentKeepalive,
        ] = line.split('\t');

        const client = clients.find((client) => client.publicKey === publicKey);
        if (!client) return;

        client.latestHandshakeAt = latestHandshakeAt === '0'
          ? null
          : new Date(Number(`${latestHandshakeAt}000`));
        client.transferRx = Number(transferRx);
        client.transferTx = Number(transferTx);
        client.persistentKeepalive = persistentKeepalive;
      });

    return clients;
  }

  async getClient({ clientId }) {
    if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
      throw new ServerError(`Client Not Found: ${clientId}`, 404);
    }

    const config = await this.getConfig();
    const client = config.clients[clientId];
    if (!client) {
      throw new ServerError(`Client Not Found: ${clientId}`, 404);
    }

    return client;
  }

  async getClientConfiguration({ clientId }) {
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
PersistentKeepalive = ${this.__serverSettings.persistentKeepalive}
Endpoint = ${this.__serverSettings.host}:${this.__serverSettings.configPort}`;
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
      };
      await this.__transactionalConfigChange(
        () => {
          config.clients[id] = client;
        },
        () => {
          delete config.clients[id];
        },
        { context: 'create-client' },
      );
      return client;
    });
  }

  async deleteClient({ clientId }) {
    return this.__withMutation(async () => {
      const config = await this.getConfig();
      if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
        throw new ServerError(`Client Not Found: ${clientId}`, 404);
      }
      if (config.clients[clientId]) {
        const removedClient = config.clients[clientId];
        await this.__transactionalDnatChange(
          () => {
            delete config.clients[clientId];
          },
          () => {
            config.clients[clientId] = removedClient;
          },
          'delete-client',
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

  async updateClientAddress({ clientId, address, addressV6 }) {
    return this.__withMutation(async () => {
      const config = await this.getConfig();
      const client = await this.getClient({ clientId });
      if (address && !Util.isValidIPv4(address)) throw new ServerError(`Invalid IPv4 Address: ${address}`, 400);
      if (addressV6 && !Util.isValidIPv6(addressV6)) throw new ServerError(`Invalid IPv6 Address: ${addressV6}`, 400);
      if (address && (address === config.server.address
        || Object.values(config.clients).some((candidate) => candidate !== client && candidate.address === address))) {
        throw new ServerError(`IPv4 address already in use: ${address}`, 400);
      }
      if (addressV6 && (addressV6 === config.server.addressV6
        || Object.values(config.clients).some((candidate) => candidate !== client && candidate.addressV6 === addressV6))) {
        throw new ServerError(`IPv6 address already in use: ${addressV6}`, 400);
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
      );
    });
  }

  async __reloadConfig() {
    // Clear cache to force re-read from disk (needed after restoreConfiguration)
    this.__config = null;
    await this.__buildConfig();
    await this.__syncConfig();
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
      );
      debug('Configuration restore process completed.');
    });
  }

  async __transactionalConfigChange(mutate, rollback, {
    applyDnat = false,
    context = 'config-change',
  } = {}) {
    await mutate();
    try {
      if (applyDnat) await this.__applyAllDnatRules();
      await this.saveConfig();
    } catch (err) {
      await rollback();
      const rollbackErrors = [];
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
      await this.__syncConfig().catch((syncErr) => {
        const msg = `WG sync rollback failed in ${context}: ${syncErr.message}`;
        debug(msg);
        rollbackErrors.push(msg);
      });
      err.rollbackErrors = rollbackErrors;
      if (rollbackErrors.length) err.data = { rollbackFailed: true };
      throw err;
    }
  }

  async __transactionalDnatChange(mutate, rollback, context = 'dnat-change') {
    return this.__transactionalConfigChange(mutate, rollback, { applyDnat: true, context });
  }

  async backupConfiguration() {
    debug('Starting configuration backup.');
    const config = await this.getConfig();
    const backup = JSON.stringify(config, null, 2);
    debug('Configuration backup completed.');
    return backup;
  }

  // Shutdown wireguard
  async Shutdown() {
    await this.__bringWireGuardDown();
    // Eliminar las tablas de DNAT para no dejar reglas huérfanas en el host
    await Util.exec('nft delete table ip wgeasy_dnat').catch(() => {});
    await Util.exec('nft delete table ip6 wgeasy_dnat').catch(() => {});
  }

  // ── Server Settings (Global IP Config) ──────────────────────────

  async getServerConfig() {
    // Ensure config is loaded (which also loads settings)
    await this.getConfig();
    return { ...this.__serverSettings };
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
        await this.__bringWireGuardUp();
        await this.__ensureNftablesSetup();
        await this.__applyAllDnatRules();
        await this.__completeSettingsTransaction();
      } catch (err) {
        const rollbackErrors = [];
        await this.__bringWireGuardDown().catch((rollbackErr) => {
          rollbackErrors.push(`WireGuard shutdown rollback failed: ${rollbackErr.message}`);
        });
        this.__serverSettings = previous;
        this.__config = previousConfig;
        await this.__saveConfig(previousConfig).catch((rollbackErr) => {
          rollbackErrors.push(`Settings config rollback failed: ${rollbackErr.message}`);
        });
        await this.__bringWireGuardUp().catch((rollbackErr) => {
          rollbackErrors.push(`WireGuard settings rollback failed: ${rollbackErr.message}`);
        });
        await this.__ensureNftablesSetup()
          .then(() => this.__applyAllDnatRules())
          .catch((rollbackErr) => {
            rollbackErrors.push(`DNAT settings rollback failed: ${rollbackErr.message}`);
          });
        await this.__completeSettingsTransaction().catch((rollbackErr) => {
          rollbackErrors.push(`Settings journal rollback failed: ${rollbackErr.message}`);
        });
        err.rollbackErrors = rollbackErrors;
        if (rollbackErrors.length) err.data = { rollbackFailed: true };
        throw err;
      }

      debug('Server settings updated, applied and persisted.');
      return { ...this.__serverSettings };
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

  async __applyAllDnatRules() {
    const config = await this.getConfig();
    this.__validateConfig(config);
    if (!this.__serverSettings.enableIpv6) await this.__removeIpv6DnatTable();
    await this.__ensureNftablesSetup();
    const commands = [
      'flush chain ip wgeasy_dnat prerouting',
    ];
    if (this.__serverSettings.enableIpv6) commands.push('flush chain ip6 wgeasy_dnat prerouting');

    for (const client of Object.values(config.clients)) {
      if (!client.enabled || !client.portForwards || !client.portForwards.length) continue;

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

    try {
      await Util.execFile('nft', ['-f', '-'], {
        input: `${commands.join('\n')}\n`,
        log: 'nft -f -',
      });
    } catch (err) {
      throw new ServerError(`Failed to apply DNAT rules atomically: ${err.message}`, 500);
    }
    debug('All DNAT rules applied atomically (IPv4 + IPv6).');
  }

  async addPortForward(clientId, proto, extPort, intPort) {
    return this.__withMutation(() => this.__addPortForward(clientId, proto, extPort, intPort));
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
      throw new ServerError('Puerto externo inválido (debe ser 1–65535)', 400);
    }
    if (!Number.isInteger(internalPort) || internalPort < 1 || internalPort > 65535) {
      throw new ServerError('Puerto interno inválido (debe ser 1–65535)', 400);
    }

    // Block unallowed ports
    if (!this.__isPortAllowed(port)) {
      throw new ServerError(`El puerto ${port} no está permitido por la política o está reservado`, 400);
    }

    // Validate extPort not already used by the same peer
    const selfConflict = client.portForwards.some((r) => (r.proto === proto || r.proto === 'both' || proto === 'both')
      && r.extPort === port);
    if (selfConflict) throw new ServerError(`El puerto ${proto}/${port} ya está configurado en este peer`, 400);

    // Validate extPort not already used by another peer
    const crossConflict = Object.values(config.clients).some((c) => c.id !== clientId
      && Array.isArray(c.portForwards)
      && c.portForwards.some((r) => (r.proto === proto || r.proto === 'both' || proto === 'both')
        && r.extPort === port));
    if (crossConflict) throw new ServerError(`El puerto ${proto}/${port} ya está asignado a otro peer`, 400);

    await this.__transactionalDnatChange(
      () => {
        client.portForwards.push({ proto, extPort: port, intPort: internalPort });
      },
      () => {
        client.portForwards.pop();
      },
      'add-port-forward',
    );
  }

  async removePortForward(clientId, index) {
    return this.__withMutation(() => this.__removePortForward(clientId, index));
  }

  async __removePortForward(clientId, index) {
    if (process.platform !== 'linux') {
      debug('Preview: Simulated removing port forward');
      DUMMY_CLIENT_PREVIEW.portForwards.splice(index, 1);
      return;
    }
    const config = await this.getConfig();
    const client = config.clients[clientId];
    if (!client) throw new ServerError(`Client not found: ${clientId}`, 404);

    if (!Number.isInteger(index) || index < 0) {
      throw new ServerError('Invalid index', 400);
    }

    if (Array.isArray(client.portForwards) && client.portForwards.length > index) {
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
      throw new ServerError('Puerto externo inválido (debe ser 1–65535)', 400);
    }
    if (!Number.isInteger(internalPort) || internalPort < 1 || internalPort > 65535) {
      throw new ServerError('Puerto interno inválido (debe ser 1–65535)', 400);
    }

    // Block unallowed ports
    if (!this.__isPortAllowed(port)) {
      throw new ServerError(`El puerto ${port} no está permitido por la política o está reservado`, 400);
    }

    // Validate extPort not already used by the same peer (excluding the rule being updated)
    const selfConflict = client.portForwards.some((r, i) => i !== idx
      && (r.proto === proto || r.proto === 'both' || proto === 'both')
      && r.extPort === port);
    if (selfConflict) throw new ServerError(`El puerto ${proto}/${port} ya está configurado en este peer`, 400);

    // Validate extPort not already used by another peer, ignoring current rule
    const crossConflict = Object.values(config.clients).some((c) => {
      if (!Array.isArray(c.portForwards)) return false;
      return c.portForwards.some((r, i) => {
        if (c.id === clientId && i === idx) return false;
        return (r.proto === proto || r.proto === 'both' || proto === 'both') && r.extPort === port;
      });
    });
    if (crossConflict) throw new ServerError(`El puerto ${proto}/${port} ya está asignado a otro peer`, 400);

    const oldRule = client.portForwards[idx];
    await this.__transactionalDnatChange(
      () => {
        client.portForwards[idx] = { proto, extPort: port, intPort: internalPort };
      },
      () => {
        client.portForwards[idx] = oldRule;
      },
      'update-port-forward',
    );
  }

};
