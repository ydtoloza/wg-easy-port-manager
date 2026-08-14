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
      port: WG_PORT,
      configPort: WG_CONFIG_PORT,
      device: process.env.WG_DEVICE || 'eth0',
      defaultDns: WG_DEFAULT_DNS,
      defaultAddress: WG_DEFAULT_ADDRESS,
      defaultAddressV6: WG_DEFAULT_ADDRESS_V6,
      enableIpv6: true,
      mtu: WG_MTU,
      allowedIps: WG_ALLOWED_IPS,
      persistentKeepalive: WG_PERSISTENT_KEEPALIVE,
      portFwdMin: Number(WG_PORT_FWD_MIN),
      portFwdMax: Number(WG_PORT_FWD_MAX),
    };
    this.__config = null;
    this.__initPromise = null;
  }

  async __buildConfig() {
    if (this.__config) return this.__config;

    if (!this.__serverSettings.host) {
      throw new Error('WG_HOST Environment Variable Not Set!');
    }

    debug('Loading configuration...');
    let config;
    try {
      config = await fs.readFile(path.join(WG_PATH, 'wg0.json'), 'utf8');
      config = JSON.parse(config);
      debug('Configuration loaded.');
    } catch (err) {
      const privateKey = await Util.exec('wg genkey');
      const publicKey = await Util.exec(`echo ${privateKey} | wg pubkey`, {
        log: 'echo ***hidden*** | wg pubkey',
      });
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
    }

    // Ensure all clients have portForwards array
    for (const client of Object.values(config.clients)) {
      if (!Array.isArray(client.portForwards)) {
        client.portForwards = [];
      }
    }

    // Migrate legacy server config: ensure server has addressV6
    if (!config.server.addressV6 && this.__serverSettings.enableIpv6) {
      config.server.addressV6 = this.__serverSettings.defaultAddressV6.replace('x', '1');
      debug('Migrated server to include addressV6.');
    }

    // Migrate legacy clients: assign addressV6 to any client missing it
    if (this.__serverSettings.enableIpv6) {
      const usedV6 = new Set(
        Object.values(config.clients)
          .filter((c) => c.addressV6)
          .map((c) => c.addressV6),
      );
      for (const client of Object.values(config.clients)) {
        if (!client.addressV6) {
          for (let i = 2; i < 255; i++) {
            const candidate = this.__serverSettings.defaultAddressV6.replace('x', i);
            if (!usedV6.has(candidate)) {
              client.addressV6 = candidate;
              usedV6.add(candidate);
              debug(`Migrated client ${client.name} → addressV6: ${candidate}`);
              break;
            }
          }
        }
      }
    }

    // Load persisted server settings if available
    try {
      const settingsRaw = await fs.readFile(path.join(WG_PATH, 'server-settings.json'), 'utf8');
      const saved = JSON.parse(settingsRaw);
      // Merge saved settings over env defaults
      Object.assign(this.__serverSettings, saved);
      debug('Server settings loaded from disk.');
    } catch {
      // No saved settings, use env defaults
    }

    this.__config = config;
    return config;
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

      await this.__saveConfig(config);
      await Util.exec('wg-quick down wg0').catch(() => {});
      await Util.exec('wg-quick up wg0').catch((err) => {
        if (err && err.message && err.message.includes('Cannot find device "wg0"')) {
          throw new Error('WireGuard exited with the error: Cannot find device "wg0"\nThis usually means that your host\'s kernel does not support WireGuard!');
        }
        throw err;
      });

      await this.__syncConfig();
      await this.__ensureNftablesSetup();
      await this.__applyAllDnatRules();

      debug('WireGuard initialization completed.');
    })();

    return this.__initPromise;
  }

  async saveConfig() {
    const config = await this.getConfig();
    await this.__saveConfig(config);
    await this.__syncConfig();
  }

  async __saveConfig(config) {
    let result = `
# Note: Do not edit this file directly.
# Your changes will be overwritten!

# Server
[Interface]
PrivateKey = ${config.server.privateKey}
Address = ${config.server.address}/24${this.__serverSettings.enableIpv6 && config.server.addressV6 ? `, ${config.server.addressV6}/64` : ''}
ListenPort = ${this.__serverSettings.port}
PreUp = ${WG_PRE_UP}
PostUp = ${WG_POST_UP}
PreDown = ${WG_PRE_DOWN}
PostDown = ${WG_POST_DOWN}
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
    const jsonTmp = path.join(WG_PATH, 'wg0.json.tmp');
    const confTmp = path.join(WG_PATH, 'wg0.conf.tmp');
    const jsonFile = path.join(WG_PATH, 'wg0.json');
    const confFile = path.join(WG_PATH, 'wg0.conf');

    try {
      await fs.writeFile(jsonTmp, JSON.stringify(config, false, 2), { mode: 0o660 });
      await fs.writeFile(confTmp, result, { mode: 0o600 });

      await fs.rename(jsonTmp, jsonFile);
      await fs.rename(confTmp, confFile);

      debug('Config saved.');
    } catch (err) {
      debug(`Error saving config: ${err.message}`);
      await fs.unlink(jsonTmp).catch(() => {});
      await fs.unlink(confTmp).catch(() => {});
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
    if (!Util.isValidName(name)) {
      throw new ServerError('Invalid name: 1-64 chars, no control characters', 400);
    }

    const config = await this.getConfig();

    const privateKey = await Util.exec('wg genkey');
    const publicKey = await Util.exec(`echo ${privateKey} | wg pubkey`, {
      log: 'echo ***hidden*** | wg pubkey',
    });
    const preSharedKey = await Util.exec('wg genpsk');

    // Calculate next IP
    let address;
    let addressV6;
    for (let i = 2; i < 255; i++) {
      const client = Object.values(config.clients).find((client) => {
        return client.address === this.__serverSettings.defaultAddress.replace('x', i)
               || (this.__serverSettings.enableIpv6 && client.addressV6 === this.__serverSettings.defaultAddressV6.replace('x', i));
      });

      if (!client) {
        address = this.__serverSettings.defaultAddress.replace('x', i);
        addressV6 = this.__serverSettings.enableIpv6 ? this.__serverSettings.defaultAddressV6.replace('x', i) : null;
        break;
      }
    }

    if (!address) {
      throw new Error('Maximum number of clients reached.');
    }

    // Create Client
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

    config.clients[id] = client;

    await this.saveConfig();

    return client;
  }

  async deleteClient({ clientId }) {
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
  }

  async enableClient({ clientId }) {
    const client = await this.getClient({ clientId });

    client.enabled = true;
    client.updatedAt = new Date();

    await this.saveConfig();
  }

  async disableClient({ clientId }) {
    const client = await this.getClient({ clientId });

    client.enabled = false;
    client.updatedAt = new Date();

    await this.saveConfig();
  }

  async updateClientName({ clientId, name }) {
    const client = await this.getClient({ clientId });

    if (!Util.isValidName(name)) {
      throw new ServerError('Invalid name: 1-64 chars, no control characters', 400);
    }

    client.name = name;
    client.updatedAt = new Date();

    await this.saveConfig();
  }

  async updateClientAddress({ clientId, address, addressV6 }) {
    const client = await this.getClient({ clientId });

    if (address && !Util.isValidIPv4(address)) {
      throw new ServerError(`Invalid IPv4 Address: ${address}`, 400);
    }

    if (addressV6 && !Util.isValidIPv6(addressV6)) {
      throw new ServerError(`Invalid IPv6 Address: ${addressV6}`, 400);
    }

    const oldAddress = client.address;
    const oldAddressV6 = client.addressV6;
    const oldUpdatedAt = client.updatedAt;

    await this.__transactionalDnatChange(
      () => {
        if (address) client.address = address;
        if (addressV6) client.addressV6 = addressV6;
        client.updatedAt = new Date();
      },
      () => {
        client.address = oldAddress;
        client.addressV6 = oldAddressV6;
        client.updatedAt = oldUpdatedAt;
      },
      'update-client-address',
    );
  }

  async __reloadConfig() {
    // Clear cache to force re-read from disk (needed after restoreConfiguration)
    this.__config = null;
    await this.__buildConfig();
    await this.__syncConfig();
  }

  async restoreConfiguration(config) {
    debug('Starting configuration restore process.');

    let _config;
    try {
      _config = JSON.parse(config);
    } catch {
      throw new ServerError('Invalid backup: not valid JSON', 400);
    }

    if (!_config || typeof _config !== 'object') {
      throw new ServerError('Invalid backup: expected an object', 400);
    }

    // Validate server settings (prevents injection of [Interface] directives).
    const server = _config.server || {};
    for (const key of ['privateKey', 'publicKey']) {
      const value = server[key];
      if (typeof value !== 'string' || !/^[A-Za-z0-9+/=_-]+$/.test(value)) {
        throw new ServerError(`Invalid backup: invalid server.${key}`, 400);
      }
    }
    if (typeof server.address !== 'string' || !Util.isValidIPv4(server.address)) {
      throw new ServerError(`Invalid backup: invalid server.address: ${server.address}`, 400);
    }
    if (server.addressV6 != null && (typeof server.addressV6 !== 'string' || !Util.isValidIPv6(server.addressV6))) {
      throw new ServerError(`Invalid backup: invalid server.addressV6: ${server.addressV6}`, 400);
    }

    // Validate clients (names, addresses) and sanitize port forward rules.
    for (const client of Object.values(_config.clients || {})) {
      if (!client || typeof client !== 'object') {
        throw new ServerError('Invalid backup: invalid client entry', 400);
      }
      if (client.name !== undefined && !Util.isValidName(client.name)) {
        throw new ServerError(`Invalid backup: invalid client name: ${client.name}`, 400);
      }
      if (typeof client.address !== 'string' || !Util.isValidIPv4(client.address)) {
        throw new ServerError(`Invalid IPv4 address: ${client.address}`, 400);
      }
      if (client.addressV6 != null && (typeof client.addressV6 !== 'string' || !Util.isValidIPv6(client.addressV6))) {
        throw new ServerError(`Invalid IPv6 address: ${client.addressV6}`, 400);
      }

      if (!Array.isArray(client.portForwards)) {
        client.portForwards = [];
        continue;
      }
      client.portForwards = client.portForwards
        .filter((rule) => {
          const ep = Number(rule.extPort);
          const ip = Number(rule.intPort);
          if (!['tcp', 'udp', 'both'].includes(rule.proto)) return false;
          if (!Number.isInteger(ep) || ep < 1 || ep > 65535) return false;
          if (!Number.isInteger(ip) || ip < 1 || ip > 65535) return false;
          if (!this.__isPortAllowed(ep)) {
            debug(`restoreConfiguration: dropping unallowed port ${ep} for client ${client.name}`);
            return false;
          }
          return true;
        })
        .map((rule) => ({
          proto: rule.proto,
          extPort: Number(rule.extPort),
          intPort: Number(rule.intPort),
        }));
    }

    const oldConfig = this.__config;
    await this.__transactionalDnatChange(
      () => {
        this.__config = _config;
      },
      () => {
        this.__config = oldConfig;
      },
      'restore',
    );
    // restoreConfiguration forces a reload after a successful save so wg0 interface syncs properly.
    await this.__reloadConfig();
    debug('Configuration restore process completed.');
  }

  async __transactionalDnatChange(mutate, rollback, context = 'dnat-change') {
    mutate();
    try {
      await this.__applyAllDnatRules(true);
      await this.saveConfig();
    } catch (err) {
      rollback();
      const rollbackErrors = [];
      await this.__applyAllDnatRules(false).catch((rollbackErr) => {
        const msg = `Host rollback failed in ${context}: ${rollbackErr.message}`;
        debug(msg);
        rollbackErrors.push(msg);
      });
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
      throw err;
    }
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
    await Util.exec('wg-quick down wg0').catch(() => {});
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
    await this.getConfig();

    if (!settings || typeof settings !== 'object') {
      throw new ServerError('Invalid body: expected an object', 400);
    }

    const isPort = (v) => Number.isInteger(Number(v)) && Number(v) >= 1 && Number(v) <= 65535;
    const isPlainString = (v) => typeof v === 'string' && !/[\r\n]/.test(v);

    const validators = {
      host: (v) => typeof v === 'string' && v.length > 0 && v.length <= 255 && isPlainString(v),
      port: (v) => isPort(v),
      configPort: (v) => isPort(v),
      device: (v) => typeof v === 'string' && /^[A-Za-z0-9_.-]+$/.test(v),
      defaultDns: (v) => typeof v === 'string' && v.length <= 255 && isPlainString(v),
      defaultAddress: (v) => typeof v === 'string' && v.length <= 255 && isPlainString(v)
        && /^[0-9A-Fa-f.:/x]+$/.test(v) && v.includes('x'),
      defaultAddressV6: (v) => typeof v === 'string' && v.length <= 255 && isPlainString(v)
        && /^[0-9A-Fa-f:x]+$/.test(v) && v.includes('x'),
      enableIpv6: (v) => typeof v === 'boolean',
      mtu: (v) => v === null || (Number.isInteger(Number(v)) && Number(v) >= 576 && Number(v) <= 65535),
      allowedIps: (v) => typeof v === 'string' && v.length <= 255 && isPlainString(v),
      persistentKeepalive: (v) => v === null || (Number.isInteger(Number(v)) && Number(v) >= 0 && Number(v) <= 65535),
      portFwdMin: (v) => isPort(v),
      portFwdMax: (v) => isPort(v),
    };

    const allowed = ['host', 'port', 'configPort', 'device', 'defaultDns',
      'defaultAddress', 'defaultAddressV6', 'enableIpv6', 'mtu', 'allowedIps',
      'persistentKeepalive', 'portFwdMin', 'portFwdMax'];

    for (const key of allowed) {
      if (settings[key] === undefined) continue;

      if (!validators[key](settings[key])) {
        throw new ServerError(`Invalid value for ${key}`, 400);
      }
      this.__serverSettings[key] = settings[key];
    }

    // Normalize numeric settings
    for (const key of ['port', 'configPort', 'mtu', 'persistentKeepalive', 'portFwdMin', 'portFwdMax']) {
      const value = this.__serverSettings[key];
      if (value !== null && value !== undefined) {
        this.__serverSettings[key] = Number(value);
      }
    }

    if (this.__serverSettings.portFwdMin > this.__serverSettings.portFwdMax) {
      throw new ServerError('portFwdMin cannot be greater than portFwdMax', 400);
    }

    // Persist to disk
    await fs.writeFile(
      path.join(WG_PATH, 'server-settings.json'),
      JSON.stringify(this.__serverSettings, null, 2),
      { mode: 0o660 },
    );

    debug('Server settings updated and persisted.');
    return { ...this.__serverSettings };
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
    try {
      await Util.exec('nft add table ip wgeasy_dnat');
      await Util.exec("nft add chain ip wgeasy_dnat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'");
      debug('nftables IPv4 table/chain ensured.');
    } catch (err) {
      // It might already exist, which is fine
    }
    try {
      await Util.exec('nft add table ip6 wgeasy_dnat');
      await Util.exec("nft add chain ip6 wgeasy_dnat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'");
      debug('nftables IPv6 table/chain ensured.');
    } catch (err) {
      // It might already exist, which is fine
    }
  }

  async __applyAllDnatRules(throwOnError = false) {
    try {
      await Util.exec('nft flush chain ip wgeasy_dnat prerouting');
      await Util.exec('nft flush chain ip6 wgeasy_dnat prerouting');
    } catch (err) {
      if (throwOnError) {
        throw new ServerError(`Failed to flush DNAT chains: ${err.message}`, 500);
      }
      debug(`Failed to flush DNAT chains: ${err.message}`);
    }

    // Use config directly
    const config = await this.getConfig();
    const errors = [];
    for (const client of Object.values(config.clients)) {
      if (!client.enabled || !client.portForwards || !client.portForwards.length) continue;

      const peerIP = client.address.split('/')[0];
      const peerIPv6 = (this.__serverSettings.enableIpv6 && client.addressV6) ? client.addressV6.split('/')[0] : null;

      // Prevención de inyección: validar IPs antes de usarlas en comandos shell
      if (!Util.isValidIPv4(peerIP)) {
        if (throwOnError) errors.push(new Error(`Invalid IPv4 address: ${peerIP}`));
        debug(`Skipping client with invalid IPv4: ${peerIP}`);
        continue;
      }
      if (peerIPv6 && !Util.isValidIPv6(peerIPv6)) {
        if (throwOnError) errors.push(new Error(`Invalid IPv6 address: ${peerIPv6}`));
        debug(`Skipping client with invalid IPv6: ${peerIPv6}`);
        continue;
      }

      for (const rule of client.portForwards) {
        const { proto } = rule;
        let { extPort, intPort } = rule;

        // Prevención de inyección: forzar tipos y validar estrictamente
        extPort = Number(extPort);
        intPort = Number(intPort);
        if (!Number.isInteger(extPort) || !Number.isInteger(intPort) || extPort < 1 || extPort > 65535 || intPort < 1 || intPort > 65535) {
          if (throwOnError) errors.push(new Error(`Invalid port: extPort=${extPort}, intPort=${intPort}`));
          debug(`Skipping rule with invalid ports: extPort=${extPort}, intPort=${intPort}`);
          continue;
        }
        if (!['tcp', 'udp', 'both'].includes(proto)) {
          if (throwOnError) errors.push(new Error(`Invalid proto: ${proto}`));
          debug(`Skipping rule with invalid proto: ${proto}`);
          continue;
        }

        const protocols = proto === 'both' ? ['tcp', 'udp'] : [proto];

        for (const p of protocols) {
          // IPv4 DNAT rule
          const cmd4 = `nft add rule ip wgeasy_dnat prerouting ${p} dport ${extPort} dnat to ${peerIP}:${intPort}`;
          await Util.exec(cmd4).catch((err) => {
            debug(`Error applying IPv4 DNAT rule: ${err.message}`);
            errors.push(err);
          });

          // IPv6 DNAT rule (only if client has an IPv6 address)
          if (peerIPv6) {
            const cmd6 = `nft add rule ip6 wgeasy_dnat prerouting ${p} dport ${extPort} dnat to [${peerIPv6}]:${intPort}`;
            await Util.exec(cmd6).catch((err) => {
              debug(`Error applying IPv6 DNAT rule: ${err.message}`);
              errors.push(err);
            });
          }
        }
      }
    }
    debug('All DNAT rules applied (IPv4 + IPv6).');
    if (throwOnError && errors.length > 0) {
      throw new ServerError(`Failed to apply DNAT rules: ${errors.map((e) => e.message).join(', ')}`, 500);
    }
  }

  async addPortForward(clientId, proto, extPort, intPort) {
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
