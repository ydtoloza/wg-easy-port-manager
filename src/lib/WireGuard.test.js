/* eslint-env jest */

'use strict';

const fs = require('node:fs/promises');
const Util = require('./Util');
const ServerError = require('./ServerError');

const KEYS = {
  serverPrivate: Buffer.alloc(32, 1).toString('base64'),
  serverPublic: Buffer.alloc(32, 2).toString('base64'),
  clientPrivate: Buffer.alloc(32, 3).toString('base64'),
  clientPublic: Buffer.alloc(32, 4).toString('base64'),
  preShared: Buffer.alloc(32, 5).toString('base64'),
  client2Public: Buffer.alloc(32, 6).toString('base64'),
};
const originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');

const makeConfig = () => ({
  server: {
    privateKey: KEYS.serverPrivate,
    publicKey: KEYS.serverPublic,
    address: '10.8.0.1',
    addressV6: 'fd42:42:42::1',
  },
  clients: {
    client1: {
      id: 'client1',
      name: 'client1',
      address: '10.8.0.2',
      addressV6: 'fd42:42:42::2',
      privateKey: KEYS.clientPrivate,
      publicKey: KEYS.clientPublic,
      preSharedKey: KEYS.preShared,
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
      enabled: true,
      portForwards: [
        { proto: 'tcp', extPort: 2000, intPort: 2000 },
      ],
    },
  },
});

jest.mock('node:fs/promises');
jest.mock('./Util');
jest.mock('../config', () => ({
  WG_PATH: '/mock/path',
  WG_HOST: '10.0.0.1',
  WG_PORT: '51820',
  WG_CONFIG_PORT: '51820',
  WG_DEVICE: 'eth0',
  WG_MTU: '1420',
  WG_DEFAULT_DNS: '1.1.1.1',
  WG_DEFAULT_ADDRESS: '10.8.0.x',
  WG_DEFAULT_ADDRESS_V6: 'fd42:42:42::x',
  WG_PERSISTENT_KEEPALIVE: '25',
  WG_ALLOWED_IPS: '0.0.0.0/0',
  WG_PRE_UP: '',
  WG_POST_UP: '',
  WG_PRE_DOWN: '',
  WG_POST_DOWN: '',
  WG_PORT_FWD_MIN: '1024',
  WG_PORT_FWD_MAX: '65535',
  WG_NFT_MASQUERADE: true,
  WG_SEED_TUNING: true,
}));

describe('WireGuard', () => {
  let wg;

  beforeEach(() => {
    jest.clearAllMocks();

    fs.readFile.mockImplementation(async (filename) => {
      if (String(filename).includes('server-settings')) {
        const err = new Error('not found');
        err.code = 'ENOENT';
        throw err;
      }
      return JSON.stringify(makeConfig());
    });

    fs.writeFile.mockResolvedValue();
    fs.rename.mockResolvedValue();
    fs.unlink.mockResolvedValue();
    fs.open.mockImplementation(async () => ({
      writeFile: jest.fn().mockResolvedValue(),
      sync: jest.fn().mockResolvedValue(),
      close: jest.fn().mockResolvedValue(),
    }));

    Util.exec.mockResolvedValue();
    Util.execFile.mockResolvedValue();
    Util.isValidIPv4.mockImplementation((ip) => /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip));
    Util.isValidIPv6.mockReturnValue(true);
    Util.isValidName.mockImplementation((s) => typeof s === 'string' && s.length > 0 && s.length <= 128
      // eslint-disable-next-line no-control-regex
      && !/[\u0000-\u001f\u007f]/.test(s));

    // mock linux to bypass process.platform check in mutating methods
    Object.defineProperty(process, 'platform', { value: 'linux' });

    const WireGuardClass = require('./WireGuard'); // eslint-disable-line global-require
    wg = new WireGuardClass();
  });

  afterAll(() => {
    Object.defineProperty(process, 'platform', originalPlatform);
  });

  describe('__isPortAllowed', () => {
    it('allows ports within range', async () => {
      await wg.getConfig(); // init
      expect(wg.__isPortAllowed(1024)).toBe(true);
      expect(wg.__isPortAllowed(65535)).toBe(true);
      expect(wg.__isPortAllowed(3000)).toBe(true);
    });

    it('rejects ports outside range', async () => {
      await wg.getConfig();
      expect(wg.__isPortAllowed(22)).toBe(false);
      expect(wg.__isPortAllowed(80)).toBe(false);
      expect(wg.__isPortAllowed(1023)).toBe(false);
      expect(wg.__isPortAllowed(65536)).toBe(false);
    });

    it('rejects decimal ports', async () => {
      await wg.getConfig();
      expect(wg.__isPortAllowed(80.5)).toBe(false);
      expect(wg.__isPortAllowed(3000.1)).toBe(false);
    });

    it('rejects WG port even if in range', async () => {
      await wg.getConfig();
      wg.__serverSettings.port = '3000';
      expect(wg.__isPortAllowed(3000)).toBe(false);
    });
  });

  describe('addPortForward', () => {
    it('validates extPort type and range', async () => {
      await expect(wg.addPortForward('client1', 'tcp', 80.5, 3000)).rejects.toThrow(ServerError);
      await expect(wg.addPortForward('client1', 'tcp', 22, 3000)).rejects.toThrow(ServerError);
    });

    it('validates intPort type and range', async () => {
      await expect(wg.addPortForward('client1', 'tcp', 3000, 80.5)).rejects.toThrow(ServerError);
      await expect(wg.addPortForward('client1', 'tcp', 3000, 70000)).rejects.toThrow(ServerError);
    });

    it('rolls back completely if nft fails', async () => {
      await wg.getConfig();
      Util.execFile.mockRejectedValue(new Error('nft failed'));

      let caught;
      await wg.addPortForward('client1', 'tcp', 3000, 3000).catch((err) => {
        caught = err;
      });
      expect(caught.message).toMatch(/Failed to apply network rules atomically: nft failed/);
      expect(caught.rollbackErrors).toEqual([
        expect.stringContaining('Host rollback failed'),
      ]);

      const config = await wg.getConfig();
      // ensure memory rollback
      expect(config.clients.client1.portForwards.length).toBe(1);

      expect(Util.execFile).toHaveBeenCalledWith('nft', ['-f', '-'], expect.objectContaining({
        input: expect.stringContaining('delete table ip wgeasy_dnat'),
      }));

      // ensure we saved back
      expect(fs.open).toHaveBeenCalled();
    });

    it('rolls back if saveConfig fails', async () => {
      await wg.getConfig();
      // nft succeeds, but save fails
      fs.rename.mockRejectedValueOnce(new Error('disk full'));

      await expect(wg.addPortForward('client1', 'tcp', 3000, 3000)).rejects.toThrow(/disk full/);

      const config = await wg.getConfig();
      expect(config.clients.client1.portForwards.length).toBe(1);
    });
  });

  describe('removePortForward / updatePortForward', () => {
    it('rejects negative or decimal index', async () => {
      await expect(wg.removePortForward('client1', -1)).rejects.toThrow(ServerError);
      await expect(wg.updatePortForward('client1', -1, 'tcp', 3000, 3000)).rejects.toThrow(ServerError);
      await expect(wg.removePortForward('client1', 0.5)).rejects.toThrow(ServerError);
    });
  });

  describe('client activation', () => {
    it('updates DNAT rules when a client is disabled and enabled', async () => {
      await wg.disableClient({ clientId: 'client1' });
      const disabledRuleset = Util.execFile.mock.calls.findLast((call) => call[0] === 'nft')[2].input;
      expect(disabledRuleset).not.toContain('dport 2000');
      const downCall = Util.exec.mock.calls.findIndex((call) => call[0] === 'wg-quick down wg0');
      const upCall = Util.exec.mock.calls.findIndex((call) => call[0] === 'wg-quick up wg0');
      expect(Util.exec.mock.invocationCallOrder[downCall]).toBeLessThan(Util.execFile.mock.invocationCallOrder[0]);
      expect(Util.execFile.mock.invocationCallOrder[0]).toBeLessThan(Util.exec.mock.invocationCallOrder[upCall]);

      await wg.enableClient({ clientId: 'client1' });
      const enabledRuleset = Util.execFile.mock.calls.findLast((call) => call[0] === 'nft')[2].input;
      expect(enabledRuleset).toContain('tcp dport 2000');
    });
  });

  describe('network initialization', () => {
    it('fsyncs files and their directory around atomic renames', async () => {
      await wg.__writeAtomic('durable.json', '{}', 0o600);
      const fileHandle = await fs.open.mock.results[0].value;
      const directoryHandle = await fs.open.mock.results[1].value;
      expect(fileHandle.sync.mock.invocationCallOrder[0]).toBeLessThan(fs.rename.mock.invocationCallOrder[0]);
      expect(fs.rename.mock.invocationCallOrder[0]).toBeLessThan(directoryHandle.sync.mock.invocationCallOrder[0]);
    });

    it('does not require nftables IPv6 support when IPv6 is disabled', async () => {
      await wg.getConfig();
      wg.__serverSettings.enableIpv6 = false;
      Util.exec.mockImplementation(async (command) => {
        if (command.includes('nft') && command.includes('ip6')) throw new Error('Address family not supported');
      });

      await expect(wg.__applyAllDnatRules()).resolves.toBeUndefined();
      const ruleset = Util.execFile.mock.calls.findLast((call) => call[0] === 'nft')[2].input;
      expect(ruleset).not.toContain('ip6');
    });

    it('takes the active interface down before replacing wg0.conf', async () => {
      await wg.init();
      const downCall = Util.exec.mock.calls.findIndex((call) => call[0] === 'wg-quick down wg0');
      const upCall = Util.exec.mock.calls.findIndex((call) => call[0] === 'wg-quick up wg0');
      expect(downCall).toBeGreaterThanOrEqual(0);
      expect(Util.exec.mock.invocationCallOrder[downCall]).toBeLessThan(fs.open.mock.invocationCallOrder[0]);
      expect(Util.execFile.mock.invocationCallOrder[0]).toBeLessThan(Util.exec.mock.invocationCallOrder[upCall]);
    });
  });

  describe('client network policies', () => {
    const addSecondClient = async () => {
      const config = await wg.getConfig();
      config.clients.client2 = {
        id: 'client2',
        name: 'client2',
        address: '10.8.0.3',
        addressV6: 'fd42:42:42::3',
        publicKey: KEYS.client2Public,
        createdAt: '2026-01-01T00:00:00.000Z',
        updatedAt: '2026-01-01T00:00:00.000Z',
        enabled: true,
        portForwards: [],
        networkPolicy: { blockedProtocols: [], customRules: [], peerAllowlist: [] },
      };
      return config;
    };

    it('migrates clients to isolated policies by default', async () => {
      const config = await wg.getConfig();
      expect(config.clients.client1.networkPolicy).toEqual({
        blockedProtocols: [],
        customRules: [],
        peerAllowlist: [],
      });

      await wg.__applyAllNetworkRules();
      const ruleset = Util.execFile.mock.calls.findLast((call) => call[0] === 'nft')[2].input;
      expect(ruleset).toContain('add element inet wgeasy_filter peer_ipv4 { 10.8.0.2 }');
      expect(ruleset).toContain('ip saddr 10.8.0.2 ip daddr @peer_ipv4 drop');
      expect(ruleset).toContain('ip6 saddr fd42:42:42::2 ip6 daddr @peer_ipv6 drop');
    });

    it('blocks presets and custom ranges while allowing selected peers symmetrically', async () => {
      const config = await addSecondClient();
      await wg.updateClientNetworkPolicy({
        clientId: 'client1',
        policy: {
          blockedProtocols: ['https', 'ssh-sftp'],
          customRules: [{
            proto: 'udp', startPort: 5000, endPort: 5010, label: 'Media',
          }],
          peerAllowlist: ['client2'],
        },
      });

      expect(config.clients.client2.networkPolicy.peerAllowlist).toEqual(['client1']);
      const ruleset = Util.execFile.mock.calls.findLast((call) => call[0] === 'nft')[2].input;
      expect(ruleset).toContain('ip saddr 10.8.0.2 tcp dport 443 drop');
      expect(ruleset).toContain('ip6 saddr fd42:42:42::2 udp dport 443 drop');
      expect(ruleset).toContain('ip saddr 10.8.0.2 tcp dport 22 drop');
      expect(ruleset).toContain('ip saddr 10.8.0.2 udp dport 5000-5010 drop');
      expect(ruleset).toContain('ip saddr 10.8.0.2 ip daddr 10.8.0.3 accept');
      expect(ruleset).toContain('ip saddr 10.8.0.3 ip daddr 10.8.0.2 accept');
    });

    it('rejects unknown presets, invalid ranges and missing peers', async () => {
      const base = { blockedProtocols: [], customRules: [], peerAllowlist: [] };
      await expect(wg.updateClientNetworkPolicy({
        clientId: 'client1',
        policy: { ...base, blockedProtocols: ['not-a-protocol'] },
      })).rejects.toThrow(/Invalid blocked protocol/);
      await expect(wg.updateClientNetworkPolicy({
        clientId: 'client1',
        policy: {
          ...base,
          customRules: [{
            proto: 'tcp', startPort: 200, endPort: 100, label: '',
          }],
        },
      })).rejects.toThrow(/Invalid custom network rule/);
      await expect(wg.updateClientNetworkPolicy({
        clientId: 'client1',
        policy: { ...base, peerAllowlist: ['missing'] },
      })).rejects.toThrow(/Client Not Found/);
    });

    it('rolls policies back when nftables rejects an update', async () => {
      const config = await addSecondClient();
      Util.execFile.mockRejectedValue(new Error('nft policy failed'));

      await expect(wg.updateClientNetworkPolicy({
        clientId: 'client1',
        policy: { blockedProtocols: ['http'], customRules: [], peerAllowlist: ['client2'] },
      })).rejects.toThrow(/Failed to apply network rules atomically/);
      expect(config.clients.client1.networkPolicy.peerAllowlist).toEqual([]);
      expect(config.clients.client2.networkPolicy.peerAllowlist).toEqual([]);
    });

    it('rejects stale policy updates and inherited client names', async () => {
      const config = await wg.getConfig();
      const expectedUpdatedAt = new Date(config.clients.client1.updatedAt).toISOString();
      config.clients.client1.updatedAt = new Date(Date.parse(expectedUpdatedAt) + 1000);

      await expect(wg.updateClientNetworkPolicy({
        clientId: 'client1',
        expectedUpdatedAt,
        policy: { blockedProtocols: [], customRules: [], peerAllowlist: [] },
      })).rejects.toMatchObject({ statusCode: 409 });
      await expect(wg.getClient({ clientId: 'toString' })).rejects.toMatchObject({ statusCode: 404 });
    });
  });

  describe('restoreConfiguration', () => {
    it('rolls back disk and host on failure', async () => {
      await wg.getConfig(); // init state

      const backup = makeConfig();
      backup.clients.client1.portForwards = [{ proto: 'tcp', extPort: 3000, intPort: 3000 }];
      const backupJson = JSON.stringify(backup);

      let startupAttempts = 0;
      Util.exec.mockImplementation(async (cmd) => {
        if (cmd.includes('wg-quick up') && startupAttempts++ === 0) throw new Error('startup failed');
      });

      try {
        await wg.restoreConfiguration(backupJson);
      } catch (err) {
        expect(err.message).toMatch(/startup failed/);
        expect(err.rollbackErrors).toEqual([]);
      }

      // Memory must be reverted
      const config = await wg.getConfig();
      expect(config.clients.client1.portForwards[0].extPort).toBe(2000);
    });

    it('rejects backup with invalid IPs entirely without saving', async () => {
      await wg.getConfig(); // init state

      const backup = makeConfig();
      backup.clients.client1.address = '10.8.0.2; touch /pwn';
      const backupJson = JSON.stringify(backup);

      await expect(wg.restoreConfiguration(backupJson)).rejects.toThrow(/Invalid or duplicate IPv4 address/);

      const config = await wg.getConfig();
      expect(config.clients.client1.address).toBe('10.8.0.2');
    });

    it('rejects backup with injected server keys (config injection)', async () => {
      await wg.getConfig(); // init state

      const backup = makeConfig();
      backup.server.privateKey = 'a\nPostUp = touch /pwn';
      const backupJson = JSON.stringify(backup);

      await expect(wg.restoreConfiguration(backupJson))
        .rejects.toThrow(/Invalid server\.privateKey/);

      const config = await wg.getConfig();
      expect(config.server.privateKey).toBe(KEYS.serverPrivate);
    });

    it('rejects backup with invalid client name', async () => {
      await wg.getConfig(); // init state

      const backup = makeConfig();
      backup.clients.client1.name = 'evil\n[Peer]';
      const backupJson = JSON.stringify(backup);

      await expect(wg.restoreConfiguration(backupJson))
        .rejects.toThrow(/Invalid client name/);
    });

    it('rejects injected client keys and unknown fields', async () => {
      const backup = makeConfig();
      backup.clients.client1.publicKey = `${KEYS.clientPublic}\nPostUp = touch /pwn`;
      await expect(wg.restoreConfiguration(JSON.stringify(backup)))
        .rejects.toThrow(/client\.publicKey/);

      const backupWithUnknownField = makeConfig();
      backupWithUnknownField.clients.client1.command = 'touch /pwn';
      await expect(wg.restoreConfiguration(JSON.stringify(backupWithUnknownField)))
        .rejects.toThrow(/Invalid client field/);
    });

    it('restores historical client subnets while new address edits remain restricted', async () => {
      const backup = makeConfig();
      backup.clients.client1.address = '192.168.50.2';
      backup.clients.client1.addressV6 = 'fd99:42:42::2';
      await expect(wg.restoreConfiguration(JSON.stringify(backup))).resolves.toBeUndefined();
      const ruleset = Util.execFile.mock.calls.findLast((call) => call[0] === 'nft')[2].input;
      expect(ruleset).toContain('peer_ipv4 { 192.168.50.2 }');
      expect(ruleset).toContain('peer_ipv6 { fd99:42:42::2 }');
      await expect(wg.updateClientAddress({ clientId: 'client1', address: '172.16.0.2' }))
        .rejects.toThrow(/must be a usable host/);
    });
  });

  describe('server settings', () => {
    it('rejects IPv6 templates that place the host inside the network prefix', async () => {
      await expect(wg.updateServerConfig({ defaultAddressV6: 'fd42:x::' }))
        .rejects.toThrow(/Invalid value for defaultAddressV6/);
    });
  });

  describe('configuration loading', () => {
    it('assigns collision-free IPv6 addresses to legacy clients', async () => {
      const legacy = makeConfig();
      delete legacy.server.addressV6;
      delete legacy.clients.client1.addressV6;
      fs.readFile.mockImplementation(async (filename) => {
        if (String(filename).includes('server-settings')) {
          const err = new Error('not found');
          err.code = 'ENOENT';
          throw err;
        }
        return JSON.stringify(legacy);
      });
      const WireGuardClass = require('./WireGuard'); // eslint-disable-line global-require
      const migrated = new WireGuardClass();

      const config = await migrated.getConfig();
      expect(config.server.addressV6).toBe('fd42:42:42::1');
      expect(config.clients.client1.addressV6).toBe('fd42:42:42::2');
    });

    it('rolls back an interrupted server settings transaction on startup', async () => {
      const previousConfig = makeConfig();
      previousConfig.server.address = '10.8.0.5';
      previousConfig.server.addressV6 = 'fd42:42:42::abcd';
      previousConfig.clients.client1.address = '10.8.0.77';
      previousConfig.clients.client1.addressV6 = 'fd42:42:42::beef';
      const candidateConfig = JSON.parse(JSON.stringify(previousConfig));
      candidateConfig.server.address = '10.9.0.5';
      candidateConfig.server.addressV6 = 'fd43:42:42::abcd';
      candidateConfig.clients.client1.address = '10.9.0.77';
      candidateConfig.clients.client1.addressV6 = 'fd43:42:42::beef';
      fs.readFile.mockImplementation(async (filename) => {
        const name = String(filename);
        if (name.endsWith('server-settings.json')) {
          return JSON.stringify({ defaultAddress: '10.8.0.x' });
        }
        if (name.endsWith('server-settings.transaction.json')) {
          return JSON.stringify({
            previous: { defaultAddress: '10.8.0.x' },
            candidate: { defaultAddress: '10.9.0.x' },
            previousConfig,
            candidateConfig,
          });
        }
        return JSON.stringify(candidateConfig);
      });
      const WireGuardClass = require('./WireGuard'); // eslint-disable-line global-require
      const recovering = new WireGuardClass();

      const recovered = await recovering.getConfig();
      expect(recovered.server.address).toBe('10.8.0.5');
      expect(recovered.server.addressV6).toBe('fd42:42:42::abcd');
      expect(recovered.clients.client1.address).toBe('10.8.0.77');
      expect(recovered.clients.client1.addressV6).toBe('fd42:42:42::beef');
    });

    it('completes a settings transaction whose candidate was committed', async () => {
      const WireGuardClass = require('./WireGuard'); // eslint-disable-line global-require
      const defaults = new WireGuardClass();
      const previous = { ...defaults.__serverSettings };
      const candidate = { ...previous, port: 51830 };
      const previousConfig = makeConfig();
      const candidateConfig = makeConfig();
      candidateConfig.server.address = '10.8.0.5';
      fs.readFile.mockImplementation(async (filename) => {
        const name = String(filename);
        if (name.endsWith('server-settings.json')) return JSON.stringify(candidate);
        if (name.endsWith('server-settings.transaction.json')) {
          return JSON.stringify({
            previous, candidate, previousConfig, candidateConfig,
          });
        }
        return JSON.stringify(previousConfig);
      });
      const recovering = new WireGuardClass();

      const recovered = await recovering.getConfig();
      expect(recovering.__serverSettings.port).toBe(51830);
      expect(recovered.server.address).toBe('10.8.0.5');
    });

    it('accepts existing names up to the historical 128-character limit', async () => {
      const existing = makeConfig();
      existing.clients.client1.name = 'a'.repeat(100);
      fs.readFile.mockImplementation(async (filename) => {
        if (String(filename).includes('server-settings')) {
          const err = new Error('not found');
          err.code = 'ENOENT';
          throw err;
        }
        return JSON.stringify(existing);
      });
      const WireGuardClass = require('./WireGuard'); // eslint-disable-line global-require
      const compatible = new WireGuardClass();

      await expect(compatible.getConfig()).resolves.toMatchObject({
        clients: { client1: { name: 'a'.repeat(100) } },
      });
    });

    it('does not assign a legacy client the server IPv6 address', async () => {
      const legacy = makeConfig();
      legacy.server.addressV6 = 'fd42:42:42::2';
      delete legacy.clients.client1.addressV6;
      fs.readFile.mockImplementation(async (filename) => {
        if (String(filename).includes('server-settings')) {
          const err = new Error('not found');
          err.code = 'ENOENT';
          throw err;
        }
        return JSON.stringify(legacy);
      });
      const WireGuardClass = require('./WireGuard'); // eslint-disable-line global-require
      const migrated = new WireGuardClass();

      const config = await migrated.getConfig();
      expect(config.clients.client1.addressV6).toBe('fd42:42:42::3');
    });

    it('does not overwrite a corrupt wg0.json', async () => {
      fs.readFile.mockImplementation(async (filename) => {
        if (String(filename).includes('server-settings')) {
          const err = new Error('not found');
          err.code = 'ENOENT';
          throw err;
        }
        return '{not-json';
      });
      const WireGuardClass = require('./WireGuard'); // eslint-disable-line global-require
      const corrupt = new WireGuardClass();

      await expect(corrupt.getConfig()).rejects.toThrow(/was not overwritten/);
      expect(fs.writeFile).not.toHaveBeenCalled();
    });

    it('propagates filesystem errors instead of generating new keys', async () => {
      fs.readFile.mockImplementation(async (filename) => {
        const err = new Error('permission denied');
        err.code = String(filename).includes('server-settings') ? 'ENOENT' : 'EACCES';
        throw err;
      });
      const WireGuardClass = require('./WireGuard'); // eslint-disable-line global-require
      const inaccessible = new WireGuardClass();

      await expect(inaccessible.getConfig()).rejects.toThrow(/Failed to read wg0\.json/);
      expect(Util.exec).not.toHaveBeenCalledWith('wg genkey');
    });
  });

  describe('name validation', () => {
    it('rejects client names with newlines/control chars', async () => {
      await expect(wg.createClient({ name: 'evil\n[Peer]\nPublicKey = x' })).rejects.toThrow(ServerError);
      await expect(wg.createClient({ name: '' })).rejects.toThrow(ServerError);
      await expect(wg.createClient({ name: 'a'.repeat(200) })).rejects.toThrow(ServerError);
      await expect(wg.updateClientName({ clientId: 'client1', name: 'evil\r\n' })).rejects.toThrow(ServerError);
      await expect(wg.updateClientName({ clientId: 'client1', name: 'ok-name' })).resolves.toBeUndefined();
    });
  });

  describe('legacy client migration and fault tolerance', () => {
    it('migrates legacy clients with empty preSharedKey, empty privateKey, and missing networkPolicy', async () => {
      const legacy = makeConfig();
      legacy.clients.client1.preSharedKey = '';
      legacy.clients.client1.privateKey = '';
      delete legacy.clients.client1.id;
      delete legacy.clients.client1.networkPolicy;
      delete legacy.clients.client1.createdAt;

      fs.readFile.mockImplementation(async (filename) => {
        if (String(filename).includes('server-settings')) {
          const err = new Error('not found');
          err.code = 'ENOENT';
          throw err;
        }
        return JSON.stringify(legacy);
      });
      const WireGuardClass = require('./WireGuard'); // eslint-disable-line global-require
      const migrated = new WireGuardClass();

      const config = await migrated.getConfig();
      expect(config.clients.client1.id).toBe('client1');
      expect(config.clients.client1.preSharedKey).toBeNull();
      expect(config.clients.client1.privateKey).toBeUndefined();
      expect(config.clients.client1.networkPolicy).toBeDefined();
      expect(config.clients.client1.networkPolicy.blockedProtocols).toEqual([]);
    });

    it('returns clients even if wg show wg0 dump fails in getClients', async () => {
      Util.exec.mockImplementation(async (cmd) => {
        if (typeof cmd === 'string' && cmd.includes('wg show wg0 dump')) {
          throw new Error('interface down');
        }
        return '';
      });

      const clients = await wg.getClients();
      expect(clients).toHaveLength(1);
      expect(clients[0].id).toBe('client1');
      expect(clients[0].latestHandshakeAt).toBeNull();
    });
  });

  describe('mutation queue consistency', () => {
    it('builds the config exactly once for concurrent first calls', async () => {
      fs.readFile.mockImplementation(async () => {
        const err = new Error('not found');
        err.code = 'ENOENT';
        throw err;
      });
      let release;
      const gate = new Promise((resolve) => {
        release = resolve;
      });
      Util.exec.mockImplementation(async (cmd) => {
        if (cmd === 'wg genkey') {
          await gate;
          return KEYS.serverPrivate;
        }
        return '';
      });
      Util.execFile.mockImplementation(async () => KEYS.serverPublic);

      const builds = [wg.getConfig(), wg.getConfig()];
      await new Promise((resolve) => setTimeout(resolve, 10));
      release();
      const [first, second] = await Promise.all(builds);

      expect(second).toBe(first);
      expect(Util.exec.mock.calls.filter(([cmd]) => cmd === 'wg genkey')).toHaveLength(1);
    });

    it('rejects nested mutation wrappers instead of deadlocking', async () => {
      await expect(wg.__withMutation(() => wg.__withMutation(async () => {})))
        .rejects.toThrow(ServerError);
    });

    it('waits for operations enqueued while draining', async () => {
      let release;
      const gate = new Promise((resolve) => {
        release = resolve;
      });
      let secondDone = false;
      const first = wg.__withMutation(async () => {
        await gate;
      });
      await new Promise((resolve) => setTimeout(resolve, 5));

      const drain = wg.waitForMutations();
      await new Promise((resolve) => setTimeout(resolve, 5));

      release();
      // The slow late operation must also settle before the drain resolves —
      // otherwise Shutdown() would down the interface mid-mutation.
      const second = wg.__withMutation(async () => {
        await new Promise((resolve) => setTimeout(resolve, 30));
        secondDone = true;
      });
      await first;

      await drain;
      const settledWhenDrainReturned = secondDone;
      await second;
      expect(settledWhenDrainReturned).toBe(true);
    });

    it('serves reads only after in-flight mutations commit or roll back', async () => {
      await wg.getConfig();
      let rejectSync;
      const gate = new Promise((_, reject) => {
        rejectSync = reject;
      });
      Util.exec.mockImplementationOnce(async (cmd) => {
        if (typeof cmd === 'string' && cmd.includes('wg syncconf')) return gate;
        return '';
      });

      // The rename is applied in memory, then the commit stalls at wg syncconf.
      const update = wg.updateClientName({ clientId: 'client1', name: 'renamed' });
      await new Promise((resolve) => setTimeout(resolve, 10));

      // A concurrent read must not observe the uncommitted name...
      const clientsPromise = wg.getClients();
      await new Promise((resolve) => setTimeout(resolve, 10));

      // ...and after the commit fails and rolls back, the read sees the
      // original name rather than state that never persisted.
      rejectSync(new Error('sync failed'));
      await update.catch(() => {});
      const clients = await clientsPromise;
      expect(clients.find((client) => client.id === 'client1').name).toBe('client1');
    });
  });
});
