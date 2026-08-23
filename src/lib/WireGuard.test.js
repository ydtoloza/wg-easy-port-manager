/* eslint-env jest */

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const Webhook = require('./Webhook');

jest.mock('./Webhook', () => ({ deliver: jest.fn() }));

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
    Util.parsePort.mockImplementation((value) => {
      if (typeof value === 'number') return value;
      if (typeof value === 'string' && value !== '' && /^\d+$/.test(value)) return Number(value);
      return NaN;
    });
    Util.isValidPort.mockImplementation((value) => {
      const port = Util.parsePort(value);
      return Number.isInteger(port) && port >= 1 && port <= 65535;
    });
    Util.isValidRuleId.mockImplementation((value) => typeof value === 'string'
      && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value));

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

    it('rejects port conflicts as 409 state conflicts', async () => {
      // client1 already forwards tcp/2000 (see mocked wg0.json above).
      await expect(wg.addPortForward('client1', 'tcp', 2000, 3000))
        .rejects.toMatchObject({ statusCode: 409 });
      await expect(wg.addPortForward('client1', 'both', 2000, 3000))
        .rejects.toMatchObject({ statusCode: 409 });
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

    it('returns 404 for an out-of-range index instead of a silent no-op', async () => {
      // client1 has exactly one rule (index 0).
      await expect(wg.removePortForward('client1', 5)).rejects.toMatchObject({ statusCode: 404 });
      const config = await wg.getConfig();
      expect(config.clients.client1.portForwards).toHaveLength(1);
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

  describe('port-forward reachability probe', () => {
    const nftTable = (present) => JSON.stringify({
      nftables: present ? [{
        rule: {
          family: 'ip',
          chain: 'prerouting',
          expr: [
            { match: { left: { payload: { protocol: 'tcp', field: 'dport' } }, op: 'eq', right: 2000 } },
            { dnat: { family: 'ip', addr: '10.8.0.2', port: 2000 } },
          ],
        },
      }] : [],
    });
    const dumpFor = (handshakeSecondsAgo) => {
      const ts = Math.floor(Date.now() / 1000) - handshakeSecondsAgo;
      return `server\n${[KEYS.clientPublic, KEYS.preShared, '203.0.113.9:51820', '10.8.0.2/32', String(ts), '1', '2', '0'].join('\t')}`;
    };

    const setupProbe = async ({ nftPresent, handshakeSecondsAgo, tcpResult }) => {
      await wg.getConfig();
      Util.exec.mockImplementation(async (cmd) => {
        if (typeof cmd === 'string' && cmd.includes('nft -j list table')) return nftTable(nftPresent);
        if (typeof cmd === 'string' && cmd.includes('wg show wg0 dump')) return dumpFor(handshakeSecondsAgo);
        return '';
      });
      jest.spyOn(wg, '__tcpConnect').mockResolvedValue(tcpResult);
    };

    it('derives ok when rule, tunnel and connect all succeed', async () => {
      await setupProbe({ nftPresent: true, handshakeSecondsAgo: 10, tcpResult: true });
      const verdict = await wg.probePortForward({ clientId: 'client1', rule: '0' });
      expect(verdict).toMatchObject({
        rulePresent: true, tunnelUp: true, tcpConnectable: true, verdict: 'ok',
      });
      expect(verdict.rule).toMatchObject({
        proto: 'tcp', extPort: 2000, intPort: 2000, peerIP: '10.8.0.2',
      });
    });

    it('derives rule-missing when the rule is absent and nothing answers', async () => {
      const instance = new (require('./WireGuard'))(); // eslint-disable-line global-require
      await instance.getConfig();
      Util.exec.mockImplementation(async (cmd) => {
        if (typeof cmd === 'string' && cmd.includes('nft -j list table')) return nftTable(false);
        if (typeof cmd === 'string' && cmd.includes('wg show wg0 dump')) return dumpFor(10);
        return '';
      });
      jest.spyOn(instance, '__tcpConnect').mockResolvedValue(false);
      const verdict = await instance.probePortForward({ clientId: 'client1', rule: '0' });
      expect(verdict).toMatchObject({ rulePresent: false, tcpConnectable: false, verdict: 'rule-missing' });
    });

    it('derives tunnel-down when the rule exists but the tunnel is stale', async () => {
      const wg2 = new (require('./WireGuard'))(); // eslint-disable-line global-require
      await wg2.getConfig();
      Util.exec.mockImplementation(async (cmd) => {
        if (typeof cmd === 'string' && cmd.includes('nft -j list table')) return nftTable(true);
        if (typeof cmd === 'string' && cmd.includes('wg show wg0 dump')) return dumpFor(3600);
        return '';
      });
      jest.spyOn(wg2, '__tcpConnect').mockResolvedValue(false);
      const verdict = await wg2.probePortForward({ clientId: 'client1', rule: '0' });
      expect(verdict).toMatchObject({ rulePresent: true, tunnelUp: false, verdict: 'tunnel-down' });
    });

    it('feeds the per-peer keepalive override into the probe tunnel verdict', async () => {
      const wg2b = new (require('./WireGuard'))(); // eslint-disable-line global-require
      await wg2b.getConfig();
      await wg2b.updateClientKeepalive({ clientId: 'client1', persistentKeepalive: 3600 });
      Util.exec.mockImplementation(async (cmd) => {
        if (typeof cmd === 'string' && cmd.includes('nft -j list table')) return nftTable(true);
        if (typeof cmd === 'string' && cmd.includes('wg show wg0 dump')) return dumpFor(3600);
        return '';
      });
      jest.spyOn(wg2b, '__tcpConnect').mockResolvedValue(false);
      const verdict = await wg2b.probePortForward({ clientId: 'client1', rule: '0' });
      // The same 3600s-old handshake as the tunnel-down case above, but the
      // per-peer 3600s override widens the window to 3h: the tunnel counts as
      // up and the honest verdict becomes unreachable, not tunnel-down.
      expect(verdict).toMatchObject({ tunnelUp: true, verdict: 'unreachable' });
    });

    it('derives unreachable when rule and tunnel are up but TCP fails', async () => {
      const wg3 = new (require('./WireGuard'))(); // eslint-disable-line global-require
      await wg3.getConfig();
      Util.exec.mockImplementation(async (cmd) => {
        if (typeof cmd === 'string' && cmd.includes('nft -j list table')) return nftTable(true);
        if (typeof cmd === 'string' && cmd.includes('wg show wg0 dump')) return dumpFor(10);
        return '';
      });
      jest.spyOn(wg3, '__tcpConnect').mockResolvedValue(false);
      const verdict = await wg3.probePortForward({ clientId: 'client1', rule: '0' });
      expect(verdict).toMatchObject({ rulePresent: true, tunnelUp: true, verdict: 'unreachable' });
    });

    it('labels hairpin connects honestly as dnat-local', async () => {
      const wg4 = new (require('./WireGuard'))(); // eslint-disable-line global-require
      await wg4.getConfig();
      Util.exec.mockImplementation(async (cmd) => {
        if (typeof cmd === 'string' && cmd.includes('nft -j list table')) return nftTable(false);
        if (typeof cmd === 'string' && cmd.includes('wg show wg0 dump')) return dumpFor(10);
        return '';
      });
      jest.spyOn(wg4, '__tcpConnect').mockResolvedValue(true);
      const verdict = await wg4.probePortForward({ clientId: 'client1', rule: '0' });
      expect(verdict).toMatchObject({ rulePresent: false, tcpConnectable: true, verdict: 'dnat-local' });
    });

    it('rate-limits repeated probes of the same rule', async () => {
      const wg5 = new (require('./WireGuard'))(); // eslint-disable-line global-require
      await wg5.getConfig();
      Util.exec.mockImplementation(async (cmd) => {
        if (typeof cmd === 'string' && cmd.includes('nft -j list table')) return nftTable(true);
        if (typeof cmd === 'string' && cmd.includes('wg show wg0 dump')) return dumpFor(10);
        return '';
      });
      jest.spyOn(wg5, '__tcpConnect').mockResolvedValue(true);
      await wg5.probePortForward({ clientId: 'client1', rule: '0' });
      await expect(wg5.probePortForward({ clientId: 'client1', rule: '0' }))
        .rejects.toMatchObject({ statusCode: 429 });
    });

    it('single-flights concurrent probes of the same rule', async () => {
      const wg6 = new (require('./WireGuard'))(); // eslint-disable-line global-require
      await wg6.getConfig();
      let release;
      const gate = new Promise((resolve) => {
        release = resolve;
      });
      let tcpCalls = 0;
      jest.spyOn(wg6, '__tcpConnect').mockImplementation(async () => {
        tcpCalls += 1;
        await gate;
        return true;
      });
      const probes = Promise.all([
        wg6.probePortForward({ clientId: 'client1', rule: '0' }),
        wg6.probePortForward({ clientId: 'client1', rule: '0' }),
      ]);
      await new Promise((resolve) => setTimeout(resolve, 10));
      release();
      const results = await probes;
      expect(tcpCalls).toBe(1);
      expect(results[0]).toEqual(results[1]);
    });

    it('returns 404 for an unknown rule', async () => {
      await wg.getConfig();
      await expect(wg.probePortForward({ clientId: 'client1', rule: '99' }))
        .rejects.toMatchObject({ statusCode: 404 });
      await expect(wg.probePortForward({ clientId: 'client1', rule: '11111111-2222-3333-4444-555555555555' }))
        .rejects.toMatchObject({ statusCode: 404 });
    });
  });

  describe('forwarding kill-switch', () => {
    it('defaults to enabled and tolerates settings files without the key', async () => {
      const settings = await wg.getServerConfig();
      expect(settings.forwardingEnabled).toBe(true);
    });

    it('emitting with the switch off omits DNAT rules but preserves the config', async () => {
      await wg.getConfig();
      await wg.updateServerConfig({ forwardingEnabled: false });

      const ruleset = Util.execFile.mock.calls.findLast((call) => call[0] === 'nft')[2].input;
      expect(ruleset).not.toContain('dnat to');

      const config = await wg.getConfig();
      expect(config.clients.client1.portForwards).toHaveLength(1);
    });

    it('restores DNAT when switched back on', async () => {
      await wg.getConfig();
      await wg.updateServerConfig({ forwardingEnabled: false });
      await wg.updateServerConfig({ forwardingEnabled: true });

      const ruleset = Util.execFile.mock.calls.findLast((call) => call[0] === 'nft')[2].input;
      expect(ruleset).toContain('dnat to 10.8.0.2:2000');
    });

    it('gates the boot-time emit too', async () => {
      fs.readFile.mockImplementation(async (filename) => {
        const name = String(filename);
        if (name.endsWith('server-settings.json')) {
          return JSON.stringify({ forwardingEnabled: false });
        }
        if (name.includes('server-settings')) {
          const err = new Error('not found');
          err.code = 'ENOENT';
          throw err;
        }
        return JSON.stringify(makeConfig());
      });
      const WireGuardClass = require('./WireGuard'); // eslint-disable-line global-require
      const booting = new WireGuardClass();
      await booting.getConfig();
      await booting.__applyAllNetworkRules();

      const ruleset = Util.execFile.mock.calls.findLast((call) => call[0] === 'nft')[2].input;
      expect(ruleset).not.toContain('dnat to');
    });

    it('rejects non-boolean values', async () => {
      await expect(wg.updateServerConfig({ forwardingEnabled: 'yes' }))
        .rejects.toMatchObject({ statusCode: 400 });
    });
  });

  describe('online flag and endpoint exposure', () => {
    const dumpLine = ({ endpoint = '203.0.113.9:51820', handshakeSecondsAgo = 0 }) => [
      KEYS.clientPublic,
      KEYS.preShared,
      endpoint,
      '10.8.0.2/32',
      String(Math.floor(Date.now() / 1000) - handshakeSecondsAgo),
      '1000',
      '2000',
      '0',
    ].join('\t');

    it('marks a fresh handshake online and passes the endpoint through', async () => {
      await wg.getConfig();
      Util.exec.mockImplementation(async (cmd) => {
        if (typeof cmd === 'string' && cmd.includes('wg show wg0 dump')) {
          return `server-line\n${dumpLine({ handshakeSecondsAgo: 10 })}`;
        }
        return '';
      });
      const clients = await wg.getClients();
      expect(clients[0].online).toBe(true);
      expect(clients[0].endpoint).toBe('203.0.113.9:51820');
    });

    it('marks a stale handshake offline', async () => {
      await wg.getConfig();
      Util.exec.mockImplementation(async (cmd) => {
        if (typeof cmd === 'string' && cmd.includes('wg show wg0 dump')) {
          // Global keepalive is 25s in the mocked config -> window is 75s.
          return `server-line\n${dumpLine({ handshakeSecondsAgo: 300 })}`;
        }
        return '';
      });
      const clients = await wg.getClients();
      expect(clients[0].online).toBe(false);
      expect(clients[0].endpoint).toBe('203.0.113.9:51820');
    });

    it('uses a 3x180s window when no keepalive is configured', async () => {
      await wg.getConfig();
      wg.__serverSettings.persistentKeepalive = 0;
      Util.exec.mockImplementation(async (cmd) => {
        if (typeof cmd === 'string' && cmd.includes('wg show wg0 dump')) {
          return `server-line\n${dumpLine({ handshakeSecondsAgo: 400 })}`;
        }
        return '';
      });
      const clients = await wg.getClients();
      // 400s ago is inside the 540s fallback window.
      expect(clients[0].online).toBe(true);
    });

    it('honors a per-peer keepalive override in the online window', async () => {
      await wg.getConfig();
      await wg.updateClientKeepalive({ clientId: 'client1', persistentKeepalive: 3600 });
      Util.exec.mockImplementation(async (cmd) => {
        if (typeof cmd === 'string' && cmd.includes('wg show wg0 dump')) {
          return `server-line\n${dumpLine({ handshakeSecondsAgo: 400 })}`;
        }
        return '';
      });
      const clients = await wg.getClients();
      // Global keepalive is 25s (75s window); the 3600s override widens the
      // window to 3h, so a 400s-old handshake is still online.
      expect(clients[0].online).toBe(true);
    });

    it('keeps the global window for peers without an override', async () => {
      await wg.getConfig();
      await wg.updateClientKeepalive({ clientId: 'client1', persistentKeepalive: null });
      Util.exec.mockImplementation(async (cmd) => {
        if (typeof cmd === 'string' && cmd.includes('wg show wg0 dump')) {
          return `server-line\n${dumpLine({ handshakeSecondsAgo: 400 })}`;
        }
        return '';
      });
      const clients = await wg.getClients();
      // No override: the global 25s setting (75s window) governs.
      expect(clients[0].online).toBe(false);
      // and the API keepalive field is typed int-or-null from the dump
      expect(clients[0].persistentKeepalive).toBe(0);
    });

    it('treats no-handshake and (none) endpoint as offline/null', async () => {
      await wg.getConfig();
      // handshake '0' means "never handshaked".
      const line = [
        KEYS.clientPublic, KEYS.preShared, '(none)', '10.8.0.2/32', '0', '0', '0', '0',
      ].join('\t');
      Util.exec.mockImplementation(async (cmd) => {
        if (typeof cmd === 'string' && cmd.includes('wg show wg0 dump')) return `server-line\n${line}`;
        return '';
      });
      const clients = await wg.getClients();
      expect(clients[0].online).toBe(false);
      expect(clients[0].endpoint).toBeNull();
      expect(clients[0].latestHandshakeAt).toBeNull();
    });
  });

  describe('per-peer persistentKeepalive', () => {
    it('migrates missing values to null and honors overrides in generated configs', async () => {
      await wg.getConfig();
      expect((await wg.getConfig()).clients.client1.persistentKeepalive).toBeNull();

      await wg.updateClientKeepalive({ clientId: 'client1', persistentKeepalive: 25 });
      const conf = await wg.getClientConfiguration({ clientId: 'client1' });
      expect(conf).toContain('PersistentKeepalive = 25');
    });

    it('falls back to the global setting when no override is set', async () => {
      await wg.getConfig();
      // Mocked config sets WG_PERSISTENT_KEEPALIVE '25'.
      const conf = await wg.getClientConfiguration({ clientId: 'client1' });
      expect(conf).toContain('PersistentKeepalive = 25');

      await wg.updateClientKeepalive({ clientId: 'client1', persistentKeepalive: 0 });
      const zeroed = await wg.getClientConfiguration({ clientId: 'client1' });
      expect(zeroed).toContain('PersistentKeepalive = 0');
    });

    it('validates bounds', async () => {
      await wg.getConfig();
      await expect(wg.updateClientKeepalive({ clientId: 'client1', persistentKeepalive: -1 }))
        .rejects.toMatchObject({ statusCode: 400 });
      await expect(wg.updateClientKeepalive({ clientId: 'client1', persistentKeepalive: 65536 }))
        .rejects.toMatchObject({ statusCode: 400 });
      await expect(wg.updateClientKeepalive({ clientId: 'client1', persistentKeepalive: 25.5 }))
        .rejects.toMatchObject({ statusCode: 400 });
      await expect(wg.updateClientKeepalive({ clientId: 'client1', persistentKeepalive: null }))
        .resolves.toMatchObject({ persistentKeepalive: null });
    });

    it('survives backup -> restore round-trips', async () => {
      await wg.getConfig();
      await wg.updateClientKeepalive({ clientId: 'client1', persistentKeepalive: 45 });

      const backup = JSON.parse(JSON.stringify(await wg.getConfig()));
      // strict restore whitelists the field, so this must round-trip:
      await wg.restoreConfiguration(JSON.stringify(backup));
      const config = await wg.getConfig();
      expect(config.clients.client1.persistentKeepalive).toBe(45);

      // and validation rejects corrupt values on restore
      const bad = JSON.parse(JSON.stringify(config));
      bad.clients.client1.persistentKeepalive = 'always';
      await expect(wg.restoreConfiguration(JSON.stringify(bad))).rejects.toMatchObject({ statusCode: 400 });
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

    it('bumps client updatedAt on restore instead of rolling it backwards', async () => {
      await wg.getConfig();
      const before = Date.now();
      const backup = makeConfig();
      backup.clients.client1.updatedAt = '2020-01-01T00:00:00.000Z';
      await wg.restoreConfiguration(JSON.stringify(backup));
      const config = await wg.getConfig();
      expect(Date.parse(config.clients.client1.updatedAt)).toBeGreaterThanOrEqual(before - 1000);
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

    it('never echoes secret-bearing settings in server-config responses', async () => {
      await wg.getConfig();
      // Simulate a future release storing a secret among the settings.
      wg.__serverSettings.webhookSecret = 'supersecret-value';
      const response = await wg.getServerConfig();
      expect(response.webhookSecret).toBeUndefined();
      expect(JSON.stringify(response)).not.toContain('supersecret-value');
      expect(response.host).toBe('10.0.0.1');
    });

    it('keeps the recovery journal when the disk rollback fails', async () => {
      await wg.getConfig();

      // Fail the nft apply so the whole settings transaction rolls back.
      Util.execFile.mockImplementation(async (command) => {
        if (command === 'nft') throw new Error('nft apply failed');
        return KEYS.clientPublic;
      });
      // Let the candidate's wg0.json write succeed, then fail the rollback's.
      let wg0JsonRenames = 0;
      fs.rename.mockImplementation(async (from, to) => {
        if (String(to).endsWith('wg0.json')) {
          wg0JsonRenames += 1;
          if (wg0JsonRenames === 2) throw new Error('ENOSPC: rollback write failed');
        }
      });

      let caught;
      await wg.updateServerConfig({ host: '10.0.0.2' }).catch((err) => {
        caught = err;
      });
      expect(caught.rollbackErrors).toEqual(expect.arrayContaining([
        expect.stringContaining('Settings config rollback failed'),
      ]));
      // The journal must survive so boot recovery can converge the disk;
      // deleting it would strand the candidate config permanently.
      expect(fs.unlink.mock.calls.some(([target]) => String(target).endsWith('server-settings.transaction.json'))).toBe(false);
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

    it('heals legacy clients missing name, address and publicKey', async () => {
      const legacy = makeConfig();
      delete legacy.clients.client1.name;
      delete legacy.clients.client1.address;
      delete legacy.clients.client1.publicKey;
      fs.readFile.mockImplementation(async (filename) => {
        if (String(filename).includes('server-settings')) {
          const err = new Error('not found');
          err.code = 'ENOENT';
          throw err;
        }
        return JSON.stringify(legacy);
      });
      Util.execFile.mockImplementation(async (command) => (command === 'wg' ? KEYS.clientPublic : ''));
      const WireGuardClass = require('./WireGuard'); // eslint-disable-line global-require
      const migrated = new WireGuardClass();

      const config = await migrated.getConfig();
      expect(config.clients.client1.name).toBe('client1');
      expect(config.clients.client1.address).toBe('10.8.0.2');
      expect(config.clients.client1.publicKey).toBe(KEYS.clientPublic);
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
      // The slow late operation must also settle before the drain resolves â€”
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

  describe('stable port-forward ids', () => {
    it('assigns a valid id at creation and preserves it across updates', async () => {
      await wg.getConfig();
      const created = await wg.addPortForward('client1', 'tcp', 3000, 3000);
      expect(created.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);

      const updated = await wg.updatePortForward('client1', 1, 'tcp', 3001, 3001);
      expect(updated.id).toBe(created.id);

      const config = await wg.getConfig();
      expect(config.clients.client1.portForwards[1].id).toBe(created.id);
    });

    it('backfills ids for legacy rules on load and on restore', async () => {
      const config = await wg.getConfig();
      // The shared fixture ships rules without ids; migration must add them.
      expect(Util.isValidRuleId(config.clients.client1.portForwards[0].id)).toBe(true);

      const backup = makeConfig(); // no ids
      await wg.restoreConfiguration(JSON.stringify(backup));
      const restored = await wg.getConfig();
      expect(Util.isValidRuleId(restored.clients.client1.portForwards[0].id)).toBe(true);
    });

    it('restore round-trips preserves existing rule ids', async () => {
      const backup = makeConfig();
      const originalId = '11111111-2222-3333-4444-555555555555';
      backup.clients.client1.portForwards[0].id = originalId;
      await wg.restoreConfiguration(JSON.stringify(backup));
      const config = await wg.getConfig();
      expect(config.clients.client1.portForwards[0].id).toBe(originalId);
    });

    it('rejects malformed rule ids at validation', async () => {
      const bad = makeConfig();
      bad.clients.client1.portForwards[0].id = 'not-a-uuid';
      await expect(wg.restoreConfiguration(JSON.stringify(bad)))
        .rejects.toMatchObject({ statusCode: 400 });
    });

    it('deletes the intended rule by id even after sibling index shifts', async () => {
      await wg.getConfig();
      const first = await wg.addPortForward('client1', 'tcp', 3000, 3000);
      const second = await wg.addPortForward('client1', 'tcp', 3001, 3001);
      await wg.addPortForward('client1', 'tcp', 3002, 3002);

      // A "stale view" edit removes index 0; the id-based delete of `second`
      // must still remove exactly that rule, not whatever now sits at its old
      // index.
      await wg.removePortForward('client1', 0);
      await wg.removePortForwardById('client1', second.id);

      const config = await wg.getConfig();
      const remaining = config.clients.client1.portForwards.map((rule) => rule.extPort);
      expect(remaining).toContain(first.extPort);
      expect(remaining).toContain(3002);
      expect(remaining).not.toContain(3001);
    });

    it('returns 404 for an unknown rule id', async () => {
      await wg.getConfig();
      await expect(wg.removePortForwardById('client1', '11111111-2222-3333-4444-555555555555'))
        .rejects.toMatchObject({ statusCode: 404 });
      await expect(wg.updatePortForwardById('client1', '11111111-2222-3333-4444-555555555555', 'tcp', 3000, 3000))
        .rejects.toMatchObject({ statusCode: 404 });
    });

    it('rejects malformed rule ids before touching the queue', async () => {
      await expect(wg.removePortForwardById('client1', 'zzz')).rejects.toMatchObject({ statusCode: 400 });
    });

    it('never resolves digit strings positionally on the peer ByRuleId methods', async () => {
      await wg.getConfig();
      // "0" is not a rule id: it must miss, not edit/delete index 0.
      await expect(wg.updatePortForwardByRuleId('client1', '0', 'tcp', 3000, 3000))
        .rejects.toMatchObject({ statusCode: 404 });
      await expect(wg.removePortForwardByRuleId('client1', '0'))
        .rejects.toMatchObject({ statusCode: 404 });
      const config = await wg.getConfig();
      expect(config.clients.client1.portForwards[0].extPort).toBe(2000);
    });
  });

  describe('autoAssignPortForward', () => {
    it('assigns the lowest free port in the policy window', async () => {
      await wg.getConfig();
      const rule = await wg.autoAssignPortForward('client1', { proto: 'tcp', intPort: 80 });
      // portFwdMin is 1024 in the mocked config and nothing else holds it.
      expect(rule.extPort).toBe(1024);
      expect(rule.proto).toBe('tcp');
      expect(rule.intPort).toBe(80);
      expect(Util.isValidRuleId(rule.id)).toBe(true);
    });

    it('prefers the port the peer already holds (sticky)', async () => {
      await wg.getConfig();
      // client1 holds tcp/2000; auto-assigning udp should reuse extPort 2000
      // so port-keyed trackers keep working.
      const rule = await wg.autoAssignPortForward('client1', { proto: 'udp', intPort: 53 });
      expect(rule.extPort).toBe(2000);
    });

    it('skips ports held by other peers', async () => {
      await wg.getConfig();
      const twoPeers = makeConfig();
      twoPeers.clients.client2 = {
        id: 'client2',
        name: 'client2',
        address: '10.8.0.3',
        addressV6: 'fd42:42:42::3',
        privateKey: KEYS.clientPrivate,
        publicKey: KEYS.client2Public,
        preSharedKey: KEYS.preShared,
        createdAt: '2026-01-01T00:00:00.000Z',
        updatedAt: '2026-01-01T00:00:00.000Z',
        enabled: true,
        portForwards: [{ proto: 'tcp', extPort: 1024, intPort: 80 }],
      };
      await wg.restoreConfiguration(JSON.stringify(twoPeers));

      const rule = await wg.autoAssignPortForward('client1', { proto: 'tcp', intPort: 8080 });
      expect(rule.extPort).toBe(1025);
    });

    it('honours explicit range bounds and rejects inverted ones', async () => {
      await wg.getConfig();
      const rule = await wg.autoAssignPortForward('client1', {
        proto: 'tcp', intPort: 80, rangeStart: 2000, rangeEnd: 2010,
      });
      expect(rule.extPort).toBeGreaterThanOrEqual(2000);
      expect(rule.extPort).toBeLessThanOrEqual(2010);

      await expect(wg.autoAssignPortForward('client1', {
        proto: 'tcp', intPort: 80, rangeStart: 2010, rangeEnd: 2000,
      })).rejects.toMatchObject({ statusCode: 400 });
    });

    it('returns 409 when the range is exhausted', async () => {
      await wg.getConfig();
      // Only candidate in range is the reserved server port (51820).
      await expect(wg.autoAssignPortForward('client1', {
        proto: 'tcp', intPort: 80, rangeStart: 51820, rangeEnd: 51820,
      })).rejects.toMatchObject({ statusCode: 409 });
    });

    it('gives N parallel assignments distinct ports', async () => {
      await wg.getConfig();
      const results = await Promise.all([
        wg.autoAssignPortForward('client1', { proto: 'tcp', intPort: 1 }),
        wg.autoAssignPortForward('client1', { proto: 'tcp', intPort: 2 }),
        wg.autoAssignPortForward('client1', { proto: 'tcp', intPort: 3 }),
      ]);
      const ports = results.map((rule) => rule.extPort);
      expect(new Set(ports).size).toBe(3);
      const config = await wg.getConfig();
      expect(config.clients.client1.portForwards).toHaveLength(4); // fixture rule + 3
    });
  });
  describe('peer tokens', () => {
    it('issues tokens shown once, storing only the sha256 hash', async () => {
      await wg.getConfig();
      const { token, tokenCreatedAt } = await wg.issueClientToken({ clientId: 'client1' });
      expect(token).toMatch(/^wgpt_[0-9a-f]{64}$/);
      expect(tokenCreatedAt).toBeInstanceOf(Date);

      const config = await wg.getConfig();
      expect(config.clients.client1.tokenHash).toBe(crypto.createHash('sha256').update(token).digest('hex'));
      expect(JSON.stringify(config)).not.toContain(token);
    });

    it('looks tokens up without leaking which peer matched', async () => {
      await wg.getConfig();
      const { token } = await wg.issueClientToken({ clientId: 'client1' });
      expect(await wg.lookupPeerToken(token)).toBe('client1');
      expect(await wg.lookupPeerToken(`wgpt_${'0'.repeat(64)}`)).toBeNull();
      expect(await wg.lookupPeerToken('not-a-token')).toBeNull();
    });

    it('revokes tokens', async () => {
      await wg.getConfig();
      const { token } = await wg.issueClientToken({ clientId: 'client1' });
      await wg.revokeClientToken({ clientId: 'client1' });
      expect(await wg.lookupPeerToken(token)).toBeNull();
      const config = await wg.getConfig();
      expect(config.clients.client1.tokenHash).toBeNull();
    });

    it('serializes peer profiles without secrets or private keys', async () => {
      await wg.getConfig();
      await wg.issueClientToken({ clientId: 'client1' });
      const profile = await wg.getPeerProfile({ clientId: 'client1' });
      expect(profile).toMatchObject({
        id: 'client1',
        name: 'client1',
        address: '10.8.0.2',
        permissions: { selfManagePorts: false },
      });
      const serialized = JSON.stringify(profile);
      expect(serialized).not.toContain('privateKey');
      expect(serialized).not.toContain('tokenHash');
      expect(serialized).not.toContain('preSharedKey');
    });

    it('toggles selfManagePorts and validates it', async () => {
      await wg.getConfig();
      await wg.setClientSelfManagePorts({ clientId: 'client1', enabled: true });
      expect((await wg.getPeerProfile({ clientId: 'client1' })).permissions.selfManagePorts).toBe(true);
      await expect(wg.setClientSelfManagePorts({ clientId: 'client1', enabled: 'yes' }))
        .rejects.toMatchObject({ statusCode: 400 });
    });

    it('migrates selfManagePorts to false and validates hashes on restore', async () => {
      await wg.getConfig();
      expect((await wg.getConfig()).clients.client1.selfManagePorts).toBe(false);

      const bad = makeConfig();
      bad.clients.client1.tokenHash = 'not-a-hash';
      await expect(wg.restoreConfiguration(JSON.stringify(bad))).rejects.toMatchObject({ statusCode: 400 });
    });
  });

  describe('port events', () => {
    let store;
    let deliveries;

    beforeEach(() => {
      store = {};
      deliveries = [];
      jest.spyOn(wg, '__writeAtomic').mockImplementation(async (filename, contents) => {
        store[filename] = contents;
      });
      fs.readFile.mockImplementation(async (filename) => {
        const name = String(filename);
        // __writeAtomic is spied with bare filenames; reads use full paths.
        const base = name.split(/[\\/]/).pop();
        if (store[base] !== undefined) return store[base];
        if (base === 'wg0.json') return JSON.stringify(makeConfig());
        const err = new Error('not found');
        err.code = 'ENOENT';
        throw err;
      });
    });

    it('emits port.confirmed / port.changed with strictly increasing persisted seqs', async () => {
      await wg.getConfig();
      await wg.setWebhookConfig({ url: 'https://example.test/hook', secret: 's3cret' });
      Webhook.deliver.mockImplementation(async (config) => {
        deliveries.push(config);
        return true;
      });

      await wg.addPortForward('client1', 'tcp', 3000, 3000);
      await wg.updatePortForward('client1', 1, 'tcp', 3001, 3000);

      expect(deliveries).toHaveLength(2);
      const confirmed = JSON.parse(deliveries[0].body);
      const changed = JSON.parse(deliveries[1].body);
      expect(confirmed).toMatchObject({
        v: 1, event: 'port.confirmed', peerId: 'client1', seq: 1, proto: 'tcp', extPort: 3000, intPort: 3000,
      });
      expect(confirmed.eventId).toMatch(/^[0-9a-f-]{36}$/);
      expect(changed).toMatchObject({
        event: 'port.changed', seq: 2, extPort: 3001, previousExtPort: 3000,
      });
      expect(deliveries[0].secret).toBe('s3cret');
      expect(deliveries[0].allowInsecure).toBe(false);
      // sidecar persisted
      expect(JSON.parse(store['wg0-events.json'])).toEqual({ client1: 2 });
    });

    it('continues the sequence across a simulated restart', async () => {
      await wg.getConfig();
      await wg.setWebhookConfig({ url: 'https://example.test/hook', secret: 's' });
      Webhook.deliver.mockResolvedValue(true);
      await wg.addPortForward('client1', 'tcp', 3000, 3000);

      const WireGuardClass = require('./WireGuard'); // eslint-disable-line global-require
      const restarted = new WireGuardClass();
      jest.spyOn(restarted, '__writeAtomic').mockImplementation(async (filename, contents) => {
        store[filename] = contents;
      });
      await restarted.getConfig();
      await restarted.setWebhookConfig({ url: 'https://example.test/hook', secret: 's' });
      deliveries = [];
      Webhook.deliver.mockImplementation(async (config) => {
        deliveries.push(config);
        return true;
      });
      await restarted.updatePortForward('client1', 1, 'tcp', 3001, 3000);
      expect(JSON.parse(deliveries[0].body).seq).toBe(2);
    });

    it('never blocks mutations on delivery', async () => {
      await wg.getConfig();
      await wg.setWebhookConfig({ url: 'https://example.test/hook', secret: 's' });
      Webhook.deliver.mockImplementation(() => new Promise(() => {})); // never settles
      await wg.addPortForward('client1', 'tcp', 3000, 3000);
      const config = await wg.getConfig();
      expect(config.clients.client1.portForwards).toHaveLength(2);
    });

    it('emits nothing when no webhook is configured', async () => {
      await wg.getConfig();
      await wg.addPortForward('client1', 'tcp', 3000, 3000);
      expect(Webhook.deliver).not.toHaveBeenCalled();
    });
  });

  describe('webhook configuration', () => {
    it('stores the config in a 0600 sidecar file and never echoes the secret', async () => {
      await wg.getConfig();
      const result = await wg.setWebhookConfig({ url: 'https://example.test/hook', secret: 'topsecret' });
      expect(result).toEqual({ configured: true, url: 'https://example.test/hook' });

      const status = await wg.getWebhookConfig();
      expect(status).toEqual({ configured: true, url: 'https://example.test/hook' });
      expect(JSON.stringify(status)).not.toContain('topsecret');
    });

    it('clears the config with url:null and rejects plaintext targets by default', async () => {
      await wg.getConfig();
      await wg.setWebhookConfig({ url: 'https://example.test/hook', secret: 's' });
      expect(await wg.setWebhookConfig({ url: null, secret: null })).toEqual({ configured: false, url: null });

      await expect(wg.setWebhookConfig({ url: 'http://example.test/hook', secret: 's' }))
        .rejects.toMatchObject({ statusCode: 400 });
      await expect(wg.setWebhookConfig({ url: 'https://example.test/hook', secret: '' }))
        .rejects.toMatchObject({ statusCode: 400 });
      await expect(wg.setWebhookConfig({ url: 'ftp://example.test/hook', secret: 's' }))
        .rejects.toMatchObject({ statusCode: 400 });
    });
  });
});
