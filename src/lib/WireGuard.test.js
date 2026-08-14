/* eslint-env jest */

'use strict';

const fs = require('node:fs/promises');
const Util = require('./Util');
const ServerError = require('./ServerError');

jest.mock('node:fs/promises');
jest.mock('./Util');
jest.mock('../config', () => ({
  WG_PATH: '/mock/path',
  WG_HOST: '10.0.0.1',
  WG_PORT: '51820',
  WG_CONFIG_PORT: '51820',
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
}));

describe('WireGuard', () => {
  let wg;

  beforeEach(() => {
    jest.clearAllMocks();

    fs.readFile.mockResolvedValue(JSON.stringify({
      server: {
        privateKey: 'server-priv',
        publicKey: 'server-pub',
        address: '10.8.0.1',
      },
      clients: {
        client1: {
          id: 'client1',
          name: 'client1',
          address: '10.8.0.2',
          enabled: true,
          portForwards: [
            { proto: 'tcp', extPort: 2000, intPort: 2000 },
          ],
        },
      },
    }));

    fs.writeFile.mockResolvedValue();
    fs.rename.mockResolvedValue();
    fs.unlink.mockResolvedValue();

    Util.exec.mockResolvedValue();
    Util.isValidIPv4.mockImplementation((ip) => /^10\.8\.0\.\d+$/.test(ip));
    Util.isValidIPv6.mockReturnValue(true);
    Util.isValidName.mockImplementation((s) => typeof s === 'string' && s.length > 0 && s.length <= 128
      // eslint-disable-next-line no-control-regex
      && !/[\u0000-\u001f\u007f]/.test(s));

    // mock linux to bypass process.platform check in mutating methods
    Object.defineProperty(process, 'platform', { value: 'linux' });

    const WireGuardClass = require('./WireGuard'); // eslint-disable-line global-require
    wg = new WireGuardClass();
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
      // Simulate nft failure during apply
      Util.exec.mockImplementation(async (cmd) => {
        if (cmd.includes('nft add rule')) {
          throw new Error('nft failed');
        }
      });

      try {
        await wg.addPortForward('client1', 'tcp', 3000, 3000);
      } catch (err) {
        expect(err.message).toMatch(/Failed to apply DNAT rules: nft failed/);
        expect(err.rollbackErrors).toEqual([]);
      }

      const config = await wg.getConfig();
      // ensure memory rollback
      expect(config.clients.client1.portForwards.length).toBe(1);

      // ensure we re-applied state (flush + re-add)
      const calls = Util.exec.mock.calls.map((c) => c[0]);
      expect(calls).toContain('nft flush chain ip wgeasy_dnat prerouting');

      // ensure we saved back
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('rolls back if saveConfig fails', async () => {
      await wg.getConfig();
      // nft succeeds, but save fails
      fs.rename.mockRejectedValueOnce(new Error('disk full'));

      try {
        await wg.addPortForward('client1', 'tcp', 3000, 3000);
      } catch (err) {
        expect(err.message).toMatch(/disk full/);
      }

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

  describe('restoreConfiguration', () => {
    it('rolls back disk and host on failure', async () => {
      await wg.getConfig(); // init state

      const backupJson = JSON.stringify({
        server: {
          privateKey: 'server-priv-valid-key==',
          publicKey: 'server-pub-valid-key==',
          address: '10.8.0.1',
        },
        clients: {
          client1: {
            id: 'client1',
            name: 'client1',
            address: '10.8.0.2', // Valid IP
            portForwards: [{ proto: 'tcp', extPort: 3000, intPort: 3000 }],
          },
        },
      });

      // Simulate wg syncconf failure in reload
      Util.exec.mockImplementation(async (cmd) => {
        if (cmd.includes('wg syncconf')) throw new Error('sync failed');
      });

      try {
        await wg.restoreConfiguration(backupJson);
      } catch (err) {
        expect(err.message).toMatch(/sync failed/);
        // The rollbackErrors should contain the wg sync error during the rollback
        expect(err.rollbackErrors.length).toBeGreaterThanOrEqual(1);
        expect(err.rollbackErrors.some((m) => m.includes('sync failed'))).toBe(true);
      }

      // Memory must be reverted
      const config = await wg.getConfig();
      expect(config.clients.client1.portForwards[0].extPort).toBe(2000);
    });

    it('rejects backup with invalid IPs entirely without saving', async () => {
      await wg.getConfig(); // init state

      const backupJson = JSON.stringify({
        server: {
          privateKey: 'server-priv-valid-key==',
          publicKey: 'server-pub-valid-key==',
          address: '10.8.0.1',
        },
        clients: {
          client1: {
            id: 'client1',
            name: 'client1',
            address: '10.8.0.2; touch /pwn', // Invalid IP
            portForwards: [{ proto: 'tcp', extPort: 3000, intPort: 3000 }],
          },
        },
      });

      try {
        await wg.restoreConfiguration(backupJson);
      } catch (err) {
        expect(err.message).toMatch(/Invalid IPv4 address/);
      }

      const config = await wg.getConfig();
      expect(config.clients.client1.address).toBe('10.8.0.2');
    });

    it('rejects backup with injected server keys (config injection)', async () => {
      await wg.getConfig(); // init state

      const backupJson = JSON.stringify({
        server: {
          privateKey: 'a\nPostUp = touch /pwn', // Injected newline
          publicKey: 'valid-public-key==',
          address: '10.8.0.1',
        },
        clients: {},
      });

      await expect(wg.restoreConfiguration(backupJson))
        .rejects.toThrow(/invalid server\.privateKey/);

      const config = await wg.getConfig();
      expect(config.server.privateKey).toBe('server-priv');
    });

    it('rejects backup with invalid client name', async () => {
      await wg.getConfig(); // init state

      const backupJson = JSON.stringify({
        server: {
          privateKey: 'server-priv-valid-key==',
          publicKey: 'server-pub-valid-key==',
          address: '10.8.0.1',
        },
        clients: {
          client1: {
            id: 'client1',
            name: 'evil\n[Peer]',
            address: '10.8.0.2',
            portForwards: [],
          },
        },
      });

      await expect(wg.restoreConfiguration(backupJson))
        .rejects.toThrow(/invalid client name/);
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
});
