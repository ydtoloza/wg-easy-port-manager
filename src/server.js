'use strict';

const Config = require('./config');

Config.validateEnvironment();

const WireGuard = require('./services/WireGuard');
const TrafficStats = require('./services/TrafficStats');
const Backup = require('./services/Backup');

const { UI_TRAFFIC_STATS } = Config;

let Server;
let shuttingDown = false;

const initialization = WireGuard.init();

initialization
  .then(() => {
    if (shuttingDown) return;
    // eslint-disable-next-line global-require
    Server = require('./services/Server');
    // Sample continuously from boot (not just while the panel is open) so the
    // 1h/24h/30d rollups stay complete and survive restarts via the
    // traffic-history.json sidecar. Gated by the dashboard flag so installs
    // without the traffic panel never pay the 1s sampling cost.
    if (UI_TRAFFIC_STATS) TrafficStats.start();
    // Scheduled state backups (wg0.json + settings sidecars, with retention).
    Backup.start();
  })
  .catch(async (err) => {
    // eslint-disable-next-line no-console
    console.error(err);
    await WireGuard.Shutdown().catch(() => {});
    if (shuttingDown) return;
    // eslint-disable-next-line no-process-exit
    process.exit(1);
  });

const shutdown = async (signal) => {
  if (shuttingDown) return;
  shuttingDown = true;
  // eslint-disable-next-line no-console
  console.log(`${signal} signal received.`);
  try {
    if (Server && Server.server) {
      await new Promise((resolve, reject) => {
        Server.server.close((err) => (err ? reject(err) : resolve()));
      });
    }
    await initialization.catch(() => {});
    await WireGuard.waitForMutations();
    // Persist traffic peaks/totals so a recreate doesn't lose the window
    // since the last periodic save. Best-effort: never block shutdown.
    try {
      Backup.stop();
      if (typeof TrafficStats.stop === 'function') TrafficStats.stop();
      await TrafficStats.save();
    } catch {
      // ignore shutdown-time persistence failures
    }
    await WireGuard.Shutdown();
    // eslint-disable-next-line no-process-exit
    process.exit(0);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    // eslint-disable-next-line no-process-exit
    process.exit(1);
  }
};

process.once('SIGTERM', () => shutdown('SIGTERM'));
process.once('SIGINT', () => shutdown('SIGINT'));
