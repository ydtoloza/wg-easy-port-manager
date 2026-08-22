'use strict';

const Config = require('./config');

Config.validateEnvironment();

const WireGuard = require('./services/WireGuard');

let Server;
let shuttingDown = false;

const initialization = WireGuard.init();

initialization
  .then(() => {
    if (shuttingDown) return;
    // eslint-disable-next-line global-require
    Server = require('./services/Server');
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
