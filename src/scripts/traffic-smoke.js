/* eslint-disable no-console, no-process-exit, global-require */

// Smoke test for the traffic dashboard: boots the real Server on an
// ephemeral port (Windows demo mode, synthetic traffic), logs in and hits
// the new endpoints + the HTML shell. Exits 0 on success.

'use strict';

process.env.PORT = '0';
process.env.WEBUI_HOST = '127.0.0.1';
process.env.PASSWORD_HASH = '$2a$10$KmH.Iyec6NgPIaP.EP5Pse7OnYy1Ve3BOxv/zopGk3mA4E7xarqWe'; // admin123
process.env.SESSION_SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef01';
process.env.WG_HOST = '127.0.0.1';
process.env.WG_PATH = 'C:\\WINDOWS\\TEMP\\opencode\\wgtest-smoke\\';
process.env.LANG = 'es';
process.env.UI_TRAFFIC_STATS = 'true';
process.env.UI_CHART_TYPE = '2';
process.env.TRAFFIC_POLL_MS = '1000';
process.env.TRAFFIC_SAMPLES = '120';

const { once } = require('node:events');
const Server = require('../lib/Server');
const TrafficStats = require('../services/TrafficStats');

const fail = (msg) => {
  console.error(`SMOKE FAIL: ${msg}`);
  process.exitCode = 1;
};

(async () => {
  // Skip WireGuard init (needs wg/nft on linux); Server only needs the
  // services for route handlers, which we exercise directly.
  const instance = new Server({ port: 0, host: '127.0.0.1' });
  await once(instance.server, 'listening');
  const base = `http://127.0.0.1:${instance.server.address().port}`;

  const login = await fetch(`${base}/api/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'admin123' }),
  });
  if (login.status !== 200) {
    fail(`login status ${login.status}`);
  }
  const cookie = (login.headers.get('set-cookie') || '').split(';')[0];
  const auth = { Cookie: cookie };
  console.log(`SMOKE login ok (cookie ${cookie.slice(0, 20)}...)`);

  for (const p of ['/api/traffic/realtime', '/api/traffic/history?range=1h', '/api/traffic/summary']) {
    const res = await fetch(`${base}${p}`, { headers: auth });
    const body = await res.text();
    console.log(`SMOKE ${p} -> ${res.status} (${body.length} bytes) ${body.slice(0, 160)}`);
    if (res.status !== 200) {
      fail(`${p} status ${res.status}`);
    }
  }
  const bad = await fetch(`${base}/api/traffic/history?range=99y`, { headers: auth });
  if (bad.status !== 400) {
    fail(`bad range status ${bad.status}`);
  } else {
    console.log('SMOKE invalid range -> 400 ok');
  }

  const anon = await fetch(`${base}/api/traffic/realtime`);
  if (anon.status !== 401) {
    fail(`anon status ${anon.status}`);
  } else {
    console.log('SMOKE anon -> 401 ok');
  }

  const html = await (await fetch(`${base}/`, { headers: auth })).text();
  for (const needle of ['traffic.bandwidth', 'trafficBwSeries', 'apexchart', 'app-template.generated.js']) {
    if (!html.includes(needle)) {
      fail(`index missing ${needle}`);
    }
  }
  console.log(`SMOKE index.html ok (${html.length} bytes, dashboard refs present)`);

  await new Promise((resolve) => instance.server.close(resolve));
  if (TrafficStats.stop) {
    TrafficStats.stop();
  }
  console.log(process.exitCode ? 'SMOKE FAILED' : 'SMOKE PASSED');
  process.exit(process.exitCode || 0);
})().catch((err) => {
  console.error(`SMOKE ERROR: ${err.stack}`);
  process.exit(1);
});
