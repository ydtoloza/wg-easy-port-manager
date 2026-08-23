'use strict';

const { isIP } = require('node:net');

const { release: { version } } = require('./package.json');

const isTrue = (value) => value === 'true' || value === '1';

module.exports.RELEASE = version;
module.exports.PORT = process.env.PORT || '51821';
module.exports.WEBUI_HOST = process.env.WEBUI_HOST || '0.0.0.0';
/** This is only kept for migration purpose. DO NOT USE! */
module.exports.PASSWORD = process.env.PASSWORD;
module.exports.PASSWORD_HASH = process.env.PASSWORD_HASH;
module.exports.SESSION_SECRET = process.env.SESSION_SECRET;
module.exports.SESSION_COOKIE_SECURE = isTrue(process.env.SESSION_COOKIE_SECURE);
module.exports.TRUSTED_PROXY_IP = process.env.TRUSTED_PROXY_IP;
// Allow http:// (plaintext) webhook targets. Never enable behind untrusted
// networks: webhook delivery runs on the host-network container.
module.exports.ALLOW_INSECURE_WEBHOOK = isTrue(process.env.ALLOW_INSECURE_WEBHOOK);
module.exports.ALLOW_INSECURE_NO_AUTH = isTrue(process.env.ALLOW_INSECURE_NO_AUTH);
module.exports.WG_PATH = process.env.WG_PATH || '/etc/wireguard/';
module.exports.WG_DEVICE = process.env.WG_DEVICE || 'eth0';
module.exports.WG_HOST = process.env.WG_HOST;
module.exports.WG_PORT = process.env.WG_PORT || '51820';
module.exports.WG_CONFIG_PORT = process.env.WG_CONFIG_PORT || process.env.WG_PORT || '51820';
module.exports.WG_MTU = process.env.WG_MTU || null;
module.exports.WG_PORT_FWD_MIN = process.env.WG_PORT_FWD_MIN || '1024';
module.exports.WG_PORT_FWD_MAX = process.env.WG_PORT_FWD_MAX || '65535';
module.exports.WG_PERSISTENT_KEEPALIVE = process.env.WG_PERSISTENT_KEEPALIVE || '0';
module.exports.WG_NFT_MASQUERADE = process.env.WG_NFT_MASQUERADE ? isTrue(process.env.WG_NFT_MASQUERADE) : true;
module.exports.WG_SEED_TUNING = process.env.WG_SEED_TUNING ? isTrue(process.env.WG_SEED_TUNING) : true;
module.exports.WG_DEFAULT_ADDRESS = process.env.WG_DEFAULT_ADDRESS || '10.8.0.x';
module.exports.WG_DEFAULT_ADDRESS_V6 = process.env.WG_DEFAULT_ADDRESS_V6 || 'fd42:42:42::x';
module.exports.WG_DEFAULT_DNS = typeof process.env.WG_DEFAULT_DNS === 'string'
  ? process.env.WG_DEFAULT_DNS
  : '1.1.1.1';
module.exports.WG_ALLOWED_IPS = process.env.WG_ALLOWED_IPS || '0.0.0.0/0, ::/0';

module.exports.WG_PRE_UP = process.env.WG_PRE_UP || '';
module.exports.WG_POST_UP = process.env.WG_POST_UP || `
iptables -t nat -I POSTROUTING 1 -s ${module.exports.WG_DEFAULT_ADDRESS.replace('x', '0')}/24 -o ${module.exports.WG_DEVICE} -j MASQUERADE;
ip6tables -t nat -I POSTROUTING 1 -s ${module.exports.WG_DEFAULT_ADDRESS_V6.replace('x', '0')}/64 -o ${module.exports.WG_DEVICE} -j MASQUERADE;
iptables -I INPUT 1 -p udp -m udp --dport ${module.exports.WG_PORT} -j ACCEPT;
iptables -I FORWARD 1 -i wg0 -j ACCEPT;
iptables -I FORWARD 1 -o wg0 -j ACCEPT;
ip6tables -I FORWARD 1 -i wg0 -j ACCEPT;
ip6tables -I FORWARD 1 -o wg0 -j ACCEPT;
`.split('\n').join(' ');

module.exports.WG_PRE_DOWN = process.env.WG_PRE_DOWN || '';
module.exports.WG_POST_DOWN = process.env.WG_POST_DOWN || `
iptables -t nat -D POSTROUTING -s ${module.exports.WG_DEFAULT_ADDRESS.replace('x', '0')}/24 -o ${module.exports.WG_DEVICE} -j MASQUERADE;
ip6tables -t nat -D POSTROUTING -s ${module.exports.WG_DEFAULT_ADDRESS_V6.replace('x', '0')}/64 -o ${module.exports.WG_DEVICE} -j MASQUERADE;
iptables -D INPUT -p udp -m udp --dport ${module.exports.WG_PORT} -j ACCEPT;
iptables -D FORWARD -i wg0 -j ACCEPT;
iptables -D FORWARD -o wg0 -j ACCEPT;
ip6tables -D FORWARD -i wg0 -j ACCEPT;
ip6tables -D FORWARD -o wg0 -j ACCEPT;
`.split('\n').join(' ');
module.exports.LANG = process.env.LANG || 'en';
module.exports.UI_TRAFFIC_STATS = isTrue(process.env.UI_TRAFFIC_STATS);
module.exports.UI_CHART_TYPE = [0, 1, 2, 3].includes(Number(process.env.UI_CHART_TYPE))
  ? Number(process.env.UI_CHART_TYPE)
  : 0;

module.exports.validateEnvironment = () => {
  if (module.exports.PASSWORD) {
    throw new Error('PASSWORD is not supported. Use PASSWORD_HASH instead.');
  }

  if (!module.exports.PASSWORD_HASH) {
    const loopbackHosts = new Set(['127.0.0.1', '::1', 'localhost']);
    if (!module.exports.ALLOW_INSECURE_NO_AUTH || !loopbackHosts.has(module.exports.WEBUI_HOST)) {
      throw new Error('PASSWORD_HASH is required. Passwordless mode requires ALLOW_INSECURE_NO_AUTH=true and a loopback WEBUI_HOST.');
    }
  } else {
    const bcryptMatch = /^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$/.exec(module.exports.PASSWORD_HASH);
    const cost = bcryptMatch ? Number(bcryptMatch[1]) : 0;
    if (!bcryptMatch || cost < 10 || cost > 15) {
      throw new Error('PASSWORD_HASH must be a valid bcrypt hash with cost 10-15.');
    }
  }

  if (typeof module.exports.SESSION_SECRET !== 'string'
    || Buffer.byteLength(module.exports.SESSION_SECRET, 'utf8') < 32) {
    throw new Error('SESSION_SECRET must contain at least 32 bytes.');
  }

  if (module.exports.TRUSTED_PROXY_IP && !isIP(module.exports.TRUSTED_PROXY_IP)) {
    throw new Error('TRUSTED_PROXY_IP must be a valid IP address.');
  }
};
