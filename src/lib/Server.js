'use strict';

const bcrypt = require('bcryptjs');
const { createServer } = require('node:http');
const { stat, readFile } = require('node:fs/promises');
const { isIP } = require('node:net');
const { resolve, sep } = require('node:path');

const expressSession = require('express-session');
const debug = require('debug')('Server');

const {
  createApp,
  createError,
  createRouter,
  deleteCookie,
  defineEventHandler,
  fromNodeMiddleware,
  getRouterParam,
  toNodeListener,
  setHeader,
  send,
  serveStatic,
} = require('h3');

const WireGuard = require('../services/WireGuard');

const {
  PORT,
  WEBUI_HOST,
  RELEASE,
  PASSWORD_HASH,
  SESSION_SECRET,
  SESSION_COOKIE_SECURE,
  TRUSTED_PROXY_IP,
  LANG,
  UI_TRAFFIC_STATS,
  UI_CHART_TYPE,
  validateEnvironment,
} = require('../config');

const requiresPassword = !!PASSWORD_HASH;

const SESSION_COOKIE_MAX_AGE = 12 * 60 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 20; // per IP per window
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const MAX_BODY_SIZE = 1024 * 1024; // 1 MB
const MAX_LOGIN_BUCKETS = 10000;
const MAX_ACTIVE_PASSWORD_CHECKS = 8;
const SESSION_COOKIE_NAME = 'connect.sid';

// In-memory login rate limiter (key: client IP)
const loginAttempts = new Map();
let activePasswordChecks = 0;

const getLoginAttempt = (key) => {
  const now = Date.now();
  const entry = loginAttempts.get(key);
  if (entry && entry.resetAt <= now) {
    loginAttempts.delete(key);
    return null;
  }
  return entry || null;
};

const beginPasswordCheck = (key) => {
  if (activePasswordChecks >= MAX_ACTIVE_PASSWORD_CHECKS) return false;
  let entry = getLoginAttempt(key);
  if (!entry) {
    if (loginAttempts.size >= MAX_LOGIN_BUCKETS) {
      loginAttempts.delete(loginAttempts.keys().next().value);
    }
    entry = { failures: 0, pending: 0, resetAt: Date.now() + LOGIN_WINDOW_MS };
    loginAttempts.set(key, entry);
  }
  if (entry.failures + entry.pending >= LOGIN_MAX_ATTEMPTS) return false;
  entry.pending += 1;
  activePasswordChecks += 1;
  return true;
};

const completePasswordCheck = (key, valid) => {
  activePasswordChecks = Math.max(0, activePasswordChecks - 1);
  const entry = loginAttempts.get(key);
  if (!entry) return;
  entry.pending = Math.max(0, entry.pending - 1);
  if (valid) entry.failures = 0;
  else entry.failures += 1;
  if (entry.pending === 0 && entry.failures === 0) loginAttempts.delete(key);
};

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of loginAttempts) {
    if (entry.resetAt <= now) {
      loginAttempts.delete(key);
    }
  }
}, LOGIN_WINDOW_MS).unref();

const getClientIp = (req) => {
  const peer = req.socket.remoteAddress || 'unknown';
  if (TRUSTED_PROXY_IP && peer === TRUSTED_PROXY_IP) {
    const forwarded = req.headers['x-forwarded-for'];
    const candidate = typeof forwarded === 'string'
      ? forwarded.split(',').at(-1).trim()
      : '';
    if (isIP(candidate)) return candidate;
  }
  return peer;
};

// Count bytes while streaming so oversized bodies are never fully buffered.
const readBodyLimited = async (event) => {
  const { req } = event.node;
  const declaredLength = Number(req.headers['content-length']);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_SIZE) {
    req.resume();
    throw createError({ statusCode: 413, message: 'Payload too large' });
  }

  const raw = await new Promise((resolveBody, rejectBody) => {
    let chunks = [];
    let size = 0;
    let settled = false;

    const fail = (err) => {
      if (settled) return;
      settled = true;
      rejectBody(err);
    };

    req.on('data', (chunk) => {
      if (chunks === null) return;
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buffer.length;
      if (size > MAX_BODY_SIZE) {
        chunks = null;
        fail(createError({ statusCode: 413, message: 'Payload too large' }));
        return;
      }
      chunks.push(buffer);
    });
    req.once('end', () => {
      if (!settled && chunks !== null) {
        settled = true;
        resolveBody(Buffer.concat(chunks, size).toString('utf8'));
      }
    });
    req.once('aborted', () => fail(createError({ statusCode: 400, message: 'Request aborted' })));
    req.once('error', fail);
  });

  try {
    return JSON.parse(raw);
  } catch (err) {
    throw createError({ statusCode: 400, message: 'Invalid JSON', cause: err });
  }
};

// Validate that cross-site requests cannot use the session cookie.
const isSameOrigin = (req) => {
  const { origin } = req.headers;
  if (!origin) {
    // Non-browser clients (curl, wg CLI) don't send Origin.
    return true;
  }
  try {
    const { host } = new URL(origin);
    return host === req.headers.host;
  } catch {
    return false;
  }
};

/**
 * Checks if `password` matches the PASSWORD_HASH.
 *
 * If environment variable is not set, the password is always invalid.
 *
 * @param {string} password String to test
 * @returns {Promise<boolean>} true if matching environment, otherwise false
 */
const isPasswordValid = async (password) => {
  if (typeof password !== 'string' || Buffer.byteLength(password, 'utf8') > 72) {
    return false;
  }

  if (PASSWORD_HASH) {
    return bcrypt.compare(password, PASSWORD_HASH);
  }

  return false;
};

module.exports = class Server {

  constructor({ port = PORT, host = WEBUI_HOST } = {}) {
    validateEnvironment();

    const app = createApp();
    this.app = app;

    app.use(fromNodeMiddleware(expressSession({
      name: SESSION_COOKIE_NAME,
      secret: SESSION_SECRET,
      proxy: !!TRUSTED_PROXY_IP,
      resave: false,
      rolling: true,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: 'strict',
        secure: SESSION_COOKIE_SECURE,
        maxAge: SESSION_COOKIE_MAX_AGE,
      },
    })));

    // Security headers
    app.use(fromNodeMiddleware((req, res, next) => {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Referrer-Policy', 'same-origin');
      if (req.url.startsWith('/api/')) {
        res.setHeader('Cache-Control', 'no-store');
      }
      res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        "script-src 'self'",
        "script-src-attr 'none'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "font-src 'self' data:",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
      ].join('; '));
      next();
    }));

    // CSRF protection: reject cross-origin state-changing requests.
    app.use(fromNodeMiddleware((req, res, next) => {
      if (!['POST', 'PUT', 'DELETE'].includes(req.method) || !req.url.startsWith('/api/')) {
        return next();
      }
      if (isSameOrigin(req)) {
        return next();
      }
      res.statusCode = 403;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Forbidden: cross-origin request' }));
    }));

    const router = createRouter();
    app.use(router);

    router
      .get('/api/release', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return JSON.stringify(RELEASE);
      }))

      .get('/api/lang', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return `"${LANG}"`;
      }))

      .get('/api/ui-traffic-stats', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return JSON.stringify(UI_TRAFFIC_STATS);
      }))

      .get('/api/ui-chart-type', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return JSON.stringify(UI_CHART_TYPE);
      }))

      // Authentication
      .get('/api/session', defineEventHandler((event) => {
        const authenticated = requiresPassword
          ? !!(event.node.req.session && event.node.req.session.authenticated)
          : true;

        return {
          requiresPassword,
          authenticated,
        };
      }))
      .post('/api/session', defineEventHandler(async (event) => {
        const ip = getClientIp(event.node.req);
        const { password } = await readBodyLimited(event);

        if (!requiresPassword) {
          // if no password is required, the API should never be called.
          // Do not automatically authenticate the user.
          throw createError({
            status: 401,
            message: 'Invalid state',
          });
        }

        if (!beginPasswordCheck(ip)) {
          throw createError({ statusCode: 429, message: 'Too many attempts, try again later' });
        }
        let passwordValid = false;
        try {
          passwordValid = await isPasswordValid(password);
        } finally {
          completePasswordCheck(ip, passwordValid);
        }
        if (!passwordValid) {
          throw createError({
            status: 401,
            message: 'Incorrect Password',
          });
        }

        // Regenerate the session ID on login to prevent session fixation.
        await new Promise((resolve, reject) => {
          event.node.req.session.regenerate((err) => {
            if (err) {
              reject(createError({ status: 500, message: 'Failed to regenerate session' }));
              return;
            }

            event.node.req.session.authenticated = true;
            event.node.req.session.save((saveErr) => {
              if (saveErr) {
                debug(`Session Save Error: ${saveErr.message}`);
                reject(createError({ status: 500, message: 'Failed to save session' }));
              } else {
                resolve();
              }
            });
          });
        });

        debug('New authenticated session');

        return { success: true };
      }))
      .delete('/api/session', defineEventHandler(async (event) => {
        const { session } = event.node.req;
        try {
          if (session) {
            await new Promise((resolveDestroy, rejectDestroy) => {
              session.destroy((err) => {
                if (err) rejectDestroy(createError({ statusCode: 500, message: 'Failed to destroy session' }));
                else resolveDestroy();
              });
            });
          }
        } finally {
          deleteCookie(event, SESSION_COOKIE_NAME, { path: '/' });
        }
        debug('Session deleted');
        return { success: true };
      }));

    // WireGuard
    app.use(
      fromNodeMiddleware((req, res, next) => {
        if (!requiresPassword || !req.url.startsWith('/api/')) {
          return next();
        }

        if (req.session && req.session.authenticated) {
          return next();
        }

        if (req.url.startsWith('/api/') && req.headers['authorization']) {
          const ip = getClientIp(req);
          if (!beginPasswordCheck(ip)) {
            res.statusCode = 429;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: 'Too many attempts, try again later' }));
            return;
          }

          isPasswordValid(req.headers['authorization'])
            .then((valid) => {
              completePasswordCheck(ip, valid);
              if (valid) {
                next();
                return;
              }
              res.statusCode = 401;
              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify({ error: 'Incorrect Password' }));
            }, (err) => {
              completePasswordCheck(ip, false);
              next(err);
            });
          return;
        }

        res.statusCode = 401;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Not Logged In' }));
      }),
    );

    const router2 = createRouter();
    app.use(router2);

    router2
      .get('/api/wireguard/network-policy-options', defineEventHandler(() => {
        return WireGuard.getNetworkPolicyOptions();
      }))
      .get('/api/wireguard/client', defineEventHandler(() => {
        return WireGuard.getClients();
      }))
      .get('/api/wireguard/client/:clientId/qrcode.svg', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 404 });
        }
        const svg = await WireGuard.getClientQRCodeSVG({ clientId });
        setHeader(event, 'Content-Type', 'image/svg+xml');
        return svg;
      }))
      .get('/api/wireguard/client/:clientId/configuration', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 404 });
        }
        const client = await WireGuard.getClient({ clientId });
        const config = await WireGuard.getClientConfiguration({ clientId });
        const configName = client.name
          .replace(/[^a-zA-Z0-9_=+.-]/g, '-')
          .replace(/(-{2,}|-$)/g, '-')
          .replace(/-$/, '')
          .substring(0, 32);
        setHeader(event, 'Content-Disposition', `attachment; filename="${configName || clientId}.conf"`);
        setHeader(event, 'Content-Type', 'text/plain');
        return config;
      }))
      .get('/api/wireguard/client/:clientId/configuration/raw', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 404 });
        }
        const config = await WireGuard.getClientConfiguration({ clientId });
        return send(event, config.trim(), 'text/plain');
      }))
      .post('/api/wireguard/client', defineEventHandler(async (event) => {
        const { name } = await readBodyLimited(event);
        await WireGuard.createClient({ name });
        return { success: true };
      }))
      .delete('/api/wireguard/client/:clientId', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 404 });
        }
        await WireGuard.deleteClient({ clientId });
        return { success: true };
      }))
      .post('/api/wireguard/client/:clientId/enable', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        await WireGuard.enableClient({ clientId });
        return { success: true };
      }))
      .post('/api/wireguard/client/:clientId/disable', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        await WireGuard.disableClient({ clientId });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/name', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        const { name } = await readBodyLimited(event);
        await WireGuard.updateClientName({ clientId, name });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/address', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        const { address, addressV6 } = await readBodyLimited(event);
        await WireGuard.updateClientAddress({ clientId, address, addressV6 });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/network-policy', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        const { policy, expectedUpdatedAt } = await readBodyLimited(event);
        if (typeof expectedUpdatedAt !== 'string') {
          throw createError({ status: 400, message: 'expectedUpdatedAt is required' });
        }
        return WireGuard.updateClientNetworkPolicy({ clientId, policy, expectedUpdatedAt });
      }))
      .post('/api/wireguard/client/:clientId/port-forward', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        const { proto, extPort, intPort } = await readBodyLimited(event);
        if (!['tcp', 'udp', 'both'].includes(proto)) {
          throw createError({ status: 400, message: 'proto debe ser tcp, udp o both' });
        }
        const p = Number(extPort);
        const ip = Number(intPort);
        if (!Number.isInteger(p) || !Number.isInteger(ip) || p < 1 || p > 65535 || ip < 1 || ip > 65535) {
          throw createError({ status: 400, message: 'Puertos inválidos' });
        }
        await WireGuard.addPortForward(clientId, proto, p, ip);
        return { success: true };
      }))
      .delete('/api/wireguard/client/:clientId/port-forward/:index', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        const index = getRouterParam(event, 'index');
        const numIndex = Number(index);
        if (!Number.isInteger(numIndex) || numIndex < 0) {
          throw createError({ status: 400, message: 'Invalid index' });
        }
        await WireGuard.removePortForward(clientId, numIndex);
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/port-forward/:index', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        const index = getRouterParam(event, 'index');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        const numIndex = Number(index);
        if (!Number.isInteger(numIndex) || numIndex < 0) {
          throw createError({ status: 400, message: 'Invalid index' });
        }
        const { proto, extPort, intPort } = await readBodyLimited(event);
        if (!['tcp', 'udp', 'both'].includes(proto)) {
          throw createError({ status: 400, message: 'proto debe ser tcp, udp o both' });
        }
        const p = Number(extPort);
        const ip = Number(intPort);
        if (!Number.isInteger(p) || !Number.isInteger(ip) || p < 1 || p > 65535 || ip < 1 || ip > 65535) {
          throw createError({ status: 400, message: 'Puertos inválidos' });
        }
        await WireGuard.updatePortForward(clientId, numIndex, proto, p, ip);
        return { success: true };
      }))
      .get('/api/wireguard/server-config', defineEventHandler(async () => {
        return WireGuard.getServerConfig();
      }))
      .put('/api/wireguard/server-config', defineEventHandler(async (event) => {
        const body = await readBodyLimited(event);
        const result = await WireGuard.updateServerConfig(body);
        return result;
      }));

    const safePathJoin = (base, target) => {
      // Manage web root (edge case)
      if (target === '/') {
        return `${base}${sep}`;
      }

      // Prepend './' to prevent absolute paths
      const targetPath = `.${sep}${target}`;

      // Resolve the absolute path
      const resolvedPath = resolve(base, targetPath);

      // Check if resolvedPath is a subpath of base
      if (resolvedPath.startsWith(`${base}${sep}`)) {
        return resolvedPath;
      }

      throw createError({
        status: 400,
        message: 'Bad Request',
      });
    };

    // backup_restore
    const router3 = createRouter();
    app.use(router3);

    router3
      .get('/api/wireguard/backup', defineEventHandler(async (event) => {
        const config = await WireGuard.backupConfiguration();
        setHeader(event, 'Content-Disposition', 'attachment; filename="wg0.json"');
        setHeader(event, 'Content-Type', 'application/json');
        return config;
      }))
      .put('/api/wireguard/restore', defineEventHandler(async (event) => {
        const { file } = await readBodyLimited(event);
        await WireGuard.restoreConfiguration(file);
        return { success: true };
      }));

    // Static assets
    const publicDir = resolve(__dirname, '../www');
    app.use(
      defineEventHandler((event) => {
        return serveStatic(event, {
          getContents: (id) => {
            return readFile(safePathJoin(publicDir, id));
          },
          getMeta: async (id) => {
            const filePath = safePathJoin(publicDir, id);

            const stats = await stat(filePath).catch(() => {});
            if (!stats || !stats.isFile()) {
              return;
            }

            if (id.endsWith('.html')) setHeader(event, 'Content-Type', 'text/html');
            if (id.endsWith('.js')) setHeader(event, 'Content-Type', 'application/javascript');
            if (id.endsWith('.json')) setHeader(event, 'Content-Type', 'application/json');
            if (id.endsWith('.css')) setHeader(event, 'Content-Type', 'text/css');
            if (id.endsWith('.png')) setHeader(event, 'Content-Type', 'image/png');

            return {
              size: stats.size,
              mtime: stats.mtimeMs,
            };
          },
        });
      }),
    );

    this.server = createServer(toNodeListener(app));
    this.server.listen(port, host);
    debug(`Listening on http://${host}:${port}`);
  }

};
