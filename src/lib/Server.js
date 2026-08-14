'use strict';

const bcrypt = require('bcryptjs');
const crypto = require('node:crypto');
const { createServer } = require('node:http');
const { stat, readFile } = require('node:fs/promises');
const { resolve, sep } = require('node:path');

const expressSession = require('express-session');
const debug = require('debug')('Server');

const {
  createApp,
  createError,
  createRouter,
  defineEventHandler,
  fromNodeMiddleware,
  getRouterParam,
  toNodeListener,
  readBody,
  readRawBody,
  setHeader,
  send,
  serveStatic,
} = require('h3');

const WireGuard = require('../services/WireGuard');

const {
  PORT,
  WEBUI_HOST,
  RELEASE,
  PASSWORD,
  PASSWORD_HASH,
  SESSION_SECRET,
  LANG,
  UI_TRAFFIC_STATS,
  UI_CHART_TYPE,
} = require('../config');

const requiresPassword = !!PASSWORD_HASH;

const SESSION_COOKIE_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days
const LOGIN_MAX_ATTEMPTS = 20; // per IP per window
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const MAX_BODY_SIZE = 1024 * 1024; // 1 MB

// In-memory login rate limiter (key: client IP)
const loginAttempts = new Map();

const isLoginRateLimited = (key) => {
  const now = Date.now();
  let entry = loginAttempts.get(key);
  if (!entry || entry.resetAt <= now) {
    entry = { count: 0, resetAt: now + LOGIN_WINDOW_MS };
    loginAttempts.set(key, entry);
  }
  entry.count += 1;
  return entry.count > LOGIN_MAX_ATTEMPTS;
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
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim() || req.socket.remoteAddress;
  }
  return req.socket.remoteAddress;
};

// Read a JSON body with a hard size limit (prevents memory exhaustion).
const readBodyLimited = async (event) => {
  const raw = await readRawBody(event);
  if (raw && raw.length > MAX_BODY_SIZE) {
    throw createError({ status: 413, message: 'Payload too large' });
  }
  return readBody(event);
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
 * @returns {boolean} true if matching environment, otherwise false
 */
const isPasswordValid = (password) => {
  if (typeof password !== 'string') {
    return false;
  }

  if (PASSWORD_HASH) {
    return bcrypt.compareSync(password, PASSWORD_HASH);
  }

  return false;
};

module.exports = class Server {

  constructor() {
    const app = createApp();
    this.app = app;

    app.use(fromNodeMiddleware(expressSession({
      secret: SESSION_SECRET || crypto.randomBytes(256).toString('hex'),
      resave: true,
      rolling: true,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: SESSION_COOKIE_MAX_AGE,
      },
    })));

    // Security headers
    app.use(fromNodeMiddleware((req, res, next) => {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Referrer-Policy', 'same-origin');
      res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https://gravatar.com",
        "connect-src 'self' https://wg-easy.github.io",
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
        return RELEASE;
      }))

      .get('/api/lang', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return `"${LANG}"`;
      }))

      .get('/api/ui-traffic-stats', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return `"${UI_TRAFFIC_STATS}"`;
      }))

      .get('/api/ui-chart-type', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return `"${UI_CHART_TYPE}"`;
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
        if (isLoginRateLimited(ip)) {
          throw createError({
            status: 429,
            message: 'Too many attempts, try again later',
          });
        }

        const { password } = await readBodyLimited(event);

        if (!requiresPassword) {
          // if no password is required, the API should never be called.
          // Do not automatically authenticate the user.
          throw createError({
            status: 401,
            message: 'Invalid state',
          });
        }

        if (!isPasswordValid(password)) {
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

        debug(`New Session: ${event.node.req.session.id}`);

        return { success: true };
      }));

    // WireGuard
    app.use(
      fromNodeMiddleware((req, res, next) => {
        if (!requiresPassword || !req.url.startsWith('/api/')) {
          return next();
        }

        if (req.session && req.session.authenticated) {
          debug(`Authenticated session: ${req.session.id}`);
          return next();
        }

        debug(`Unauthenticated request to ${req.url} (Session: ${req.session ? req.session.id : 'none'})`);

        if (req.url.startsWith('/api/') && req.headers['authorization']) {
          if (isLoginRateLimited(getClientIp(req))) {
            res.statusCode = 429;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: 'Too many attempts, try again later' }));
            return;
          }

          if (isPasswordValid(req.headers['authorization'])) {
            debug('Authenticated via authorization header');
            return next();
          }
          debug('Invalid authorization header');
          res.statusCode = 401;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ error: 'Incorrect Password' }));
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
      .delete('/api/session', defineEventHandler((event) => {
        const sessionId = event.node.req.session.id;

        event.node.req.session.destroy();

        debug(`Deleted Session: ${sessionId}`);
        return { success: true };
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
        setHeader(event, 'Content-Type', 'text/json');
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

    if (PASSWORD) {
      throw new Error('DO NOT USE PASSWORD ENVIRONMENT VARIABLE. USE PASSWORD_HASH INSTEAD.\nSee https://github.com/wg-easy/wg-easy/blob/v14/How_to_generate_an_bcrypt_hash.md');
    }

    createServer(toNodeListener(app)).listen(PORT, WEBUI_HOST);
    debug(`Listening on http://${WEBUI_HOST}:${PORT}`);
  }

};
