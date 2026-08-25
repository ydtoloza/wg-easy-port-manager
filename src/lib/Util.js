'use strict';

const childProcess = require('child_process');

const RULE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

module.exports = class Util {

  static isValidIPv4(str) {
    // Use strict digit-only check per octet to prevent injection via parseInt quirks.
    // e.g. parseInt('2; touch /tmp/pwn', 10) === 2, which would bypass the old validator.
    if (typeof str !== 'string') return false;
    const blocks = str.split('.');
    if (blocks.length !== 4) return false;

    return blocks.every((block) => {
      if (!/^\d+$/.test(block)) return false;
      const value = Number(block);
      return value >= 0 && value <= 255;
    });
  }

  static isValidIPv6(str) {
    if (typeof str !== 'string' || str.includes('%')) return false;
    const regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
    return regex.test(str);
  }

  static isValidIP(str) {
    return this.isValidIPv4(str) || this.isValidIPv6(str);
  }

  static isValidName(str) {
    if (typeof str !== 'string' || str.length === 0 || str.length > 128) {
      return false;
    }
    // Reject control characters (e.g. newlines) that could break config files.
    return !this.hasControlChars(str);
  }

  // C0 controls and DEL must never reach generated WireGuard configuration:
  // they can terminate or alter wg directives. Hook variables (WG_PRE_UP,
  // WG_POST_UP, WG_PRE_DOWN, WG_POST_DOWN) are exempt at their call sites —
  // they intentionally contain shell commands.
  static hasControlChars(str) {
    if (typeof str !== 'string') return false;
    // eslint-disable-next-line no-control-regex
    return /[\x00-\x1f\x7f]/.test(str);
  }

  // Type-strict port parsing. `Number()` alone accepts `true` → 1,
  // `'0x10'` → 16 and `'5e2'` → 500 — none of those are ports.
  static parsePort(value) {
    if (typeof value === 'number') return value;
    if (typeof value === 'string' && value !== '' && /^\d+$/.test(value)) return Number(value);
    return NaN;
  }

  static isValidPort(value) {
    const port = this.parsePort(value);
    return Number.isInteger(port) && port >= 1 && port <= 65535;
  }

  static isValidRuleId(value) {
    return typeof value === 'string' && RULE_ID_RE.test(value);
  }

  static async exec(cmd, {
    log = true,
  } = {}) {
    if (typeof log === 'string') {
      // eslint-disable-next-line no-console
      console.log(`$ ${log}`);
    } else if (log === true) {
      // eslint-disable-next-line no-console
      console.log(`$ ${cmd}`);
    }

    if (process.platform !== 'linux') {
      return '';
    }

    return new Promise((resolve, reject) => {
      childProcess.exec(cmd, {
        shell: 'bash',
        timeout: 10000,
      }, (err, stdout) => {
        if (err) return reject(err);
        return resolve(String(stdout).trim());
      });
    });
  }

  static async execFile(command, args, {
    input = '',
    log = true,
    timeout = 10000,
  } = {}) {
    if (typeof log === 'string') {
      // eslint-disable-next-line no-console
      console.log(`$ ${log}`);
    } else if (log === true) {
      // eslint-disable-next-line no-console
      console.log(`$ ${command} ${args.join(' ')}`);
    }

    if (process.platform !== 'linux') {
      return '';
    }

    return new Promise((resolve, reject) => {
      const child = childProcess.spawn(command, args, {
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      const stdout = [];
      const stderr = [];
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        reject(new Error(`${command} timed out after ${timeout}ms`));
      }, timeout);

      child.stdout.on('data', (chunk) => stdout.push(chunk));
      child.stderr.on('data', (chunk) => stderr.push(chunk));
      child.once('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
      child.once('close', (code) => {
        clearTimeout(timer);
        if (code !== 0) {
          reject(new Error(Buffer.concat(stderr).toString('utf8').trim() || `${command} exited with code ${code}`));
          return;
        }
        resolve(Buffer.concat(stdout).toString('utf8').trim());
      });
      child.stdin.end(input);
    });
  }

};
