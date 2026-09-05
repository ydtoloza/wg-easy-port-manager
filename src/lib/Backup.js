'use strict';

// Scheduled filesystem backups of the WireGuard state files.
//
// Pure fs, no new dependencies: every interval hours (plus once shortly
// after boot) the state files are copied into `WG_PATH/backups/<timestamp>/`
// and only the newest RETENTION backup directories are kept. wg0.json holds
// the canonical state (peers, rules, tokens); server-settings.json and
// webhook.json are the optional sidecars. Failures are logged and swallowed:
// a backup problem must never take the VPN panel down, and reads never touch
// the mutation queue (atomic renames in __writeAtomic guarantee the copy
// sees either the old or the new file, never a partial one).

const fs = require('node:fs/promises');
const path = require('node:path');
const debug = require('debug')('Backup');

const {
  WG_PATH,
  WG_BACKUP_ENABLED,
  WG_BACKUP_INTERVAL_HOURS,
  WG_BACKUP_RETENTION,
} = require('../config');

const BACKUP_FILES = ['wg0.json', 'server-settings.json', 'webhook.json'];
const DIR_PREFIX = 'backup-';
const BOOT_DELAY_MS = 30000;

module.exports = class Backup {

  constructor({
    wgPath = WG_PATH,
    enabled = WG_BACKUP_ENABLED,
    intervalHours = WG_BACKUP_INTERVAL_HOURS,
    retention = WG_BACKUP_RETENTION,
    now = Date.now,
  } = {}) {
    this.wgPath = wgPath;
    this.enabled = enabled !== false;
    // Clamp to sane bounds: at most every hour, at least 1 kept.
    this.intervalMs = Math.max(1, Number(intervalHours) || 24) * 3600000;
    this.retention = Math.max(1, Number(retention) || 7);
    this.now = now;
    this.timer = null;
  }

  get backupDir() {
    return path.join(this.wgPath, 'backups');
  }

  // One backup pass. Returns the written directory, or null when backups are
  // disabled, there is nothing to back up yet (fresh install), or the pass
  // failed (the partial directory is removed best-effort).
  async runOnce() {
    if (!this.wgPath || this.enabled === false) return null;
    const stamp = new Date(this.now()).toISOString().replace(/[:.]/g, '-');
    const target = path.join(this.backupDir, `${DIR_PREFIX}${stamp}`);
    const copied = [];
    try {
      await fs.mkdir(target, { recursive: true });
      for (const name of BACKUP_FILES) {
        try {
          await fs.copyFile(path.join(this.wgPath, name), path.join(target, name));
          copied.push(name);
        } catch (err) {
          // Optional sidecars may not exist yet on a fresh install.
          if (err.code !== 'ENOENT') throw err;
        }
      }
      if (!copied.length) {
        await fs.rm(target, { recursive: true, force: true });
        // Do not leave an empty backups/ parent behind on fresh installs.
        await fs.rmdir(this.backupDir).catch(() => {});
        debug('No state files to back up yet.');
        return null;
      }
      debug(`Backup written: ${target} (${copied.join(', ')})`);
      await this.prune();
      return target;
    } catch (err) {
      await fs.rm(target, { recursive: true, force: true }).catch(() => {});
      debug(`Backup failed: ${err.message}`);
      return null;
    }
  }

  // Keep only the newest `retention` backup directories.
  async prune() {
    let entries = [];
    try {
      entries = await fs.readdir(this.backupDir);
    } catch {
      return; // no backup dir yet
    }
    const dirs = [];
    for (const name of entries) {
      if (!name.startsWith(DIR_PREFIX)) continue;
      const full = path.join(this.backupDir, name);
      try {
        const stat = await fs.stat(full);
        if (stat.isDirectory()) dirs.push({ full, mtime: stat.mtimeMs });
      } catch {
        // Raced with a concurrent prune; ignore.
      }
    }
    dirs.sort((a, b) => b.mtime - a.mtime);
    for (const stale of dirs.slice(this.retention)) {
      await fs.rm(stale.full, { recursive: true, force: true }).catch(() => {});
      debug(`Pruned old backup: ${stale.full}`);
    }
  }

  start() {
    if (!this.enabled || this.timer) return;
    // First pass shortly after boot (once the interface state has settled),
    // then a pass every interval. Both timers are unref'd so they never keep
    // the process alive on shutdown.
    this.timer = setTimeout(() => {
      this.runOnce().catch(() => {});
      const interval = setInterval(() => {
        this.runOnce().catch(() => {});
      }, this.intervalMs);
      if (typeof interval.unref === 'function') interval.unref();
      this.timer = interval;
    }, BOOT_DELAY_MS);
    if (typeof this.timer.unref === 'function') this.timer.unref();
  }

  stop() {
    // The handle may be the boot timeout or the interval; both are Node
    // Timeout objects, so clearTimeout releases either.
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

};

module.exports.BACKUP_FILES = BACKUP_FILES;
module.exports.DIR_PREFIX = DIR_PREFIX;
