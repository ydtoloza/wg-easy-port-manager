/* eslint-env jest */

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Backup = require('./Backup');

describe('Backup scheduled state backups', () => {
  let wgPath;

  beforeEach(() => {
    wgPath = fs.mkdtempSync(path.join(os.tmpdir(), 'wgpm-backup-'));
    fs.writeFileSync(path.join(wgPath, 'wg0.json'), '{"clients":{}}');
    fs.writeFileSync(path.join(wgPath, 'server-settings.json'), '{"port":51820}');
  });

  afterEach(() => {
    fs.rmSync(wgPath, { recursive: true, force: true });
  });

  it('copies present state files and skips missing optional sidecars', async () => {
    const backup = new Backup({ wgPath, now: () => Date.UTC(2026, 0, 1) });
    const target = await backup.runOnce();
    expect(target).toBeTruthy();
    expect(fs.readFileSync(path.join(target, 'wg0.json'), 'utf8')).toBe('{"clients":{}}');
    expect(fs.readFileSync(path.join(target, 'server-settings.json'), 'utf8')).toBe('{"port":51820}');
    // webhook.json does not exist here: skipped instead of failing the pass.
    expect(fs.readdirSync(target).sort()).toEqual(['server-settings.json', 'wg0.json']);
  });

  it('writes nothing on a fresh install and leaves no empty directory', async () => {
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'wgpm-empty-'));
    try {
      const backup = new Backup({ wgPath: empty });
      expect(await backup.runOnce()).toBeNull();
      expect(fs.existsSync(path.join(empty, 'backups'))).toBe(false);
    } finally {
      fs.rmSync(empty, { recursive: true, force: true });
    }
  });

  it('does nothing when disabled', async () => {
    const backup = new Backup({ wgPath, enabled: false });
    expect(await backup.runOnce()).toBeNull();
    expect(fs.existsSync(backup.backupDir)).toBe(false);
  });

  it('keeps only the newest retention directories', async () => {
    const backup = new Backup({ wgPath, retention: 3, now: () => Date.UTC(2026, 0, 1) });
    for (let i = 0; i < 5; i += 1) {
      // Distinct mtimes: the prune keeps the three NEWEST by modification time.
      const when = new Date(Date.UTC(2025, 0, 1 + i));
      const dir = path.join(backup.backupDir, `backup-2025-0${i}`);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'wg0.json'), `v${i}`);
      fs.utimesSync(dir, when, when);
    }
    await backup.prune();
    const kept = fs.readdirSync(backup.backupDir).sort();
    expect(kept).toHaveLength(3);
    // The two oldest directories (2025-00, 2025-01) are pruned first.
    expect(kept.every((name) => name >= 'backup-2025-02')).toBe(true);
  });

  it('survives a source path that is not a directory and removes the partial directory', async () => {
    fs.unlinkSync(path.join(wgPath, 'wg0.json'));
    // Simulate a copy failure: point wgPath at a file, not a dir.
    const notADir = path.join(wgPath, 'server-settings.json');
    const backup = new Backup({ wgPath: notADir });
    expect(await backup.runOnce()).toBeNull();
    expect(fs.existsSync(backup.backupDir)).toBe(false);
  });

  it('falls back to defaults on invalid interval/retention values', () => {
    expect(new Backup({ intervalHours: 0, retention: 0 }).intervalMs).toBe(24 * 3600000);
    expect(new Backup({ intervalHours: 0, retention: 0 }).retention).toBe(7);
    expect(new Backup({ intervalHours: '12' }).intervalMs).toBe(12 * 3600000);
    expect(new Backup({}).intervalMs).toBe(24 * 3600000);
    expect(new Backup({}).retention).toBe(7);
  });
});
