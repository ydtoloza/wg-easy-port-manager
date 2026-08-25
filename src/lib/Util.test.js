/* eslint-env jest */

'use strict';

const Util = require('./Util');

describe('Util control-character validation', () => {
  it('detects every C0 control and DEL', () => {
    // NUL, TAB, LF, CR, other C0 (VT, ESC) and DEL.
    for (const bad of ['\x00', '\t', '\n', '\r', '\x0b', '\x1b', '\x7f', 'a\x00b', '10.0.0.0/8\t']) {
      expect(Util.hasControlChars(bad)).toBe(true);
    }
    // Every C0 code point, exhaustively.
    for (let code = 0x00; code <= 0x1f; code += 1) {
      expect(Util.hasControlChars(String.fromCharCode(code))).toBe(true);
    }
  });

  it('accepts ordinary and Unicode values', () => {
    for (const good of ['', 'vpn.example.test', '0.0.0.0/0, ::/0', '1.1.1.1', 'café-☎-peer', 'Münchën']) {
      expect(Util.hasControlChars(good)).toBe(false);
    }
  });

  it('only inspects strings', () => {
    expect(Util.hasControlChars(undefined)).toBe(false);
    expect(Util.hasControlChars(null)).toBe(false);
    expect(Util.hasControlChars(42)).toBe(false);
  });

  it('keeps isValidName rejecting controls while allowing Unicode names', () => {
    expect(Util.isValidName('café peer ☎')).toBe(true);
    expect(Util.isValidName('a'.repeat(128))).toBe(true);
    expect(Util.isValidName('peer\x00')).toBe(false);
    expect(Util.isValidName('peer\tname')).toBe(false);
    expect(Util.isValidName('peer\nname')).toBe(false);
    expect(Util.isValidName('peer\rname')).toBe(false);
    expect(Util.isValidName('peer\x7f')).toBe(false);
  });
});
