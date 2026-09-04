/* eslint-env jest */

'use strict';

const { parseDnatRules, rulePresent } = require('./NftRules');

const dport = (protocol, port, op = 'eq') => ({
  match: {
    left: { payload: { protocol, field: 'dport' } },
    op,
    right: port,
  },
});

const dnat = (addr, port) => ({ dnat: { family: 'ip', addr, port } });

const table = (rules) => ({
  nftables: rules.map((expr) => ({ rule: { family: 'ip', chain: 'prerouting', expr } })),
});

describe('NftRules', () => {
  it('parses tcp dnat rules from nft -j output', () => {
    const json = table([[dport('tcp', 2000), dnat('10.8.0.2', 2000)]]);
    expect(parseDnatRules(json)).toEqual([
      {
        protocol: 'tcp', dport: 2000, addr: '10.8.0.2', port: 2000,
      },
    ]);
  });

  it('parses from raw JSON strings and tolerates garbage', () => {
    const json = table([[dport('udp', 53), dnat('10.8.0.3', 53)]]);
    expect(parseDnatRules(JSON.stringify(json))).toHaveLength(1);
    expect(parseDnatRules('not json')).toEqual([]);
    expect(parseDnatRules({ nftables: null })).toEqual([]);
    expect(parseDnatRules(null)).toEqual([]);
  });

  it("parses the real nft -j shape (op '==')", () => {
    // Ground truth from production (nft 1.1.5): match uses '=='.
    const json = table([
      [dport('tcp', 6884, '=='), dnat('10.8.0.5', 6884)],
      [dport('udp', 6884, '=='), dnat('10.8.0.5', 6884)],
    ]);
    expect(parseDnatRules(json)).toEqual([
      {
        protocol: 'tcp', dport: 6884, addr: '10.8.0.5', port: 6884,
      },
      {
        protocol: 'udp', dport: 6884, addr: '10.8.0.5', port: 6884,
      },
    ]);
    expect(rulePresent(parseDnatRules(json), {
      proto: 'both', extPort: 6884, intPort: 6884, peerIP: '10.8.0.5',
    })).toBe(true);
  });

  it('ignores rules without both a dport match and a dnat target', () => {
    const json = table([
      [dport('tcp', 2000)],
      [dnat('10.8.0.2', 2000)],
      [{ counter: { bytes: 5 } }],
    ]);
    expect(parseDnatRules(json)).toEqual([]);
  });

  it('matches per protocol, including both', () => {
    const rules = parseDnatRules(table([
      [dport('tcp', 2000), dnat('10.8.0.2', 2000)],
      [dport('udp', 2000), dnat('10.8.0.2', 2000)],
    ]));
    const target = {
      proto: 'tcp', extPort: 2000, intPort: 2000, peerIP: '10.8.0.2',
    };
    expect(rulePresent(rules, target)).toBe(true);
    expect(rulePresent(rules, { ...target, proto: 'udp' })).toBe(true);
    expect(rulePresent(rules, { ...target, proto: 'both' })).toBe(true);
    expect(rulePresent(rules, { ...target, intPort: 80 })).toBe(false);
    expect(rulePresent(rules, { ...target, peerIP: '10.8.0.3' })).toBe(false);
    expect(rulePresent(rules, { ...target, extPort: 3000 })).toBe(false);
  });
});
