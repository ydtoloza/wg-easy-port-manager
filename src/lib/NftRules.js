'use strict';

// Parses `nft -j list table` output into flat DNAT rule descriptors.
// Kept pure so probe verdicts can be unit-tested against real payload
// fixtures without touching nftables.

const isPayloadDport = (expr) => expr && expr.payload && expr.payload.field === 'dport';

const extractFromExpr = (rule) => {
  const dports = [];
  const dnats = [];
  if (!Array.isArray(rule.expr)) return [];

  let pendingDport = null;
  for (const expr of rule.expr) {
    // Real `nft -j` output uses op '==' (fixtures also cover 'eq' and the
    // op-less shape). Anything else (ranges, sets) is not a single dport.
    if (expr.match && isPayloadDport(expr.match.left)
      && (expr.match.op === undefined || expr.match.op === 'eq' || expr.match.op === '==')) {
      pendingDport = {
        protocol: expr.match.left.payload.protocol,
        port: Number(expr.match.right),
      };
      continue;
    }
    if (expr.dnat && typeof expr.dnat === 'object') {
      if (pendingDport) {
        dports.push(pendingDport);
        pendingDport = null;
      }
      dnats.push({
        addr: expr.dnat.addr === null ? null : String(expr.dnat.addr),
        port: expr.dnat.port === null ? null : Number(expr.dnat.port),
      });
    }
  }
  if (!dports.length || !dnats.length) return [];
  return dports.flatMap((dport) => dnats.map((dnat) => ({
    protocol: dport.protocol,
    dport: dport.port,
    addr: dnat.addr,
    port: dnat.port,
  })));
};

module.exports.parseDnatRules = (nftJson) => {
  let parsed;
  try {
    parsed = typeof nftJson === 'string' ? JSON.parse(nftJson) : nftJson;
  } catch {
    return [];
  }
  if (!parsed || !Array.isArray(parsed.nftables)) return [];
  return parsed.nftables
    .filter((entry) => entry && entry.rule)
    .flatMap((entry) => extractFromExpr(entry.rule));
};

// A rule satisfies the probe when its dport matches the external port for the
// relevant protocol (a 'both' forward is emitted as one rule per protocol) and
// its dnat target is the peer's internal endpoint.
module.exports.rulePresent = (rules, {
  proto, extPort, intPort, peerIP,
}) => rules.some((rule) => {
  if (!rule || rule.dport !== extPort || rule.port !== intPort) return false;
  if (rule.addr !== peerIP) return false;
  return rule.protocol === proto || proto === 'both';
});
