# wgpm-agent — client-side port receiver

A dependency-free Python 3.9+ daemon that runs on the box behind CGNAT (the
one running your torrent client) and keeps the client's **listen port** in
sync with the port forwards managed by
[wg-easy-port-manager](../../README.md): webhook → set listen port →
reannounce.

It closes the loop the server cannot: the server assigns the external port,
but only the client box can tell qBittorrent/Transmission/Deluge to listen
on the matching internal port and reannounce its torrents.

---

## Admin flow (server side, once)

1. Create a WireGuard peer for the client box in the wg-easy UI.
2. Enable **self port management** for that peer (Client → self-manage ports).
3. Issue a peer token (Client → issue token). The `wgpt_...` token is shown
   exactly once — copy it, never commit it anywhere.
4. Optionally configure a webhook (`PUT /api/wireguard/webhook-config`) with
   a secret. The agent verifies the `X-WGPM-Signature` header
   (`t=<unix>,v1=hex`, HMAC-SHA256 over `<t>.<raw body>`); if the server has
   **no** webhook secret configured, the agent accepts unsigned bodies
   **only while its listener is bound to loopback** — binding it anywhere
   else without a secret is rejected.

## Setup (client side)

Copy `agent.py` to e.g. `/opt/wgpm-agent/agent.py`. All configuration is
env-only:

| Variable | Meaning | Default |
|---|---|---|
| `WGPM_URL` | HTTPS server URL; a base path is supported (e.g. `https://vps.example.com/wgpm`) | required |
| `WGPM_TOKEN` | Peer token `wgpt_...` | required |
| `WGPM_PEER_ID` | Exact WireGuard peer id associated with the token; filters the shared webhook stream | required |
| `WGPM_CLIENT` | `qbittorrent` \| `transmission` \| `deluge` | required |
| `WGPM_STATE_FILE` | State file `{seq, extPort, intPort, ruleId}` | `~/.wgpm-agent.json` |
| `WGPM_WEBHOOK_TOLERANCE` | Signature timestamp tolerance, seconds | `120` (CGNAT clock skew is real) |
| `WGPM_POLL_SECONDS` | Reconcile poll interval; `0` disables | `300` |
| `WGPM_LISTEN` | Listener bind, `host:port` | `127.0.0.1:8080` |
| `WGPM_WEBHOOK_SECRET` | Shared webhook secret (recommended) | none |

Client-specific:

| Client | Variables |
|---|---|
| qBittorrent | `QBIT_URL` (e.g. `http://127.0.0.1:8081`), `QBIT_USER`, `QBIT_PASS` |
| Transmission | `TR_HOST` (e.g. `http://127.0.0.1:9091`), `TR_USER`, `TR_PASS` |
| Deluge | `DELUGE_HOST` (e.g. `http://127.0.0.1:8112`), `DELUGE_PASS` |

All client endpoint variables require an explicit `http://` or `https://`
scheme and preserve any configured base path. Use HTTPS for non-loopback
client endpoints.

Quick check:

```sh
WGPM_URL=https://vps.example.com WGPM_PEER_ID=client1 \
WGPM_TOKEN=wgpt_... WGPM_CLIENT=qbittorrent \
QBIT_URL=http://127.0.0.1:8081 QBIT_USER=admin QBIT_PASS=... \
python3 /opt/wgpm-agent/agent.py --check
```

Point the server's webhook at the agent's listener
(`http://<client-box>:8080/` by default — keep it loopback plus an SSH
tunnel or a reverse proxy unless you know why not).

## systemd install

```sh
sudo install -m 644 wgpm-agent.service /etc/systemd/system/wgpm-agent.service
sudo useradd --system --home-dir /var/lib/wgpm-agent --shell /usr/sbin/nologin wgpm-agent
sudo install -d -m 0750 -o root -g wgpm-agent /opt/wgpm-agent
sudo install -m 755 agent.py /opt/wgpm-agent/agent.py

sudo install -m 600 -o root -g root wgpm-agent.env.example /etc/wgpm-agent.env
sudoedit /etc/wgpm-agent.env
sudo chown root:root /etc/wgpm-agent.env && sudo chmod 600 /etc/wgpm-agent.env

sudo systemctl daemon-reload
sudo systemctl enable --now wgpm-agent
journalctl -u wgpm-agent -f
```

The unit runs as the dedicated, unprivileged `wgpm-agent` user, creates its
state directory as mode `0700`, writes state as `0600`, drops all capabilities,
and applies filesystem, kernel, namespace, device, syscall and address-family
restrictions. `systemd` assigns `/var/lib/wgpm-agent` to that service identity;
keep `WGPM_STATE_FILE` inside it as shown above.

## One-shot mode (cron users)

`--once` reconciles once (polls `/api/peer/me`, selects the lowest own external
rule, and applies that rule's internal port if client read-back differs),
probes reachability and exits:

| Exit code | Meaning |
|---|---|
| 0 | probe verdict `ok` (or `dnat-local`) |
| 1 | `unreachable` |
| 2 | `tunnel-down` |
| 3 | `rule-missing` |
| 4 | probe unavailable (no forward matched / request failed) |
| 5 | torrent-client adapter failed (login, set, or read-back) |

```sh
*/5 * * * * WGPM_URL=https://... WGPM_PEER_ID=... WGPM_TOKEN=... ... python3 /opt/wgpm-agent/agent.py --once
```

## How it behaves

- **Peer-scoped and idempotent**: the server has one global webhook sink, so
  the agent compares every event's `peerId` with `WGPM_PEER_ID`; profile polls
  also confirm that the token resolves to that peer. Matching events carry a
  per-peer `seq` plus `eventId`; replays and stale sequences are dropped and
  the in-memory seen set is capped at 256 entries.
- **At-least-once and retry-safe**: sequence and dedupe state commit only
  after client read-back, a best-effort probe attempt, successful all-torrent
  reannounce and atomic persistence. A failed webhook returns HTTP 500 for
  at-least-once redelivery.
  Client set and reannounce operations are safe to repeat, and can run more
  than once when a failure occurs after the client accepted an operation but
  before state commits.
- **Correct port semantics**: `extPort` identifies the public rule and probe;
  the torrent client's listen port is always the corresponding `intPort`.
  State persists both values plus `ruleId` atomically (file fsync, rename,
  parent-directory fsync).
- **Change-only**: the client's actual listen port is read on every reconcile.
  Drift is repaired and reannounced; an already-correct client is not changed
  or gratuitously reannounced.
- **Reconcile safety net**: every matching webhook and every
  `WGPM_POLL_SECONDS`, the agent polls its profile and converges to the internal
  port associated with the lowest external forward. Events for non-selected
  rules only advance sequence state. Polls never invent or
  advance server sequence numbers. Transient HTTP/socket failures are logged
  and retried on the next interval. Keep polling enabled as a safety net for
  missed events and client-side drift.
- **Probes**: after a change the agent calls its own probe endpoint and
  logs the verdict. It addresses rules by their stable id when present and
  falls back to the numeric index only for legacy servers.

## Security

- The token is read from the environment, sent as an `Authorization: Bearer`
  header, and **never** written to logs, argv, child processes or URLs.
- `WGPM_URL` must use HTTPS. URLs containing credentials, query strings,
  fragments, missing schemes, or unsupported schemes are rejected.
- The listener binds `127.0.0.1` by default (`WGPM_LISTEN` to override).
  Unsigned webhook bodies are rejected outright when bound non-loopback.
- No shell-outs: all HTTP is Python's stdlib `http.client`.
- HTTP responses and webhook bodies are capped at 1 MiB.
- The state file is created with mode `0600`.

## Troubleshooting (probe verdicts)

| Verdict | Meaning | Typical cause / fix |
|---|---|---|
| `ok` | DNAT rule present, tunnel up, TCP connect succeeded | — |
| `unreachable` | Rule + tunnel fine, TCP failed | torrent client not listening on the internal port; firewall on the client box; agent not applied yet |
| `tunnel-down` | WireGuard handshake outside the keepalive window | client offline / NAT rebinding; check the tunnel, not the port |
| `rule-missing` | No DNAT rule for the port | forwarding kill-switch on, rule deleted, or server table not applied |
| `dnat-local` | Connect succeeded without traversing DNAT | probe ran from a host taking the hairpin path — verify from outside |

## Notes on ports, passkeys and reannouncing

Your tracker **passkey and announce URLs do not change** when the external
port changes — nothing breaks at announce-URL level. But external peers
cached your old `ip:port` pair, so **every torrent must reannounce before
the tracker (and other peers) see the new port**. The agent reannounces all
torrents at least once per observed port change; delivery retries can safely
repeat a reannounce before durable state commits. Until a tracker-side announce
interval or the agent's reannounce completes, incoming connections may
still target the old port.

## Tests

```sh
cd contrib/agent && python3 -m unittest -v test_agent.py
```

Pure `unittest`, no network — adapters and the wg-easy API are exercised
through scripted fake connections.
