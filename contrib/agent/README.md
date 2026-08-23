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
| `WGPM_SERVER_URL` | Server base URL, no trailing slash (e.g. `https://vps.example.com`) | required |
| `WGPM_TOKEN` | Peer token `wgpt_...` | required |
| `WGPM_CLIENT` | `qbittorrent` \| `transmission` \| `deluge` | required |
| `WGPM_STATE_FILE` | State file `{seq, extPort}` | `~/.wgpm-agent.json` |
| `WGPM_WEBHOOK_TOLERANCE` | Signature timestamp tolerance, seconds | `120` (CGNAT clock skew is real) |
| `WGPM_POLL_SECONDS` | Reconcile poll interval; `0` disables | `300` |
| `WGPM_LISTEN` | Listener bind, `host:port` | `127.0.0.1:8080` |
| `WGPM_WEBHOOK_SECRET` | Shared webhook secret (recommended) | none |

Client-specific:

| Client | Variables |
|---|---|
| qBittorrent | `QBIT_URL` (e.g. `http://127.0.0.1:8081`), `QBIT_USER`, `QBIT_PASS` |
| Transmission | `TR_HOST` (e.g. `127.0.0.1:9091`), `TR_USER`, `TR_PASS` |
| Deluge | `DELUGE_HOST` (e.g. `127.0.0.1:8112`), `DELUGE_PASS` |

Quick check:

```sh
WGPM_SERVER_URL=https://vps.example.com \
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
sudo install -d -m 700 /opt/wgpm-agent
sudo install -m 755 agent.py /opt/wgpm-agent/agent.py

sudo tee /etc/wgpm-agent.env >/dev/null <<'EOF'
WGPM_SERVER_URL=https://vps.example.com
WGPM_TOKEN=wgpt_paste_your_token_here
WGPM_CLIENT=qbittorrent
QBIT_URL=http://127.0.0.1:8081
QBIT_USER=admin
QBIT_PASS=secret
WGPM_WEBHOOK_SECRET=shared-with-the-server
WGPM_STATE_FILE=/var/lib/wgpm-agent/state.json
EOF
sudo chown root:root /etc/wgpm-agent.env && sudo chmod 600 /etc/wgpm-agent.env

sudo systemctl daemon-reload
sudo systemctl enable --now wgpm-agent
journalctl -u wgpm-agent -f
```

The unit hardens the service (`ProtectSystem=strict`, `ProtectHome=true`,
`PrivateTmp`) and writes state under `/var/lib/wgpm-agent` (0600), so set
`WGPM_STATE_FILE` accordingly as shown above.

## One-shot mode (cron users)

`--once` reconciles once (polls `/api/peer/me`, applies the lowest own
forward's external port if it differs), probes reachability and exits:

| Exit code | Meaning |
|---|---|
| 0 | probe verdict `ok` (or `dnat-local`) |
| 1 | `unreachable` |
| 2 | `tunnel-down` |
| 3 | `rule-missing` |
| 4 | probe unavailable (no forward matched / request failed) |
| 5 | torrent-client adapter failed (login, set, or read-back) |

```sh
*/5 * * * * WGPM_SERVER_URL=... WGPM_TOKEN=... ... python3 /opt/wgpm-agent/agent.py --once
```

## How it behaves

- **Idempotent**: events carry a strictly increasing `seq` plus an
  `eventId`; replays and stale sequences are dropped (seen-set capped at
  256 entries). State persists `{seq, extPort}` atomically
  (write-temp + `rename`), so a crash never corrupts it.
- **Change-only**: if the announced port already equals the configured
  listen port, no client call and no reannounce happen — trackers penalize
  gratuitous reannounces. The port is always verified by reading it back
  from the client (one retry, then a hard error).
- **Reconcile safety net**: every `WGPM_POLL_SECONDS`, and immediately on a
  detected seq gap, the agent polls its profile and converges to the lowest
  external port among its own forwards. Deletions currently emit no webhook
  event on the server (this may change); the poll is what keeps the agent
  correct — do not set `WGPM_POLL_SECONDS=0` because of that.
- **Probes**: after a change the agent calls its own probe endpoint and
  logs the verdict. It addresses rules by their stable id when present and
  falls back to the numeric index only for legacy servers.

## Security

- The token is read from the environment, sent as an `Authorization: Bearer`
  header, and **never** written to logs, argv, child processes or URLs.
- The listener binds `127.0.0.1` by default (`WGPM_LISTEN` to override).
  Unsigned webhook bodies are rejected outright when bound non-loopback.
- No shell-outs: all HTTP is Python's stdlib `http.client`.
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
torrents exactly once per real port change; until a tracker-side announce
interval or the agent's reannounce completes, incoming connections may
still target the old port.

## Tests

```sh
cd contrib/agent && python3 -m unittest -v test_agent.py
```

Pure `unittest`, no network — adapters and the wg-easy API are exercised
through scripted fake connections.
