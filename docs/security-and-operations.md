# Security and Operations

This panel runs with permission to change the host network. Treat it as an administrative service, not as a public website.

## Required configuration

The process validates security settings before starting WireGuard. Startup fails without:

- `WG_HOST`: public IP address or DNS name used by clients.
- `PASSWORD_HASH`: bcrypt `$2a$`, `$2b$` or `$2y$` hash with cost 10 to 15.
- `SESSION_SECRET`: persistent random value containing at least 32 bytes.

Generate values with:

```sh
docker run --rm ghcr.io/ydtoloza/wg-easy-port-manager wgpw 'YOUR_PASSWORD'
openssl rand -hex 32
```

Put the bcrypt hash in single quotes in `.env`. This prevents Compose from interpreting `$` sequences:

```dotenv
PASSWORD_HASH='$2b$12$...'
SESSION_SECRET=...
```

Passwordless operation is disabled by default. It is accepted only when `ALLOW_INSECURE_NO_AUTH=true` and `WEBUI_HOST` is `127.0.0.1`, `::1` or `localhost`.

## TLS and reverse proxies

Terminate TLS at a trusted reverse proxy and do not expose port 51821 directly to untrusted networks. Set both:

```dotenv
TRUSTED_PROXY_IP=127.0.0.1
SESSION_COOKIE_SECURE=true
```

The proxy must overwrite `X-Forwarded-For`, send `X-Forwarded-Proto: https`, and restrict direct access to the backend. Headers from other source addresses are ignored for rate limiting.

Sessions expire after 12 hours. Changing `SESSION_SECRET` invalidates every active session.

## Persistent state and recovery

`/etc/wireguard/wg0.json` is the canonical state and contains every private key. It is written with mode `0600`. Before replacing it, the application stores the previous version as `/etc/wireguard/wg0.json.bak`.

The process does not regenerate keys when `wg0.json` is unreadable or invalid. It stops without overwriting the file. To recover:

1. Stop the service.
2. Preserve the invalid `wg0.json` for diagnosis.
3. Validate `wg0.json.bak` or an external backup as JSON.
4. Restore it as `wg0.json` with mode `0600`.
5. Start the service and verify WireGuard and both nftables tables.

Backups downloaded from the API contain private keys. Store them encrypted and never attach them to issues or logs.

## Network transactions

All state-changing API operations run through a single in-process mutation queue. Each DNAT update is submitted to `nft -f -` as one atomic ruleset. If persistence or WireGuard synchronization fails, the application restores memory, disk and host rules and reports rollback failures.

Changing server settings briefly restarts `wg0` so the listening port and firewall hooks match the persisted settings. Existing forwarding rules must remain inside the configured port policy or the update is rejected.

Server-setting changes use `/etc/wireguard/server-settings.transaction.json` as a recovery journal. Do not delete it manually: startup uses it to complete or roll back an interrupted update before accepting requests.

Only one instance may manage `wg0` and the `wgeasy_dnat` tables on a host. Do not share those resources with another manager.

## Deployment hardening

- Load the WireGuard kernel module on the host; the container does not receive `SYS_MODULE`.
- Keep `cap_drop: ALL`, `NET_ADMIN`, `NET_RAW` and `no-new-privileges` from the provided Compose file.
- Pin an immutable image version for production instead of `latest`.
- Restrict access with a host firewall and a TLS reverse proxy.
- Monitor container restarts, failed logins, `wg show wg0` and `nft list table` output.

The healthcheck verifies both `wg0` and the HTTP session endpoint. It does not replace an external end-to-end check through the TLS proxy.

## Validation

Run before deployment:

```sh
cd src
npm ci
npm run lint
npm run check:www-template
npm run test:ci
npm audit --omit=dev
```

Test actual WireGuard and nftables behavior only in a disposable Linux host or network namespace. The integration changes host routing and firewall state.
