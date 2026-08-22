# VPS deployment guide

This guide deploys WG-Easy Port Manager 2.0 with Docker Compose on a Linux VPS. Commands assume a Debian or Ubuntu host and a user with `sudo` access.

## Image selection

Choose one image channel before deployment:

| Tag | Purpose | Production recommendation |
| --- | --- | --- |
| `2.0.0` | Immutable 2.0 release | Recommended |
| `2.0` | Latest compatible 2.0 patch | Suitable after testing |
| `latest` | Latest stable release | Convenient, but less explicit |
| `main` | Latest validated commit on `main` | Staging only |
| `sha-<full commit>` | One exact source commit | Best for reproducible testing or rollback |

The provided Compose file defaults to `2.0.0`. CI only publishes images; it never logs into or changes the VPS.

## Host requirements

- A supported Linux kernel with WireGuard loaded.
- Docker Engine with the Compose v2 plugin.
- `iptables` and `nftables` support in the host kernel.
- UDP port `51820` reachable from VPN clients.
- TCP port `51821` restricted to a private administrative network or a local HTTPS reverse proxy.
- An `amd64` or `arm64` host.

Verify the host:

Add the deployment user to Docker's group, then log out and back in. Docker group membership is equivalent to root access; use a dedicated administrator account.

```sh
sudo usermod -aG docker "$USER"
sudo modprobe wireguard
docker version
docker compose version
docker info >/dev/null
ip route show default
```

Use the default-route interface shown by the last command as `WG_DEVICE`, commonly `eth0`, `ens3` or `enp1s0`.

## Install the deployment files

```sh
sudo install -d -m 0750 /opt/wg-easy-port-manager
sudo chown "$USER":"$USER" /opt/wg-easy-port-manager
cd /opt/wg-easy-port-manager

curl -fsSL https://raw.githubusercontent.com/ydtoloza/wg-easy-port-manager/v2.0.0/docker-compose.yml -o docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/ydtoloza/wg-easy-port-manager/v2.0.0/.env.example -o .env
chmod 0600 .env
```

If GHCR is private, authenticate with a classic personal access token that only has `read:packages`. Authorize the token for organization SSO when applicable:

```sh
printf '%s' "$GHCR_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USER --password-stdin
```

Public packages do not require a login.

## Create secrets and configure the service

Generate a bcrypt password hash and a persistent session secret:

```sh
docker run --rm ghcr.io/ydtoloza/wg-easy-port-manager:2.0.0 wgpw 'USE_A_LONG_UNIQUE_PASSWORD'
openssl rand -hex 32
```

Edit `/opt/wg-easy-port-manager/.env`:

```dotenv
IMAGE_TAG=2.0.0
WG_HOST=vpn.example.com
PASSWORD_HASH='$2b$12$REPLACE_WITH_THE_GENERATED_HASH'
SESSION_SECRET=REPLACE_WITH_OPENSSL_OUTPUT
WG_EASY_LANG=es
WG_DEVICE=eth0
WG_PORT=51820
PORT=51821
WG_PERSISTENT_KEEPALIVE=25
```

Keep the bcrypt hash in single quotes so Compose treats every `$` literally. Never rotate `SESSION_SECRET` during a normal update; changing it invalidates every web session.

Optional dual-stack and client settings can also be placed in `.env`:

```dotenv
WG_DEFAULT_ADDRESS=10.8.0.x
WG_DEFAULT_ADDRESS_V6=fd42:42:42::x
WG_DEFAULT_DNS=1.1.1.1
WG_ALLOWED_IPS=0.0.0.0/0, ::/0
WG_MTU=1420
```

## Firewall and HTTPS

Allow WireGuard publicly, but limit the administration panel. Example with UFW and a known administration address:

```sh
sudo ufw allow 51820/udp
sudo ufw allow from ADMIN_PUBLIC_IP to any port 51821 proto tcp
```

For a reverse proxy on the same VPS, set:

```dotenv
SESSION_COOKIE_SECURE=true
TRUSTED_PROXY_IP=127.0.0.1
```

Proxy HTTPS traffic to `http://127.0.0.1:51821`, overwrite `X-Forwarded-For`, and pass the original host and protocol. A minimal Nginx location is:

```nginx
location / {
    proxy_pass http://127.0.0.1:51821;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

Do not expose port `51821` directly to the internet when a reverse proxy is in use.

## First deployment

Validate interpolation before starting anything:

```sh
cd /opt/wg-easy-port-manager
docker compose config --quiet
docker compose pull
docker compose up -d --remove-orphans
docker compose ps
```

Inspect startup and health:

```sh
docker logs --tail 100 wg-easy-port-manager
docker inspect --format '{{.State.Health.Status}}' wg-easy-port-manager
docker exec wg-easy-port-manager wg show wg0
docker exec wg-easy-port-manager nft list table ip wgeasy_dnat
docker exec wg-easy-port-manager nft list table inet wgeasy_filter
```

The health status should become `healthy`. Confirm that a client can connect before configuring port forwarding or network policy exceptions.

## Back up before an upgrade

The WireGuard volume contains private keys. The procedure below creates a plaintext local snapshot inside a root-only directory. Transfer it immediately to encrypted storage or encrypt it with `age` or GPG before retaining it.

The following procedure briefly stops the VPN to obtain a consistent filesystem snapshot:

```sh
set -eu
cd /opt/wg-easy-port-manager
docker pull alpine:3.22

VOLUME=$(docker inspect wg-easy-port-manager --format '{{range .Mounts}}{{if eq .Destination "/etc/wireguard"}}{{.Name}}{{end}}{{end}}')
test -n "$VOLUME"
docker volume inspect "$VOLUME" >/dev/null

BACKUP_DIR="/var/backups/wg-easy-port-manager/$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -d -o "$USER" -g "$(id -gn)" -m 0700 "$BACKUP_DIR"

docker compose stop
restart_vpn() { docker compose start >/dev/null; }
trap restart_vpn EXIT

docker run --rm \
  --mount "type=volume,src=$VOLUME,dst=/source,readonly" \
  --mount "type=bind,src=$BACKUP_DIR,dst=/backup" \
  alpine:3.22 \
  tar -C /source -czf /backup/wireguard.tgz .

docker run --rm \
  --mount "type=bind,src=$BACKUP_DIR,dst=/backup,readonly" \
  alpine:3.22 \
  tar -tzf /backup/wireguard.tgz >/dev/null

cp .env docker-compose.yml "$BACKUP_DIR/"
sudo chmod 0600 "$BACKUP_DIR/wireguard.tgz" "$BACKUP_DIR/.env"

docker compose start
trap - EXIT
```

Optionally encrypt the complete backup directory with `age` before moving it off-host:

```sh
sudo apt-get install age
sudo tar -C "$(dirname "$BACKUP_DIR")" -czf "${BACKUP_DIR}.tgz" "$(basename "$BACKUP_DIR")"
sudo age -p -o "${BACKUP_DIR}.tgz.age" "${BACKUP_DIR}.tgz"
sudo rm "${BACKUP_DIR}.tgz"
```

Keep the passphrase outside the VPS. After confirming the encrypted copy is recoverable, remove the plaintext directory if the local snapshot is no longer required.

## Upgrade to 2.0

1. Create and verify the backup above.
2. Download the 2.0 Compose file.
3. Set `IMAGE_TAG=2.0.0` in `.env`.
4. Pull and recreate the service.

```sh
set -eu
cd /opt/wg-easy-port-manager
TMP_COMPOSE=$(mktemp './docker-compose.yml.XXXXXX')
cleanup_compose() { rm -f "$TMP_COMPOSE"; }
trap cleanup_compose EXIT

curl -fsSL https://raw.githubusercontent.com/ydtoloza/wg-easy-port-manager/v2.0.0/docker-compose.yml -o "$TMP_COMPOSE"
docker compose --env-file .env -f "$TMP_COMPOSE" config --quiet
mv "$TMP_COMPOSE" docker-compose.yml
trap - EXIT

docker compose pull
docker compose up -d --remove-orphans
docker compose ps
docker logs --tail 100 wg-easy-port-manager
```

Version 2.0 migrates existing clients to isolated network policies. After the service is healthy, open each client in the UI and explicitly select every peer pair that must communicate. Internet access remains available unless blocked by that client's protocol policy.

Repeat the health, WireGuard and `nftables` checks from the first deployment section.

## Deploy one CI commit

Every code commit on `main` publishes a full immutable SHA tag. To test one exact build:

```sh
NEW_TAG=sha-0123456789abcdef0123456789abcdef01234567
if grep -q '^IMAGE_TAG=' .env; then
  sed -i "s/^IMAGE_TAG=.*/IMAGE_TAG=$NEW_TAG/" .env
else
  printf '\nIMAGE_TAG=%s\n' "$NEW_TAG" >> .env
fi
docker compose config | grep 'image:'
docker compose pull
docker compose up -d
```

Replace the example with the full SHA tag shown in the GitHub Actions run. Use `IMAGE_TAG=main` only when intentionally tracking the newest validated commit.

## Roll back

Rolling back from 2.0 to an older application may require restoring the pre-upgrade WireGuard state because old versions do not understand the new `networkPolicy` fields.

Validate and extract the backup into a staging volume before removing the container. Replace `BACKUP_ID` first:

```sh
set -eu
cd /opt/wg-easy-port-manager
BACKUP_DIR=/var/backups/wg-easy-port-manager/BACKUP_ID
ARCHIVE="$BACKUP_DIR/wireguard.tgz"
test -f "$ARCHIVE"
sudo tar -tzf "$ARCHIVE" >/dev/null

docker pull alpine:3.22
VOLUME=$(docker inspect wg-easy-port-manager --format '{{range .Mounts}}{{if eq .Destination "/etc/wireguard"}}{{.Name}}{{end}}{{end}}')
test -n "$VOLUME"
docker volume inspect "$VOLUME" >/dev/null

STAGING_VOLUME="wg-easy-restore-$(date +%s)"
docker volume create "$STAGING_VOLUME" >/dev/null
cleanup_staging() { docker volume rm -f "$STAGING_VOLUME" >/dev/null 2>&1 || true; }
trap cleanup_staging EXIT

docker run --rm \
  --mount "type=volume,src=$STAGING_VOLUME,dst=/staging" \
  --mount "type=bind,src=$BACKUP_DIR,dst=/backup,readonly" \
  alpine:3.22 \
  tar -C /staging -xzf /backup/wireguard.tgz
docker run --rm \
  --mount "type=volume,src=$STAGING_VOLUME,dst=/staging,readonly" \
  alpine:3.22 \
  test -f /staging/wg0.json

docker compose down
docker run --rm \
  --mount "type=volume,src=$VOLUME,dst=/data" \
  --mount "type=volume,src=$STAGING_VOLUME,dst=/staging,readonly" \
  alpine:3.22 \
  sh -c 'find /data -mindepth 1 -maxdepth 1 -exec rm -rf {} + && cp -a /staging/. /data/'

sudo cp "$BACKUP_DIR/.env" .env
sudo cp "$BACKUP_DIR/docker-compose.yml" docker-compose.yml
sudo chown "$USER":"$USER" .env docker-compose.yml
chmod 0600 .env

trap - EXIT
cleanup_staging
docker compose config --quiet
docker compose pull
docker compose up -d
```

Replace `BACKUP_ID` with the actual backup directory. For a rollback between compatible 2.0 builds, changing `IMAGE_TAG` to a previous `sha-…` tag normally does not require restoring the volume, but keep a backup available.

## Routine operations

```sh
# Current image and digest
docker inspect --format '{{.Config.Image}} {{.Image}}' wg-easy-port-manager

# Follow logs
docker logs -f --tail 100 wg-easy-port-manager

# Restart
docker compose restart

# Stop and start
docker compose stop
docker compose start
```

Do not run two instances that manage `wg0` or the `wgeasy_dnat` and `wgeasy_filter` tables on the same host.

## Troubleshooting

- `Cannot find device wg0`: load the WireGuard kernel module and confirm the container has `NET_ADMIN` and `NET_RAW`.
- No internet from clients: verify `WG_DEVICE` matches the host default-route interface and inspect the generated iptables rules.
- Image pull denied: make the GHCR package public or authenticate with a classic PAT that has `read:packages`.
- Container remains unhealthy: inspect `docker logs`, `wg show wg0`, and the session endpoint on `127.0.0.1:51821`.
- Policy changes fail: inspect `nft list ruleset` and confirm no other service manages the `wgeasy_dnat` or `wgeasy_filter` tables.

Additional security and recovery details are in [Security and Operations](security-and-operations.md).
