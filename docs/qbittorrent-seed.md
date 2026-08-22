# qBittorrent - Preset para seed en trackers privados via WireGuard

Este documento es el preset recomendado para exprimir velocidad de subida cuando el peer `qBittorrent` se conecta a través de `wg-easy-port-manager` (caso principal de este fork).

## 1. Host tuning (una vez, en el VPS)

El cuello de botella para seeding no es la UI sino `conntrack`, buffers UDP y `TCP BBR`.

```bash
# En el VPS, como root:
WG_DEVICE=$(ip route show default | awk '/default/ {print $5; exit}')
WG_DEVICE=$WG_DEVICE sudo bash scripts/host-tune.sh --apply
sudo bash scripts/host-tune.sh --check

# Verifica BBR activo:
sysctl net.ipv4.tcp_congestion_control   # debe ser bbr
lsmod | grep bbr
cat /proc/sys/net/netfilter/nf_conntrack_max  # 262144
```

Si ves `table full, dropping packet` en `dmesg`, ya estabas saturando conntrack. El script sube de `65536 -> 262144` y aplica `fq`, `rmem/wmem 16M`, `udp_mem`, `netdev_max_backlog 5000`.

### MTU correcto (evita fragmentación WireGuard)

* MTU host 1500 -> `WG_MTU=1420` en `.env` (ahora sí se aplica al `[Interface]` del servidor, ver `src/lib/WireGuard.js:650`).
* Si tu VPS/host va con PPPoE/VLAN (1492) o ves `ping: frag needed`, baja a `1280`:
```bash
ping -M do -s 1380 -c 3 10.8.0.1   # via wg0 desde el peer; si frag -> usa 1280
```
* Tras cambiar `WG_MTU`, recrea contenedor: `docker compose up -d`.

El código ahora también hace `ip link set wg0 txqueuelen 5000` en `__bringWireGuardUp:599` para subida sostenida.

## 2. Peer WireGuard (qBittorrent host) - config generada

La config descargada de la UI ya trae:

```
[Interface]
PrivateKey = ...
Address = 10.8.0.2/24, fd42:42:42::2/128
DNS = 1.1.1.1
MTU = 1420
[Peer]
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
Endpoint = TU_IP:51820
```

* No cambies `AllowedIPs` si quieres que todo el torrent salga por VPN (recomendado para privacidad/privado).
* En Linux seedbox, fija MTU también en el peer `ip link set wg0 mtu 1420`.

## 3. Port Forward (DNAT) - imprescindible para ser conectable

Trackers privados exigen peer conectable (open port). En la UI por peer:

* Protocolo: `Both (TCP+UDP)` - qBittorrent usa TCP para BitTorrent y uTP/UDP mejora.
* `External port == Internal port` (ej `42150 -> 42150`) para simplificar announce.
* Un solo puerto por peer, único en toda la tabla. Si usas `both`, se crean 2 reglas nft: `ip wgeasy_dnat prerouting tcp dport 42150 dnat to 10.8.0.2:42150` y la de `ip6` si hay IPv6 `src/lib/WireGuard.js:1412`.

Verifica:

```bash
docker exec wg-easy-port-manager nft list table ip wgeasy_dnat
docker exec wg-easy-port-manager nft list table ip6 wgeasy_dnat  # si IPv6
docker exec wg-easy-port-manager nft list table inet wgeasy_filter
# Debe aparecer dnat rule y masquerade postrouting oifname "eth0" masquerade (si WG_NFT_MASQUERADE=true)
```

Desde fuera: `nc -vz TU_IP 42150` o checker del tracker.

## 4. qBittorrent - ajustes finos

**Conexión:**

* `Herramientas > Opciones > Conexión > Puerto de escucha = 42150` (igual al forward)
* `Usar UPnP/NAT-PMP = OFF` (ya hay DNAT manual)
* `Conexiones globales máximas = 800-1500` (no 5000, saturas conntrack)
* `Conexiones máximas por torrent = 150-250`
* `Slots máximos de subida = 80-150` (para seed, más slots = más peers satisfechos)
* `Interfaz de red = wg0` (Avanzado > Interfaz de red) - evita fuga si wg cae. En Linux, `Opciones > Avanzado > Interfaz de red = wg0`.
* `Dirección IP opcional para bindear = 10.8.0.2` (la del peer wg).

**BitTorrent:**

* `DHT, PeX, LSD = OFF` (trackers privados lo exigen y ahorra UDP).
* `Cifrado = Preferir cifrado` o `Requerir cifrado` si el tracker lo permite (reduce DPI throttling pero +CPU).
* `uTP = ON` si tu port es both, OFF si solo TCP.
* `Limites`: desactiva límite de subida para seed, o pon 80-90% de tu uplink para dejar ACKs. `Límites > Límite global subida = 0 (ilimitado)` y gestiona via `qos` externo si necesitas.

**Avanzado (qbittorrent.conf):**

```ini
[BitTorrent]
Session\MaxConnections=1200
Session\MaxConnectionsPerTorrent=200
Session\MaxUploads=100
Session\MaxUploadsPerTorrent=20
```

**SO del seedbox (peer, no VPS):**

Si el peer es Linux, también allí:

```bash
sudo sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
```

## 5. Verificación de velocidad

```bash
# En peer via wg
iperf3 -c 10.8.0.1 -P 4 -t 30   # debe dar ~90-95% del uplink del VPS

# En VPS, monitorea
watch -n1 'cat /proc/sys/net/netfilter/nf_conntrack_count; ss -s; nft list ruleset | grep -c dnat'
docker logs --tail 50 wg-easy-port-manager
wg show wg0  # latest handshake < 2m, transfer crece

# qBittorrent debe mostrar en tracker: "Trabajando" y puerto testeable
```

## 6. Troubleshooting seeding lento

| Síntoma | Causa probable | Fix |
|---|---|---|
| `dmesg` `nf_conntrack: table full` | `max 65536` insuficiente | `host-tune.sh --apply` -> 262144 |
| `ping -M do -s 1380` frag | `MTU 1420` > path | `WG_MTU=1280` en `.env` |
| Tracker `No conectable` | DNAT no aplicado / firewall host | `nft list table ip wgeasy_dnat` vacío -> revisa `WG_PORT_FWD_MIN/MAX` `src/config.js:25` |
| Subida picos/dientes sierra | Sin BBR, `default_qdisc pfifo_fast` | `sysctl tcp_congestion_control=bbr`, `default_qdisc=fq` |
| `wg show` handshake viejo >5m | `PersistentKeepalive 0` + NAT peer | Deja `25` |
| Velocidad baja solo con muchos torrents | `MaxConnections` muy alto -> churn conntrack | Baja a `800` globales, `60s udp_timeout` ya en tune |

## 7. Notas de implementación del fork

* `WG_NFT_MASQUERADE=true` (default) mueve `masquerade` a `nft` `ip wgeasy_dnat postrouting` `src/lib/WireGuard.js:1383` atómico y sin duplicar `iptables`. Ponlo `false` si necesitas compatibilidad con reglas `iptables` custom en `WG_POST_UP`.
* `WG_SEED_TUNING=true` aplica `sysctl fq/bbr` e `ip_forward` en `PostUp` `src/lib/WireGuard.js:634` y `txqueuelen 5000` en `__bringWireGuardUp:599`. Desactívalo si gestionas `sysctl` solo vía `host-tune.sh`.
* El `MASQUERADE` preciso es `ip saddr 10.8.0.0/24 oifname "eth0" masquerade`, no genérico, para no NATear tráfico del host.
