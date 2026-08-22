#!/usr/bin/env bash
# host-tune.sh - Optimizacion host para seed en trackers privados via WireGuard + qBittorrent
# Aplica sysctls idempotentes para throughput alto, muchas conexiones concurrentes y NAT estable.
# Uso: sudo bash scripts/host-tune.sh [--apply] [--check]
#  --apply  escribe /etc/sysctl.d/99-wg-seed.conf y recarga (default si --check no se pasa)
#  --check  solo muestra diff y valida BBR/conntrack
set -euo pipefail

MODE="apply"
if [[ "${1:-}" == "--check" ]]; then MODE="check"; fi
if [[ "${1:-}" == "--apply" ]]; then MODE="apply"; fi

SYSCTL_FILE="/etc/sysctl.d/99-wg-seed.conf"
WG_DEVICE="${WG_DEVICE:-$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')}"
WG_DEVICE="${WG_DEVICE:-eth0}"

DESIRED=$(cat <<'EOF'
# 99-wg-seed.conf - generado por wg-easy-port-manager/host-tune.sh
# Optimizado para seeding qBittorrent sobre WireGuard (muchos peers, subida sostenida)
# Ajusta con WG_DEVICE=eth0 sudo bash scripts/host-tune.sh --apply
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.src_valid_mark=1
net.ipv4.conf.default.src_valid_mark=1
# BBR + fq para saturar uplink sin bufferbloat
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_fastopen=3
# Buffers para WireGuard UDP + torrent uTP/TCP
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.rmem_default=262144
net.core.wmem_default=262144
net.core.optmem_max=81920
net.ipv4.udp_mem=102400 524288 16777216
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.core.netdev_max_backlog=5000
net.core.somaxconn=65535
# Conntrack para miles de conexiones BitTorrent (evita "table full, dropping packet")
net.netfilter.nf_conntrack_max=262144
net.netfilter.nf_conntrack_tcp_timeout_established=86400
net.netfilter.nf_conntrack_udp_timeout=60
net.netfilter.nf_conntrack_udp_timeout_stream=180
net.netfilter.nf_conntrack_helper=0
# Vecino/ARP para /24 lleno (253 peers posibles)
net.ipv4.neigh.default.gc_thresh1=1024
net.ipv4.neigh.default.gc_thresh2=2048
net.ipv4.neigh.default.gc_thresh3=4096
EOF
)

check_bbr() {
  echo "== BBR check =="
  if lsmod | grep -q bbr 2>/dev/null || grep -q bbr /proc/modules 2>/dev/null; then
    echo "  bbr module loaded: ok"
  else
    echo "  bbr module NOT loaded -> intenta: modprobe tcp_bbr && echo tcp_bbr >> /etc/modules"
  fi
  echo "  tcp_congestion_control=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
  echo "  default_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"
}

check_conntrack() {
  echo "== conntrack check =="
  local cur max
  cur=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo "?")
  max=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo "?")
  echo "  count=$cur / max=$max"
  if conntrack -C >/dev/null 2>&1; then
    echo "  conntrack tools: ok"
  else
    echo "  conntrack tools no instalados (opcional): apt install conntrack"
  fi
}

check_buffers() {
  echo "== buffers / mtu =="
  echo "  rmem_max=$(sysctl -n net.core.rmem_max 2>/dev/null || echo ?)"
  echo "  wmem_max=$(sysctl -n net.core.wmem_max 2>/dev/null || echo ?)"
  if ip link show wg0 >/dev/null 2>&1; then
    echo "  wg0 txqueuelen=$(ip -o link show wg0 2>/dev/null | grep -o 'qlen [0-9]*' || echo unknown)"
    echo "  wg0 mtu=$(ip -o link show wg0 2>/dev/null | grep -o 'mtu [0-9]*' || echo unknown)"
  else
    echo "  wg0 not up (normal antes del primer deploy)"
  fi
  echo "  WG_DEVICE=$WG_DEVICE mtu=$(cat /sys/class/net/$WG_DEVICE/mtu 2>/dev/null || echo ?)"
}

if [[ "$MODE" == "check" ]]; then
  check_bbr
  check_conntrack
  check_buffers
  echo ""
  echo "Diff vs $SYSCTL_FILE:"
  if [[ -f "$SYSCTL_FILE" ]]; then
    diff -u "$SYSCTL_FILE" <(echo "$DESIRED") || true
  else
    echo "(file not exists, would create)"
    echo "$DESIRED"
  fi
  exit 0
fi

# --apply
echo "[host-tune] WG_DEVICE=$WG_DEVICE"
mkdir -p "$(dirname "$SYSCTL_FILE")"
echo "$DESIRED" > "$SYSCTL_FILE"
chmod 0644 "$SYSCTL_FILE"
echo "[host-tune] written $SYSCTL_FILE"

# Intentar cargar BBR sin reiniciar
modprobe tcp_bbr 2>/dev/null || echo "[host-tune] warn: modprobe tcp_bbr failed (kernel sin BBR?)"

if command -v sysctl >/dev/null 2>&1; then
  echo "[host-tune] reloading sysctl..."
  sysctl --system >/dev/null 2>&1 || sysctl -p "$SYSCTL_FILE" 2>/dev/null || true
fi

# Ajustes runtime que sysctl --system no garantiza en algunos kernels/containers
echo 262144 > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true
if ip link show wg0 >/dev/null 2>&1; then
  ip link set dev wg0 txqueuelen 5000 2>/dev/null || ip link set wg0 txqueuelen 5000 2>/dev/null || true
  echo "[host-tune] wg0 txqueuelen -> 5000"
fi

echo ""
check_bbr
check_conntrack
check_buffers
echo ""
echo "[host-tune] done. Verifica con: sudo bash scripts/host-tune.sh --check"
echo "  y test MTU: ping -M do -s 1380 -c 3 10.8.0.1  (ajusta WG_MTU=1420 o 1280 en .env si hay frag)"
