# WG-Easy Port Manager (Advanced Fork)

[![Build & Publish Latest](https://github.com/ydtoloza/wg-easy-port-manager/actions/workflows/deploy.yml/badge.svg)](https://github.com/ydtoloza/wg-easy-port-manager/actions/workflows/deploy.yml)
[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)
![GitHub repo size](https://img.shields.io/github/repo-size/ydtoloza/wg-easy-port-manager)
![GitHub last commit](https://img.shields.io/github/last-commit/ydtoloza/wg-easy-port-manager)


### 📸 UI Preview (Port Forwarding Manager)
<p align="center">
  <img src="assets/ui_preview.png" alt="WG-Easy Port Manager UI" width="600" />
</p>

---

[🇺🇸 English](#english) | [🇪🇸 Español](#español)

---

<a name="español"></a>
## 🇪🇸 Español

> **Aviso**: Este proyecto es un fork especializado del [wg-easy](https://github.com/wg-easy/wg-easy) original de Weejewel. Este fork introduce características avanzadas de red y mejoras en la interfaz que no están presentes en el repositorio original, diseñadas específicamente para usuarios avanzados que requieren una gestión profesional de redireccionamiento de puertos.

### 🚀 Características Principales y Mejoras

Este fork mantiene la simplicidad de la interfaz original de WireGuard e introduce potentes capacidades nuevas:

*   **Gestor de Puertos por Cliente (DNAT/Port Forwarding)**: Una interfaz totalmente integrada para gestionar el redireccionamiento de puertos por cada cliente de WireGuard. Puedes mapear dinámicamente puertos externos del servidor a las IPs internas de los clientes (Soporta IPv4 e IPv6).
*   **Soporte Completo IPv6 (Dual-Stack)**: Conectividad nativa IPv6. El servidor asigna automáticamente direcciones IPv6 a nuevos clientes y migra de forma transparente los clientes existentes.
*   **Soporte para Protocolo "Ambos" (TCP + UDP)**: Capacidad de abrir puertos tanto en TCP como en UDP con una sola regla, ideal para juegos y servicios complejos.
*   **Integración Automatizada con `nftables`**: El backend provisiona, sincroniza y limpia automáticamente las reglas DNAT de `nftables` para IPv4 e IPv6 basándose en la configuración de la interfaz.
*   **Validación en Tiempo Real**: La interfaz te avisa instantáneamente si intentas usar un puerto que ya está ocupado o reservado.
*   **Estabilidad Mejorada**: Se corrigieron condiciones de carrera (race conditions) durante la inicialización de WireGuard, asegurando un arranque mucho más estable.
*   **Gestión de Sesiones Robusta**: Se resolvieron problemas de bloqueos silenciosos durante el inicio de sesión y caídas de tokens de autenticación en entornos con proxy inverso o alta latencia.
*   **Soporte para Modo de Red Host**: Optimizado para ejecutarse con `network_mode: "host"` para obtener el máximo rendimiento.

### 🛠 Instalación y Despliegue

Desplegar este fork es tan sencillo como ejecutar un archivo `docker-compose.yml`.

#### Requisitos Previos

Asegúrate de que tu sistema cumple con lo siguiente:
* Docker y Docker Compose instalados.
* `nftables` e `iptables` disponibles en el sistema host.
* Módulo del kernel de WireGuard cargado.
* Un proxy HTTPS o una red administrativa privada. No expongas el puerto 51821 directamente a Internet.

#### Ejemplo de `docker-compose.yml`

```yaml
volumes:
  etc_wireguard:

services:
  wg-easy-port-manager:
    image: ghcr.io/ydtoloza/wg-easy-port-manager:latest
    container_name: wg-easy-port-manager
    env_file: .env
    environment:
      - LANG=es # Idioma de la interfaz
      - WG_HOST=${WG_HOST} # Cambia por la IP pública de tu servidor
      - PASSWORD_HASH=${PASSWORD_HASH} # Genera tu propio hash bcrypt (ver abajo)
      - SESSION_SECRET=${SESSION_SECRET} # Mínimo 32 bytes aleatorios
      - WG_PERSISTENT_KEEPALIVE=25
      - WG_DEVICE=eth0 # Cambia si tu interfaz principal no es eth0
      - WG_DEFAULT_ADDRESS_V6=fd42:42:42::x # Rango IPv6 opcional
    volumes:
      - etc_wireguard:/etc/wireguard
    restart: unless-stopped
    network_mode: "host" # Modo de red de alto rendimiento
    cap_add:
      - NET_ADMIN
      - NET_RAW
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
```

> **Configuración obligatoria**: No uses contraseñas en texto plano y **nunca subas tu hash real al repositorio**. Copia `.env.example` a `.env`, genera `PASSWORD_HASH` con `wgpw` y `SESSION_SECRET` con `openssl rand -hex 32`. Escribe el hash entre comillas simples en `.env` para que Compose no interprete sus símbolos `$`.

Consulta [Security and Operations](docs/security-and-operations.md) para TLS, proxy inverso, backups, recuperación y limitaciones operativas.

---

<a name="english"></a>
## 🇺🇸 English

> **Disclaimer**: This project is a specialized fork of the original [wg-easy](https://github.com/wg-easy/wg-easy) by Weejewel. This fork introduces advanced networking features and interface enhancements not present in the upstream repository, specifically tailored for power users requiring advanced port forwarding management.

### 🚀 Key Features & Enhancements

This fork maintains the simplicity of the original WireGuard UI while injecting powerful new capabilities:

*   **Peer Port Manager (DNAT/Port Forwarding)**: A fully integrated UI to manage port forwarding per WireGuard peer. You can dynamically map external server ports to internal peer IPs (Supports IPv4 & IPv6).
*   **Full IPv6 Support (Dual-Stack)**: Native IPv6 connectivity. The server automatically assigns IPv6 addresses to new peers and transparently migrates existing ones.
*   **"Both" Protocol Support (TCP + UDP)**: Ability to open both TCP and UDP ports with a single rule, perfect for games and complex services.
*   **Automated `nftables` Integration**: The backend automatically provisions, syncs, and flushes `nftables` DNAT rules for both IPv4 and IPv6 based on the UI configuration.
*   **Real-Time Validation**: The UI instantly warns you if you try to use a port that is already occupied or reserved.
*   **Enhanced Stability**: Fixed underlying race conditions during WireGuard initialization, ensuring a smoother startup sequence.
*   **Robust Session Management**: Resolved silent hanging issues during login and authentication token drops in reverse-proxy or high-latency environments.
*   **Host Network Mode Support**: Optimized to run with `network_mode: "host"` for maximum performance and reduced overhead.

### 🛠 Installation & Deployment

Deploying this fork is as simple as running a `docker-compose.yml` file.

#### Prerequisites

Ensure your host system meets the following requirements:
* Docker & Docker Compose installed.
* `nftables` and `iptables` available on the host system (required for port forwarding and Docker routing compatibility).
* WireGuard kernel module loaded.
* An HTTPS reverse proxy or private administrative network. Do not expose port 51821 directly to the Internet.

#### Example `docker-compose.yml`

```yaml
volumes:
  etc_wireguard:

services:
  wg-easy-port-manager:
    image: ghcr.io/ydtoloza/wg-easy-port-manager:latest
    container_name: wg-easy-port-manager
    env_file: .env
    environment:
      - LANG=en # Set UI Language
      - WG_HOST=${WG_HOST} # Change to your server's public IP
      - PASSWORD_HASH=${PASSWORD_HASH} # Replace with your own bcrypt hash (see below)
      - SESSION_SECRET=${SESSION_SECRET} # At least 32 random bytes
      - WG_PERSISTENT_KEEPALIVE=25
      - WG_DEVICE=eth0 # Change if your main interface is not eth0
      - WG_DEFAULT_ADDRESS_V6=fd42:42:42::x # Optional IPv6 range
    volumes:
      - etc_wireguard:/etc/wireguard
    restart: unless-stopped
    network_mode: "host"
    cap_add:
      - NET_ADMIN
      - NET_RAW
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
```

> **Required configuration**: Never use plain-text passwords and **never commit your real hash**. Copy `.env.example` to `.env`, generate `PASSWORD_HASH` with `wgpw`, and generate `SESSION_SECRET` with `openssl rand -hex 32`. Put the hash in single quotes in `.env` so Compose does not interpret its `$` characters.

See [Security and Operations](docs/security-and-operations.md) for TLS, reverse proxy, backup, recovery and operational limitations.

---

## 🤝 Credits & Upstream

All credit for the original design and core application architecture goes to [Weejewel](https://github.com/weejewel/wg-easy). Developed and maintained as a fork by [ydtoloza](https://github.com/ydtoloza/wg-easy-port-manager).
