# Architecture Notes

This document provides a brief overview of the architectural decisions and directory structure of the `wg-easy-port-manager` fork, specifically regarding the separation of backend code.

## Directory Structure: `lib/` vs `services/`

At first glance, having both `src/lib/` and `src/services/` might seem redundant, as they contain files with similar names (e.g., `Server.js` and `WireGuard.js` in both directories). However, this is a deliberate design pattern inherited from the original `wg-easy` project:

### 1. `src/lib/` (Class Definitions)
This directory contains the actual business logic and class definitions. The files here export uninstantiated Classes.
- Example: `src/lib/WireGuard.js` defines the `WireGuard` class, which includes all the methods for interacting with the wg interfaces, iptables, and nftables.

### 2. `src/services/` (Singleton Instances)
This directory acts as an initializer and registry for singletons. The files here import the classes from `lib/`, instantiate them using the `new` keyword, and export that single instance.
- Example: `src/services/WireGuard.js` looks like this:
  ```javascript
  const WireGuard = require('../lib/WireGuard');
  module.exports = new WireGuard();
  ```

### Why this pattern?
By requiring the modules from `src/services/*` throughout the rest of the application (like in API routes or the main `server.js` entry point), we guarantee that all parts of the app are interacting with the exact same instance in memory. This is critical for maintaining a single, consistent state representing the WireGuard configuration and active peer connections.

## Startup order

`src/server.js` validates authentication, session and proxy settings before loading the WireGuard service. The application then:

1. Loads and validates persisted server settings.
2. Loads and validates `wg0.json`, or creates it only when the file does not exist.
3. Writes `wg0.conf`, restarts `wg0` and synchronizes peers.
4. Ensures the dedicated nftables tables and atomically applies DNAT rules.
5. Starts the HTTP listener.

Any failure before step 5 leaves the management API unavailable. Corrupt or unreadable state is never replaced automatically.

## State and mutation model

`wg0.json` is canonical. `wg0.conf` is generated from it and from `server-settings.json`. All files containing secrets use mode `0600` and temporary files have unique names.

Server-setting updates use `server-settings.transaction.json` as a recovery journal. The journal is written before changing the interface and removed only after addresses, generated configuration, host rules and persisted settings agree. Startup completes or rolls back an interrupted journal before opening the API.

The WireGuard singleton owns a promise-based mutation queue. Create, update, delete, restore and server-setting operations are serialized so two requests cannot mutate memory, disk and nftables concurrently.

DNAT rules are built entirely in memory after schema and policy validation. They are then passed to `nft -f -` in one transaction. A failed rule cannot leave a partially rebuilt chain. Rollback errors are propagated to the caller instead of being logged as success.

## Web UI and CSP

Vue 2 is currently retained for compatibility, but the DOM template is compiled at build time by `scripts/build-www-template.js`. Production loads the runtime-only Vue bundle and `app-template.generated.js`; no runtime `new Function` compilation is required. CI runs `check:www-template` to ensure generated assets match `index.html`.

The long-term direction is migration to a supported frontend framework version. Until then, Vue and `vue-template-compiler` must stay on exactly the same version.

## Operational boundaries

The implementation manages the fixed interface `wg0` and fixed nftables tables `wgeasy_dnat`. It supports one manager instance per host. Address allocation currently assumes IPv4 `/24` and IPv6 `/64` templates.

Security and recovery procedures are documented in [security-and-operations.md](security-and-operations.md).
