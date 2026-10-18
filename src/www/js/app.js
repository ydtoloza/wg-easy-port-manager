/* eslint-disable no-console */
/* eslint-disable no-alert */
/* eslint-disable no-undef */
/* eslint-disable no-new */

'use strict';

function bytes(bytes, decimals, kib, maxunit) {
  kib = kib || false;
  if (bytes === 0) return '0 B';
  if (Number.isNaN(parseFloat(bytes)) && !Number.isFinite(bytes)) return 'NaN';
  const k = kib ? 1024 : 1000;
  const dm = decimals != null && !Number.isNaN(decimals) && decimals >= 0 ? decimals : 2;
  const sizes = kib
    ? ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB', 'BiB']
    : ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB', 'BB'];
  let i = Math.floor(Math.log(bytes) / Math.log(k));
  if (maxunit !== undefined) {
    const index = sizes.indexOf(maxunit);
    if (index !== -1) i = index;
  }
  // eslint-disable-next-line no-restricted-properties
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

const i18n = new VueI18n({
  locale: localStorage.getItem('lang') || 'en',
  fallbackLocale: 'en',
  messages,
});

const UI_CHART_TYPES = [
  { type: false, strokeWidth: 0 },
  { type: 'line', strokeWidth: 3 },
  { type: 'area', strokeWidth: 0 },
  { type: 'bar', strokeWidth: 0 },
];

const CHART_COLORS = {
  rx: { light: 'rgba(128,128,128,0.3)', dark: 'rgba(255,255,255,0.3)' },
  tx: { light: 'rgba(128,128,128,0.4)', dark: 'rgba(255,255,255,0.3)' },
  gradient: { light: ['rgba(0,0,0,1.0)', 'rgba(0,0,0,1.0)'], dark: ['rgba(128,128,128,0)', 'rgba(128,128,128,0)'] },
};

// Traffic palette, validated for colour-blind separation on both surfaces
// (same values as the CSS tokens --rx/--tx/--fg-muted in www/src/css/app.css).
const THEME_COLORS = {
  light: {
    download: '#0969da', upload: '#d4570f', muted: '#59636e', grid: '#eff2f5', text: '#59636e',
  },
  dark: {
    download: '#4493f8', upload: '#e0712c', muted: '#a1a1a1', grid: '#1a1a1a', text: '#a1a1a1',
  },
};

// Ports the random generator must never suggest even though they sit in the
// dynamic range: popular services an admin will plausibly run on the host
// (databases, alt-HTTP, RDP/VNC/SMB, discovery protocols) plus this app's own
// default WireGuard/panel ports. Server ports and already-assigned ports are
// excluded separately at draw time.
const RANDOM_PORT_BLOCKLIST = new Set([
  51820, 51821,
  1900, 5353,
  3000, 5000, 8000, 8080, 8081, 8443, 8888,
  1433, 3306, 5432, 6379, 11211, 9200, 27017,
  1723, 3389, 445, 5060, 5061, 5900,
]);

// Linux default ephemeral range. docs/v2.1-security-constraints.md (Phase 1)
// prefers auto-assigned forwards outside it so an inbound DNAT port never
// competes with outbound source binds. Soft exclusion: only when the whole
// configured window sits inside it do we fall back to drawing from there.
const LINUX_EPHEMERAL_MIN = 32768;
const LINUX_EPHEMERAL_MAX = 60999;

const isEphemeralPort = (port) => port >= LINUX_EPHEMERAL_MIN && port <= LINUX_EPHEMERAL_MAX;

// Uniform draw from [min, max] avoiding blocked values, preferring ports that
// also avoid softBlocked (ephemeral range). Random draws are capped, then
// deterministic sweeps cover tiny windows, so the function always terminates
// and returns null only when the window is exhausted.
function pickRandomPort({
  min, max, blocked, softBlocked,
}) {
  const low = Math.ceil(min);
  const high = Math.floor(max);
  const span = high - low + 1;
  if (span <= 0) return null;
  const isFree = (port, strict) => !blocked.has(port) && !(strict && softBlocked && softBlocked(port));
  const maxAttempts = Math.min(span, 1000);
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const port = low + Math.floor(Math.random() * span);
    if (isFree(port, true)) return port;
  }
  for (let port = low; port <= high; port += 1) {
    if (isFree(port, true)) return port;
  }
  // The whole window is soft-blocked (or nearly): allow it rather than fail.
  for (let port = low; port <= high; port += 1) {
    if (isFree(port, false)) return port;
  }
  return null;
}

const appTemplate = window.WgEasyAppTemplate;
if (!appTemplate) throw new Error('Precompiled application template was not loaded.');

new Vue({
  el: '#app',
  render: appTemplate.render,
  staticRenderFns: appTemplate.staticRenderFns,
  components: {
    apexchart: VueApexCharts,
  },
  i18n,
  data: {
    authenticated: null,
    authenticating: false,
    password: null,
    requiresPassword: null,

    clients: null,
    clientsPersist: {},
    clientDelete: null,
    pfDelete: null,
    clientCreate: null,
    clientCreateName: '',
    clientEditName: null,
    clientEditNameId: null,
    clientEditAddress: null,
    clientEditAddressId: null,
    clientEditAddressV6: null,
    clientEditAddressV6Id: null,
    qrcode: null,
    configDialog: null,
    copyConfigSuccess: false,
    newPf: {},
    pfError: null,
    editingPfClientId: null,
    editingPfIndex: null,
    editingPfRule: {},
    expandedPfClients: {},
    networkPolicyDialog: null,
    networkPolicyOptions: null,
    networkPolicySaving: false,
    networkPolicyError: null,
    newNetworkPolicyRule: {
      proto: 'tcp', label: '', startPort: null, endPort: null,
    },

    // Toast notifications
    toasts: [],
    toastId: 0,

    // Server config (global IP settings)
    showServerConfig: false,
    serverConfig: null,
    serverConfigEdit: null,
    serverConfigSaving: false,

    // Port-forwarding kill switch (live from server config) and the
    // debounced auto-probe bookkeeping.
    forwardingEnabled: false,
    autoProbeTimer: null,
    lastPfSignature: null,
    lastProbeAt: {},
    // key `${clientId}:${ruleId}` -> { verdict, at }. Drives the per-rule
    // reachability dot and the probe section of the notification center.
    lastProbeVerdict: {},

    // Notification center behind the topbar bell. Toasts vanish by design;
    // this durable log keeps the last 100 entries (50 persisted) so probe
    // events stay reviewable. Unread = entry.at > notificationsReadAt.
    notifications: [],
    notificationLogId: 0,
    notificationsReadAt: 0,
    showNotifications: false,

    // Public slice of the server settings (ports + forwarding window) as
    // returned by /api/wireguard/server-config; the random-port generator
    // stays inside the admin-configured window with it.
    publicServerConfig: null,

    // Current screen, driven by location.hash so the back button works:
    // '' → panel, '#/ports' → all ports, '#/client/<id>' → client detail.
    view: 'panel',
    viewClientId: null,
    clientSearch: '',
    users: [],
    userNewName: '',
    userNewCanCreate: true,
    userCodeShown: null, // { name, code } right after creating or rotating; never stored
    clientFilter: 'all',

    // Consolidated "all ports" view: every forwarding rule in one table with
    // search and filters, so admins don't expand peer by peer. Read-only:
    // clicking a row opens that peer's detail.
    allPortsSearch: '',
    allPortsProto: 'all',
    allPortsStatus: 'all',

    uiTrafficStats: false,

    // Traffic dashboard (Plex-style ANCHO DE BANDA / CPU / RAM + peaks).
    // Realtime sampler lives server-side in lib/TrafficStats.js; here we
    // only poll it and shape ApexCharts series. Chart data survives reloads
    // via localStorage, like ydtoloza/network-dashboard does.
    traffic: null,
    trafficSummary: null,
    trafficRange: localStorage.getItem('trafficRange') || 'realtime',
    // Snapshot for non-realtime ranges (1h/24h/30d come from the server's
    // per-minute/per-hour rollups). refreshTraffic() keeps realtime live
    // and re-fetches the snapshot at most every 30s without awaiting it.
    trafficRangeData: null,
    trafficRangeAt: 0,
    trafficRangeFetch: null,
    trafficScope: 'all',
    trafficPollCount: 0,
    // Traffic is the centre of the panel: shown unless the user hid it
    // (persisted as '0').
    uiShowTraffic: localStorage.getItem('uiShowTraffic') !== '0',
    trafficHidden: { download: false, upload: false },

    uiChartType: 0,
    uiShowCharts: localStorage.getItem('uiShowCharts') === '1',
    uiTheme: localStorage.theme || 'dark',
    prefersDarkScheme: window.matchMedia('(prefers-color-scheme: dark)'),
    pollTimer: null,
    polling: false,
    refreshGeneration: 0,

    chartOptions: {
      chart: {
        background: 'transparent',
        stacked: false,
        toolbar: {
          show: false,
        },
        animations: {
          enabled: false,
        },
        parentHeightOffset: 0,
        sparkline: {
          enabled: true,
        },
      },
      colors: [],
      stroke: {
        curve: 'smooth',
      },
      fill: {
        type: 'gradient',
        gradient: {
          shade: 'dark',
          type: 'vertical',
          shadeIntensity: 0,
          gradientToColors: CHART_COLORS.gradient.dark,
          inverseColors: false,
          opacityTo: 0,
          stops: [0, 100],
        },
      },
      dataLabels: {
        enabled: false,
      },
      plotOptions: {
        bar: {
          horizontal: false,
        },
      },
      xaxis: {
        labels: {
          show: false,
        },
        axisTicks: {
          show: false,
        },
        axisBorder: {
          show: false,
        },
      },
      yaxis: {
        labels: {
          show: false,
        },
        min: 0,
      },
      tooltip: {
        enabled: false,
      },
      legend: {
        show: false,
      },
      grid: {
        show: false,
        padding: {
          left: -10,
          right: 0,
          bottom: -15,
          top: -15,
        },
        column: {
          opacity: 0,
        },
        xaxis: {
          lines: {
            show: false,
          },
        },
      },
    },
  },
  methods: {
    // ── Toast notification system ─────────────────────────────────────────
    notify(msg, type = 'error', duration = 5000) {
      const id = ++this.toastId;
      this.toasts.push({ id, msg, type });
      setTimeout(() => this.dismissToast(id), duration);
      // Every toast also lands in the bell's durable history, so probe
      // warnings that flash once stay reviewable later.
      this.logNotification(msg, type);
    },
    dismissToast(id) {
      const idx = this.toasts.findIndex((t) => t.id === id);
      if (idx !== -1) this.toasts.splice(idx, 1);
    },
    // ── Notification center (bell) ────────────────────────────────────────
    logNotification(msg, type) {
      this.notifications.push({
        id: ++this.notificationLogId, msg, type, at: Date.now(),
      });
      if (this.notifications.length > 100) {
        this.notifications.splice(0, this.notifications.length - 100);
      }
      this.persistNotifications();
    },
    persistNotifications() {
      try {
        localStorage.setItem('wgNotifications', JSON.stringify(this.notifications.slice(-50)));
      } catch (err) {
        console.error(err);
      }
    },
    toggleNotifications() {
      this.showNotifications = !this.showNotifications;
      if (this.showNotifications) this.markNotificationsRead();
    },
    closeNotifications() {
      this.showNotifications = false;
    },
    markNotificationsRead() {
      const newest = this.notifications.length
        ? this.notifications[this.notifications.length - 1].at
        : Date.now();
      if (newest > this.notificationsReadAt) {
        this.notificationsReadAt = newest;
        try {
          localStorage.setItem('wgNotificationsReadAt', String(this.notificationsReadAt));
        } catch (err) {
          console.error(err);
        }
      }
    },
    clearNotifications() {
      this.notifications = [];
      this.persistNotifications();
    },
    // ─────────────────────────────────────────────────────────────────────

    dateTime: (value) => {
      return new Intl.DateTimeFormat(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: 'numeric',
      }).format(value);
    },
    getNewPf(clientId) {
      if (!this.newPf[clientId]) {
        this.$set(this.newPf, clientId, { proto: 'tcp', extPort: null, intPort: null });
      }
      return this.newPf[clientId];
    },
    isPfExpanded(clientId) {
      return !!this.expandedPfClients[clientId];
    },
    togglePfExpanded(clientId) {
      const expanded = !this.expandedPfClients[clientId];
      this.$set(this.expandedPfClients, clientId, expanded);
      this.persistPfExpanded();
      if (expanded) this.scheduleAutoProbe();
    },
    // The open/closed state of each port-forwarding section survives reloads:
    // only expanded peers are stored, so the default is collapsed.
    persistPfExpanded() {
      try {
        const stored = {};
        for (const [key, value] of Object.entries(this.expandedPfClients)) {
          if (value === true) stored[key] = true;
        }
        localStorage.setItem('pfExpanded', JSON.stringify(stored));
      } catch (err) {
        console.error(err);
      }
    },
    // Open a peer's detail: its port-forwarding section counts as expanded
    // (persisted, drives the auto-probe) and the hash route moves there.
    jumpToPeer(clientId) {
      if (this.expandedPfClients[clientId] !== true) {
        this.$set(this.expandedPfClients, clientId, true);
        this.persistPfExpanded();
        this.scheduleAutoProbe();
      }
      this.navigate('client', clientId);
    },
    navigate(view, clientId) {
      const routes = { client: `#/client/${encodeURIComponent(clientId)}`, ports: '#/ports', users: '#/users' };
      const hash = routes[view] || '';
      if (window.location && window.location.hash !== hash) {
        window.location.hash = hash; // hashchange → applyRoute
      } else {
        this.applyRoute();
      }
    },
    applyRoute() {
      const hash = (window.location && window.location.hash) || '';
      const client = /^#\/client\/(.+)$/.exec(hash);
      if (client) {
        this.view = 'client';
        this.viewClientId = decodeURIComponent(client[1]);
      } else {
        this.view = { '#/ports': 'ports', '#/users': 'users' }[hash] || 'panel';
        this.viewClientId = null;
      }
      if (typeof window.scrollTo === 'function') window.scrollTo(0, 0);
    },
    async createUser() {
      try {
        const { user, code } = await this.api.createUser({ name: this.userNewName, canCreate: this.userNewCanCreate });
        this.userCodeShown = { name: user.name, code };
        this.userNewName = '';
        await this.refresh();
      } catch (err) {
        this.notify(err.message || err.toString());
      }
    },
    // One click for an existing profile: a new user named after it, linked, code shown.
    async createAccessForClient(client) {
      try {
        const { user, code } = await this.api.createUser({ name: client.name.slice(0, 100), canCreate: false });
        await this.api.setClientOwner({ clientId: client.id, userId: user.id });
        this.userCodeShown = { name: user.name, code };
        window.location.hash = '#/users';
        await this.refresh();
      } catch (err) {
        this.notify(err.message || err.toString());
      }
    },
    async rotateUserCode(user) {
      if (!window.confirm(this.$t('users.rotateConfirm', { name: user.name }))) return;
      try {
        const { code } = await this.api.rotateUserCode({ userId: user.id });
        this.userCodeShown = { name: user.name, code };
      } catch (err) {
        this.notify(err.message || err.toString());
      }
    },
    async deleteUser(user) {
      if (!window.confirm(this.$t('users.deleteConfirm', { name: user.name }))) return;
      await this.api.deleteUser({ userId: user.id })
        .catch((err) => this.notify(err.message || err.toString()));
      await this.refresh().catch(console.error);
    },
    async setUserCanCreate(user, canCreate) {
      await this.api.updateUser({ userId: user.id, canCreate })
        .catch((err) => this.notify(err.message || err.toString()));
      await this.refresh().catch(console.error);
    },
    async setClientOwner(client, userId) {
      await this.api.setClientOwner({ clientId: client.id, userId: userId || null })
        .catch((err) => this.notify(err.message || err.toString()));
      await this.refresh().catch(console.error);
    },
    clientName(clientId) {
      const client = (this.clients || []).find((candidate) => candidate.id === clientId);
      return client ? client.name : clientId;
    },
    copyText(text) {
      if (navigator.clipboard) navigator.clipboard.writeText(text).catch(() => {});
    },
    // Same as the `timeago` filter, usable inside template expressions.
    ago(value) {
      return timeago.format(value, i18n.locale);
    },
    clientStatus(client) {
      if (!client.enabled) return { label: this.$t('ui.statusDisabled'), dot: 'dot-none' };
      return client.online
        ? { label: this.$t('ui.statusOnline'), dot: 'dot-ok' }
        : { label: this.$t('ui.statusOffline'), dot: 'dot-off' };
    },
    toggleSeries(key) {
      this.trafficHidden = { ...this.trafficHidden, [key]: !this.trafficHidden[key] };
    },
    hydratePersistentState() {
      try {
        const stored = JSON.parse(localStorage.getItem('wgNotifications') || 'null');
        if (Array.isArray(stored)) {
          this.notifications = stored
            .filter((entry) => entry && typeof entry.msg === 'string' && Number.isFinite(entry.at))
            .slice(-50);
        }
        this.notificationsReadAt = Number(localStorage.getItem('wgNotificationsReadAt')) || 0;
        const expanded = JSON.parse(localStorage.getItem('pfExpanded') || 'null');
        if (expanded && typeof expanded === 'object') {
          for (const [key, value] of Object.entries(expanded)) {
            if (value === true) this.expandedPfClients[key] = true;
          }
        }
      } catch (err) {
        console.error(err);
      }
    },
    // ── Reachability dot + random port ────────────────────────────────────
    probeVerdictFor(clientId, ruleId) {
      const entry = this.lastProbeVerdict[`${clientId}:${ruleId}`];
      return entry ? entry.verdict : null;
    },
    probeDotClass(clientId, ruleId) {
      switch (this.probeVerdictFor(clientId, ruleId)) {
        case 'ok':
          return 'dot-ok';
        case 'dnat-local':
          return 'dot-warn';
        case 'unreachable':
        case 'rule-missing':
          return 'dot-bad';
        default:
          // Unknown yet, UDP (not TCP-verifiable) or peer offline.
          return 'dot-off';
      }
    },
    probeDotTitle(client, rule) {
      const verdict = this.probeVerdictFor(client.id, rule.id);
      if (!verdict) return this.$t('networkPolicy.probeNever');
      return this.$t('networkPolicy.verdictTitle', {
        verdict: this.$t(`networkPolicy.verdict.${verdict}`),
      });
    },
    probeEntries() {
      if (!this.clients) return [];
      const entries = [];
      for (const client of this.clients) {
        for (const rule of client.portForwards || []) {
          const entry = this.lastProbeVerdict[`${client.id}:${rule.id}`];
          if (entry) {
            entries.push({
              client, rule, verdict: entry.verdict, at: entry.at,
            });
          }
        }
      }
      return entries.sort((a, b) => b.at - a.at).slice(0, 10);
    },
    usedExternalPorts() {
      const used = new Set();
      for (const client of this.clients || []) {
        for (const rule of client.portForwards || []) {
          const port = Number(rule.extPort);
          if (Number.isInteger(port)) used.add(port);
        }
      }
      return used;
    },
    // Suggests a random free port for seeding: inside the admin-configured
    // forwarding window when known, never privileged, never colliding with
    // assigned rules, the server's own ports or the well-known blocklist.
    // The server re-validates authoritatively on add.
    randomPortFor(client) {
      if (!this.forwardingEnabled) return;
      const settings = this.publicServerConfig || {};
      const configMin = Number(settings.portFwdMin);
      const configMax = Number(settings.portFwdMax);
      const min = Math.max(Number.isFinite(configMin) ? configMin : 1024, 1024);
      const max = Math.min(Number.isFinite(configMax) ? configMax : 65535, 65535);
      const blocked = new Set(RANDOM_PORT_BLOCKLIST);
      for (const port of this.usedExternalPorts()) blocked.add(port);
      blocked.add(Number(settings.port));
      blocked.add(Number(settings.configPort));

      const pf = this.getNewPf(client.id);
      const port = pickRandomPort({
        min, max, blocked, softBlocked: isEphemeralPort,
      });
      if (!port) {
        this.notify(this.$t('pf.randomPortNone'), 'error');
        return;
      }
      // Seeding default: the internal port mirrors the draw unless the user
      // already typed one (qBittorrent listens on a single port).
      this.$set(this.newPf, client.id, {
        proto: pf.proto || 'tcp',
        extPort: port,
        intPort: pf.intPort || port,
      });
      this.pfError = null;
    },
    isPortConflicting(client) {
      const pf = this.newPf[client.id];
      if (!pf || !pf.extPort) return false;
      const port = Number(pf.extPort);
      const proto = pf.proto || 'tcp';
      return this.clients.some((c) => Array.isArray(c.portForwards)
        && c.portForwards.some((r) => (r.proto === proto || r.proto === 'both' || proto === 'both')
          && r.extPort === port));
    },
    async refresh({
      updateCharts = false,
    } = {}) {
      if (!this.authenticated) return;

      const generation = ++this.refreshGeneration;
      const [clients, serverConfig, users] = await Promise.all([
        this.api.getClients(),
        this.api.getServerConfig().catch(() => null),
        this.api.getUsers().catch(() => null),
      ]);
      if (generation !== this.refreshGeneration) return;
      if (users) this.users = users;
      if (serverConfig) this.publicServerConfig = serverConfig;
      const forwardingChanged = this.forwardingEnabled !== (serverConfig?.forwardingEnabled === true);
      this.forwardingEnabled = serverConfig?.forwardingEnabled === true;
      this.clients = clients.map((client) => {
        if (!this.clientsPersist[client.id]) {
          this.clientsPersist[client.id] = {};
          this.clientsPersist[client.id].transferRxHistory = Array(50).fill(0);
          this.clientsPersist[client.id].transferRxPrevious = client.transferRx;
          this.clientsPersist[client.id].transferTxHistory = Array(50).fill(0);
          this.clientsPersist[client.id].transferTxPrevious = client.transferTx;
        }

        // Ensure newPf entry exists for this client (reactive)
        if (!this.newPf[client.id]) {
          this.$set(this.newPf, client.id, { proto: 'tcp', extPort: null, intPort: null });
        }

        // Sections stay collapsed unless the user expanded them (persisted in
        // localStorage, hydrated once in mounted()): no auto-expand on load.

        this.clientsPersist[client.id].transferRxCurrent = client.transferRx - this.clientsPersist[client.id].transferRxPrevious;
        this.clientsPersist[client.id].transferRxPrevious = client.transferRx;
        this.clientsPersist[client.id].transferTxCurrent = client.transferTx - this.clientsPersist[client.id].transferTxPrevious;
        this.clientsPersist[client.id].transferTxPrevious = client.transferTx;

        if (updateCharts) {
          this.clientsPersist[client.id].transferRxHistory.push(this.clientsPersist[client.id].transferRxCurrent);
          this.clientsPersist[client.id].transferRxHistory.shift();

          this.clientsPersist[client.id].transferTxHistory.push(this.clientsPersist[client.id].transferTxCurrent);
          this.clientsPersist[client.id].transferTxHistory.shift();

          this.clientsPersist[client.id].transferTxSeries = [{
            name: 'Tx',
            data: this.clientsPersist[client.id].transferTxHistory,
          }];

          this.clientsPersist[client.id].transferRxSeries = [{
            name: 'Rx',
            data: this.clientsPersist[client.id].transferRxHistory,
          }];

          client.transferTxHistory = this.clientsPersist[client.id].transferTxHistory;
          client.transferRxHistory = this.clientsPersist[client.id].transferRxHistory;
          client.transferMax = Math.max(...client.transferTxHistory, ...client.transferRxHistory);

          client.transferTxSeries = this.clientsPersist[client.id].transferTxSeries;
          client.transferRxSeries = this.clientsPersist[client.id].transferRxSeries;
        }

        client.transferTxCurrent = this.clientsPersist[client.id].transferTxCurrent;
        client.transferRxCurrent = this.clientsPersist[client.id].transferRxCurrent;

        client.hoverTx = this.clientsPersist[client.id].hoverTx;
        client.hoverRx = this.clientsPersist[client.id].hoverRx;

        return client;
      });

      // Re-arm the debounced auto-probe whenever the observed forwarding
      // structure changes (mutations land through refresh()).
      const pfSignature = JSON.stringify(this.clients.map((client) => [
        client.id,
        client.enabled,
        (client.portForwards || []).map((rule) => [rule.id, rule.proto, rule.extPort, rule.intPort]),
      ]));
      if (forwardingChanged || pfSignature !== this.lastPfSignature) {
        this.lastPfSignature = pfSignature;
        // Drop probe bookkeeping for peers/rules that just disappeared so the
        // maps cannot grow without bound across deletes and restores.
        const liveKeys = new Set();
        for (const client of this.clients) {
          for (const rule of client.portForwards || []) liveKeys.add(`${client.id}:${rule.id}`);
        }
        for (const key of Object.keys(this.lastProbeAt)) {
          if (!liveKeys.has(key)) delete this.lastProbeAt[key];
        }
        for (const key of Object.keys(this.lastProbeVerdict)) {
          if (!liveKeys.has(key)) delete this.lastProbeVerdict[key];
        }
        this.scheduleAutoProbe();
      }
    },
    login(e) {
      e.preventDefault();

      if (!this.password) return;
      if (this.authenticating) return;

      this.authenticating = true;
      this.api.createSession({
        password: this.password,
      })
        .then(async () => {
          const session = await this.api.getSession();
          this.authenticated = session.authenticated;
          this.requiresPassword = session.requiresPassword;
          await this.refresh({ updateCharts: this.chartsEnabled });
          this.schedulePoll();
        })
        .catch((err) => {
          this.notify(err.message || err.toString());
        })
        .finally(() => {
          this.authenticating = false;
          this.password = null;
        });
    },
    logout(e) {
      e.preventDefault();

      this.api.deleteSession()
        .then(() => {
          this.authenticated = false;
          this.clients = null;
          this.showNotifications = false;
          clearTimeout(this.pollTimer);
        })
        .catch((err) => {
          this.notify(err.message || err.toString());
        });
    },
    createClient() {
      const name = this.clientCreateName;
      if (!name) return;

      this.api.createClient({ name })
        .catch((err) => this.notify(err.message || err.toString()))
        .finally(() => this.refresh().catch(console.error));
    },
    deleteClient(client) {
      this.api.deleteClient({ clientId: client.id })
        .catch((err) => this.notify(err.message || err.toString()))
        .finally(() => this.refresh().catch(console.error));
    },
    enableClient(client) {
      this.api.enableClient({ clientId: client.id })
        .catch((err) => this.notify(err.message || err.toString()))
        .finally(() => this.refresh().catch(console.error));
    },
    disableClient(client) {
      this.api.disableClient({ clientId: client.id })
        .catch((err) => this.notify(err.message || err.toString()))
        .finally(() => this.refresh().catch(console.error));
    },
    updateClientName(client, name) {
      this.api.updateClientName({ clientId: client.id, name })
        .catch((err) => this.notify(err.message || err.toString()))
        .finally(() => this.refresh().catch(console.error));
    },
    updateClientAddress(client, address, addressV6) {
      this.api.updateClientAddress({ clientId: client.id, address, addressV6 })
        .catch((err) => this.notify(err.message || err.toString()))
        .finally(() => this.refresh().catch(console.error));
    },
    async openNetworkPolicy(client) {
      this.networkPolicyError = null;
      try {
        if (!this.networkPolicyOptions) {
          this.networkPolicyOptions = await this.api.getNetworkPolicyOptions();
        }
        const policy = client.networkPolicy || {
          blockedProtocols: [], customRules: [], peerAllowlist: [],
        };
        this.networkPolicyDialog = {
          clientId: client.id,
          clientName: client.name,
          expectedUpdatedAt: client.updatedAt.toISOString(),
          blockedProtocols: [...policy.blockedProtocols],
          customRules: policy.customRules.map((rule) => ({ ...rule })),
          peerAllowlist: [...policy.peerAllowlist],
        };
        this.newNetworkPolicyRule = {
          proto: 'tcp', label: '', startPort: null, endPort: null,
        };
      } catch (err) {
        this.notify(err.message || err.toString());
      }
    },
    closeNetworkPolicy() {
      if (this.networkPolicySaving) return;
      this.networkPolicyDialog = null;
      this.networkPolicyError = null;
    },
    formatPolicyRule(rule) {
      const ports = rule.startPort === rule.endPort
        ? rule.startPort
        : `${rule.startPort}-${rule.endPort}`;
      return `${rule.proto.toUpperCase()} ${ports}`;
    },
    addNetworkPolicyRule() {
      if (!this.networkPolicyDialog || !this.networkPolicyOptions) return;
      const startPort = Number(this.newNetworkPolicyRule.startPort);
      const endPort = this.newNetworkPolicyRule.endPort !== null && this.newNetworkPolicyRule.endPort !== ''
        ? Number(this.newNetworkPolicyRule.endPort)
        : startPort;
      if (!Number.isInteger(startPort) || !Number.isInteger(endPort)
        || startPort < 1 || endPort > 65535 || startPort > endPort) {
        this.networkPolicyError = this.$t('networkPolicy.invalidPortRange');
        return;
      }
      if (this.networkPolicyDialog.customRules.length >= this.networkPolicyOptions.maxCustomRules) {
        this.networkPolicyError = this.$t('networkPolicy.ruleLimit', {
          count: this.networkPolicyOptions.maxCustomRules,
        });
        return;
      }
      this.networkPolicyDialog.customRules.push({
        proto: this.newNetworkPolicyRule.proto,
        label: this.newNetworkPolicyRule.label.trim(),
        startPort,
        endPort,
      });
      this.newNetworkPolicyRule = {
        proto: 'tcp', label: '', startPort: null, endPort: null,
      };
      this.networkPolicyError = null;
    },
    removeNetworkPolicyRule(index) {
      this.networkPolicyDialog.customRules.splice(index, 1);
    },
    async saveNetworkPolicy() {
      if (!this.networkPolicyDialog || this.networkPolicySaving) return;
      this.networkPolicySaving = true;
      this.networkPolicyError = null;
      try {
        const policy = {
          blockedProtocols: [...this.networkPolicyDialog.blockedProtocols],
          customRules: this.networkPolicyDialog.customRules.map((rule) => ({ ...rule })),
          peerAllowlist: [...this.networkPolicyDialog.peerAllowlist],
        };
        await this.api.updateClientNetworkPolicy({
          clientId: this.networkPolicyDialog.clientId,
          policy,
          expectedUpdatedAt: this.networkPolicyDialog.expectedUpdatedAt,
        });
        this.networkPolicyDialog = null;
        this.notify(this.$t('networkPolicy.saved'), 'success');
        this.refresh().catch((err) => this.notify(err.message || err.toString()));
      } catch (err) {
        this.networkPolicyError = err.message || err.toString();
      } finally {
        this.networkPolicySaving = false;
      }
    },
    restoreConfig(e) {
      e.preventDefault();
      const file = e.currentTarget.files.item(0);
      if (file) {
        file.text()
          .then((content) => {
            this.api.restoreConfiguration(content)
              .then(() => this.notify('La configuración fue actualizada correctamente.', 'success'))
              .catch((err) => this.notify(err.message || err.toString()))
              .finally(() => this.refresh().catch(console.error));
          })
          .catch((err) => this.notify(err.message || err.toString()));
      } else {
        this.notify('Error al cargar el archivo.');
      }
    },
    viewConfiguration(client) {
      if (!client.downloadableConfig) return;
      fetch(`./api/wireguard/client/${encodeURIComponent(client.id)}/configuration/raw`, { credentials: 'include' })
        .then((res) => {
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          return res.text();
        })
        .then((text) => {
          this.configDialog = { text };
          this.copyConfigSuccess = false;
        })
        .catch((err) => this.notify(`Error al obtener la configuración: ${err.message}`));
    },
    preventUnavailableDownload(event, client) {
      if (!client.downloadableConfig) event.preventDefault();
    },
    copyConfigToClipboard() {
      if (!this.configDialog || !this.configDialog.text) return;
      const { text } = this.configDialog;
      // Try modern clipboard API first (requires HTTPS)
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
          this.copyConfigSuccess = true;
          setTimeout(() => {
            this.copyConfigSuccess = false;
          }, 3000);
        }).catch(() => this._fallbackCopy(text));
      } else {
        // Fallback for HTTP
        this._fallbackCopy(text);
      }
    },
    _fallbackCopy(text) {
      const el = document.createElement('textarea');
      el.value = text;
      el.style.position = 'fixed';
      el.style.opacity = '0';
      document.body.appendChild(el);
      el.focus();
      el.select();
      try {
        document.execCommand('copy');
        this.copyConfigSuccess = true;
        setTimeout(() => {
          this.copyConfigSuccess = false;
        }, 3000);
      } catch (err) {
        this.notify('No se pudo copiar al portapapeles.');
      }
      document.body.removeChild(el);
    },
    addPortForward(client) {
      if (!this.forwardingEnabled) return;
      const pf = this.newPf[client.id];
      if (!pf || !pf.extPort || !pf.intPort) return;

      this.pfError = null;

      // Client-side duplicate check (all peers)
      const extPort = Number(pf.extPort);
      const proto = pf.proto || 'tcp';
      const alreadyUsed = this.clients.some((c) => Array.isArray(c.portForwards)
        && c.portForwards.some((r) => (r.proto === proto || r.proto === 'both' || proto === 'both')
          && r.extPort === extPort));
      if (alreadyUsed) {
        this.pfError = { clientId: client.id, msg: `El puerto ${proto}/${extPort} ya está en uso.` };
        return;
      }

      this.api.addPortForward({
        clientId: client.id,
        proto,
        extPort,
        intPort: pf.intPort,
      })
        .then(() => {
          this.$set(this.newPf, client.id, { proto: 'tcp', extPort: null, intPort: null });
          this.$set(this.expandedPfClients, client.id, true);
          this.pfError = null;
        })
        .catch((err) => {
          this.pfError = { clientId: client.id, msg: err.message || err.toString() };
        })
        .finally(() => this.refresh().catch(console.error));
    },
    removePortForward(client, index) {
      if (!this.forwardingEnabled) return;
      this.pfDelete = { client, index, rule: client.portForwards[index] };
    },
    confirmRemovePortForward() {
      if (!this.forwardingEnabled || !this.pfDelete) return;
      const { client, rule } = this.pfDelete;
      if (!rule || !rule.id) return;
      this.api.removePortForward({ clientId: client.id, ruleId: rule.id })
        .catch((err) => this.notify(err.message || err.toString()))
        .finally(() => {
          this.pfDelete = null;
          this.refresh().catch(console.error);
        });
    },
    editPortForward(client, index) {
      if (!this.forwardingEnabled) return;
      this.editingPfClientId = client.id;
      this.editingPfIndex = index;
      this.editingPfRule = { ...client.portForwards[index] };
    },
    cancelEditPortForward() {
      this.editingPfClientId = null;
      this.editingPfIndex = null;
      this.editingPfRule = {};
    },
    updatePortForward(client) {
      if (!this.forwardingEnabled) return;
      if (!this.editingPfRule || !this.editingPfRule.extPort || !this.editingPfRule.intPort) return;
      if (!this.editingPfRule.id) return;

      this.pfError = null;

      // Client-side duplicate check (skip current rule being edited)
      const extPort = Number(this.editingPfRule.extPort);
      const proto = this.editingPfRule.proto || 'tcp';
      const editingId = this.editingPfRule.id;
      const alreadyUsed = this.clients.some((c) => Array.isArray(c.portForwards)
        && c.portForwards.some((r) => {
          if (c.id === client.id && r.id === editingId) return false;
          return (r.proto === proto || r.proto === 'both' || proto === 'both') && r.extPort === extPort;
        }));
      if (alreadyUsed) {
        this.pfError = { clientId: client.id, msg: `El puerto ${proto}/${extPort} ya está en uso.` };
        return;
      }

      this.api.updatePortForward({
        clientId: client.id,
        ruleId: editingId,
        proto,
        extPort,
        intPort: this.editingPfRule.intPort,
      })
        .then(() => {
          this.cancelEditPortForward();
          this.pfError = null;
        })
        .catch((err) => {
          this.pfError = { clientId: client.id, msg: err.message || err.toString() };
        })
        .finally(() => this.refresh().catch(console.error));
    },
    // Server Config methods
    openServerConfig() {
      this.serverConfigSaving = false;
      this.api.getServerConfig()
        .then((config) => {
          this.serverConfig = config;
          this.serverConfigEdit = { ...config };
          this.showServerConfig = true;
        })
        .catch((err) => this.notify(err.message || err.toString()));
    },
    closeServerConfig() {
      this.showServerConfig = false;
      this.serverConfigEdit = null;
    },
    saveServerConfig() {
      if (!this.serverConfigEdit) return;
      this.serverConfigSaving = true;
      this.api.updateServerConfig(this.serverConfigEdit)
        .then((result) => {
          this.serverConfig = result;
          const forwardingChanged = this.forwardingEnabled !== (result?.forwardingEnabled === true);
          this.forwardingEnabled = result?.forwardingEnabled === true;
          if (forwardingChanged) this.scheduleAutoProbe();
          this.showServerConfig = false;
          this.serverConfigEdit = null;
          this.notify('Configuración del servidor guardada.', 'success');
          this.refresh().catch(console.error);
        })
        .catch((err) => this.notify(err.message || err.toString()))
        .finally(() => {
          this.serverConfigSaving = false;
        });
    },
    // ── Debounced auto-probe (trailing edge, re-armed not stacked) ────────
    scheduleAutoProbe() {
      clearTimeout(this.autoProbeTimer);
      // No point probing while the kill switch is on: DNAT is not emitted,
      // every verdict would be rule-missing/dnat-local noise.
      if (!this.forwardingEnabled) return;
      this.autoProbeTimer = setTimeout(() => this.runAutoProbe().catch(console.error), 2000);
    },
    async runAutoProbe() {
      if (!this.forwardingEnabled || !this.clients) return;
      const now = Date.now();
      for (const client of this.clients) {
        if (!client.enabled || !this.isPfExpanded(client.id)) continue;
        for (const rule of client.portForwards || []) {
          if (!rule || !rule.id) continue;
          const key = `${client.id}:${rule.id}`;
          // Mirror the server's 30s per-rule rate limit client-side.
          if (now - (this.lastProbeAt[key] || 0) < 30000) continue;
          this.lastProbeAt[key] = now;
          try {
            const result = await this.api.probePortForward({ clientId: client.id, ruleId: rule.id });
            if (!result || !result.verdict) continue;
            const record = { verdict: result.verdict, at: Date.now() };
            // 'tunnel-down' just means the peer device is offline (phones go
            // quiet routinely): the online dot already shows it, a toast on
            // every cycle would be pure noise.
            if (result.verdict === 'tunnel-down') {
              this.$set(this.lastProbeVerdict, key, record);
              continue;
            }
            if (['ok', 'dnat-local', 'indeterminate'].includes(result.verdict)) {
              this.$set(this.lastProbeVerdict, key, record);
              continue;
            }
            // Notify once per verdict transition, not on every cycle, so a
            // persistently unreachable rule shows a single toast.
            const previous = this.lastProbeVerdict[key];
            if (previous && previous.verdict === result.verdict) continue;
            this.$set(this.lastProbeVerdict, key, record);
            this.notify(this.$t('networkPolicy.probeProblem', {
              client: client.name, proto: rule.proto, port: rule.extPort, verdict: result.verdict,
            }), 'error', 8000);
          } catch (err) {
            // 429 rate limits and transient failures are expected; stay quiet.
            console.error(err);
          }
        }
      }
    },
    toggleTheme() {
      this.uiTheme = this.theme === 'dark' ? 'light' : 'dark';
      localStorage.theme = this.uiTheme;
      this.setTheme(this.uiTheme);
    },
    setTheme(theme) {
      const { classList } = document.documentElement;
      const shouldAddDarkClass = theme === 'dark' || (theme === 'auto' && this.prefersDarkScheme.matches);
      classList.toggle('dark', shouldAddDarkClass);
    },
    handlePrefersChange(e) {
      if (localStorage.theme === 'auto') {
        this.setTheme(e.matches ? 'dark' : 'light');
      }
    },
    toggleCharts() {
      localStorage.setItem('uiShowCharts', this.uiShowCharts ? 1 : 0);
      if (this.uiShowCharts) this.schedulePoll(0);
    },
    clientPathId(clientId) {
      return encodeURIComponent(clientId);
    },
    schedulePoll(delay = 1000) {
      clearTimeout(this.pollTimer);
      if (!document.hidden && this.authenticated) {
        this.pollTimer = setTimeout(() => this.poll(), delay);
      }
    },
    async poll() {
      if (this.polling || document.hidden || !this.authenticated) return;
      this.polling = true;
      try {
        await this.refresh({ updateCharts: this.chartsEnabled });
        await this.refreshTraffic().catch((err) => console.error(err));
      } catch (err) {
        console.error(err);
      } finally {
        this.polling = false;
        this.schedulePoll();
      }
    },
    async refreshTraffic() {
      if (!this.authenticated || !this.uiShowTraffic) return;
      let realtime = null;
      try {
        realtime = await this.api.getTrafficRealtime();
      } catch (err) {
        console.error(err);
        return;
      }
      this.traffic = realtime;
      this.trafficPollCount += 1;
      // Summary (totals + peaks) is cheap but only needed every ~10 polls.
      if (this.trafficPollCount % 10 === 1) {
        this.api.getTrafficSummary().then((s) => {
          this.trafficSummary = s;
        }).catch((err) => console.error(err));
      }
      // A historic range shows its own snapshot; refresh it in the
      // background at most every 30s so the 1s poll never overwrites it.
      if (this.trafficRange !== 'realtime' && !this.trafficRangeFetch
        && Date.now() - this.trafficRangeAt > 30000) {
        const range = this.trafficRange;
        this.trafficRangeFetch = this.api.getTrafficHistory(range).then((fetched) => {
          if (this.trafficRange === range) {
            this.trafficRangeData = fetched;
            this.trafficRangeAt = Date.now();
          }
        }).catch((err) => console.error(err)).finally(() => {
          this.trafficRangeFetch = null;
        });
      }
      // Persist the rolling window so the chart survives reloads.
      try {
        const hist = (realtime.history && realtime.history.wg0) || [];
        if (hist.length) localStorage.setItem('wgTrafficHistory', JSON.stringify(hist.slice(-120)));
      } catch (err) {
        console.error(err);
      }
    },
    async setTrafficRange(range) {
      this.trafficRange = range;
      try {
        localStorage.setItem('trafficRange', range);
      } catch (err) {
        console.error(err);
      }
      if (range === 'realtime') {
        this.trafficRangeData = null;
        this.refreshTraffic().catch((err) => console.error(err));
        return;
      }
      try {
        const fetched = await this.api.getTrafficHistory(range);
        // Ignore late responses after the user switched range again.
        if (this.trafficRange === range) {
          this.trafficRangeData = fetched;
          this.trafficRangeAt = Date.now();
        }
      } catch (err) {
        console.error(err);
      }
    },
    toggleTraffic() {
      this.uiShowTraffic = !this.uiShowTraffic;
      try {
        localStorage.setItem('uiShowTraffic', this.uiShowTraffic ? '1' : '0');
      } catch (err) {
        console.error(err);
      }
      if (this.uiShowTraffic) this.refreshTraffic().catch((err) => console.error(err));
    },
    fmtSpeed(bps) {
      if (bps === null || bps === undefined || Number.isNaN(Number(bps))) return '-';
      return `${bytes(Number(bps), 1)}/s`;
    },
    fmtBytes(total) {
      if (total === null || total === undefined || Number.isNaN(Number(total))) return '-';
      return bytes(Number(total), 1);
    },
    handleVisibilityChange() {
      if (document.hidden) clearTimeout(this.pollTimer);
      else this.schedulePoll(0);
    },
    async initialize() {
      const [session, trafficStats, chartTypeRaw, lang] = await Promise.all([
        this.api.getSession(),
        this.api.getUiTrafficStats().catch(() => false),
        this.api.getChartType().catch(() => 0),
        this.api.getLang().catch(() => null),
      ]);
      this.uiTrafficStats = trafficStats === true || trafficStats === 1 || trafficStats === '1' || trafficStats === 'true';
      if (localStorage.getItem('uiShowTraffic') === null && this.uiTrafficStats) {
        this.uiShowTraffic = true;
      }
      const chartType = Number.parseInt(chartTypeRaw, 10);
      this.uiChartType = Number.isInteger(chartType) && UI_CHART_TYPES[chartType] ? chartType : 0;
      if (lang && lang !== localStorage.getItem('lang') && i18n.availableLocales.includes(lang)) {
        localStorage.setItem('lang', lang);
        i18n.locale = lang;
      }
      this.authenticated = session.authenticated;
      this.requiresPassword = session.requiresPassword;
      if (this.authenticated) {
        await this.refresh({ updateCharts: this.chartsEnabled });
        // Paint instantly from the persisted window, then replace with live.
        try {
          const cached = JSON.parse(localStorage.getItem('wgTrafficHistory') || 'null');
          if (Array.isArray(cached) && cached.length) {
            this.traffic = {
              history: { wg0: cached },
              interfaces: [],
              peers: [],
              cpu: {
                system: 0, process: 0, history: [], procHistory: [],
              },
              mem: {
                system: 0, process: 0, history: [], procHistory: [],
              },
              peaks: {
                rxSpeed: 0, txSpeed: 0, cpu: 0, mem: 0,
              },
            };
          }
        } catch (err) {
          console.error(err);
        }
        await this.refreshTraffic().catch((err) => console.error(err));
        this.schedulePoll();
      }
    },
  },
  filters: {
    bytes,
    timeago: (value) => {
      return timeago.format(value, i18n.locale);
    },
  },
  mounted() {
    this.prefersDarkScheme.addListener(this.handlePrefersChange);
    this.setTheme(this.uiTheme);
    this.hydratePersistentState();
    this.api = new API();
    document.addEventListener('visibilitychange', this.handleVisibilityChange);
    window.addEventListener('hashchange', this.applyRoute);
    this.applyRoute();
    this.initialize().catch((err) => this.notify(err.message || err.toString()));
  },
  beforeDestroy() {
    clearTimeout(this.pollTimer);
    clearTimeout(this.autoProbeTimer);
    document.removeEventListener('visibilitychange', this.handleVisibilityChange);
    window.removeEventListener('hashchange', this.applyRoute);
    this.prefersDarkScheme.removeListener(this.handlePrefersChange);
  },
  computed: {
    availablePolicyPeers() {
      if (!this.networkPolicyDialog || !this.clients) return [];
      return this.clients.filter((client) => client.id !== this.networkPolicyDialog.clientId);
    },
    // ── Notification center ─────────────────────────────────────────
    unreadCount() {
      return this.notifications.filter((entry) => entry.at > this.notificationsReadAt).length;
    },
    notificationsSlice() {
      return this.notifications.slice(-30).reverse();
    },
    // ── All-ports consolidated view ─────────────────────────────────
    totalPortRules() {
      if (!this.clients) return 0;
      return this.clients.reduce((sum, client) => sum + ((client.portForwards || []).length), 0);
    },
    allPortsRows() {
      if (!this.clients) return [];
      const search = (this.allPortsSearch || '').trim().toLowerCase();
      const rows = [];
      for (const client of this.clients) {
        for (const rule of client.portForwards || []) {
          const entry = this.lastProbeVerdict[`${client.id}:${rule.id}`];
          rows.push({
            client, rule, verdict: entry ? entry.verdict : null, at: entry ? entry.at : 0,
          });
        }
      }
      return rows.filter((row) => {
        if (this.allPortsProto !== 'all' && row.rule.proto !== this.allPortsProto) return false;
        if (this.allPortsStatus === 'ok' && !['ok', 'dnat-local'].includes(row.verdict)) return false;
        if (this.allPortsStatus === 'problems' && !['unreachable', 'rule-missing'].includes(row.verdict)) return false;
        // Unknown = gray dot: never probed, UDP (not verifiable) or peer offline.
        if (this.allPortsStatus === 'unknown'
          && row.verdict !== null && !['tunnel-down', 'indeterminate'].includes(row.verdict)) return false;
        if (search) {
          const haystack = `${row.client.name} ${row.rule.proto} ${row.rule.extPort} ${row.rule.intPort}`.toLowerCase();
          if (!haystack.includes(search)) return false;
        }
        return true;
      }).sort((a, b) => a.rule.extPort - b.rule.extPort);
    },
    chartTypeConfig() {
      return UI_CHART_TYPES[this.uiChartType] || UI_CHART_TYPES[0];
    },
    chartsEnabled() {
      return this.uiShowCharts && Boolean(this.chartTypeConfig.type);
    },
    chartOptionsTX() {
      const opts = {
        ...this.chartOptions,
        chart: { ...this.chartOptions.chart },
        stroke: { ...this.chartOptions.stroke },
        colors: [CHART_COLORS.tx[this.theme]],
      };
      opts.chart.type = this.chartTypeConfig.type || false;
      opts.stroke.width = this.chartTypeConfig.strokeWidth;
      return opts;
    },
    chartOptionsRX() {
      const opts = {
        ...this.chartOptions,
        chart: { ...this.chartOptions.chart },
        stroke: { ...this.chartOptions.stroke },
        colors: [CHART_COLORS.rx[this.theme]],
      };
      opts.chart.type = this.chartTypeConfig.type || false;
      opts.stroke.width = this.chartTypeConfig.strokeWidth;
      return opts;
    },
    // ── Traffic dashboard (Plex-style) ──────────────────────────────
    // trafficBw is the DISPLAYED window: the range snapshot when a
    // historic range is active, otherwise the realtime rolling window.
    // Averages/peaks below therefore describe what the chart shows.
    trafficBw() {
      if (this.trafficRange !== 'realtime' && this.trafficRangeData
        && Array.isArray(this.trafficRangeData.wg0) && this.trafficRangeData.wg0.length) {
        return this.trafficRangeData.wg0;
      }
      const hist = (this.traffic && this.traffic.history && this.traffic.history.wg0) || [];
      return hist;
    },
    trafficBwSeries() {
      // Named from the clients' point of view: what wg0 transmits is what
      // clients download. x/y pairs so the tooltip shows the hour.
      return [
        { key: 'download', name: this.$t('ui.download'), data: this.trafficBw.map((s) => ({ x: s.t, y: Math.round(s.tx || 0) })) },
        { key: 'upload', name: this.$t('ui.upload'), data: this.trafficBw.map((s) => ({ x: s.t, y: Math.round(s.rx || 0) })) },
      ];
    },
    trafficChartSeries() {
      return this.trafficBwSeries.filter((s) => !this.trafficHidden[s.key]);
    },
    trafficChartOptions() {
      const c = THEME_COLORS[this.theme] || THEME_COLORS.dark;
      return { ...this.trafficPanelOptions, colors: this.trafficChartSeries.map((s) => c[s.key]) };
    },
    // Legend numbers for the displayed window: current, average, peak and
    // bytes transferred (rate integrated over each sample interval).
    trafficStats() {
      const hist = this.trafficBw;
      const stats = (field) => {
        if (!hist.length) {
          return {
            now: 0, avg: 0, peak: 0, total: 0,
          };
        }
        let total = 0;
        for (let i = 1; i < hist.length; i += 1) {
          total += (hist[i][field] || 0) * Math.max(0, (hist[i].t - hist[i - 1].t) / 1000);
        }
        return {
          now: hist[hist.length - 1][field] || 0,
          avg: hist.reduce((a, s) => a + (s[field] || 0), 0) / hist.length,
          peak: Math.max(...hist.map((s) => s[field] || 0)),
          total,
        };
      };
      return { download: stats('tx'), upload: stats('rx') };
    },
    viewClient() {
      if (!this.clients || !this.viewClientId) return null;
      return this.clients.find((client) => client.id === this.viewClientId) || null;
    },
    onlineCount() {
      return (this.clients || []).filter((client) => client.enabled && client.online).length;
    },
    portalUrl() {
      return `${window.location.origin}${window.location.pathname.replace(/[^/]*$/, '')}portal.html`;
    },
    ownerByClient() {
      const owners = {};
      for (const user of this.users) for (const clientId of user.clientIds) owners[clientId] = user;
      return owners;
    },
    filteredClients() {
      const search = (this.clientSearch || '').trim().toLowerCase();
      return (this.clients || []).filter((client) => {
        if (search && !`${client.name} ${client.address} ${client.addressV6 || ''}`.toLowerCase().includes(search)) return false;
        if (this.clientFilter === 'online') return client.enabled && client.online;
        if (this.clientFilter === 'offline') return client.enabled && !client.online;
        if (this.clientFilter === 'disabled') return !client.enabled;
        return true;
      });
    },
    trafficCpuSeries() {
      const ranged = this.trafficRange !== 'realtime' && this.trafficRangeData;
      const cpu = (this.traffic && this.traffic.cpu) || {};
      const hist = ranged && ranged.cpu && ranged.cpu.length ? ranged.cpu : (cpu.history || []);
      const proc = ranged && ranged.procCpu && ranged.procCpu.length
        ? ranged.procCpu
        : (cpu.procHistory || []);
      const point = (s) => ({ x: s.t, y: Number((s.v || 0).toFixed(2)) });
      return [
        { name: 'SISTEMA', data: hist.map(point) },
        { name: 'WG-EASY', data: proc.map(point) },
      ];
    },
    trafficMemSeries() {
      const ranged = this.trafficRange !== 'realtime' && this.trafficRangeData;
      const mem = (this.traffic && this.traffic.mem) || {};
      const hist = ranged && ranged.mem && ranged.mem.length ? ranged.mem : (mem.history || []);
      const proc = ranged && ranged.procMem && ranged.procMem.length
        ? ranged.procMem
        : (mem.procHistory || []);
      const point = (s) => ({ x: s.t, y: Number((s.v || 0).toFixed(2)) });
      return [
        { name: 'SISTEMA', data: hist.map(point) },
        { name: 'WG-EASY', data: proc.map(point) },
      ];
    },
    trafficPanelOptions() {
      const dark = this.theme === 'dark';
      const c = THEME_COLORS[this.theme] || THEME_COLORS.dark;
      return {
        chart: {
          background: 'transparent',
          type: 'area',
          toolbar: { show: false },
          animations: { enabled: false },
          zoom: { enabled: false },
          fontFamily: 'inherit',
        },
        colors: [c.download, c.upload],
        stroke: { curve: 'smooth', width: 2 },
        fill: { type: 'solid', opacity: 0.12 },
        markers: { size: 0, hover: { size: 4 } },
        dataLabels: { enabled: false },
        grid: {
          show: true,
          borderColor: c.grid,
          strokeDashArray: 0,
          xaxis: { lines: { show: true } },
          padding: {
            left: 8, right: 8, top: 0, bottom: 0,
          },
        },
        xaxis: {
          type: 'datetime',
          labels: { show: true, datetimeUTC: false, style: { colors: c.text, fontSize: '12px' } },
          axisTicks: { show: false },
          axisBorder: { show: false },
          tooltip: { enabled: false },
        },
        yaxis: {
          min: 0,
          forceNiceScale: true,
          labels: {
            show: true,
            style: { colors: c.text, fontSize: '12px' },
            formatter: (v) => `${bytes(v, 0)}/s`,
          },
        },
        tooltip: {
          enabled: true,
          shared: true,
          theme: dark ? 'dark' : 'light',
          x: { format: 'dd MMM HH:mm' },
          y: { formatter: (v) => `${bytes(v, 1)}/s` },
        },
        legend: { show: false },
      };
    },
    trafficPctOptions() {
      const base = this.trafficPanelOptions;
      const c = THEME_COLORS[this.theme] || THEME_COLORS.dark;
      return {
        ...base,
        xaxis: { ...base.xaxis, labels: { show: false } },
        yaxis: {
          min: 0,
          max: 100,
          tickAmount: 2,
          labels: {
            show: true,
            style: { colors: c.text, fontSize: '11px' },
            formatter: (v) => `${Math.round(v)}%`,
          },
        },
        tooltip: {
          enabled: true,
          theme: this.theme === 'dark' ? 'dark' : 'light',
          x: { format: 'dd MMM HH:mm' },
          y: { formatter: (v) => `${Number(v).toFixed(2)}%` },
        },
      };
    },
    // CPU/RAM stay neutral (system = grey, wg-easy = blue) so they never
    // compete with the traffic colours.
    trafficCpuOptions() {
      const c = THEME_COLORS[this.theme] || THEME_COLORS.dark;
      return { ...this.trafficPctOptions, colors: [c.muted, c.download] };
    },
    trafficMemOptions() {
      return this.trafficCpuOptions;
    },
    trafficAvg() {
      const hist = this.trafficBw;
      if (!hist.length) return { rx: 0, tx: 0 };
      return {
        rx: hist.reduce((a, s) => a + (s.rx || 0), 0) / hist.length,
        tx: hist.reduce((a, s) => a + (s.tx || 0), 0) / hist.length,
      };
    },
    trafficPeak() {
      if (!this.trafficBw.length) return { rx: 0, tx: 0 };
      return {
        rx: Math.max(...this.trafficBw.map((s) => s.rx || 0)),
        tx: Math.max(...this.trafficBw.map((s) => s.tx || 0)),
      };
    },
    trafficPeakMax() {
      return Math.max(this.trafficPeak.rx, this.trafficPeak.tx);
    },
    updateCharts() {
      return this.chartsEnabled;
    },
    theme() {
      if (this.uiTheme === 'auto') {
        return this.prefersDarkScheme.matches ? 'dark' : 'light';
      }
      return this.uiTheme;
    },
  },
});
