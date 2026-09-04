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
    lastProbeVerdict: {},

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
    // Opt-in: the panel stays hidden until UI_TRAFFIC_STATS=true or the
    // user toggles it (persisted). Production with default flags keeps the
    // exact previous layout (max-w-3xl, single column).
    uiShowTraffic: localStorage.getItem('uiShowTraffic') === '1',

    uiChartType: 0,
    uiShowCharts: localStorage.getItem('uiShowCharts') === '1',
    uiTheme: localStorage.theme || 'auto',
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
    },
    dismissToast(id) {
      const idx = this.toasts.findIndex((t) => t.id === id);
      if (idx !== -1) this.toasts.splice(idx, 1);
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
      if (expanded) this.scheduleAutoProbe();
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
      const [clients, serverConfig] = await Promise.all([
        this.api.getClients(),
        this.api.getServerConfig().catch(() => null),
      ]);
      if (generation !== this.refreshGeneration) return;
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

        // Auto-expand if client has port forwards
        if (client.portForwards && client.portForwards.length > 0 && this.expandedPfClients[client.id] === undefined) {
          this.$set(this.expandedPfClients, client.id, true);
        }

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
            // 'tunnel-down' just means the peer device is offline (phones go
            // quiet routinely): the online dot already shows it, a toast on
            // every cycle would be pure noise.
            if (result.verdict === 'tunnel-down') {
              this.lastProbeVerdict[key] = result.verdict;
              continue;
            }
            if (['ok', 'dnat-local', 'indeterminate'].includes(result.verdict)) {
              this.lastProbeVerdict[key] = result.verdict;
              continue;
            }
            // Notify once per verdict transition, not on every cycle, so a
            // persistently unreachable rule shows a single toast.
            if (this.lastProbeVerdict[key] === result.verdict) continue;
            this.lastProbeVerdict[key] = result.verdict;
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
      const themes = ['light', 'dark', 'auto'];
      const currentIndex = themes.indexOf(this.uiTheme);
      const newIndex = (currentIndex + 1) % themes.length;
      this.uiTheme = themes[newIndex];
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
    this.api = new API();
    document.addEventListener('visibilitychange', this.handleVisibilityChange);
    this.initialize().catch((err) => this.notify(err.message || err.toString()));
  },
  beforeDestroy() {
    clearTimeout(this.pollTimer);
    clearTimeout(this.autoProbeTimer);
    document.removeEventListener('visibilitychange', this.handleVisibilityChange);
    this.prefersDarkScheme.removeListener(this.handlePrefersChange);
  },
  computed: {
    availablePolicyPeers() {
      if (!this.networkPolicyDialog || !this.clients) return [];
      return this.clients.filter((client) => client.id !== this.networkPolicyDialog.clientId);
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
      // x/y pairs so the tooltip shows the hour instead of the point index.
      return [
        { name: 'REMOTO (RX)', data: this.trafficBw.map((s) => ({ x: s.t, y: Math.round(s.rx || 0) })) },
        { name: 'LOCAL (TX)', data: this.trafficBw.map((s) => ({ x: s.t, y: Math.round(s.tx || 0) })) },
      ];
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
      return {
        chart: {
          background: 'transparent',
          type: 'line',
          toolbar: { show: false },
          animations: { enabled: false },
          zoom: { enabled: false },
        },
        colors: ['#3b82f6', '#f59e0b'],
        // First series solid, second dashed: instant TX/RX distinction even
        // at a glance or in grayscale. NOTE: no `fill` key here — ApexCharts
        // 3.49 drops the whole series when fill.opacity is 0 on line charts.
        stroke: { curve: 'smooth', width: 3, dashArray: [0, 7] },
        markers: { size: 0, hover: { size: 4 } },
        dataLabels: { enabled: false },
        grid: {
          show: true,
          borderColor: dark ? '#525252' : '#e5e7eb',
          strokeDashArray: 0,
          xaxis: { lines: { show: false } },
          padding: {
            left: 8, right: 8, top: 0, bottom: 0,
          },
        },
        xaxis: {
          type: 'datetime',
          labels: { show: false },
          axisTicks: { show: false },
          axisBorder: { show: false },
          tooltip: { enabled: false },
        },
        yaxis: {
          min: 0,
          labels: {
            show: true,
            style: { colors: dark ? '#d1d5db' : '#4b5563', fontSize: '10px' },
            formatter: (v) => bytes(v, 0),
          },
        },
        tooltip: {
          enabled: true,
          theme: dark ? 'dark' : 'light',
          x: { format: 'dd MMM HH:mm' },
          y: { formatter: (v) => `${bytes(v, 1)}/s` },
        },
        legend: { show: false },
      };
    },
    trafficPctOptions() {
      const base = this.trafficPanelOptions;
      return {
        ...base,
        yaxis: {
          min: 0,
          max: 100,
          labels: {
            show: true,
            style: { colors: this.theme === 'dark' ? '#d1d5db' : '#4b5563', fontSize: '10px' },
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
    trafficCpuOptions() {
      // Brighter strokes in dark mode so thin lines don't wash out.
      const dark = this.theme === 'dark';
      return { ...this.trafficPctOptions, colors: dark ? ['#fb7185', '#6ee7b7'] : ['#e11d48', '#16a34a'] };
    },
    trafficMemOptions() {
      const dark = this.theme === 'dark';
      return { ...this.trafficPctOptions, colors: dark ? ['#d8b4fe', '#5eead4'] : ['#9333ea', '#0d9488'] };
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
