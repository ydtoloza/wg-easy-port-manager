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

new Vue({
  el: '#app',
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

    // Toast notifications
    toasts: [],
    _toastId: 0,

    // Server config (global IP settings)
    showServerConfig: false,
    serverConfig: null,
    serverConfigEdit: null,
    serverConfigSaving: false,

    currentRelease: null,
    latestRelease: null,

    uiTrafficStats: false,

    uiChartType: 0,
    uiShowCharts: localStorage.getItem('uiShowCharts') === '1',
    uiTheme: localStorage.theme || 'auto',
    prefersDarkScheme: window.matchMedia('(prefers-color-scheme: dark)'),

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
      const id = ++this._toastId;
      this.toasts.push({ id, msg, type });
      setTimeout(() => this.dismissToast(id), duration);
    },
    dismissToast(id) {
      const idx = this.toasts.findIndex(t => t.id === id);
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
      this.$set(this.expandedPfClients, clientId, !this.expandedPfClients[clientId]);
    },
    isPortConflicting(client) {
      const pf = this.newPf[client.id];
      if (!pf || !pf.extPort) return false;
      const port = Number(pf.extPort);
      const proto = pf.proto || 'tcp';
      return this.clients.some(c =>
        Array.isArray(c.portForwards) &&
        c.portForwards.some(r => 
          (r.proto === proto || r.proto === 'both' || proto === 'both') && 
          r.extPort === port
        )
      );
    },
    async refresh({
      updateCharts = false,
    } = {}) {
      if (!this.authenticated) return;

      const clients = await this.api.getClients();
      this.clients = clients.map((client) => {
        if (client.name.includes('@') && client.name.includes('.')) {
          client.avatar = `https://gravatar.com/avatar/${sha256(client.name.toLowerCase().trim())}.jpg`;
        }

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
          return this.refresh();
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
      fetch(`./api/wireguard/client/${client.id}/configuration`)
        .then(res => res.text())
        .then(text => {
          this.configDialog = { text };
          this.copyConfigSuccess = false;
        })
        .catch(err => this.notify('Error al obtener la configuración: ' + err.message));
    },
    copyConfigToClipboard() {
      if (!this.configDialog || !this.configDialog.text) return;
      navigator.clipboard.writeText(this.configDialog.text).then(() => {
        this.copyConfigSuccess = true;
        setTimeout(() => { this.copyConfigSuccess = false; }, 3000);
      }).catch(err => {
        this.notify('Error al copiar al portapapeles: ' + err.message);
      });
    },
    addPortForward(client) {
      const pf = this.newPf[client.id];
      if (!pf || !pf.extPort || !pf.intPort) return;

      this.pfError = null;

      // Client-side duplicate check (all peers)
      const extPort = Number(pf.extPort);
      const proto = pf.proto || 'tcp';
      const alreadyUsed = this.clients.some(c =>
        Array.isArray(c.portForwards) &&
        c.portForwards.some(r => 
          (r.proto === proto || r.proto === 'both' || proto === 'both') && 
          r.extPort === extPort
        )
      );
      if (alreadyUsed) {
        this.pfError = { clientId: client.id, msg: `El puerto ${proto}/${extPort} ya está en uso.` };
        return;
      }

      this.api.addPortForward({
        clientId: client.id,
        proto,
        extPort,
        intPort: pf.intPort
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
      this.pfDelete = { client, index, rule: client.portForwards[index] };
    },
    confirmRemovePortForward() {
      if (!this.pfDelete) return;
      const { client, index } = this.pfDelete;
      this.api.removePortForward({ clientId: client.id, index })
        .catch((err) => this.notify(err.message || err.toString()))
        .finally(() => {
          this.pfDelete = null;
          this.refresh().catch(console.error);
        });
    },
    editPortForward(client, index) {
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
      if (!this.editingPfRule || !this.editingPfRule.extPort || !this.editingPfRule.intPort) return;

      this.pfError = null;

      // Client-side duplicate check (skip current rule being edited)
      const extPort = Number(this.editingPfRule.extPort);
      const proto = this.editingPfRule.proto || 'tcp';
      const idx = this.editingPfIndex;
      const alreadyUsed = this.clients.some(c =>
        Array.isArray(c.portForwards) &&
        c.portForwards.some((r, i) => {
          if (c.id === client.id && i === idx) return false;
          return (r.proto === proto || r.proto === 'both' || proto === 'both') && r.extPort === extPort;
        })
      );
      if (alreadyUsed) {
        this.pfError = { clientId: client.id, msg: `El puerto ${proto}/${extPort} ya está en uso.` };
        return;
      }

      this.api.updatePortForward({
        clientId: client.id,
        index: idx,
        proto,
        extPort,
        intPort: this.editingPfRule.intPort
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
          this.showServerConfig = false;
          this.serverConfigEdit = null;
          this.notify('Configuración del servidor guardada.', 'success');
        })
        .catch((err) => this.notify(err.message || err.toString()))
        .finally(() => {
          this.serverConfigSaving = false;
        });
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
    this.api.getSession()
      .then((session) => {
        this.authenticated = session.authenticated;
        this.requiresPassword = session.requiresPassword;
        this.refresh({
          updateCharts: this.updateCharts,
        }).catch((err) => {
          this.notify(err.message || err.toString());
        });
      })
      .catch((err) => {
        this.notify(err.message || err.toString());
      });

    setInterval(() => {
      this.refresh({
        updateCharts: this.updateCharts,
      }).catch(console.error);
    }, 1000);

    this.api.getuiTrafficStats()
      .then((res) => {
        this.uiTrafficStats = res;
      })
      .catch(() => {
        this.uiTrafficStats = false;
      });

    this.api.getChartType()
      .then((res) => {
        this.uiChartType = parseInt(res, 10);
      })
      .catch(() => {
        this.uiChartType = 0;
      });

    Promise.resolve().then(async () => {
      const lang = await this.api.getLang();
      if (lang !== localStorage.getItem('lang') && i18n.availableLocales.includes(lang)) {
        localStorage.setItem('lang', lang);
        i18n.locale = lang;
      }

      const currentRelease = await this.api.getRelease();
      const latestRelease = await fetch('https://wg-easy.github.io/wg-easy/changelog.json')
        .then((res) => res.json())
        .then((releases) => {
          const releasesArray = Object.entries(releases).map(([version, changelog]) => ({
            version: parseInt(version, 10),
            changelog,
          }));
          releasesArray.sort((a, b) => {
            return b.version - a.version;
          });

          return releasesArray[0];
        });

      if (currentRelease >= latestRelease.version) return;

      this.currentRelease = currentRelease;
      this.latestRelease = latestRelease;
    }).catch((err) => console.error(err));
  },
  computed: {
    chartOptionsTX() {
      const opts = {
        ...this.chartOptions,
        colors: [CHART_COLORS.tx[this.theme]],
      };
      opts.chart.type = UI_CHART_TYPES[this.uiChartType].type || false;
      opts.stroke.width = UI_CHART_TYPES[this.uiChartType].strokeWidth;
      return opts;
    },
    chartOptionsRX() {
      const opts = {
        ...this.chartOptions,
        colors: [CHART_COLORS.rx[this.theme]],
      };
      opts.chart.type = UI_CHART_TYPES[this.uiChartType].type || false;
      opts.stroke.width = UI_CHART_TYPES[this.uiChartType].strokeWidth;
      return opts;
    },
    updateCharts() {
      return this.uiChartType > 0 && this.uiShowCharts;
    },
    theme() {
      if (this.uiTheme === 'auto') {
        return this.prefersDarkScheme.matches ? 'dark' : 'light';
      }
      return this.uiTheme;
    },
  },
});
