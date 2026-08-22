/* eslint-disable no-unused-vars */
/* eslint-disable no-undef */

'use strict';

class API {

  async call({ method, path, body }) {
    const res = await fetch(`./api${path}`, {
      method,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
      },
      body: body
        ? JSON.stringify(body)
        : undefined,
    });

    if (res.status === 204) {
      return undefined;
    }

    const text = await res.text();
    let json;
    try {
      json = text ? JSON.parse(text) : undefined;
    } catch {
      if (!res.ok) throw new Error(text || res.statusText);
      throw new Error('El servidor devolvió una respuesta inválida.');
    }

    if (!res.ok) {
      throw new Error((json && (json.error || json.message)) || res.statusText);
    }

    return json;
  }

  async getRelease() {
    return this.call({
      method: 'get',
      path: '/release',
    });
  }

  async getLang() {
    return this.call({
      method: 'get',
      path: '/lang',
    });
  }

  async getUiTrafficStats() {
    return this.call({
      method: 'get',
      path: '/ui-traffic-stats',
    });
  }

  async getChartType() {
    return this.call({
      method: 'get',
      path: '/ui-chart-type',
    });
  }

  async getSession() {
    return this.call({
      method: 'get',
      path: '/session',
    });
  }

  async createSession({ password }) {
    return this.call({
      method: 'post',
      path: '/session',
      body: { password },
    });
  }

  async deleteSession() {
    return this.call({
      method: 'delete',
      path: '/session',
    });
  }

  async getClients() {
    return this.call({
      method: 'get',
      path: '/wireguard/client',
    }).then((clients) => clients.map((client) => ({
      ...client,
      createdAt: new Date(client.createdAt),
      updatedAt: new Date(client.updatedAt),
      latestHandshakeAt: client.latestHandshakeAt !== null
        ? new Date(client.latestHandshakeAt)
        : null,
    })));
  }

  async createClient({ name }) {
    return this.call({
      method: 'post',
      path: '/wireguard/client',
      body: { name },
    });
  }

  async deleteClient({ clientId }) {
    const id = encodeURIComponent(clientId);
    return this.call({
      method: 'delete',
      path: `/wireguard/client/${id}`,
    });
  }

  async enableClient({ clientId }) {
    const id = encodeURIComponent(clientId);
    return this.call({
      method: 'post',
      path: `/wireguard/client/${id}/enable`,
    });
  }

  async disableClient({ clientId }) {
    const id = encodeURIComponent(clientId);
    return this.call({
      method: 'post',
      path: `/wireguard/client/${id}/disable`,
    });
  }

  async updateClientName({ clientId, name }) {
    const id = encodeURIComponent(clientId);
    return this.call({
      method: 'put',
      path: `/wireguard/client/${id}/name/`,
      body: { name },
    });
  }

  async updateClientAddress({ clientId, address, addressV6 }) {
    const id = encodeURIComponent(clientId);
    return this.call({
      method: 'put',
      path: `/wireguard/client/${id}/address/`,
      body: { address, addressV6 },
    });
  }

  async restoreConfiguration(file) {
    return this.call({
      method: 'put',
      path: '/wireguard/restore',
      body: { file },
    });
  }

  async addPortForward({
    clientId, proto, extPort, intPort,
  }) {
    const id = encodeURIComponent(clientId);
    return this.call({
      method: 'post',
      path: `/wireguard/client/${id}/port-forward`,
      body: { proto, extPort, intPort },
    });
  }

  async removePortForward({ clientId, index }) {
    const id = encodeURIComponent(clientId);
    return this.call({
      method: 'delete',
      path: `/wireguard/client/${id}/port-forward/${index}`,
    });
  }

  async updatePortForward({
    clientId, index, proto, extPort, intPort,
  }) {
    const id = encodeURIComponent(clientId);
    return this.call({
      method: 'put',
      path: `/wireguard/client/${id}/port-forward/${index}`,
      body: { proto, extPort, intPort },
    });
  }

  async getServerConfig() {
    return this.call({
      method: 'get',
      path: '/wireguard/server-config',
    });
  }

  async updateServerConfig(settings) {
    return this.call({
      method: 'put',
      path: '/wireguard/server-config',
      body: settings,
    });
  }

}
