/* eslint-env browser */

'use strict';

// User portal: sign in with an access code, see linked profiles, and create
// one IPv4 and one IPv6 profile, each on a port picked from server offers.
(() => {
  const STORAGE_KEY = 'wgpmPortalCode';
  const FAMILY_LABEL = { v4: 'IPv4', v6: 'IPv6' };
  const $ = (id) => document.getElementById(id);
  const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);

  let code = null;
  try {
    code = sessionStorage.getItem(STORAGE_KEY);
  } catch { /* storage blocked */ }
  let me = null;
  const offers = {}; // family -> offered ports, while that create form is open

  function signOut() {
    code = null;
    me = null;
    try {
      sessionStorage.removeItem(STORAGE_KEY);
    } catch { /* storage blocked */ }
    $('home').hidden = true;
    $('login').hidden = false;
  }

  const request = async (path, { method = 'GET', body, as = 'json' } = {}) => {
    const res = await fetch(`./api/portal${path}`, {
      method,
      headers: { Authorization: `Bearer ${code}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (res.status === 401) {
      signOut();
      throw new Error('El código no es válido o fue reemplazado.');
    }
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.message || data.error || res.statusText);
    }
    return as === 'text' ? res.text() : res.json();
  };

  const showError = (el, err) => {
    el.textContent = err ? (err.message || String(err)) : '';
    el.hidden = !err;
  };

  const forwardLine = (profile, rule) => {
    const proto = rule.proto === 'both' ? 'TCP y UDP' : rule.proto.toUpperCase();
    const device = profile.family === 'v6' && profile.addressV6 ? `[${profile.addressV6}]` : profile.address;
    return `<div class="mono">${esc(me.host)}:<strong>${rule.extPort}</strong> <span class="muted">→</span> ${esc(device)}:${rule.intPort} <span class="muted small">${proto}</span></div>`;
  };

  const profileCard = (profile) => {
    const kind = profile.family ? FAMILY_LABEL[profile.family] : 'Vinculado';
    let status = 'Sin conexión';
    if (!profile.enabled) status = 'Desactivado';
    else if (profile.online) status = 'Conectado';
    const address = profile.family === 'v6' ? profile.addressV6 : [profile.address, profile.family ? null : profile.addressV6].filter(Boolean).join(' · ');
    const rules = profile.portForwards.length
      ? profile.portForwards.map((rule) => forwardLine(profile, rule)).join('')
      : '<div class="muted">Sin puertos abiertos.</div>';
    const actions = profile.downloadableConfig
      ? `<button type="button" class="btn" data-download="${esc(profile.id)}">Descargar .conf</button>
         <button type="button" class="btn" data-qr="${esc(profile.id)}">Mostrar QR</button>`
      : '<span class="small muted">El servidor no guarda la clave privada de este perfil; pide la configuración a tu administrador.</span>';
    return `<section class="box" style="flex:1 1 340px;min-width:0">
      <div class="box-head"><h2>${esc(profile.name)}</h2><span class="badge">${kind}</span><span class="badge ${profile.enabled && profile.online ? 'ok' : ''}">${status}</span></div>
      <div class="box-body stack">
        <dl class="kv">
          <dt>Dirección en la VPN</dt><dd class="mono">${esc(address)}</dd>
          <dt>Puertos abiertos</dt><dd>${rules}</dd>
        </dl>
        <div class="row">${actions}</div>
      </div>
    </section>`;
  };

  const createForm = (family) => {
    const ports = offers[family];
    if (!ports) {
      return `<div class="row"><span class="grow">Perfil ${FAMILY_LABEL[family]}: aún no lo tienes.</span>
        <button type="button" class="btn btn-primary" data-offer="${family}">Crear perfil ${FAMILY_LABEL[family]}</button></div>`;
    }
    if (!ports.length) return `<div class="notice">No hay puertos libres para el perfil ${FAMILY_LABEL[family]}. Avísale a tu administrador.</div>`;
    return `<form class="stack" data-create="${family}" style="border:1px solid var(--border);border-radius:6px;padding:12px">
      <fieldset style="margin:0;padding:0;border:0">
        <legend style="padding:0;margin-bottom:6px;font-weight:600">Elige el puerto del perfil ${FAMILY_LABEL[family]}</legend>
        <div class="row">${ports.map((port, i) => `<label class="choice mono"><input type="radio" name="port" value="${port}" ${i === 0 ? 'checked' : ''} />${port}</label>`).join('')}</div>
      </fieldset>
      <p class="small muted" style="margin:0">Se abre en TCP y UDP hacia el mismo puerto de tu dispositivo. Después solo tu administrador puede cambiarlo.</p>
      <div class="row">
        <button type="submit" class="btn btn-primary">Crear perfil ${FAMILY_LABEL[family]}</button>
        <button type="button" class="btn-link" data-offer="${family}">Otras opciones</button>
        <button type="button" class="btn-link" data-cancel="${family}">Cancelar</button>
      </div>
    </form>`;
  };

  const render = () => {
    $('user-name').textContent = me.name;
    $('profiles').innerHTML = me.profiles.length
      ? me.profiles.map(profileCard).join('')
      : '<p class="muted" style="margin:0">Aún no tienes perfiles.</p>';
    const families = ['v4', 'v6'].filter((family) => !me.profiles.some((profile) => profile.family === family));
    const creatable = families.filter((family) => family === 'v4' || me.ipv6Available);
    $('create').hidden = me.canCreate ? !creatable.length : !families.length;
    if (!me.canCreate) {
      $('create-body').innerHTML = '<p class="muted" style="margin:0">Tu administrador no te permite crear perfiles; pídele uno.</p>';
      return;
    }
    $('create-body').innerHTML = creatable.map(createForm).join('')
      + (families.includes('v6') && !me.ipv6Available ? '<p class="small muted" style="margin:0">Este servidor no tiene IPv6 activado.</p>' : '');
  };

  const load = async () => {
    me = await request('/me');
    $('login').hidden = true;
    $('home').hidden = false;
    render();
  };

  const download = async (profile) => {
    const text = await request(`/profiles/${encodeURIComponent(profile.id)}/configuration`, { as: 'text' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    link.download = `${profile.name.replace(/[^\w.-]/g, '_').slice(0, 32)}.conf`;
    link.click();
    URL.revokeObjectURL(link.href);
  };

  const showQr = async (profile) => {
    const svg = await request(`/profiles/${encodeURIComponent(profile.id)}/qrcode.svg`, { as: 'text' });
    const img = $('qr-img');
    if (img.src) URL.revokeObjectURL(img.src);
    img.src = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' }));
    $('qr').hidden = false;
  };

  $('login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    code = new FormData(event.target).get('code').trim();
    try {
      await load();
      try {
        sessionStorage.setItem(STORAGE_KEY, code);
      } catch { /* storage blocked */ }
      showError($('login-error'), null);
    } catch (err) {
      signOut();
      showError($('login-error'), err);
    }
  });

  $('logout').addEventListener('click', signOut);
  $('qr').addEventListener('click', (event) => {
    if (event.target.closest('[data-close]')) $('qr').hidden = true;
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') $('qr').hidden = true;
  });

  $('home').addEventListener('click', async (event) => {
    const button = event.target.closest('button');
    if (!button) return;
    const profile = me && me.profiles.find((candidate) => candidate.id === (button.dataset.download || button.dataset.qr));
    try {
      if (button.dataset.offer) {
        // The server keeps one offer per user: only one create form at a time.
        const { ports } = await request('/port-options');
        for (const key of Object.keys(offers)) delete offers[key];
        offers[button.dataset.offer] = ports;
        render();
      } else if (button.dataset.cancel) {
        delete offers[button.dataset.cancel];
        render();
      } else if (button.dataset.download && profile) {
        await download(profile);
      } else if (button.dataset.qr && profile) {
        await showQr(profile);
      }
      showError($('error'), null);
    } catch (err) {
      showError($('error'), err);
    }
  });

  $('home').addEventListener('submit', async (event) => {
    event.preventDefault();
    const family = event.target.dataset.create;
    const port = Number(new FormData(event.target).get('port'));
    event.target.querySelector('[type=submit]').disabled = true;
    try {
      await request('/profiles', { method: 'POST', body: { family, port } });
      delete offers[family];
      await load();
      showError($('error'), null);
    } catch (err) {
      delete offers[family];
      render();
      showError($('error'), err);
    }
  });

  if (code) load().catch(() => signOut());
  else signOut();
})();
