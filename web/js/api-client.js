/**
 * SENTINELLE — Client API
 * ========================
 * Communication avec le backend Flask.
 * Toutes les routes API en un seul endroit.
 */

'use strict';

const api = (() => {

  let _baseUrl = window.location.origin;
  let _apiKey  = '';

  function _headers(extra = {}) {
    const h = { 'Content-Type': 'application/json' };
    if (_apiKey) h['X-API-Key'] = _apiKey;
    return { ...h, ...extra };
  }

  async function _fetch(path, options = {}) {
    const url = `${_baseUrl}${path}`;
    try {
      const response = await fetch(url, {
        ...options,
        headers: _headers(options.headers || {}),
      });

      if (!response.ok) {
        let msg = `Erreur serveur (${response.status})`;
        try {
          const data = await response.json();
          if (data.error) msg = data.error;
        } catch (_) {}
        throw new Error(msg);
      }

      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('text/csv')) return response.blob();
      return response.json();

    } catch (err) {
      if (err.name === 'TypeError') {
        throw new Error('Serveur inaccessible — vérifiez que SENTINELLE est démarré.');
      }
      throw err;
    }
  }

  return {

    setBaseUrl(url) { _baseUrl = url.replace(/\/$/, ''); },
    setApiKey(key)  { _apiKey  = key; },
    getBaseUrl()    { return _baseUrl; },

    // ── Santé ──
    async getHealth()  { return _fetch('/api/health'); },

    // ── Stats ──
    async getStats()   { return _fetch('/api/stats');  },

    // ── Alertes ──
    async getAlerts(limit = 100) {
      return _fetch(`/api/alerts?limit=${limit}`);
    },

    async getAlertDetails(alertId) {
      return _fetch(`/api/alerts/${encodeURIComponent(alertId)}`);
    },

    async acknowledgeAlert(alertId, analyst = 'analyste') {
      return _fetch(`/api/alerts/${encodeURIComponent(alertId)}/acknowledge`, {
        method: 'POST',
        body: JSON.stringify({ analyst }),
      });
    },

    async resolveAlert(alertId, resolution = '') {
      return _fetch(`/api/alerts/${encodeURIComponent(alertId)}/resolve`, {
        method: 'POST',
        body: JSON.stringify({ resolution }),
      });
    },

    async markFalsePositive(alertId, reason = '') {
      return _fetch(`/api/alerts/${encodeURIComponent(alertId)}/false-positive`, {
        method: 'POST',
        body: JSON.stringify({ reason }),
      });
    },

    /** Déclenche le téléchargement CSV dans le navigateur. */
    async exportAlertsCsv() {
      const blob = await _fetch('/api/alerts/export');
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `sentinelle_alertes_${new Date().toISOString().slice(0,10)}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    },

    // ── Surveillance ──
    async startMonitoring() {
      return _fetch('/api/start', { method: 'POST' });
    },
    async stopMonitoring() {
      return _fetch('/api/stop', { method: 'POST' });
    },

    // ── Top sources ──
    async getTopSources() {
      return _fetch('/api/top-sources');
    },

    // ── Blacklist ──
    async getBlacklist() {
      return _fetch('/api/blacklist');
    },
    async addToBlacklist(ip) {
      return _fetch('/api/blacklist', { method: 'POST', body: JSON.stringify({ ip }) });
    },
    async removeFromBlacklist(ip) {
      return _fetch(`/api/blacklist/${encodeURIComponent(ip)}`, { method: 'DELETE' });
    },

    // ── Whitelist ──
    async addToWhitelist(ip) {
      return _fetch('/api/whitelist', { method: 'POST', body: JSON.stringify({ ip }) });
    },
  };

})();
