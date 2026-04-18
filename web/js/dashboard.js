/**
 * SENTINELLE — Dashboard JS
 * ==========================
 * Gestion des graphiques, du polling et de toutes les interactions.
 */

'use strict';

document.addEventListener('DOMContentLoaded', () => {
  window._dashboardInstance = new SentinelleDashboard();
  window._dashboardInstance.init();
});


class SentinelleDashboard {

  constructor() {
    this.trafficChart    = null;
    this.alertChart      = null;
    this.protocolChart   = null;
    this.topSourcesChart = null;

    this.updateInterval = 5000;
    this.alertsLimit    = 100;
    this.maxDataPoints  = 20;
    this.pollerHandle   = null;
    this._pollCount     = 0;

    this._allAlerts  = [];
    this._trafficLabels = [];
    this._trafficValues = [];
    this._prevPackets   = 0;
  }

  // ════════════════════════════════════════════════
  // INIT
  // ════════════════════════════════════════════════
  async init() {
    this._initCharts();
    this._setupButtons();
    this._setupFilters();
    this._setupSettingsModal();
    this._setupBlacklist();
    await this._loadAll();
    this._startPoller();
  }

  // ════════════════════════════════════════════════
  // GRAPHIQUES
  // ════════════════════════════════════════════════
  _initCharts() {

    // ── Trafic réseau ──
    const trafficEl = document.getElementById('trafficChart');
    if (trafficEl) {
      this.trafficChart = new Chart(trafficEl.getContext('2d'), {
        type: 'line',
        data: {
          labels: this._trafficLabels,
          datasets: [{
            label: 'Paquets/s',
            data: this._trafficValues,
            borderColor: '#4f46e5',
            backgroundColor: 'rgba(79,70,229,0.07)',
            borderWidth: 2, tension: 0.4, fill: true,
            pointRadius: 3, pointBackgroundColor: '#4f46e5',
          }]
        },
        options: {
          responsive: true, animation: { duration: 250 },
          plugins: { legend: { display: false } },
          scales: {
            y: { beginAtZero: true,
                 ticks: { color: '#94a3b8', font: { size: 11 } },
                 grid: { color: 'rgba(0,0,0,0.04)' } },
            x: { ticks: { color: '#94a3b8', maxTicksLimit: 8, font: { size: 11 } },
                 grid: { display: false } },
          },
        }
      });
    }

    // ── Répartition sévérités ──
    const alertEl = document.getElementById('alertChart');
    if (alertEl) {
      this.alertChart = new Chart(alertEl.getContext('2d'), {
        type: 'doughnut',
        data: {
          labels: ['Critique', 'Haute', 'Moyenne', 'Basse'],
          datasets: [{
            data: [0, 0, 0, 0],
            backgroundColor: ['#dc2626', '#ea580c', '#d97706', '#059669'],
            borderWidth: 3, borderColor: '#fff',
          }]
        },
        options: {
          responsive: true, cutout: '68%',
          plugins: {
            legend: { position: 'bottom',
                      labels: { color: '#334155', padding: 12, font: { size: 12 } } }
          }
        }
      });
    }

    // ── Protocoles ──
    const protocolEl = document.getElementById('protocolChart');
    if (protocolEl) {
      this.protocolChart = new Chart(protocolEl.getContext('2d'), {
        type: 'doughnut',
        data: {
          labels: ['TCP', 'UDP', 'ICMP', 'Autre'],
          datasets: [{
            data: [65, 25, 7, 3],
            backgroundColor: ['#4f46e5', '#0d9488', '#d97706', '#94a3b8'],
            borderWidth: 3, borderColor: '#fff',
          }]
        },
        options: {
          responsive: true, cutout: '68%',
          plugins: {
            legend: { position: 'bottom',
                      labels: { color: '#334155', padding: 12, font: { size: 12 } } }
          }
        }
      });
    }

    // ── Top 5 sources — Bar horizontal ──
    const topEl = document.getElementById('topSourcesChart');
    if (topEl) {
      this.topSourcesChart = new Chart(topEl.getContext('2d'), {
        type: 'bar',
        data: {
          labels: [],
          datasets: [{
            label: 'Alertes',
            data: [],
            backgroundColor: [
              'rgba(220,38,38,0.75)',
              'rgba(234,88,12,0.75)',
              'rgba(217,119,6,0.75)',
              'rgba(79,70,229,0.75)',
              'rgba(13,148,136,0.75)',
            ],
            borderRadius: 6, borderWidth: 0,
          }]
        },
        options: {
          indexAxis: 'y', responsive: true, animation: { duration: 400 },
          plugins: {
            legend: { display: false },
            tooltip: { callbacks: { label: ctx => ` ${ctx.parsed.x} alerte${ctx.parsed.x > 1 ? 's' : ''}` } }
          },
          scales: {
            x: { beginAtZero: true,
                 ticks: { color: '#94a3b8', precision: 0, font: { size: 11 } },
                 grid: { color: 'rgba(0,0,0,0.04)' } },
            y: { ticks: { color: '#334155', font: { size: 12, family: 'monospace' } },
                 grid: { display: false } },
          },
        }
      });
    }
  }

  // ════════════════════════════════════════════════
  // BOUTONS
  // ════════════════════════════════════════════════
  _setupButtons() {

    document.getElementById('startBtn')?.addEventListener('click', async () => {
      this._setLoading('startBtn', true, 'Démarrage…');
      try {
        await api.startMonitoring();
        this._toast('Surveillance démarrée', 'success');
        await this._loadAll();
      } catch (e) {
        this._toast('Erreur : ' + e.message, 'danger');
      } finally {
        this._setLoading('startBtn', false, '<i class="fas fa-play me-1"></i>Démarrer');
      }
    });

    document.getElementById('stopBtn')?.addEventListener('click', async () => {
      this._setLoading('stopBtn', true, 'Arrêt…');
      try {
        await api.stopMonitoring();
        this._toast('Surveillance arrêtée', 'warning');
        this._updateStatusBadge('stopped', 0);
      } catch (e) {
        this._toast('Erreur : ' + e.message, 'danger');
      } finally {
        this._setLoading('stopBtn', false, '<i class="fas fa-stop me-1"></i>Arrêter');
      }
    });

    document.getElementById('refreshBtn')?.addEventListener('click', async () => {
      const btn = document.getElementById('refreshBtn');
      if (btn) btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Actualisation…';
      await this._loadAll();
      if (btn) btn.innerHTML = '<i class="fas fa-arrows-rotate me-1"></i>Actualiser';
    });

    document.getElementById('exportCsvBtn')?.addEventListener('click', async () => {
      try {
        await api.exportAlertsCsv();
        this._toast('Fichier CSV téléchargé !', 'success');
      } catch (e) {
        this._toast('Erreur export : ' + e.message, 'danger');
      }
    });
  }

  // ════════════════════════════════════════════════
  // FILTRES
  // ════════════════════════════════════════════════
  _setupFilters() {
    document.getElementById('filterSeverity')?.addEventListener('change', () => this._renderAlertsTable(this._allAlerts));
    document.getElementById('filterStatus')?.addEventListener('change',   () => this._renderAlertsTable(this._allAlerts));
  }

  _getFilteredAlerts(alerts) {
    const sev = document.getElementById('filterSeverity')?.value || '';
    const sta = document.getElementById('filterStatus')?.value   || '';
    return alerts.filter(a => (!sev || a.severity === sev) && (!sta || a.status === sta));
  }

  // ════════════════════════════════════════════════
  // BLACKLIST
  // ════════════════════════════════════════════════
  _setupBlacklist() {
    document.getElementById('addBlacklistBtn')?.addEventListener('click', async () => {
      const input = document.getElementById('blacklistInput');
      const ip = input?.value.trim();
      if (!ip) { this._toast('Entrez une adresse IP', 'warning'); return; }
      try {
        await api.addToBlacklist(ip);
        this._toast(`${ip} bloquée`, 'success');
        if (input) input.value = '';
        this._loadBlacklist();
      } catch (e) { this._toast('Erreur : ' + e.message, 'danger'); }
    });

    document.getElementById('addWhitelistBtn')?.addEventListener('click', async () => {
      const input = document.getElementById('whitelistInput');
      const ip = input?.value.trim();
      if (!ip) { this._toast('Entrez une adresse IP', 'warning'); return; }
      try {
        await api.addToWhitelist(ip);
        this._toast(`${ip} autorisée`, 'success');
        if (input) input.value = '';
      } catch (e) { this._toast('Erreur : ' + e.message, 'danger'); }
    });

    this._loadBlacklist();
  }

  async _loadBlacklist() {
    try {
      const data      = await api.getBlacklist();
      const container = document.getElementById('blacklistContainer');
      if (!container) return;
      const list = data.blacklist || [];
      if (!list.length) {
        container.innerHTML = '<p class="text-muted small mb-0">Aucune IP bloquée.</p>';
        return;
      }
      container.innerHTML = list.map(ip => `
        <div class="ip-pill">
          <code>${this._esc(ip)}</code>
          <button class="btn-remove" onclick="window._removeBlacklist('${this._esc(ip)}')" title="Débloquer">
            <i class="fas fa-xmark"></i>
          </button>
        </div>`).join('');
    } catch (_) {}
  }

  // ════════════════════════════════════════════════
  // PARAMÈTRES
  // ════════════════════════════════════════════════
  _setupSettingsModal() {
    document.getElementById('saveSettings')?.addEventListener('click', () => {
      const urlVal      = document.getElementById('apiUrl')?.value.trim();
      const intervalVal = parseInt(document.getElementById('refreshInterval')?.value || '5', 10);
      const limitVal    = parseInt(document.getElementById('alertsLimit')?.value    || '100', 10);
      const keyVal      = document.getElementById('apiKeyInput')?.value.trim();

      if (urlVal)   api.setBaseUrl(urlVal);
      if (keyVal)   api.setApiKey(keyVal);
      if (limitVal) this.alertsLimit = limitVal;

      if (intervalVal >= 1 && intervalVal <= 60) {
        this.updateInterval = intervalVal * 1000;
        this._stopPoller();
        if (document.getElementById('autoRefresh')?.checked !== false) this._startPoller();
      }

      this._toast('Paramètres enregistrés', 'success');
      bootstrap.Modal.getInstance(document.getElementById('settingsModal'))?.hide();
    });
  }

  // ════════════════════════════════════════════════
  // CHARGEMENT GLOBAL
  // ════════════════════════════════════════════════
  async _loadAll() {
    const [statsR, alertsR, topR] = await Promise.allSettled([
      api.getStats(),
      api.getAlerts(this.alertsLimit),
      api.getTopSources(),
    ]);

    if (statsR.status === 'fulfilled') {
      this._updateKPI(statsR.value);
      this._updateStatusBadge(
        statsR.value.status === 'Actif' ? 'running' : 'stopped',
        statsR.value.uptime_seconds
      );
    }
    if (alertsR.status === 'fulfilled') {
      this._allAlerts = alertsR.value || [];
      this._renderAlertsTable(this._allAlerts);
      this._updateAlertChart(this._allAlerts);
    }
    if (topR.status === 'fulfilled') {
      this._updateTopSourcesChart(topR.value || []);
    }
  }

  // ════════════════════════════════════════════════
  // POLLER
  // ════════════════════════════════════════════════
  _startPoller() {
    if (this.pollerHandle) return;
    this.pollerHandle = setInterval(async () => {
      try {
        const stats = await api.getStats();
        this._updateKPI(stats);
        this._appendTrafficPoint(stats);
        this._updateStatusBadge(
          stats.status === 'Actif' ? 'running' : 'stopped',
          stats.uptime_seconds
        );
      } catch (_) {}

      this._pollCount++;
      if (this._pollCount % 3 === 0) {
        try {
          const alerts = await api.getAlerts(this.alertsLimit);
          this._allAlerts = alerts || [];
          this._renderAlertsTable(this._allAlerts);
          this._updateAlertChart(this._allAlerts);
        } catch (_) {}
        try {
          const top = await api.getTopSources();
          this._updateTopSourcesChart(top || []);
        } catch (_) {}
      }
    }, this.updateInterval);
  }

  _stopPoller() {
    if (this.pollerHandle) { clearInterval(this.pollerHandle); this.pollerHandle = null; }
  }

  // ════════════════════════════════════════════════
  // KPI
  // ════════════════════════════════════════════════
  _updateKPI(stats) {
    this._setText('packetsCount',  stats.total_packets        ?? 0);
    this._setText('threatsCount',  stats.anomalies_detected   ?? 0);
    this._setText('criticalCount', stats.critical_alerts      ?? 0);
    this._setText('resolvedCount', stats.resolved             ?? 0);
    this._setText('ppsDisplay',    `${stats.packets_per_second ?? 0} pkt/s`);
  }

  // ════════════════════════════════════════════════
  // GRAPHIQUE TRAFIC
  // ════════════════════════════════════════════════
  _appendTrafficPoint(stats) {
    if (!this.trafficChart) return;
    const total = stats.total_packets ?? 0;
    const pps   = Math.max(0, total - this._prevPackets);
    this._prevPackets = total;
    const time = new Date().toLocaleTimeString('fr-FR',
      { hour:'2-digit', minute:'2-digit', second:'2-digit' });
    this._trafficLabels.push(time);
    this._trafficValues.push(pps);
    if (this._trafficLabels.length > this.maxDataPoints) {
      this._trafficLabels.shift(); this._trafficValues.shift();
    }
    this.trafficChart.update('none');
  }

  // ════════════════════════════════════════════════
  // GRAPHIQUE ALERTES
  // ════════════════════════════════════════════════
  _updateAlertChart(alerts) {
    if (!this.alertChart) return;
    const c = { critical:0, high:0, medium:0, low:0 };
    alerts.forEach(a => { if (a.severity in c) c[a.severity]++; });
    this.alertChart.data.datasets[0].data = [c.critical, c.high, c.medium, c.low];
    this.alertChart.update();
  }

  // ════════════════════════════════════════════════
  // GRAPHIQUE TOP SOURCES
  // ════════════════════════════════════════════════
  _updateTopSourcesChart(sources) {
    if (!this.topSourcesChart) return;
    this.topSourcesChart.data.labels                   = sources.map(s => s.ip    || '—');
    this.topSourcesChart.data.datasets[0].data         = sources.map(s => s.count || 0);
    this.topSourcesChart.update();
  }

  // ════════════════════════════════════════════════
  // TABLEAU
  // ════════════════════════════════════════════════
  _renderAlertsTable(allAlerts) {
    const tbody = document.getElementById('alertsTable');
    if (!tbody) return;
    const alerts = this._getFilteredAlerts(allAlerts);

    if (!alerts.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center py-5 text-muted">
        <i class="fas fa-circle-check text-success me-2"></i>
        ${allAlerts.length ? 'Aucune alerte pour ce filtre.' : 'Aucune menace détectée.'}
      </td></tr>`;
      return;
    }

    tbody.innerHTML = alerts.map(a => `
      <tr class="${a.severity === 'critical' ? 'row-critical' : a.severity === 'high' ? 'row-high' : ''}">
        <td class="text-muted small" style="white-space:nowrap">${this._formatDate(a.timestamp)}</td>
        <td><strong>${this._esc(a.type ?? '—')}</strong></td>
        <td><code class="small" style="color:#dc2626">${this._esc(a.source_ip ?? '—')}</code></td>
        <td><code class="small">${this._esc(a.destination_ip ?? '—')}</code></td>
        <td><span class="sev-badge sev-${this._esc(a.severity ?? 'low')}">${this._sevLabel(a.severity)}</span></td>
        <td><span class="stat-badge stat-${this._esc(a.status ?? 'open')}">${this._statusLabel(a.status)}</span></td>
        <td class="text-end" style="white-space:nowrap">
          <button class="btn btn-action btn-outline-secondary"
                  onclick="window._showAlertDetail('${this._esc(a.id)}')" title="Voir">
            <i class="fas fa-eye"></i>
          </button>
          ${a.status === 'open' ? `
          <button class="btn btn-action btn-outline-warning ms-1"
                  onclick="window._acknowledgeAlert('${this._esc(a.id)}')" title="Prendre en charge">
            <i class="fas fa-hand"></i>
          </button>
          <button class="btn btn-action btn-outline-success ms-1"
                  onclick="window._resolveAlert('${this._esc(a.id)}')" title="Résoudre">
            <i class="fas fa-check"></i>
          </button>` : ''}
        </td>
      </tr>`).join('');
  }

  // ════════════════════════════════════════════════
  // BADGE STATUT NAVBAR
  // ════════════════════════════════════════════════
  _updateStatusBadge(state, uptimeSeconds) {
    const dot   = document.getElementById('statusDot');
    const label = document.getElementById('statusText');
    if (dot)   dot.className = 'status-dot ' + (state === 'running' ? 'online' : 'offline');
    if (label) label.textContent = state === 'running' ? 'Système actif' : 'Arrêté';

    const upEl = document.getElementById('uptimeDisplay');
    if (upEl) {
      upEl.textContent = uptimeSeconds > 0
        ? 'Uptime : ' + this._formatUptime(uptimeSeconds)
        : '';
    }
  }

  // ════════════════════════════════════════════════
  // HELPERS
  // ════════════════════════════════════════════════
  _setText(id, val) { const el = document.getElementById(id); if (el) el.textContent = val; }

  _setLoading(id, loading, html) {
    const btn = document.getElementById(id);
    if (!btn) return;
    btn.disabled  = loading;
    btn.innerHTML = loading ? `<i class="fas fa-spinner fa-spin me-1"></i>${html}` : html;
  }

  _esc(s) {
    if (s == null) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
                    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }

  _formatDate(iso) {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleString('fr-FR',
        { day:'2-digit', month:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit' });
    } catch (_) { return iso; }
  }

  _formatUptime(s) {
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = Math.floor(s % 60);
    return [h > 0 ? `${h}h` : '', m > 0 ? `${m}m` : '', `${sec}s`].filter(Boolean).join(' ');
  }

  _sevLabel(s)   { return { critical:'Critique', high:'Haute', medium:'Moyenne', low:'Basse' }[s] ?? s ?? '—'; }
  _statusLabel(s){ return { open:'Ouvert', acknowledged:'Pris en charge', resolved:'Résolu', false_positive:'Faux positif' }[s] ?? s ?? '—'; }

  _toast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container || !window.bootstrap) { console.info('[SENTINELLE]', message); return; }
    const id = 'toast-' + Date.now();
    const cls = { success:'text-bg-success', danger:'text-bg-danger',
                  warning:'text-bg-warning',  info:'text-bg-info' }[type] ?? 'text-bg-secondary';
    container.insertAdjacentHTML('beforeend', `
      <div id="${id}" class="toast align-items-center ${cls} border-0">
        <div class="d-flex">
          <div class="toast-body">${this._esc(message)}</div>
          <button type="button" class="btn-close me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
      </div>`);
    const el = document.getElementById(id);
    new bootstrap.Toast(el, { delay: 3500 }).show();
    el.addEventListener('hidden.bs.toast', () => el.remove());
  }
}


// ════════════════════════════════════════════════════
// FONCTIONS GLOBALES (boutons onclick dans le tableau)
// ════════════════════════════════════════════════════

window._showAlertDetail = async function(alertId) {
  const body   = document.getElementById('alertDetailBody');
  const footer = document.getElementById('alertDetailFooter');
  if (!body) return;
  body.innerHTML = '<p class="text-muted"><i class="fas fa-spinner fa-spin me-2"></i>Chargement…</p>';
  const modal = new bootstrap.Modal(document.getElementById('alertDetailModal'));
  modal.show();
  try {
    const a = await api.getAlertDetails(alertId);
    const sevColors = { critical:'danger', high:'warning', medium:'info', low:'success' };
    const color = sevColors[a.severity] ?? 'secondary';
    body.innerHTML = `
      <div class="row g-3">
        <div class="col-6"><small class="text-muted d-block mb-1">Identifiant</small><code>${a.id ?? alertId}</code></div>
        <div class="col-6"><small class="text-muted d-block mb-1">Type</small><strong>${a.type ?? '—'}</strong></div>
        <div class="col-6"><small class="text-muted d-block mb-1">IP Source</small><code class="text-danger">${a.source_ip ?? '—'}</code></div>
        <div class="col-6"><small class="text-muted d-block mb-1">IP Destination</small><code>${a.destination_ip ?? '—'}</code></div>
        <div class="col-6"><small class="text-muted d-block mb-1">Sévérité</small>
          <span class="badge text-bg-${color}">${a.severity ?? '—'}</span></div>
        <div class="col-6"><small class="text-muted d-block mb-1">Statut</small>
          <span class="badge text-bg-secondary">${a.status ?? 'open'}</span></div>
        <div class="col-12"><small class="text-muted d-block mb-1">Horodatage</small>${a.timestamp ?? '—'}</div>
        ${a.details && a.details.length ? `<div class="col-12"><small class="text-muted d-block mb-1">Anomalies</small>
          ${a.details.map(d => `<span class="badge bg-light text-dark border me-1">${d}</span>`).join('')}</div>` : ''}
      </div>`;
    if (footer) footer.innerHTML = `
      <button class="btn btn-secondary" data-bs-dismiss="modal">Fermer</button>
      ${a.status === 'open' ? `
        <button class="btn btn-warning" onclick="window._acknowledgeAlert('${alertId}');
          bootstrap.Modal.getInstance(document.getElementById('alertDetailModal'))?.hide()">
          <i class="fas fa-hand me-1"></i>Prendre en charge</button>
        <button class="btn btn-success" onclick="window._resolveAlert('${alertId}');
          bootstrap.Modal.getInstance(document.getElementById('alertDetailModal'))?.hide()">
          <i class="fas fa-check me-1"></i>Résoudre</button>
        <button class="btn btn-outline-secondary" onclick="window._falsePositive('${alertId}');
          bootstrap.Modal.getInstance(document.getElementById('alertDetailModal'))?.hide()">
          Faux positif</button>` : ''}`;
  } catch (e) {
    body.innerHTML = `<div class="alert alert-danger">Erreur : ${e.message}</div>`;
  }
};

window._acknowledgeAlert = async function(alertId) {
  try {
    await api.acknowledgeAlert(alertId, 'analyste');
    document.getElementById('refreshBtn')?.click();
  } catch (e) { alert('Erreur : ' + e.message); }
};

window._resolveAlert = async function(alertId) {
  if (!confirm(`Marquer l'alerte ${alertId} comme résolue ?`)) return;
  try {
    await api.resolveAlert(alertId, 'Résolu depuis SENTINELLE');
    document.getElementById('refreshBtn')?.click();
  } catch (e) { alert('Erreur : ' + e.message); }
};

window._falsePositive = async function(alertId) {
  const reason = prompt('Raison du faux positif (optionnel) :') ?? '';
  try {
    await api.markFalsePositive(alertId, reason);
    document.getElementById('refreshBtn')?.click();
  } catch (e) { alert('Erreur : ' + e.message); }
};

window._removeBlacklist = async function(ip) {
  if (!confirm(`Débloquer ${ip} ?`)) return;
  try {
    await api.removeFromBlacklist(ip);
    window._dashboardInstance?._loadBlacklist();
  } catch (e) { alert('Erreur : ' + e.message); }
};
