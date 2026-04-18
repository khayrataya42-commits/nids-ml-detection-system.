"""
SENTINELLE — Système de Surveillance et Détection d'Intrusion Réseau
=====================================================================
Backend Flask — Version Finale Corrigée

CORRECTIONS :
  ✅ BUG 404 : acknowledge/resolve cherchent dans alerts_storage (source de vérité)
     au lieu de passer par AlertManager (IDs désynchronisés après restart)
  ✅ Route /api/alerts/export AVANT /<alert_id> (évite confusion Flask)
  ✅ Limite RAM : 1000 alertes max en mémoire
  ✅ IDs unifiés en :06d dans tout le projet
  ✅ Vérification doublon SQLite (IntegrityError sur restart évité)
  ✅ Stats enrichies : resolved, acknowledged, false_positives
"""

from flask import Flask, jsonify, request, send_from_directory, send_file, Response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import logging
import os
import csv
import io
from threading import Thread, Lock
from functools import wraps
import time

from src.logger import setup_logger
from src.config import load_config
from src.nids_engine import NIDSEngine


# ════════════════════════════════════════════════════
# BASE DE DONNÉES SQLite
# ════════════════════════════════════════════════════
db = SQLAlchemy()


class AlertDB(db.Model):
    """Persistance des alertes (survit aux redémarrages du serveur)."""
    __tablename__ = 'alerts'

    id             = db.Column(db.Integer, primary_key=True)
    alert_id       = db.Column(db.String(30), unique=True, index=True)
    attack_type    = db.Column(db.String(100))
    source_ip      = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    severity       = db.Column(db.String(20))
    status         = db.Column(db.String(20), default='open')
    timestamp      = db.Column(db.String(50))

    def to_dict(self):
        return {
            'id':             self.alert_id,
            'type':           self.attack_type,
            'source_ip':      self.source_ip,
            'destination_ip': self.destination_ip,
            'severity':       self.severity,
            'status':         self.status,
            'timestamp':      self.timestamp,
        }


# ════════════════════════════════════════════════════
# FACTORY
# ════════════════════════════════════════════════════
def create_app(
    config_param = None,
    interface:   str  = None,
    blacklist:   list = None,
    whitelist:   list = None,
    model_path:  str  = None,
):
    app = Flask(__name__)
    CORS(app)

    app.config['SQLALCHEMY_DATABASE_URI']        = 'sqlite:///sentinelle.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    with app.app_context():
        db.create_all()

    logger = setup_logger('sentinelle', logging.INFO)
    config = config_param if config_param else load_config('config.json')

    # ── Authentification API ──
    API_KEY = os.environ.get('SENTINELLE_API_KEY', 'sentinelle-2024')

    def require_api_key(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if request.headers.get('X-API-Key', '') != API_KEY:
                return jsonify({'error': 'Non autorisé'}), 401
            return f(*args, **kwargs)
        return decorated

    # ════════════════════════════════════════════════
    # ÉTAT GLOBAL
    # ════════════════════════════════════════════════
    nids_engine       = None
    monitoring_thread = None
    data_lock         = Lock()

    MAX_ALERTS_RAM = 1000  # Limite mémoire RAM

    stats_storage = {
        'total_packets':      0,
        'anomalies_detected': 0,
        'alerts_raised':      0,
        'status':             'Arrêté',
        'start_time':         None,
        'uptime_seconds':     0,
        'critical_alerts':    0,
        'high_alerts':        0,
        'medium_alerts':      0,
        'low_alerts':         0,
        'resolved':           0,
        'acknowledged':       0,
        'false_positives':    0,
    }

    alerts_storage = []
    alert_counter  = [0]

    # ════════════════════════════════════════════════
    # CALLBACK — reçoit chaque alerte du moteur
    # ════════════════════════════════════════════════
    def on_threat_detected(threat_info: dict):
        """
        ✅ FIX BUG 404 :
        On utilise l'ID fourni par NIDSEngine (threat_info['id'])
        et non un ID local — garantit la synchronisation avec AlertManager.
        """
        with data_lock:
            alert_counter[0] += 1

            engine_id = threat_info.get('id')
            alert_id  = engine_id if engine_id else f'ALERT-{alert_counter[0]:06d}'

            severity = str(threat_info.get('severity', 'medium')).lower()

            alert = {
                'id':             alert_id,
                'timestamp':      threat_info.get('timestamp', datetime.now().isoformat()),
                'type':           threat_info.get('type', 'Inconnu'),
                'source_ip':      threat_info.get('source_ip', '-'),
                'destination_ip': threat_info.get('destination_ip', '-'),
                'severity':       severity,
                'status':         'open',
                'details':        threat_info.get('details', []),
                'ml_detected':    threat_info.get('ml_detected', False),
            }

            # Limite RAM
            if len(alerts_storage) >= MAX_ALERTS_RAM:
                alerts_storage.pop(0)
            alerts_storage.append(alert)

            # Compteurs par sévérité
            sev_key = f'{severity}_alerts'
            if sev_key in stats_storage:
                stats_storage[sev_key] = stats_storage.get(sev_key, 0) + 1

            # Persistance SQLite
            try:
                with app.app_context():
                    if not AlertDB.query.filter_by(alert_id=alert_id).first():
                        db.session.add(AlertDB(
                            alert_id       = alert_id,
                            attack_type    = alert['type'],
                            source_ip      = alert['source_ip'],
                            destination_ip = alert['destination_ip'],
                            severity       = alert['severity'],
                            timestamp      = alert['timestamp'],
                        ))
                        db.session.commit()
            except Exception as e:
                logger.error(f'DB error: {e}')

    # ════════════════════════════════════════════════
    # BOUCLE STATS (1 fois/seconde)
    # ════════════════════════════════════════════════
    def update_stats_loop():
        while True:
            if nids_engine and nids_engine.is_running:
                with data_lock:
                    s = nids_engine.get_statistics()
                    stats_storage['total_packets']      = s.get('packets_processed',  0)
                    stats_storage['anomalies_detected'] = s.get('anomalies_detected', 0)
                    stats_storage['alerts_raised']      = s.get('alerts_raised',      0)
                    if stats_storage['start_time']:
                        stats_storage['uptime_seconds'] = int(
                            (datetime.now() - stats_storage['start_time']).total_seconds()
                        )
                    stats_storage['resolved']        = sum(1 for a in alerts_storage if a['status'] == 'resolved')
                    stats_storage['acknowledged']    = sum(1 for a in alerts_storage if a['status'] == 'acknowledged')
                    stats_storage['false_positives'] = sum(1 for a in alerts_storage if a['status'] == 'false_positive')
            time.sleep(1)

    Thread(target=update_stats_loop, daemon=True).start()

    # ════════════════════════════════════════════════
    # ROUTES — SANTÉ
    # ════════════════════════════════════════════════
    @app.route('/api/health')
    def health():
        return jsonify({'status': 'ok', 'app': 'SENTINELLE', 'timestamp': datetime.now().isoformat()})

    # ════════════════════════════════════════════════
    # ROUTES — SURVEILLANCE
    # ════════════════════════════════════════════════
    @app.route('/api/start', methods=['GET', 'POST'])
    def start_monitoring():
        nonlocal nids_engine, monitoring_thread
        try:
            if nids_engine and nids_engine.is_running:
                return jsonify({'status': 'already_running', 'message': 'Surveillance déjà active'})

            nids_engine = NIDSEngine(
                config_path = 'config/nids_config.yaml',
                model_path  = model_path,
                interface   = interface,
            )
            nids_engine.register_detection_callback(on_threat_detected)

            for ip in (blacklist or []):
                nids_engine.add_to_blacklist(ip)
            for ip in (whitelist or []):
                nids_engine.add_to_whitelist(ip)

            stats_storage['status']     = 'Actif'
            stats_storage['start_time'] = datetime.now()

            monitoring_thread = Thread(target=nids_engine.start, daemon=True)
            monitoring_thread.start()

            return jsonify({'status': 'started', 'message': 'Surveillance démarrée'})
        except Exception as e:
            logger.error(str(e))
            return jsonify({'error': str(e)}), 500

    @app.route('/api/stop', methods=['GET', 'POST'])
    def stop_monitoring():
        nonlocal nids_engine
        if nids_engine and nids_engine.is_running:
            nids_engine.stop()
        stats_storage['status'] = 'Arrêté'
        return jsonify({'status': 'stopped', 'message': 'Surveillance arrêtée'})

    # ════════════════════════════════════════════════
    # ROUTES — STATS
    # ════════════════════════════════════════════════
    @app.route('/api/stats')
    def stats():
        return jsonify(stats_storage.copy())

    # ════════════════════════════════════════════════
    # ROUTES — ALERTES
    # ⚠️ /export DOIT être AVANT /<alert_id>
    # ════════════════════════════════════════════════
    @app.route('/api/alerts/export')
    def export_alerts():
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            'id','type','severity','status','source_ip','destination_ip','timestamp'
        ])
        writer.writeheader()
        for a in alerts_storage:
            writer.writerow({k: a.get(k,'') for k in ['id','type','severity','status','source_ip','destination_ip','timestamp']})
        filename = f"sentinelle_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        return Response(output.getvalue(), mimetype='text/csv; charset=utf-8',
                        headers={'Content-Disposition': f'attachment;filename={filename}'})

    @app.route('/api/alerts')
    def alerts():
        limit = request.args.get('limit', 100, type=int)
        return jsonify(alerts_storage[-limit:][::-1])

    @app.route('/api/alerts/<alert_id>')
    def alert_details(alert_id):
        for a in alerts_storage:
            if a['id'] == alert_id:
                return jsonify(a)
        return jsonify({'error': 'Alerte non trouvée'}), 404

    # ── Actions alertes — FIX BUG 404 ──────────────
    # Cherche dans alerts_storage EN PREMIER (source de vérité),
    # puis met à jour AlertManager et SQLite en bonus.
    # ────────────────────────────────────────────────

    @app.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
    def acknowledge_alert(alert_id):
        analyst = (request.json or {}).get('analyst', 'analyste') if request.is_json else 'analyste'
        found = False
        for a in alerts_storage:
            if a['id'] == alert_id:
                a['status'] = 'acknowledged'
                found = True
                break
        if not found:
            return jsonify({'error': f'{alert_id} non trouvée'}), 404
        if nids_engine:
            try: nids_engine.get_alert_manager().acknowledge_alert(alert_id, analyst)
            except Exception: pass
        try:
            with app.app_context():
                r = AlertDB.query.filter_by(alert_id=alert_id).first()
                if r: r.status = 'acknowledged'; db.session.commit()
        except Exception: pass
        return jsonify({'status': 'ok', 'message': f'{alert_id} prise en charge'})

    @app.route('/api/alerts/<alert_id>/resolve', methods=['POST'])
    def resolve_alert(alert_id):
        resolution = (request.json or {}).get('resolution', '') if request.is_json else ''
        found = False
        for a in alerts_storage:
            if a['id'] == alert_id:
                a['status'] = 'resolved'
                found = True
                break
        if not found:
            return jsonify({'error': f'{alert_id} non trouvée'}), 404
        if nids_engine:
            try: nids_engine.get_alert_manager().resolve_alert(alert_id, resolution)
            except Exception: pass
        try:
            with app.app_context():
                r = AlertDB.query.filter_by(alert_id=alert_id).first()
                if r: r.status = 'resolved'; db.session.commit()
        except Exception: pass
        return jsonify({'status': 'ok', 'message': f'{alert_id} résolue'})

    @app.route('/api/alerts/<alert_id>/false-positive', methods=['POST'])
    def mark_false_positive(alert_id):
        reason = (request.json or {}).get('reason', '') if request.is_json else ''
        found = False
        for a in alerts_storage:
            if a['id'] == alert_id:
                a['status'] = 'false_positive'
                found = True
                break
        if not found:
            return jsonify({'error': f'{alert_id} non trouvée'}), 404
        if nids_engine:
            try: nids_engine.get_alert_manager().mark_false_positive(alert_id, reason)
            except Exception: pass
        try:
            with app.app_context():
                r = AlertDB.query.filter_by(alert_id=alert_id).first()
                if r: r.status = 'false_positive'; db.session.commit()
        except Exception: pass
        return jsonify({'status': 'ok', 'message': f'{alert_id} marquée faux positif'})

    # ════════════════════════════════════════════════
    # ROUTES — TOP SOURCES
    # ════════════════════════════════════════════════
    @app.route('/api/top-sources')
    def top_sources():
        counts = {}
        for a in alerts_storage:
            ip = a.get('source_ip', '-')
            if ip and ip != '-':
                counts[ip] = counts.get(ip, 0) + 1
        top5 = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]
        return jsonify([{'ip': ip, 'count': c} for ip, c in top5])

    # ════════════════════════════════════════════════
    # ROUTES — BLACKLIST / WHITELIST
    # ════════════════════════════════════════════════
    @app.route('/api/blacklist', methods=['GET'])
    def get_blacklist():
        if nids_engine:
            return jsonify({'blacklist': sorted(list(nids_engine.ip_blacklist))})
        return jsonify({'blacklist': []})

    @app.route('/api/blacklist', methods=['POST'])
    def add_to_blacklist():
        ip = (request.json or {}).get('ip', '').strip()
        if not ip: return jsonify({'error': 'IP manquante'}), 400
        if not nids_engine: return jsonify({'error': 'Démarrez la surveillance'}), 400
        nids_engine.add_to_blacklist(ip)
        return jsonify({'status': 'ok', 'message': f'{ip} bloquée'})

    @app.route('/api/blacklist/<ip>', methods=['DELETE'])
    def remove_from_blacklist(ip):
        if not nids_engine: return jsonify({'error': 'Moteur non démarré'}), 400
        nids_engine.remove_from_blacklist(ip)
        return jsonify({'status': 'ok', 'message': f'{ip} débloquée'})

    @app.route('/api/whitelist', methods=['POST'])
    def add_to_whitelist():
        ip = (request.json or {}).get('ip', '').strip()
        if not ip: return jsonify({'error': 'IP manquante'}), 400
        if not nids_engine: return jsonify({'error': 'Démarrez la surveillance'}), 400
        nids_engine.add_to_whitelist(ip)
        return jsonify({'status': 'ok', 'message': f'{ip} autorisée'})

    # ════════════════════════════════════════════════
    # FRONTEND STATIQUE
    # ════════════════════════════════════════════════
    @app.route('/')
    def dashboard_page():
        return send_file(os.path.join('web', 'index.html'))

    @app.route('/<path:path>')
    def static_files(path):
        return send_from_directory('web', path)

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
