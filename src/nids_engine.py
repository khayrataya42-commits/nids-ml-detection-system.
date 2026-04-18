"""
SENTINELLE — Moteur de Détection (NIDSEngine)
=============================================
Corrections et améliorations :
  ✅ IDs unifiés en :06d (synchronisé avec AlertManager et app.py)
  ✅ Bug fix detect_anomalies() — reçoit la vraie flow_key
  ✅ __init__() accepte config_path + interface séparément
  ✅ Blacklist / Whitelist d'IPs
  ✅ Détection Brute Force (SSH/FTP/RDP/Telnet/VNC)
  ✅ AlertManager connecté (plus de code mort)
  ✅ features ML : vecteur fixe de 17 valeurs
  ✅ Limite mémoire threats_identified (500 max)
"""

from typing import Dict, List, Optional, Callable
from datetime import datetime
import time

from .logger import ThreatLogger
from .config import Config
from .packet_processor import PacketProcessor
from .feature_extractor import FeatureExtractor
from .ml_model import MLModel
from .alert_system import AlertManager, AlertSeverity


# ════════════════════════════════════════════════════
# FEATURES ML — vecteur fixe 17 valeurs
# ════════════════════════════════════════════════════
FEATURE_NAMES = [
    'payload_size', 'port_number', 'protocol_type',
    'flag_count', 'has_syn', 'has_fin', 'has_rst', 'has_ack',
    'packet_count', 'total_bytes', 'avg_payload_size',
    'unique_ports', 'syn_count', 'fin_count', 'rst_count',
    'syn_fin_ratio', 'syn_rst_ratio',
]


def features_to_vector(features_dict: dict) -> list:
    """Convertit un dict de features en vecteur de taille fixe."""
    return [float(features_dict.get(k, 0.0)) for k in FEATURE_NAMES]


# ════════════════════════════════════════════════════
# MOTEUR PRINCIPAL
# ════════════════════════════════════════════════════
class NIDSEngine:

    # ── Seuils de détection ──
    PORT_SCAN_WINDOW      = 10    # secondes
    PORT_SCAN_THRESHOLD   = 5     # ports distincts
    BRUTE_FORCE_WINDOW    = 30    # secondes
    BRUTE_FORCE_THRESHOLD = 10    # tentatives
    BRUTE_FORCE_PORTS     = {22, 21, 23, 3389, 5900}   # SSH, FTP, Telnet, RDP, VNC

    # ── Whitelist par défaut ──
    DEFAULT_WHITELIST = {'127.0.0.1', '::1'}

    def __init__(
        self,
        config_path: Optional[str] = None,
        model_path:  Optional[str] = None,
        interface:   Optional[str] = None,
    ):
        self.config            = Config(config_path) if config_path else Config()
        self.logger            = ThreatLogger()
        self.feature_extractor = FeatureExtractor()
        self.packet_processor  = None
        self.alert_manager     = AlertManager()

        # Interface réseau (priorité argument > config)
        self._interface = interface or self.config.get('network.interface', 'Wi-Fi')

        # ── Modèle ML ──
        self.ml_model = MLModel(name="SENTINELLE-ML")
        if model_path:
            try:
                self.ml_model.load(model_path)
                print("✅ Modèle ML chargé :", model_path)
            except Exception as e:
                print("⚠️  Modèle ML indisponible :", e)

        # ── Trackers de détection ──
        self.port_scan_tracker   = {}   # { src_ip: [(dst_port, ts), ...] }
        self.brute_force_tracker = {}   # { src_ip: [ts, ...] }

        # ── Listes de contrôle ──
        self.ip_blacklist: set = set()
        self.ip_whitelist: set = set(self.DEFAULT_WHITELIST)

        # ── État ──
        self.is_running = False
        self.detection_callbacks: List[Callable] = []

        self.stats = {
            'packets_processed':  0,
            'anomalies_detected': 0,
            'alerts_raised':      0,
            'threats_identified': [],
        }

    # ════════════════════════════════════════════════
    # BLACKLIST / WHITELIST
    # ════════════════════════════════════════════════
    def add_to_blacklist(self, ip: str) -> None:
        self.ip_blacklist.add(ip)
        self.ip_whitelist.discard(ip)
        self.logger.log_threat('info', 'blacklist', f'{ip} bloquée')

    def remove_from_blacklist(self, ip: str) -> None:
        self.ip_blacklist.discard(ip)

    def add_to_whitelist(self, ip: str) -> None:
        self.ip_whitelist.add(ip)
        self.ip_blacklist.discard(ip)

    def is_blacklisted(self, ip: str) -> bool:
        return ip in self.ip_blacklist

    def is_whitelisted(self, ip: str) -> bool:
        return ip in self.ip_whitelist

    # ════════════════════════════════════════════════
    # DÉTECTION PORT SCAN
    # ════════════════════════════════════════════════
    def detect_port_scan(self, packet_data: dict) -> bool:
        """Détecte si src_ip touche >= PORT_SCAN_THRESHOLD ports distincts en PORT_SCAN_WINDOW s."""
        src_ip   = packet_data.get('src_ip')
        dst_port = packet_data.get('dst_port')
        if not src_ip or not dst_port:
            return False

        now = time.time()
        if src_ip not in self.port_scan_tracker:
            self.port_scan_tracker[src_ip] = []

        self.port_scan_tracker[src_ip].append((dst_port, now))
        self.port_scan_tracker[src_ip] = [
            (p, t) for p, t in self.port_scan_tracker[src_ip]
            if now - t <= self.PORT_SCAN_WINDOW
        ]
        return len({p for p, _ in self.port_scan_tracker[src_ip]}) >= self.PORT_SCAN_THRESHOLD

    # ════════════════════════════════════════════════
    # DÉTECTION BRUTE FORCE
    # ════════════════════════════════════════════════
    def detect_brute_force(self, packet_data: dict) -> bool:
        """Détecte >= BRUTE_FORCE_THRESHOLD connexions sur un port sensible en BRUTE_FORCE_WINDOW s."""
        src_ip   = packet_data.get('src_ip')
        dst_port = packet_data.get('dst_port')
        if not src_ip or dst_port not in self.BRUTE_FORCE_PORTS:
            return False

        now = time.time()
        if src_ip not in self.brute_force_tracker:
            self.brute_force_tracker[src_ip] = []

        self.brute_force_tracker[src_ip].append(now)
        self.brute_force_tracker[src_ip] = [
            t for t in self.brute_force_tracker[src_ip]
            if now - t <= self.BRUTE_FORCE_WINDOW
        ]
        return len(self.brute_force_tracker[src_ip]) >= self.BRUTE_FORCE_THRESHOLD

    # ════════════════════════════════════════════════
    # CLASSIFICATION
    # ════════════════════════════════════════════════
    def classify_attack(self, anomalies: List[str], ml_detected: bool, blacklisted: bool) -> tuple:
        """Retourne (attack_type, severity) selon les anomalies détectées."""
        if blacklisted:          return "IP Blacklistée",   "CRITICAL"
        if "brute_force" in anomalies: return "Brute Force",     "HIGH"
        if "port_scan"   in anomalies: return "Scan de Ports",   "HIGH"
        if "syn_flood"   in anomalies: return "Inondation SYN",  "HIGH"
        if ml_detected:               return "Anomalie ML",      "HIGH"
        if "high_packet_rate" in anomalies: return "Patron DDoS", "MEDIUM"
        if "unusual_flag_combo" in anomalies: return "Drapeaux Suspects", "MEDIUM"
        if anomalies:                 return "Anomalie Réseau",  "MEDIUM"
        return "Normal", "LOW"

    # ════════════════════════════════════════════════
    # TRAITEMENT DES PAQUETS
    # ════════════════════════════════════════════════
    def _process_packet(self, packet_data: dict) -> None:
        """Callback principal — traite chaque paquet capturé par Scapy."""
        try:
            self.stats['packets_processed'] += 1

            src_ip = packet_data.get('src_ip')
            dst_ip = packet_data.get('dst_ip')

            # Whitelist → ignorer
            if src_ip and self.is_whitelisted(src_ip):
                return

            anomalies   = []
            blacklisted = bool(src_ip and self.is_blacklisted(src_ip))
            if blacklisted:
                anomalies.append("blacklisted")

            # ── Features ──
            packet_features = self.feature_extractor.extract_packet_features(packet_data)
            flow_features   = self.feature_extractor.extract_flow_features(packet_data)
            features = {}
            if packet_features: features.update(packet_features)
            if flow_features:   features.update(flow_features)

            # ── Règles de flux — FIX : vraie flow_key ──
            if flow_features and src_ip and dst_ip:
                proto    = packet_data.get('protocol', 0)
                flow_key = f"{src_ip}:{dst_ip}:{proto}"
                detected = self.feature_extractor.detect_anomalies(flow_key)
                if detected:
                    anomalies.extend(detected)

            # ── Port Scan ──
            if self.detect_port_scan(packet_data) and "port_scan" not in anomalies:
                anomalies.append("port_scan")

            # ── Brute Force ──
            if self.detect_brute_force(packet_data) and "brute_force" not in anomalies:
                anomalies.append("brute_force")

            # ── ML ──
            ml_detected = False
            if features and self.ml_model.is_trained:
                try:
                    vector = features_to_vector(features)
                    if self.ml_model.predict([vector])[0] == 1:
                        ml_detected = True
                except Exception as e:
                    print("⚠️  Erreur ML :", e)

            # ── Décision ──
            if anomalies or ml_detected:
                attack_type, severity = self.classify_attack(anomalies, ml_detected, blacklisted)
                self._handle_alert(packet_data, attack_type, severity, anomalies, ml_detected)

        except Exception as e:
            print("❌ Erreur traitement paquet :", e)

    # ════════════════════════════════════════════════
    # GESTION DES ALERTES
    # ════════════════════════════════════════════════
    def _handle_alert(
        self,
        packet_data: dict,
        attack_type: str,
        severity:    str,
        anomalies:   List[str],
        ml_detected: bool,
    ) -> None:
        self.stats['anomalies_detected'] += 1
        self.stats['alerts_raised']      += 1

        src_ip = packet_data.get('src_ip', '-')
        dst_ip = packet_data.get('dst_ip', '-')

        # ── AlertManager ──
        severity_enum = {
            'CRITICAL': AlertSeverity.CRITICAL,
            'HIGH':     AlertSeverity.HIGH,
            'MEDIUM':   AlertSeverity.MEDIUM,
            'LOW':      AlertSeverity.LOW,
        }.get(severity, AlertSeverity.MEDIUM)

        self.alert_manager.create_alert(
            threat_type    = attack_type,
            severity       = severity_enum,
            source_ip      = src_ip,
            destination_ip = dst_ip,
            description    = f"Détection : {attack_type} depuis {src_ip}",
            threat_details = {
                'anomalies':   anomalies,
                'ml_detected': ml_detected,
                'dst_port':    packet_data.get('dst_port'),
                'protocol':    packet_data.get('protocol_name'),
            },
        )

        # ── Alerte pour les callbacks (app.py) ──
        # ✅ ID unifié :06d — synchronisé avec AlertManager
        alert = {
            'id':             f"ALERT-{self.stats['alerts_raised']:06d}",
            'timestamp':      datetime.now().isoformat(),
            'type':           attack_type,
            'details':        anomalies,
            'source_ip':      src_ip,
            'destination_ip': dst_ip,
            'severity':       severity,
            'ml_detected':    ml_detected,
        }

        print(f"🚨 [{severity}] {attack_type} — {src_ip} → {dst_ip}")

        # Limite mémoire : 500 max
        if len(self.stats['threats_identified']) >= 500:
            self.stats['threats_identified'].pop(0)
        self.stats['threats_identified'].append(alert)

        self.logger.log_threat('warning', attack_type, str(alert))

        for cb in self.detection_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    # ════════════════════════════════════════════════
    # INITIALISATION
    # ════════════════════════════════════════════════
    def initialize(self) -> bool:
        try:
            print(f"[SENTINELLE] Interface réseau : {self._interface}")
            self.packet_processor = PacketProcessor(interface=self._interface)
            self.packet_processor.set_packet_callback(self._process_packet)
            self.logger.log_threat('info', 'system', 'Moteur SENTINELLE initialisé')
            return True
        except Exception as e:
            self.logger.log_threat('error', 'system', f'Erreur init : {e}')
            return False

    # ════════════════════════════════════════════════
    # START / STOP
    # ════════════════════════════════════════════════
    def start(self) -> bool:
        if self.is_running:
            return False
        if not self.initialize():
            return False
        self.is_running = True
        print("🚀 SENTINELLE — Surveillance active")
        self.packet_processor.start_sniffing()
        return True

    def stop(self) -> None:
        if not self.is_running:
            return
        self.is_running = False
        if self.packet_processor:
            self.packet_processor.stop_sniffing()
        print("🛑 SENTINELLE — Surveillance arrêtée")

    # ════════════════════════════════════════════════
    # UTILITAIRES
    # ════════════════════════════════════════════════
    def get_statistics(self) -> dict:
        return {
            **self.stats,
            'alert_manager_stats': self.alert_manager.get_statistics(),
            'blacklist_size':      len(self.ip_blacklist),
            'whitelist_size':      len(self.ip_whitelist),
        }

    def register_detection_callback(self, callback: Callable) -> None:
        self.detection_callbacks.append(callback)

    def get_alert_manager(self) -> AlertManager:
        return self.alert_manager
