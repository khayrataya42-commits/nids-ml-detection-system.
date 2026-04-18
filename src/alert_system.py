"""
Alert System Module — Version Corrigée et Améliorée
=====================================================
Corrections apportées :
  - AlertManager maintenant utilisé dans NIDSEngine (plus code mort)
  - EmailAlertChannel : vraie implémentation smtplib
  - WebhookAlertChannel : vraie implémentation requests
  - Ajout : export_to_csv() dans AlertManager
  - Ajout : get_top_sources() pour le dashboard
  - Amélioration : statistiques enrichies
"""

from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from enum import Enum
import json
import csv
import io

from .logger import ThreatLogger


# ============================================================
# ENUMS
# ============================================================
class AlertSeverity(Enum):
    LOW      = 'low'
    MEDIUM   = 'medium'
    HIGH     = 'high'
    CRITICAL = 'critical'


class AlertStatus(Enum):
    OPEN           = 'open'
    ACKNOWLEDGED   = 'acknowledged'
    RESOLVED       = 'resolved'
    FALSE_POSITIVE = 'false_positive'


# ============================================================
# ALERT
# ============================================================
class Alert:
    """Représente une alerte de sécurité complète."""

    def __init__(
        self,
        alert_id:       str,
        threat_type:    str,
        severity:       AlertSeverity,
        source_ip:      str,
        destination_ip: str,
        description:    str,
        threat_details: Dict[str, Any],
    ):
        self.alert_id       = alert_id
        self.threat_type    = threat_type
        self.severity       = severity
        self.source_ip      = source_ip
        self.destination_ip = destination_ip
        self.description    = description
        self.threat_details = threat_details

        self.created_at:      datetime            = datetime.now()
        self.status:          AlertStatus         = AlertStatus.OPEN
        self.acknowledged_at: Optional[datetime]  = None
        self.resolved_at:     Optional[datetime]  = None
        self.response_actions: List[str]          = []

    # ---- Actions ----
    def acknowledge(self, analyst: str = "system") -> None:
        """Marque l'alerte comme prise en charge."""
        self.status          = AlertStatus.ACKNOWLEDGED
        self.acknowledged_at = datetime.now()
        self.response_actions.append(f'Prise en charge par {analyst}')

    def resolve(self, resolution: str = "") -> None:
        """Marque l'alerte comme résolue."""
        self.status      = AlertStatus.RESOLVED
        self.resolved_at = datetime.now()
        self.response_actions.append(f'Résolue : {resolution}')

    def mark_false_positive(self, reason: str = "") -> None:
        """Marque l'alerte comme faux positif."""
        self.status = AlertStatus.FALSE_POSITIVE
        self.response_actions.append(f'Faux positif : {reason}')

    # ---- Sérialisation ----
    def to_dict(self) -> Dict[str, Any]:
        return {
            'alert_id':        self.alert_id,
            'threat_type':     self.threat_type,
            'severity':        self.severity.value,
            'source_ip':       self.source_ip,
            'destination_ip':  self.destination_ip,
            'description':     self.description,
            'created_at':      self.created_at.isoformat(),
            'status':          self.status.value,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'resolved_at':     self.resolved_at.isoformat()     if self.resolved_at     else None,
            'response_actions': self.response_actions,
            'threat_details':  self.threat_details,
        }


# ============================================================
# CANAUX DE NOTIFICATION — base
# ============================================================
class AlertNotificationChannel:
    """Classe de base pour les canaux de notification."""

    def __init__(self, name: str):
        self.name       = name
        self.logger     = ThreatLogger()
        self.is_enabled = True

    def send(self, alert: Alert) -> bool:
        raise NotImplementedError


# ============================================================
# CANAL EMAIL — implémentation réelle avec smtplib
# ============================================================
class EmailAlertChannel(AlertNotificationChannel):
    """
    Envoi d'alertes par email via SMTP.

    Exemple d'utilisation :
        channel = EmailAlertChannel(
            smtp_server='smtp.gmail.com',
            smtp_port=587,
            username='ton_email@gmail.com',
            password='ton_mot_de_passe_app',
            recipients=['admin@domaine.com'],
        )
        alert_manager.add_notification_channel(channel)
    """

    def __init__(
        self,
        smtp_server: str,
        smtp_port:   int,
        recipients:  List[str],
        username:    str = "",
        password:    str = "",
        use_tls:     bool = True,
    ):
        super().__init__('Email')
        self.smtp_server = smtp_server
        self.smtp_port   = smtp_port
        self.recipients  = recipients
        self.username    = username
        self.password    = password
        self.use_tls     = use_tls

    def send(self, alert: Alert) -> bool:
        """Envoie l'alerte par email."""
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text      import MIMEText

            # ---- Construction du message ----
            msg            = MIMEMultipart('alternative')
            msg['Subject'] = f"[NIDS] {alert.severity.value.upper()} — {alert.threat_type}"
            msg['From']    = self.username or "nids@local"
            msg['To']      = ", ".join(self.recipients)

            # Corps texte simple
            body_text = (
                f"=== ALERTE NIDS ===\n\n"
                f"ID        : {alert.alert_id}\n"
                f"Type      : {alert.threat_type}\n"
                f"Sévérité  : {alert.severity.value.upper()}\n"
                f"Source IP : {alert.source_ip}\n"
                f"Dest. IP  : {alert.destination_ip}\n"
                f"Timestamp : {alert.created_at.isoformat()}\n\n"
                f"Description : {alert.description}\n\n"
                f"Détails : {json.dumps(alert.threat_details, indent=2, ensure_ascii=False)}\n"
            )

            # Corps HTML
            severity_colors = {
                'critical': '#dc2626',
                'high':     '#ea580c',
                'medium':   '#d97706',
                'low':      '#16a34a',
            }
            color = severity_colors.get(alert.severity.value, '#6b7280')

            body_html = f"""
            <html><body style="font-family:sans-serif;max-width:600px;margin:0 auto">
            <div style="background:{color};color:white;padding:16px 24px;border-radius:8px 8px 0 0">
                <h2 style="margin:0">[NIDS] {alert.severity.value.upper()} — {alert.threat_type}</h2>
            </div>
            <div style="border:1px solid #e5e7eb;border-top:none;padding:24px;border-radius:0 0 8px 8px">
                <table style="width:100%;border-collapse:collapse">
                    <tr><td style="color:#6b7280;padding:6px 0">ID Alerte</td>
                        <td style="font-weight:500">{alert.alert_id}</td></tr>
                    <tr><td style="color:#6b7280;padding:6px 0">Type</td>
                        <td style="font-weight:500">{alert.threat_type}</td></tr>
                    <tr><td style="color:#6b7280;padding:6px 0">IP Source</td>
                        <td style="font-family:monospace">{alert.source_ip}</td></tr>
                    <tr><td style="color:#6b7280;padding:6px 0">IP Destination</td>
                        <td style="font-family:monospace">{alert.destination_ip}</td></tr>
                    <tr><td style="color:#6b7280;padding:6px 0">Date/Heure</td>
                        <td>{alert.created_at.strftime('%d/%m/%Y %H:%M:%S')}</td></tr>
                </table>
                <p style="color:#374151;margin-top:16px">{alert.description}</p>
                <pre style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:4px;
                            padding:12px;font-size:12px;overflow-x:auto">
{json.dumps(alert.threat_details, indent=2, ensure_ascii=False)}
                </pre>
            </div>
            </body></html>
            """

            msg.attach(MIMEText(body_text, 'plain', 'utf-8'))
            msg.attach(MIMEText(body_html, 'html',  'utf-8'))

            # ---- Envoi ----
            with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(
                    msg['From'],
                    self.recipients,
                    msg.as_string(),
                )

            self.logger.log_threat(
                'info', 'EmailAlert',
                f'Email envoyé pour {alert.threat_type} → {self.recipients}'
            )
            return True

        except ImportError:
            self.logger.log_threat('error', 'EmailAlert', 'smtplib non disponible')
            return False
        except Exception as e:
            self.logger.log_threat('error', 'EmailAlert', f'Échec envoi email : {e}')
            return False


# ============================================================
# CANAL WEBHOOK — implémentation réelle avec requests
# ============================================================
class WebhookAlertChannel(AlertNotificationChannel):
    """
    Envoi d'alertes via webhook HTTP (Slack, Discord, Teams, etc.).

    Exemple pour Slack :
        channel = WebhookAlertChannel(
            webhook_url='https://hooks.slack.com/services/XXX/YYY/ZZZ'
        )
    """

    def __init__(self, webhook_url: str, timeout: int = 10):
        super().__init__('Webhook')
        self.webhook_url = webhook_url
        self.timeout     = timeout

    def send(self, alert: Alert) -> bool:
        """Envoie l'alerte via HTTP POST JSON."""
        try:
            import requests

            severity_emoji = {
                'critical': '🔴',
                'high':     '🟠',
                'medium':   '🟡',
                'low':      '🟢',
            }.get(alert.severity.value, '⚪')

            payload = {
                "text": (
                    f"{severity_emoji} *[NIDS] {alert.severity.value.upper()} — "
                    f"{alert.threat_type}*\n"
                    f"• Source : `{alert.source_ip}`\n"
                    f"• Destination : `{alert.destination_ip}`\n"
                    f"• Heure : {alert.created_at.strftime('%d/%m/%Y %H:%M:%S')}\n"
                    f"• ID : `{alert.alert_id}`"
                ),
                "alert": alert.to_dict(),
            }

            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()

            self.logger.log_threat(
                'info', 'WebhookAlert',
                f'Webhook envoyé pour {alert.threat_type} → {self.webhook_url[:40]}...'
            )
            return True

        except ImportError:
            self.logger.log_threat('error', 'WebhookAlert', 'requests non installé (pip install requests)')
            return False
        except Exception as e:
            self.logger.log_threat('error', 'WebhookAlert', f'Échec webhook : {e}')
            return False


# ============================================================
# ALERT MANAGER
# ============================================================
class AlertManager:
    """
    Gestionnaire central des alertes NIDS.

    Utilisé par NIDSEngine pour créer, gérer et notifier les alertes.
    Expose des méthodes pour l'API Flask (acknowledge, resolve, export CSV...).
    """

    # Nombre maximum d'alertes conservées en mémoire
    MAX_ALERTS = 5000

    def __init__(self):
        self.logger:        ThreatLogger                   = ThreatLogger()
        self.alerts:        Dict[str, Alert]               = {}
        self.channels:      List[AlertNotificationChannel] = []
        self.alert_counter: int                            = 0

    # ---- Canaux ----
    def add_notification_channel(self, channel: AlertNotificationChannel) -> None:
        """Ajoute un canal de notification (email, webhook...)."""
        self.channels.append(channel)
        self.logger.log_threat('info', 'AlertManager', f'Canal ajouté : {channel.name}')

    # ---- Création ----
    def create_alert(
        self,
        threat_type:    str,
        severity:       AlertSeverity,
        source_ip:      str,
        destination_ip: str,
        description:    str,
        threat_details: Dict[str, Any],
    ) -> Alert:
        """Crée, enregistre et notifie une nouvelle alerte."""
        self.alert_counter += 1
        alert_id = f'ALERT-{self.alert_counter:06d}'

        alert = Alert(
            alert_id       = alert_id,
            threat_type    = threat_type,
            severity       = severity,
            source_ip      = source_ip,
            destination_ip = destination_ip,
            description    = description,
            threat_details = threat_details,
        )

        # Limite mémoire
        if len(self.alerts) >= self.MAX_ALERTS:
            oldest_key = next(iter(self.alerts))
            del self.alerts[oldest_key]

        self.alerts[alert_id] = alert

        # Notifier les canaux configurés
        self._notify_channels(alert)

        self.logger.log_threat(
            'warning', threat_type,
            f'{alert_id} | {severity.value.upper()} | src={source_ip}'
        )

        return alert

    # ---- Notifications ----
    def _notify_channels(self, alert: Alert) -> None:
        """Envoie l'alerte à tous les canaux activés."""
        for channel in self.channels:
            if channel.is_enabled:
                try:
                    channel.send(alert)
                except Exception as e:
                    self.logger.log_threat(
                        'error', 'AlertManager',
                        f'Erreur canal {channel.name} : {e}'
                    )

    # ---- Actions sur les alertes ----
    def acknowledge_alert(self, alert_id: str, analyst: str = "analyst") -> bool:
        """Marque une alerte comme prise en charge. Retourne True si trouvée."""
        alert = self.alerts.get(alert_id)
        if not alert:
            return False
        alert.acknowledge(analyst)
        return True

    def resolve_alert(self, alert_id: str, resolution: str = "") -> bool:
        """Marque une alerte comme résolue. Retourne True si trouvée."""
        alert = self.alerts.get(alert_id)
        if not alert:
            return False
        alert.resolve(resolution)
        return True

    def mark_false_positive(self, alert_id: str, reason: str = "") -> bool:
        """Marque une alerte comme faux positif. Retourne True si trouvée."""
        alert = self.alerts.get(alert_id)
        if not alert:
            return False
        alert.mark_false_positive(reason)
        return True

    # ---- Requêtes ----
    def get_alert(self, alert_id: str) -> Optional[Alert]:
        return self.alerts.get(alert_id)

    def get_all_alerts(self, limit: int = 100) -> List[Alert]:
        """Retourne les alertes les plus récentes en premier."""
        return list(reversed(list(self.alerts.values())))[:limit]

    def get_open_alerts(self) -> List[Alert]:
        return [a for a in self.alerts.values() if a.status == AlertStatus.OPEN]

    def get_alerts_by_severity(self, severity: AlertSeverity) -> List[Alert]:
        return [a for a in self.alerts.values() if a.severity == severity]

    def get_alerts_by_ip(self, ip: str) -> List[Alert]:
        """Retourne toutes les alertes dont l'IP source correspond."""
        return [a for a in self.alerts.values() if a.source_ip == ip]

    def get_top_sources(self, n: int = 5) -> List[Dict[str, Any]]:
        """
        Retourne les N IPs sources les plus actives.
        Utilisé par le widget 'Sources principales' du dashboard.
        """
        counts: Dict[str, int] = {}
        for alert in self.alerts.values():
            ip = alert.source_ip
            counts[ip] = counts.get(ip, 0) + 1

        sorted_ips = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]
        return [{'ip': ip, 'count': count} for ip, count in sorted_ips]

    # ---- Export CSV ----
    def export_to_csv(self) -> str:
        """
        Exporte toutes les alertes au format CSV.
        Retourne une chaîne CSV (à envoyer via Flask send_file ou Response).

        Exemple d'utilisation dans app.py :
            @app.route('/api/alerts/export')
            def export_alerts():
                csv_data = nids_engine.get_alert_manager().export_to_csv()
                return Response(
                    csv_data,
                    mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment;filename=alertes_nids.csv'}
                )
        """
        output = io.StringIO()
        fieldnames = [
            'alert_id', 'threat_type', 'severity', 'status',
            'source_ip', 'destination_ip', 'description', 'created_at',
            'acknowledged_at', 'resolved_at',
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for alert in self.alerts.values():
            writer.writerow({
                'alert_id':        alert.alert_id,
                'threat_type':     alert.threat_type,
                'severity':        alert.severity.value,
                'status':          alert.status.value,
                'source_ip':       alert.source_ip,
                'destination_ip':  alert.destination_ip,
                'description':     alert.description,
                'created_at':      alert.created_at.isoformat(),
                'acknowledged_at': alert.acknowledged_at.isoformat() if alert.acknowledged_at else '',
                'resolved_at':     alert.resolved_at.isoformat()     if alert.resolved_at     else '',
            })

        return output.getvalue()

    # ---- Statistiques ----
    def get_statistics(self) -> Dict[str, Any]:
        """Retourne les statistiques complètes pour le dashboard."""
        total = len(self.alerts)
        return {
            'total_alerts':    total,
            'open_alerts':     len(self.get_open_alerts()),
            'critical_alerts': len(self.get_alerts_by_severity(AlertSeverity.CRITICAL)),
            'high_alerts':     len(self.get_alerts_by_severity(AlertSeverity.HIGH)),
            'medium_alerts':   len(self.get_alerts_by_severity(AlertSeverity.MEDIUM)),
            'low_alerts':      len(self.get_alerts_by_severity(AlertSeverity.LOW)),
            'acknowledged':    sum(1 for a in self.alerts.values() if a.status == AlertStatus.ACKNOWLEDGED),
            'resolved':        sum(1 for a in self.alerts.values() if a.status == AlertStatus.RESOLVED),
            'false_positives': sum(1 for a in self.alerts.values() if a.status == AlertStatus.FALSE_POSITIVE),
            'top_sources':     self.get_top_sources(5),
        }
