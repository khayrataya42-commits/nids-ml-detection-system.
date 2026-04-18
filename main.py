#!/usr/bin/env python3
"""
SENTINELLE — Point d'Entrée Principal
======================================
Modes : api (défaut) | detection | training

Usage :
  python main.py --mode api
  python main.py --mode detection --interface eth0
  python main.py --mode training
  python main.py --mode api --blacklist 192.168.1.100 10.0.0.5
"""

import sys
import argparse
import logging
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR / 'src'))

from src.config import Config
from src.logger import setup_logger


BANNER = """
 ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██╗     ███████╗
 ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██║     ██╔════╝
 ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ██║     █████╗  
 ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██║     ██╔══╝  
 ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗███████╗███████╗
 ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝╚══════╝
 Système de Surveillance et Détection d'Intrusion Réseau — v1.1.0
"""


def setup_argparse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='SENTINELLE — Système de Surveillance Réseau',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python main.py --mode api                        # Dashboard web (défaut)
  python main.py --mode api --port 8080            # Port personnalisé
  python main.py --mode detection --interface eth0 # Console uniquement
  python main.py --mode training                   # Entraîner le modèle ML
  python main.py --mode api --blacklist 192.168.1.5 10.0.0.99
        """
    )

    parser.add_argument('--mode', choices=['detection','training','api'],
                        default='api', help='Mode de démarrage (défaut : api)')
    parser.add_argument('--config', default=str(BASE_DIR/'config'/'nids_config.yaml'),
                        help='Fichier de configuration YAML')
    parser.add_argument('--interface', default=None,
                        help='Interface réseau (eth0, Wi-Fi, wlan0…)')
    parser.add_argument('--log-level',
                        choices=['DEBUG','INFO','WARNING','ERROR','CRITICAL'],
                        default='INFO', help='Niveau de log')
    parser.add_argument('--model', default=str(BASE_DIR/'models'/'sentinelle_model.pkl'),
                        help='Chemin vers le modèle ML (.pkl)')
    parser.add_argument('--port', type=int, default=5000,
                        help='Port Flask (défaut : 5000)')
    parser.add_argument('--host', default='0.0.0.0',
                        help='Adresse d\'écoute Flask')
    parser.add_argument('--blacklist', nargs='*', default=[], metavar='IP',
                        help='IPs à blacklister dès le démarrage')
    parser.add_argument('--whitelist', nargs='*', default=[], metavar='IP',
                        help='IPs à whitelister dès le démarrage')

    return parser.parse_args()


def run_detection_mode(args, logger) -> None:
    """Surveillance réseau en mode terminal — pas de dashboard."""
    from src.nids_engine import NIDSEngine

    logger.info(f"Mode DETECTION | Interface : {args.interface or '(config)'}")

    engine = NIDSEngine(
        config_path = args.config,
        model_path  = args.model if Path(args.model).exists() else None,
        interface   = args.interface,
    )

    for ip in args.blacklist: engine.add_to_blacklist(ip); logger.info(f"Blacklist : {ip}")
    for ip in args.whitelist: engine.add_to_whitelist(ip); logger.info(f"Whitelist : {ip}")

    logger.info("Surveillance démarrée — Ctrl+C pour arrêter")
    engine.start()

    import time
    try:
        while engine.is_running:
            time.sleep(10)
            s = engine.get_statistics()
            logger.info(
                f"Paquets : {s['packets_processed']} | "
                f"Anomalies : {s['anomalies_detected']} | "
                f"Alertes : {s['alerts_raised']}"
            )
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()


def run_training_mode(args, logger) -> None:
    """Entraîne le modèle ML IsolationForest."""
    from src.ml_model import MLModel
    import numpy as np

    logger.info("Mode TRAINING")

    feature_names = [
        'payload_size','port_number','protocol_type',
        'flag_count','has_syn','has_fin','has_rst','has_ack',
        'packet_count','total_bytes','avg_payload_size',
        'unique_ports','syn_count','fin_count','rst_count',
        'syn_fin_ratio','syn_rst_ratio',
    ]

    logger.info("Génération des données d'entraînement synthétiques…")
    n = 1000
    data = np.random.normal(
        loc   = [500,80,1,2,0.3,0.2,0.05,0.8,50,25000,500,2,3,2,0.5,1.5,6],
        scale = [200,30,0.5,1,0.2,0.1,0.02,0.2,20,10000,200,1,2,1,0.3,0.5,2],
        size  = (n, len(feature_names)),
    )
    data = np.clip(data, 0, None)

    X_train = [{name: float(v) for name, v in zip(feature_names, row)} for row in data]

    model = MLModel(name="SENTINELLE-ML")
    if model.train(X_train):
        path = str(BASE_DIR / 'models' / 'sentinelle_model.pkl')
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        model.save(path)
        logger.info(f"✅ Modèle sauvegardé : {path}")
        logger.info("💡 Remplacez les données synthétiques par du vrai trafic capturé")
    else:
        logger.error("❌ Échec de l'entraînement")


def run_api_mode(args, logger) -> None:
    """Démarre le serveur Flask avec le dashboard SENTINELLE."""
    from app import create_app

    logger.info(f"Mode API | Dashboard : http://localhost:{args.port}")

    config = Config(args.config)
    app = create_app(
        config_param = config.config,
        interface    = args.interface,
        blacklist    = args.blacklist,
        whitelist    = args.whitelist,
        model_path   = args.model if Path(args.model).exists() else None,
    )
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


def main() -> None:
    args   = setup_argparse()
    logger = setup_logger('SENTINELLE', level=getattr(logging, args.log_level))

    print(BANNER)
    logger.info(f"Mode : {args.mode.upper()}")

    try:
        if   args.mode == 'detection': run_detection_mode(args, logger)
        elif args.mode == 'training':  run_training_mode(args,  logger)
        elif args.mode == 'api':       run_api_mode(args,       logger)
    except KeyboardInterrupt:
        logger.info("🛑 Arrêté par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"💥 Erreur fatale : {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
