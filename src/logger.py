"""
Logging Configuration Module for NIDS
Provides centralized logging setup with file and console outputs
"""

import logging
import logging.handlers
import os
from pathlib import Path
from datetime import datetime


def setup_logger(name: str, level=logging.INFO, log_dir: str = "logs"):
    """
    Setup logger with console and file handlers
    
    Args:
        name (str): Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir (str): Directory for log files
    
    Returns:
        logging.Logger: Configured logger instance
    """

    # Create logs directory
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent duplicate handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    # Formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(simple_formatter)
    logger.addHandler(console_handler)

    # File handler (general logs)
    log_file = os.path.join(log_dir, f"nids_{datetime.now().strftime('%Y%m%d')}.log")
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    logger.addHandler(file_handler)

    # File handler (errors only)
    error_log = os.path.join(log_dir, f"nids_errors_{datetime.now().strftime('%Y%m%d')}.log")
    error_handler = logging.handlers.RotatingFileHandler(
        error_log,
        maxBytes=5 * 1024 * 1024,
        backupCount=3
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(detailed_formatter)
    logger.addHandler(error_handler)

    return logger


def setup_threat_logger(log_dir: str = "logs"):
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    threat_logger = logging.getLogger('NIDS.THREATS')
    threat_logger.setLevel(logging.INFO)

    if threat_logger.hasHandlers():
        threat_logger.handlers.clear()

    threat_formatter = logging.Formatter(
        '%(asctime)s - [THREAT] - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    threat_file = os.path.join(log_dir, f"threats_{datetime.now().strftime('%Y%m%d')}.log")
    threat_handler = logging.handlers.RotatingFileHandler(
        threat_file,
        maxBytes=50 * 1024 * 1024,
        backupCount=10
    )
    threat_handler.setFormatter(threat_formatter)
    threat_logger.addHandler(threat_handler)

    return threat_logger


class ThreatLogger:

    def __init__(self, log_dir: str = "logs"):
        self.logger = setup_threat_logger(log_dir)

    def log_threat(self, threat_type: str, severity: str, message: str):
        log_message = f"[{threat_type}] [{severity}] {message}"
        self.logger.warning(log_message)

    def log_alert(self, alert_message: str):
        self.logger.error(alert_message)