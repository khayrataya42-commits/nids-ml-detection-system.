"""
Machine Learning Model Handler for NIDS (REAL ML VERSION)

Uses IsolationForest for anomaly detection.
Supports training, prediction, evaluation, and persistence.
"""

from typing import Dict, List, Optional, Tuple, Any
import pickle
import os
from datetime import datetime
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from .logger import ThreatLogger


class MLModel:
    """Base class for ML models in NIDS (REAL IMPLEMENTATION)."""
    
    def __init__(self, name: str, model_type: str = "Isolation Forest"):
        self.name = name
        self.model_type = model_type
        self.logger = ThreatLogger()
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False
        self.training_date = None
        self.metrics = {}

    def _convert_features(self, X: List[Dict]) -> np.ndarray:
        """Convert dict features to numpy array."""
        if not X:
            return np.array([])
        
        return np.array([
            list(sample.values()) for sample in X
        ])

    def train(self, X_train: List[Dict], y_train: List[int] = None) -> bool:
        try:
            self.logger.log_threat(
                'info',
                f'Start training model: {self.name}',
                {'samples': len(X_train)}
            )

            X = self._convert_features(X_train)

            if len(X) == 0:
                raise ValueError("Empty training data")

            self.model.fit(X)

            self.is_trained = True
            self.training_date = datetime.now()

            self.logger.log_threat(
                'info',
                f'Model {self.name} trained successfully'
            )
            return True

        except Exception as e:
            self.logger.log_threat(
                'error',
                f'Training failed: {str(e)}',
                {'error_type': type(e).__name__}
            )
            return False

    def predict(self, X: List[Dict]) -> List[float]:
        if not self.is_trained:
            self.logger.log_threat('warning', f'Model {self.name} not trained')
            return [0.0] * len(X)

        try:
            X_np = self._convert_features(X)

            preds = self.model.predict(X_np)

            # sklearn: -1 = anomaly, 1 = normal
            return [1.0 if p == -1 else 0.0 for p in preds]

        except Exception as e:
            self.logger.log_threat(
                'error',
                f'Prediction error: {str(e)}',
                {'error_type': type(e).__name__}
            )
            return [0.0] * len(X)

    def evaluate(self, X_test: List[Dict], y_test: List[int]) -> Dict[str, float]:
        try:
            preds = self.predict(X_test)
            preds_binary = [int(p) for p in preds]

            metrics = {
                'accuracy': accuracy_score(y_test, preds_binary),
                'precision': precision_score(y_test, preds_binary, zero_division=0),
                'recall': recall_score(y_test, preds_binary, zero_division=0),
                'f1_score': f1_score(y_test, preds_binary, zero_division=0),
                'test_samples': len(X_test),
            }

            self.metrics = metrics

            self.logger.log_threat(
                'info',
                f'Evaluation done for {self.name}',
                metrics
            )

            return metrics

        except Exception as e:
            self.logger.log_threat(
                'error',
                f'Evaluation error: {str(e)}',
                {'error_type': type(e).__name__}
            )
            return {}

    def save(self, filepath: str) -> bool:
        try:
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)

            with open(filepath, 'wb') as f:
                pickle.dump(self, f)

            self.logger.log_threat('info', f'Model saved to {filepath}')
            return True

        except Exception as e:
            self.logger.log_threat(
                'error',
                f'Save failed: {str(e)}',
                {'error_type': type(e).__name__}
            )
            return False

    def load(self, filepath: str) -> bool:
        try:
            if not os.path.exists(filepath):
                self.logger.log_threat('warning', f'File not found: {filepath}')
                return False

            with open(filepath, 'rb') as f:
                loaded_model = pickle.load(f)

            self.__dict__.update(loaded_model.__dict__)

            self.logger.log_threat('info', f'Model loaded from {filepath}')
            return True

        except Exception as e:
            self.logger.log_threat(
                'error',
                f'Load failed: {str(e)}',
                {'error_type': type(e).__name__}
            )
            return False

    def get_info(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'type': self.model_type,
            'is_trained': self.is_trained,
            'training_date': self.training_date.isoformat() if self.training_date else None,
            'metrics': self.metrics.copy(),
        }


class ModelEnsemble:
    """Ensemble of multiple ML models."""

    def __init__(self):
        self.logger = ThreatLogger()
        self.models: Dict[str, MLModel] = {}
        self.weights: Dict[str, float] = {}

    def add_model(self, model: MLModel, weight: float = 1.0) -> None:
        self.models[model.name] = model
        self.weights[model.name] = weight

    def predict_ensemble(self, X: List[Dict]) -> List[float]:
        if not self.models:
            return [0.0] * len(X)

        results = []
        total_weight = sum(self.weights.values())

        for i in range(len(X)):
            score = 0.0
            for name, model in self.models.items():
                pred = model.predict([X[i]])[0]
                score += pred * self.weights[name]

            results.append(score / total_weight if total_weight > 0 else 0.0)

        return results