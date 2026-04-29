import json
import structlog
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

logger = structlog.get_logger()

MODEL_PATH = Path(__file__).parent / "ml_model" / "waf_model.json"


class WAFMLModel:
    def __init__(self):
        self._weights = None
        self._bias = 0.0
        self._trained = False
        self._feature_names = [
            "path_length", "query_length", "body_length",
            "has_special_chars", "has_sql_keywords", "has_script_tags",
            "has_traversal", "has_command_chars"
        ]
        self.load()

    def extract_features(self, method: str, path: str, query_string: str, body_preview: str) -> Dict:
        combined = (query_string + " " + body_preview).lower()
        return {
            "path_length": len(path),
            "query_length": len(query_string),
            "body_length": len(body_preview),
            "has_special_chars": 1 if any(c in combined for c in ["'", '"', "<", ">", ";", "|", "`"]) else 0,
            "has_sql_keywords": 1 if any(kw in combined for kw in ["select", "union", "drop", "insert", "delete", "update", "or 1=1", "and 1=1", "or '1'='1"]) else 0,
            "has_script_tags": 1 if any(kw in combined for kw in ["<script", "javascript:", "onerror=", "onload=", "onclick="]) else 0,
            "has_traversal": 1 if "../" in query_string or "..\\" in query_string or "/etc/" in combined else 0,
            "has_command_chars": 1 if any(c in combined for c in [";cat ", "|ls ", "&&", "`", "$("]) else 0
        }

    def predict(self, features: Dict) -> Dict:
        if not self._trained:
            return {"is_malicious": False, "confidence": 0.0, "reason": "model_not_trained"}
        feature_values = np.array([features.get(f, 0) for f in self._feature_names])
        score = np.dot(feature_values, self._weights) + self._bias
        probability = 1 / (1 + np.exp(-score))
        return {
            "is_malicious": probability > 0.5,
            "confidence": float(probability),
            "reason": "ml_prediction"
        }

    def train(self, training_data: List[Dict], epochs: int = 100, learning_rate: float = 0.01):
        if not training_data:
            logger.warning("no_training_data_provided")
            return {"status": "no_data", "accuracy": 0.0}
        X = []
        y = []
        for sample in training_data:
            features = [sample.get(f, 0) for f in self._feature_names]
            X.append(features)
            label = 1 if sample.get("decision") == "block" or sample.get("threat_level") in ["high", "critical"] else 0
            y.append(label)
        X = np.array(X, dtype=np.float64)
        y = np.array(y, dtype=np.float64)
        X_mean = X.mean(axis=0)
        X_std = X.std(axis=0)
        X_std[X_std == 0] = 1
        X_normalized = (X - X_mean) / X_std
        n_samples, n_features = X_normalized.shape
        self._weights = np.random.randn(n_features) * 0.01
        self._bias = 0.0
        best_loss = float("inf")
        for epoch in range(epochs):
            linear = np.dot(X_normalized, self._weights) + self._bias
            predictions = 1 / (1 + np.exp(-linear))
            error = predictions - y
            loss = -np.mean(y * np.log(predictions + 1e-15) + (1 - y) * np.log(1 - predictions + 1e-15))
            dw = np.dot(X_normalized.T, error) / n_samples
            db = np.mean(error)
            self._weights -= learning_rate * dw
            self._bias -= learning_rate * db
            if loss < best_loss:
                best_loss = loss
        predictions_final = 1 / (1 + np.exp(-(np.dot(X_normalized, self._weights) + self._bias)))
        predicted_classes = (predictions_final > 0.5).astype(int)
        accuracy = float(np.mean(predicted_classes == y))
        self._trained = True
        self._model_meta = {"X_mean": X_mean.tolist(), "X_std": X_std.tolist(), "accuracy": accuracy, "samples": n_samples, "epochs": epochs}
        self.save()
        logger.info("ml_model_trained", accuracy=accuracy, samples=n_samples, loss=best_loss)
        return {"status": "trained", "accuracy": accuracy, "samples": n_samples, "loss": float(best_loss), "epochs": epochs}

    def save(self):
        if self._weights is None:
            return
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        model_data = {
            "weights": self._weights.tolist(),
            "bias": float(self._bias),
            "trained": self._trained,
            "feature_names": self._feature_names,
            "meta": self._model_meta if hasattr(self, "_model_meta") else {}
        }
        with open(MODEL_PATH, "w") as f:
            json.dump(model_data, f, indent=2)

    def load(self):
        if not MODEL_PATH.exists():
            return
        try:
            with open(MODEL_PATH, "r") as f:
                model_data = json.load(f)
            self._weights = np.array(model_data["weights"])
            self._bias = model_data["bias"]
            self._trained = model_data.get("trained", False)
            self._model_meta = model_data.get("meta", {})
            logger.info("ml_model_loaded", trained=self._trained)
        except Exception as e:
            logger.error("ml_model_load_failed", error=str(e))

    def get_model_info(self) -> Dict:
        return {
            "trained": self._trained,
            "accuracy": self._model_meta.get("accuracy", 0.0) if hasattr(self, "_model_meta") else 0.0,
            "samples_trained": self._model_meta.get("samples", 0) if hasattr(self, "_model_meta") else 0,
            "feature_names": self._feature_names,
            "model_path": str(MODEL_PATH)
        }

    def retrain_from_db(self, db) -> Dict:
        import asyncio
        async def _fetch():
            return await db.get_ml_training_data(limit=10000)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(_fetch())
                return {"status": "training_queued"}
        except Exception:
            pass
        return {"status": "no_async_loop"}


waf_ml_model = WAFMLModel()
