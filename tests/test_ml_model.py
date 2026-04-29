import pytest
import os
from unittest.mock import patch, MagicMock
from src.waf.ml_model import WAFMLModel


@pytest.fixture
def ml_model():
    with patch("src.waf.ml_model.MODEL_PATH"):
        with patch.object(WAFMLModel, "load", return_value=None):
            model = WAFMLModel()
            model._weights = None
            model._trained = False
            yield model


class TestExtractFeatures:
    def test_clean_request_features(self, ml_model):
        features = ml_model.extract_features(
            method="GET",
            path="/api/users",
            query_string="",
            body_preview='{"name": "John"}',
        )
        assert features["path_length"] == len("/api/users")
        assert features["has_sql_keywords"] == 0
        assert features["has_script_tags"] == 0
        assert features["has_traversal"] == 0

    def test_sql_injection_features(self, ml_model):
        features = ml_model.extract_features(
            method="GET",
            path="/search",
            query_string="q=1' OR 1=1--",
            body_preview="",
        )
        assert features["has_sql_keywords"] == 1

    def test_xss_features(self, ml_model):
        features = ml_model.extract_features(
            method="GET",
            path="/comment",
            query_string="text=<script>alert(1)</script>",
            body_preview="",
        )
        assert features["has_script_tags"] == 1

    def test_path_traversal_features(self, ml_model):
        features = ml_model.extract_features(
            method="GET",
            path="/files",
            query_string="f=../../../etc/passwd",
            body_preview="",
        )
        assert features["has_traversal"] == 1

    def test_command_injection_features(self, ml_model):
        features = ml_model.extract_features(
            method="GET",
            path="/run",
            query_string="cmd=ls;cat /etc/passwd",
            body_preview="",
        )
        assert features["has_command_chars"] == 1

    def test_empty_request_features(self, ml_model):
        features = ml_model.extract_features("GET", "", "", "")
        assert features["path_length"] == 0
        assert features["has_special_chars"] == 0


class TestPredictWithoutTraining:
    def test_predict_untrained_returns_not_trained(self, ml_model):
        result = ml_model.predict({})
        assert result["is_malicious"] is False
        assert result["reason"] == "model_not_trained"

    def test_predict_untrained_confidence_zero(self, ml_model):
        result = ml_model.predict({"path_length": 100})
        assert result["confidence"] == 0.0


class TestModelTraining:
    def test_train_creates_weights(self, ml_model, tmp_path):
        with patch("src.waf.ml_model.MODEL_PATH", tmp_path / "model.json"):
            training_data = [
                {"path_length": 10, "query_length": 0, "body_length": 20, "has_special_chars": 0,
                 "has_sql_keywords": 0, "has_script_tags": 0, "has_traversal": 0, "has_command_chars": 0,
                 "decision": "allow", "threat_level": "safe"},
            ] * 30 + [
                {"path_length": 50, "query_length": 30, "body_length": 200, "has_special_chars": 1,
                 "has_sql_keywords": 1, "has_script_tags": 1, "has_traversal": 1, "has_command_chars": 1,
                 "decision": "block", "threat_level": "high"},
            ] * 30
            result = ml_model.train(training_data, epochs=50)
            assert result["status"] == "trained"
            assert "accuracy" in result
            assert ml_model._trained is True

    def test_train_requires_data(self, ml_model, tmp_path):
        with patch("src.waf.ml_model.MODEL_PATH", tmp_path / "model.json"):
            result = ml_model.train([], epochs=10)
            assert result["status"] == "no_data"

    def test_predict_after_training(self, ml_model, tmp_path):
        with patch("src.waf.ml_model.MODEL_PATH", tmp_path / "model.json"):
            training_data = [
                {"path_length": 10, "query_length": 0, "body_length": 20, "has_special_chars": 0,
                 "has_sql_keywords": 0, "has_script_tags": 0, "has_traversal": 0, "has_command_chars": 0,
                 "decision": "allow"},
            ] * 30 + [
                {"path_length": 50, "query_length": 30, "body_length": 200, "has_special_chars": 1,
                 "has_sql_keywords": 1, "has_script_tags": 1, "has_traversal": 1, "has_command_chars": 1,
                 "decision": "block"},
            ] * 30
            ml_model.train(training_data, epochs=50)
            clean_features = {"path_length": 10, "query_length": 0, "body_length": 20, "has_special_chars": 0,
                              "has_sql_keywords": 0, "has_script_tags": 0, "has_traversal": 0, "has_command_chars": 0}
            result = ml_model.predict(clean_features)
            assert "is_malicious" in result
            assert "confidence" in result


class TestModelPersistence:
    def test_save_and_load(self, tmp_path):
        model_path = tmp_path / "model.json"
        with patch("src.waf.ml_model.MODEL_PATH", model_path):
            model = WAFMLModel()
            training_data = [
                {"path_length": 10, "query_length": 0, "body_length": 20, "has_special_chars": 0,
                 "has_sql_keywords": 0, "has_script_tags": 0, "has_traversal": 0, "has_command_chars": 0,
                 "decision": "allow"},
            ] * 30 + [
                {"path_length": 50, "query_length": 30, "body_length": 200, "has_special_chars": 1,
                 "has_sql_keywords": 1, "has_script_tags": 1, "has_traversal": 1, "has_command_chars": 1,
                 "decision": "block"},
            ] * 30
            model.train(training_data, epochs=50)
            assert model_path.exists()
            model2 = WAFMLModel()
            assert model2._trained is True

    def test_load_nonexistent_no_error(self, ml_model, tmp_path):
        with patch("src.waf.ml_model.MODEL_PATH", tmp_path / "nonexistent.json"):
            ml_model.load()
            assert ml_model._trained is False


class TestGetModelInfo:
    def test_info_before_training(self, ml_model):
        info = ml_model.get_model_info()
        assert info["trained"] is False
        assert info["accuracy"] == 0.0

    def test_info_after_training(self, ml_model, tmp_path):
        with patch("src.waf.ml_model.MODEL_PATH", tmp_path / "model.json"):
            training_data = [
                {"path_length": 10, "query_length": 0, "body_length": 20, "has_special_chars": 0,
                 "has_sql_keywords": 0, "has_script_tags": 0, "has_traversal": 0, "has_command_chars": 0,
                 "decision": "allow"},
            ] * 30 + [
                {"path_length": 50, "query_length": 30, "body_length": 200, "has_special_chars": 1,
                 "has_sql_keywords": 1, "has_script_tags": 1, "has_traversal": 1, "has_command_chars": 1,
                 "decision": "block"},
            ] * 30
            ml_model.train(training_data, epochs=50)
            info = ml_model.get_model_info()
            assert info["trained"] is True
            assert info["accuracy"] > 0
            assert len(info["feature_names"]) == 8
