import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch, MagicMock

from main import app


@pytest.fixture
def client():
    return TestClient(app)


class TestHealthEndpoints:
    def test_health(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert "version" in response.json()

    def test_waf_health(self, client):
        response = client.get("/waf/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data

    def test_waf_metrics(self, client):
        response = client.get("/waf/metrics")
        assert response.status_code == 200
        data = response.json()
        assert "total_requests" in data
        assert "blocked_requests" in data
