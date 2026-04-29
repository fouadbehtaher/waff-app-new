import pytest
import os
import tempfile
from src.waf.tls_config import TLSConfig, generate_self_signed_cert


class TestTLSConfig:
    def test_not_configured_without_paths(self):
        config = TLSConfig()
        assert config.is_configured() is False

    def test_configured_with_paths(self):
        config = TLSConfig(cert_path="/tmp/cert.pem", key_path="/tmp/key.pem")
        assert config.is_configured() is True

    def test_get_info_not_configured(self):
        config = TLSConfig()
        info = config.get_info()
        assert info["configured"] is False
        assert info["context_ready"] is False

    def test_get_info_configured(self):
        config = TLSConfig(cert_path="/tmp/cert.pem", key_path="/tmp/key.pem")
        info = config.get_info()
        assert info["cert_path"] == "/tmp/cert.pem"
        assert info["key_path"] == "/tmp/key.pem"
        assert info["configured"] is True

    def test_create_context_missing_cert(self):
        config = TLSConfig(cert_path="/nonexistent/cert.pem", key_path="/nonexistent/key.pem")
        ctx = config.create_ssl_context()
        assert ctx is None

    def test_create_context_missing_key(self, tmp_path):
        cert_path = tmp_path / "cert.pem"
        cert_path.write_text("dummy cert")
        config = TLSConfig(cert_path=str(cert_path), key_path="/nonexistent/key.pem")
        ctx = config.create_ssl_context()
        assert ctx is None


class TestTLSCertGeneration:
    def test_generate_self_signed_cert(self, tmp_path):
        cert_path = str(tmp_path / "test.crt")
        key_path = str(tmp_path / "test.key")
        result = generate_self_signed_cert(cert_path, key_path)
        assert result is True
        assert os.path.exists(cert_path)
        assert os.path.exists(key_path)

    def test_generate_cert_with_custom_days(self, tmp_path):
        cert_path = str(tmp_path / "custom.crt")
        key_path = str(tmp_path / "custom.key")
        result = generate_self_signed_cert(cert_path, key_path, days=30)
        assert result is True
        assert os.path.getsize(cert_path) > 0

    def test_generate_cert_creates_parent_dirs(self, tmp_path):
        cert_path = str(tmp_path / "subdir" / "cert.pem")
        key_path = str(tmp_path / "subdir" / "key.pem")
        result = generate_self_signed_cert(cert_path, key_path)
        assert result is True
        assert os.path.exists(cert_path)
        assert os.path.exists(key_path)

    def test_generated_cert_is_valid_pem(self, tmp_path):
        cert_path = str(tmp_path / "valid.crt")
        key_path = str(tmp_path / "valid.key")
        generate_self_signed_cert(cert_path, key_path)
        with open(cert_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        assert "BEGIN CERTIFICATE" in content
        assert "END CERTIFICATE" in content

    def test_generated_key_is_valid_pem(self, tmp_path):
        cert_path = str(tmp_path / "valid2.crt")
        key_path = str(tmp_path / "valid2.key")
        generate_self_signed_cert(cert_path, key_path)
        with open(key_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        assert "PRIVATE KEY" in content


class TestTLSConfigWithGeneratedCerts:
    def test_create_context_with_generated_certs(self, tmp_path):
        cert_path = str(tmp_path / "ctx.crt")
        key_path = str(tmp_path / "ctx.key")
        generate_self_signed_cert(cert_path, key_path)
        config = TLSConfig(cert_path=cert_path, key_path=key_path)
        ctx = config.create_ssl_context()
        assert ctx is not None
        assert config.get_info()["context_ready"] is True

    def test_info_after_context_creation(self, tmp_path):
        cert_path = str(tmp_path / "info.crt")
        key_path = str(tmp_path / "info.key")
        generate_self_signed_cert(cert_path, key_path)
        config = TLSConfig(cert_path=cert_path, key_path=key_path)
        config.create_ssl_context()
        info = config.get_info()
        assert info["configured"] is True
        assert info["context_ready"] is True
