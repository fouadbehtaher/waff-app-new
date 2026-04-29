import pytest
import os
import tempfile
from datetime import datetime, timedelta
from database import WAFDatabase


@pytest.fixture
def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return WAFDatabase(db_path=path)


class TestBlacklistViolationLifecycle:
    def test_violation_increments_correctly(self, db):
        c1 = db.blacklist_add_violation("10.0.0.1", "SQL Injection", "high")
        assert c1 == 1
        c2 = db.blacklist_add_violation("10.0.0.1", "XSS", "medium")
        assert c2 == 2
        c3 = db.blacklist_add_violation("10.0.0.1", "Command Injection", "critical")
        assert c3 == 3

    def test_violation_stores_threat_info(self, db):
        db.blacklist_add_violation("10.0.0.1", "SQL Injection", "critical")
        conn = db._get_conn()
        row = conn.execute("SELECT * FROM ip_violations WHERE ip = ?", ("10.0.0.1",)).fetchone()
        assert row["threat"] == "SQL Injection"
        assert row["threat_level"] == "critical"
        conn.close()

    def test_violation_updates_blacklist_threat_level(self, db):
        db.blacklist_add_violation("10.0.0.1", "Low threat", "low")
        db.blacklist_add_violation("10.0.0.1", "Critical threat", "critical")
        entries = db.blacklist_get_all()
        assert len(entries) == 1
        assert entries[0]["threat_level"] == "critical"

    def test_multiple_ips_independent(self, db):
        c1 = db.blacklist_add_violation("10.0.0.1", "SQLi", "high")
        c2 = db.blacklist_add_violation("10.0.0.2", "XSS", "medium")
        assert c1 == 1
        assert c2 == 1


class TestBlacklistBanOperations:
    def test_ban_without_prior_violation(self, db):
        db.blacklist_ban("10.0.0.1", "manual ban")
        assert db.blacklist_is_blocked("10.0.0.1") is True

    def test_ban_with_expiration(self, db):
        db.blacklist_ban("10.0.0.1", "temp ban", permanent=False, duration_hours=2)
        entries = db.blacklist_get_all()
        assert len(entries) == 1
        assert entries[0]["expires_at"] is not None
        assert entries[0]["is_permanent"] == 0

    def test_ban_permanent(self, db):
        db.blacklist_ban("10.0.0.1", "permanent ban", permanent=True)
        entries = db.blacklist_get_all()
        assert entries[0]["is_permanent"] == 1
        assert entries[0]["expires_at"] is None

    def test_ban_overwrites_previous(self, db):
        db.blacklist_ban("10.0.0.1", "old reason", permanent=False)
        db.blacklist_ban("10.0.0.1", "new reason", permanent=True)
        entries = db.blacklist_get_all()
        assert len(entries) == 1
        assert entries[0]["reason"] == "new reason"
        assert entries[0]["is_permanent"] == 1

    def test_unban_removes_entry(self, db):
        db.blacklist_ban("10.0.0.1", "test ban")
        db.blacklist_unban("10.0.0.1")
        entries = db.blacklist_get_all()
        assert len(entries) == 0
        assert db.blacklist_is_blocked("10.0.0.1") is False

    def test_unban_nonexistent_ip(self, db):
        db.blacklist_unban("10.0.0.1")
        assert db.blacklist_is_blocked("10.0.0.1") is False


class TestBlacklistIsBlocked:
    def test_clean_ip_returns_false(self, db):
        assert db.blacklist_is_blocked("10.0.0.1") is False

    def test_permanently_banned_ip_returns_true(self, db):
        db.blacklist_ban("10.0.0.1", "permanent", permanent=True)
        assert db.blacklist_is_blocked("10.0.0.1") is True

    def test_temporary_banned_ip_returns_true(self, db):
        db.blacklist_ban("10.0.0.1", "temp", permanent=False, duration_hours=1)
        assert db.blacklist_is_blocked("10.0.0.1") is True

    def test_expired_ban_returns_false(self, db):
        conn = db._get_conn()
        past = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        conn.execute("""
            INSERT INTO ip_blacklist (ip, reason, is_permanent, banned_at, expires_at)
            VALUES ('10.0.0.1', 'expired', 0, ?, ?)
        """, (datetime.utcnow().isoformat(), past))
        conn.commit()
        conn.close()
        assert db.blacklist_is_blocked("10.0.0.1") is False

    def test_whitelisted_ip_returns_false(self, db):
        conn = db._get_conn()
        conn.execute("INSERT INTO ip_blacklist (ip, reason, is_whitelisted) VALUES (?, ?, 1)", ("10.0.0.1", "whitelisted"))
        conn.commit()
        conn.close()
        assert db.blacklist_is_blocked("10.0.0.1") is False

    def test_future_expiration_still_blocked(self, db):
        future = (datetime.utcnow() + timedelta(hours=1)).isoformat()
        conn = db._get_conn()
        conn.execute("""
            INSERT INTO ip_blacklist (ip, reason, is_permanent, banned_at, expires_at)
            VALUES ('10.0.0.1', 'future', 0, ?, ?)
        """, (datetime.utcnow().isoformat(), future))
        conn.commit()
        conn.close()
        assert db.blacklist_is_blocked("10.0.0.1") is True


class TestBlacklistGetAll:
    def test_returns_empty_when_no_entries(self, db):
        assert db.blacklist_get_all() == []

    def test_returns_all_entries(self, db):
        db.blacklist_ban("10.0.0.1", "ban1")
        db.blacklist_ban("10.0.0.2", "ban2")
        db.blacklist_ban("10.0.0.3", "ban3")
        entries = db.blacklist_get_all()
        assert len(entries) == 3

    def test_excludes_whitelisted(self, db):
        db.blacklist_ban("10.0.0.1", "ban")
        conn = db._get_conn()
        conn.execute("INSERT INTO ip_blacklist (ip, reason, is_whitelisted) VALUES (?, ?, 1)", ("10.0.0.2", "whitelisted"))
        conn.commit()
        conn.close()
        entries = db.blacklist_get_all()
        assert len(entries) == 1
        assert entries[0]["ip"] == "10.0.0.1"

    def test_ordered_by_violation_count(self, db):
        db.blacklist_add_violation("10.0.0.1", "threat1", "high")
        db.blacklist_add_violation("10.0.0.1", "threat2", "high")
        db.blacklist_add_violation("10.0.0.1", "threat3", "high")
        db.blacklist_add_violation("10.0.0.2", "threat1", "medium")
        entries = db.blacklist_get_all()
        assert entries[0]["ip"] == "10.0.0.1"
        assert entries[0]["violation_count"] == 3


class TestBlacklistGetStats:
    def test_empty_stats(self, db):
        stats = db.blacklist_get_stats()
        assert stats["total_blacklisted"] == 0
        assert stats["permanent_bans"] == 0
        assert stats["whitelisted"] == 0

    def test_stats_with_data(self, db):
        db.blacklist_ban("10.0.0.1", "ban1", permanent=True)
        db.blacklist_ban("10.0.0.2", "ban2", permanent=False)
        db.blacklist_add_violation("10.0.0.3", "threat", "low")
        stats = db.blacklist_get_stats()
        assert stats["total_blacklisted"] == 3
        assert stats["permanent_bans"] == 1
        assert stats["total_ips_tracked"] == 1

    def test_stats_whitelisted_count(self, db):
        db.blacklist_ban("10.0.0.1", "ban")
        conn = db._get_conn()
        conn.execute("INSERT INTO ip_blacklist (ip, reason, is_whitelisted) VALUES (?, ?, 1)", ("10.0.0.2", "wl"))
        conn.commit()
        conn.close()
        stats = db.blacklist_get_stats()
        assert stats["whitelisted"] == 1


class TestBlacklistAutoBanFlow:
    def test_violation_then_ban(self, db):
        for i in range(5):
            db.blacklist_add_violation("10.0.0.1", f"threat{i}", "high")
        db.blacklist_ban("10.0.0.1", "auto-banned after threshold")
        assert db.blacklist_is_blocked("10.0.0.1") is True
        entries = db.blacklist_get_all()
        assert entries[0]["violation_count"] == 5

    def test_ban_then_more_violations(self, db):
        db.blacklist_ban("10.0.0.1", "manual ban")
        db.blacklist_add_violation("10.0.0.1", "additional threat", "critical")
        entries = db.blacklist_get_all()
        assert len(entries) == 1
        assert entries[0]["violation_count"] >= 1
        assert db.blacklist_is_blocked("10.0.0.1") is True


class TestBlacklistEdgeCases:
    def test_empty_ip_string(self, db):
        db.blacklist_ban("", "empty ip ban")
        entries = db.blacklist_get_all()
        assert len(entries) == 1

    def test_special_characters_in_reason(self, db):
        db.blacklist_ban("10.0.0.1", "ban with 'quotes' and \"double quotes\"")
        assert db.blacklist_is_blocked("10.0.0.1") is True

    def test_ipv6_address(self, db):
        db.blacklist_ban("::1", "ipv6 ban")
        assert db.blacklist_is_blocked("::1") is True

    def test_very_long_reason(self, db):
        long_reason = "A" * 500
        db.blacklist_ban("10.0.0.1", long_reason)
        entries = db.blacklist_get_all()
        assert len(entries[0]["reason"]) == 500

    def test_zero_violation_count(self, db):
        db.blacklist_ban("10.0.0.1", "ban without violations")
        entries = db.blacklist_get_all()
        assert entries[0]["violation_count"] == 0

    def test_unban_and_reban(self, db):
        db.blacklist_ban("10.0.0.1", "first ban")
        db.blacklist_unban("10.0.0.1")
        db.blacklist_ban("10.0.0.1", "second ban", permanent=True)
        assert db.blacklist_is_blocked("10.0.0.1") is True
        entries = db.blacklist_get_all()
        assert len(entries) == 1
        assert entries[0]["is_permanent"] == 1
