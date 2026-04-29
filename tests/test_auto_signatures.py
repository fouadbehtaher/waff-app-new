import pytest
from unittest.mock import patch
from src.waf.auto_signatures import AutoSignatureGenerator


@pytest.fixture
def sig_gen():
    with patch("src.waf.auto_signatures.SIGNATURE_RULES_PATH"):
        with patch.object(AutoSignatureGenerator, "_load_rules", return_value=None):
            gen = AutoSignatureGenerator()
            gen._rules = []
            yield gen


class TestAnalyzeAndGenerate:
    def test_generate_from_sqli_request(self, sig_gen):
        blocked = [{"path": "/search", "query_string": "q=1' OR 1=1--", "body_preview": "", "reason": "sqli"}]
        new_sigs = sig_gen.analyze_and_generate(blocked)
        assert len(new_sigs) > 0
        assert any(s["category"] == "SQL Injection" for s in new_sigs)

    def test_generate_from_xss_request(self, sig_gen):
        blocked = [{"path": "/comment", "query_string": "", "body_preview": "<script>alert(1)</script>", "reason": "xss"}]
        new_sigs = sig_gen.analyze_and_generate(blocked)
        assert len(new_sigs) > 0
        assert any(s["category"] == "XSS" for s in new_sigs)

    def test_generate_from_cmd_injection(self, sig_gen):
        blocked = [{"path": "/run", "query_string": "cmd=ls;cat /etc/passwd", "body_preview": "", "reason": "cmdi"}]
        new_sigs = sig_gen.analyze_and_generate(blocked)
        assert len(new_sigs) > 0
        assert any(s["category"] == "Command Injection" for s in new_sigs)

    def test_generate_from_traversal(self, sig_gen):
        blocked = [{"path": "/files", "query_string": "f=../../../etc/passwd", "body_preview": "", "reason": "traversal"}]
        new_sigs = sig_gen.analyze_and_generate(blocked)
        assert len(new_sigs) > 0
        assert any(s["category"] == "File Inclusion" for s in new_sigs)

    def test_generate_empty_requests(self, sig_gen):
        new_sigs = sig_gen.analyze_and_generate([])
        assert new_sigs == []

    def test_generated_sigs_have_required_fields(self, sig_gen):
        blocked = [{"path": "/test", "query_string": "q=<script>", "body_preview": "", "reason": "test"}]
        new_sigs = sig_gen.analyze_and_generate(blocked)
        for sig in new_sigs:
            assert "pattern" in sig
            assert "category" in sig
            assert "threat_level" in sig
            assert sig["status"] == "pending_review"

    def test_duplicate_requests_not_duplicated(self, sig_gen):
        blocked = [{"path": "/search", "query_string": "q=' or '", "body_preview": "", "reason": "sqli"}] * 3
        new_sigs = sig_gen.analyze_and_generate(blocked)
        patterns = [s["pattern"] for s in new_sigs]
        assert len(patterns) == len(set(patterns))


class TestGetRules:
    def test_get_all_rules_empty(self, sig_gen):
        assert sig_gen.get_rules() == []

    def test_get_rules_by_status(self, sig_gen):
        sig_gen._rules = [
            {"pattern": "p1", "status": "pending_review"},
            {"pattern": "p2", "status": "approved"},
        ]
        pending = sig_gen.get_rules(status="pending_review")
        assert len(pending) == 1
        assert pending[0]["pattern"] == "p1"

    def test_get_approved_rules(self, sig_gen):
        sig_gen._rules = [
            {"pattern": "p1", "status": "approved"},
            {"pattern": "p2", "status": "pending_review"},
        ]
        approved = sig_gen.get_rules(status="approved")
        assert len(approved) == 1


class TestRuleReview:
    def test_approve_rule(self, sig_gen):
        sig_gen._rules = [{"pattern": "test", "status": "pending_review"}]
        result = sig_gen.approve_rule(0)
        assert result["status"] == "approved"
        assert sig_gen._rules[0]["status"] == "approved"

    def test_reject_rule(self, sig_gen):
        sig_gen._rules = [{"pattern": "test", "status": "pending_review"}]
        result = sig_gen.reject_rule(0)
        assert result["status"] == "rejected"
        assert sig_gen._rules[0]["status"] == "rejected"

    def test_approve_invalid_index(self, sig_gen):
        result = sig_gen.approve_rule(999)
        assert result["status"] == "not_found"

    def test_reject_invalid_index(self, sig_gen):
        result = sig_gen.reject_rule(-1)
        assert result["status"] == "not_found"

    def test_delete_rule(self, sig_gen):
        sig_gen._rules = [{"pattern": "test", "status": "pending_review"}]
        result = sig_gen.delete_rule(0)
        assert result["status"] == "deleted"
        assert len(sig_gen._rules) == 0

    def test_delete_invalid_index(self, sig_gen):
        result = sig_gen.delete_rule(0)
        assert result["status"] == "not_found"


class TestGetStats:
    def test_stats_empty(self, sig_gen):
        stats = sig_gen.get_stats()
        assert stats["total"] == 0
        assert stats["approved"] == 0
        assert stats["pending"] == 0
        assert stats["rejected"] == 0

    def test_stats_with_mixed_rules(self, sig_gen):
        sig_gen._rules = [
            {"pattern": "p1", "status": "pending_review", "category": "SQL Injection"},
            {"pattern": "p2", "status": "approved", "category": "XSS"},
            {"pattern": "p3", "status": "rejected", "category": "SQL Injection"},
        ]
        stats = sig_gen.get_stats()
        assert stats["total"] == 3
        assert stats["pending"] == 1
        assert stats["approved"] == 1
        assert stats["rejected"] == 1
        assert "SQL Injection" in stats["categories"]


class TestPatternExtraction:
    def test_extract_sql_keywords(self, sig_gen):
        candidates = sig_gen._extract_patterns("select union drop table", "sqli")
        assert len(candidates) >= 3

    def test_extract_xss_keywords(self, sig_gen):
        candidates = sig_gen._extract_patterns("<script>alert(document.cookie)</script>", "xss")
        assert len(candidates) >= 1

    def test_extract_no_pattern_for_clean_text(self, sig_gen):
        candidates = sig_gen._extract_patterns("hello world normal text", "none")
        assert candidates == []
