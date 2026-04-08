"""
Security tests for CodeGraphContext hardening.
"""

import pytest
from pathlib import Path
import tempfile
import os

from codegraphcontext.security import (
    validate_path,
    is_path_allowed,
    sanitize_cypher_query,
    validate_query_params,
    BLOCKED_PATTERNS,
    ALLOWED_QUERY_PREFIXES,
)


class TestPathValidation:
    """Tests for path validation security."""

    def test_valid_project_path(self):
        """Valid project path should pass."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Set allowed roots to tmpdir
            original_roots = os.environ.get("CGC_ALLOWED_ROOTS", "")
            try:
                os.environ["CGC_ALLOWED_ROOTS"] = tmpdir
                path, error = validate_path(tmpdir)
                assert path is not None
                assert error is None
            finally:
                if original_roots:
                    os.environ["CGC_ALLOWED_ROOTS"] = original_roots
                else:
                    os.environ.pop("CGC_ALLOWED_ROOTS", None)

    def test_blocked_ssh_key(self):
        """SSH key path should be blocked."""
        path, error = validate_path("~/.ssh/id_rsa")
        assert path is None
        assert "blocked" in error.lower() or "not allowed" in error.lower()

    def test_blocked_env_file(self):
        """Env file should be blocked."""
        path, error = validate_path(".env")
        assert path is None
        assert "blocked" in error.lower() or "not allowed" in error.lower()

    def test_blocked_credentials(self):
        """Credentials file should be blocked."""
        path, error = validate_path("/home/user/credentials.json")
        assert path is None
        assert "blocked" in error.lower() or "credential" in error.lower()

    def test_blocked_pem_file(self):
        """PEM file should be blocked."""
        path, error = validate_path("/etc/ssl/cert.pem")
        assert path is None

    def test_blocked_etc_shadow(self):
        """System shadow file should be blocked."""
        path, error = validate_path("/etc/shadow")
        assert path is None

    def test_path_traversal_attack(self):
        """Path traversal outside allowed roots should be blocked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_roots = os.environ.get("CGC_ALLOWED_ROOTS", "")
            try:
                os.environ["CGC_ALLOWED_ROOTS"] = tmpdir
                # Try to access /etc/passwd from within tmpdir
                path, error = validate_path("/etc/passwd")
                assert path is None
                assert "blocked" in error.lower() or "allowed" in error.lower()
            finally:
                if original_roots:
                    os.environ["CGC_ALLOWED_ROOTS"] = original_roots
                else:
                    os.environ.pop("CGC_ALLOWED_ROOTS", None)

    def test_empty_path(self):
        """Empty path should be rejected."""
        path, error = validate_path("")
        assert path is None
        assert "empty" in error.lower()

    def test_nonexistent_path(self):
        """Non-existent path should still be validated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_roots = os.environ.get("CGC_ALLOWED_ROOTS", "")
            try:
                os.environ["CGC_ALLOWED_ROOTS"] = tmpdir
                # Non-existent path within allowed roots
                path, error = validate_path(f"{tmpdir}/nonexistent")
                # Path should be validated but marked as not existing
                # (the exists check happens later in the handler)
                assert path is not None or error is not None
            finally:
                if original_roots:
                    os.environ["CGC_ALLOWED_ROOTS"] = original_roots
                else:
                    os.environ.pop("CGC_ALLOWED_ROOTS", None)


class TestCypherSanitization:
    """Tests for Cypher query sanitization."""

    def test_valid_match_query(self):
        """Valid MATCH query should pass."""
        is_safe, result, _ = sanitize_cypher_query("MATCH (n) RETURN n")
        assert is_safe is True
        assert result == "MATCH (n) RETURN n"

    def test_valid_with_query(self):
        """Valid WITH query should pass."""
        is_safe, result, _ = sanitize_cypher_query("WITH 1 as x RETURN x")
        assert is_safe is True

    def test_valid_return_query(self):
        """Valid RETURN query should pass."""
        is_safe, result, _ = sanitize_cypher_query("RETURN 1")
        assert is_safe is True

    def test_blocked_create_query(self):
        """CREATE query should be blocked."""
        is_safe, result, _ = sanitize_cypher_query("CREATE (n:Node)")
        assert is_safe is False
        assert "CREATE" in result

    def test_blocked_merge_query(self):
        """MERGE query should be blocked."""
        is_safe, result, _ = sanitize_cypher_query("MERGE (n:Node)")
        assert is_safe is False
        assert "MERGE" in result

    def test_blocked_delete_query(self):
        """DELETE query should be blocked."""
        is_safe, result, _ = sanitize_cypher_query("MATCH (n) DELETE n")
        assert is_safe is False
        assert "DELETE" in result

    def test_blocked_set_query(self):
        """SET query should be blocked."""
        is_safe, result, _ = sanitize_cypher_query("MATCH (n) SET n.prop = 1")
        assert is_safe is False
        assert "SET" in result

    def test_blocked_apoc_call(self):
        """APOC procedure call should be blocked."""
        is_safe, result, _ = sanitize_cypher_query("CALL apoc.create.node(['Node'], {})")
        assert is_safe is False
        assert "apoc" in result.lower()

    def test_unicode_normalization(self):
        """Unicode bypass attempts should be caught."""
        # Using Unicode variants of CREATE
        is_safe, result, _ = sanitize_cypher_query("ＣREATE (n:Node)")  # Fullwidth C
        assert is_safe is False

    def test_string_literal_injection(self):
        """Keywords inside string literals should not trigger false positives."""
        is_safe, result, _ = sanitize_cypher_query("MATCH (n) WHERE n.name = 'CREATE' RETURN n")
        assert is_safe is True

    def test_empty_query(self):
        """Empty query should be rejected."""
        is_safe, result, _ = sanitize_cypher_query("")
        assert is_safe is False
        assert "empty" in result.lower()

    def test_parameterized_query(self):
        """Parameterized queries should work."""
        query = "MATCH (n) WHERE n.name = $name RETURN n"
        params = {"name": "test"}
        is_safe, result, validated_params = sanitize_cypher_query(query, params)
        assert is_safe is True
        assert validated_params == params

    def test_allowed_db_procedure(self):
        """Allowed database procedures should pass."""
        is_safe, result, _ = sanitize_cypher_query("CALL db.labels()")
        assert is_safe is True

    def test_blocked_dbms_procedure(self):
        """DBMS admin procedures should be blocked."""
        is_safe, result, _ = sanitize_cypher_query("CALL dbms.security.listUsers()")
        assert is_safe is False


class TestQueryParamValidation:
    """Tests for query parameter validation."""

    def test_valid_params(self):
        """Valid parameters should pass."""
        is_valid, error = validate_query_params({"name": "test", "count": 5})
        assert is_valid is True
        assert error is None

    def test_string_params(self):
        """String parameters should pass."""
        is_valid, error = validate_query_params({"name": "John Doe"})
        assert is_valid is True

    def test_empty_params(self):
        """Empty params dict should pass."""
        is_valid, error = validate_query_params({})
        assert is_valid is True

    def test_none_params(self):
        """None params should pass."""
        is_valid, error = validate_query_params(None)
        assert is_valid is True

    def test_non_dict_params(self):
        """Non-dict params should fail."""
        is_valid, error = validate_query_params("not a dict")
        assert is_valid is False
        assert "dictionary" in error.lower()

    def test_non_string_keys(self):
        """Non-string keys should fail."""
        is_valid, error = validate_query_params({123: "value"})
        assert is_valid is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])