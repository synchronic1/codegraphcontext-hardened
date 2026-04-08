# Security module for CodeGraphContext hardening
"""
Security hardening for CodeGraphContext MCP server.

Provides:
- Path validation to prevent traversal attacks
- Cypher query sanitization
- Sensitive file protection
"""

from .path_validation import (
    validate_path,
    is_path_allowed,
    BLOCKED_PATTERNS,
    get_allowed_roots_str,
)
from .cypher_sanitization import (
    sanitize_cypher_query,
    validate_query_params,
    ALLOWED_QUERY_PREFIXES,
)

__all__ = [
    "validate_path",
    "is_path_allowed",
    "BLOCKED_PATTERNS",
    "get_allowed_roots_str",
    "sanitize_cypher_query",
    "validate_query_params",
    "ALLOWED_QUERY_PREFIXES",
]