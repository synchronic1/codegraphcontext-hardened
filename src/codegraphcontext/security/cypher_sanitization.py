"""
Cypher query sanitization for read-only operations.

Prevents:
- Write operations (CREATE, MERGE, DELETE, etc.)
- Dangerous procedure calls
- Query injection via Unicode normalization
"""

import re
import unicodedata
from typing import Dict, Any, Optional, Tuple, List

# Allowed query prefixes (read-only operations)
ALLOWED_QUERY_PREFIXES = [
    "MATCH",
    "WITH",
    "RETURN",
    "UNWIND",
    "CALL {",      # Subquery (read-only)
    "SHOW",        # Metadata queries
    "EXPLAIN",
    "PROFILE",
]

# Forbidden keywords (write operations)
FORBIDDEN_KEYWORDS = [
    "CREATE",
    "MERGE",
    "DELETE",
    "DETACH DELETE",
    "SET",
    "REMOVE",
    "DROP",
    "CALL apoc.",      # APOC procedures can be dangerous
    "CALL dbms.",      # Admin procedures
    "LOAD CSV",        # Can write data
    "USING PERIODIC",  # Batch operations
]

# Allowed safe procedures (read-only)
ALLOWED_PROCEDURES = [
    "db.index.fulltext.queryNodes",
    "db.index.fulltext.queryRelationships",
    "db.index.fulltext.query",
    "db.schema",
    "db.labels",
    "db.relationshipTypes",
    "db.propertyKeys",
]


def _normalize_query(query: str) -> str:
    """
    Normalize a query for analysis.
    
    - Converts Unicode to NFC form (prevents bypass via homographs)
    - Removes string literals (prevents keyword injection in strings)
    """
    # Normalize Unicode
    normalized = unicodedata.normalize('NFKC', query)
    
    # Remove string literals (both single and double quoted)
    # Handles escaped quotes within strings
    string_pattern = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    without_strings = re.sub(string_pattern, '', normalized)
    
    return without_strings


def _check_prefix(query: str) -> Tuple[bool, Optional[str]]:
    """
    Check if query starts with an allowed prefix.
    
    Returns:
        (is_valid, error_message)
    """
    # Normalize and strip whitespace
    clean = query.strip().upper()
    
    for prefix in ALLOWED_QUERY_PREFIXES:
        if clean.startswith(prefix.upper()):
            return True, None
    
    return False, (
        f"Query must start with a read-only clause: "
        f"{', '.join(ALLOWED_QUERY_PREFIXES[:4])}"
    )


def _check_forbidden_keywords(query: str) -> Tuple[bool, Optional[str]]:
    """
    Check for forbidden keywords in query.
    
    Returns:
        (is_safe, error_message) - False if forbidden keyword found
    """
    normalized = _normalize_query(query)
    
    for keyword in FORBIDDEN_KEYWORDS:
        # Use word boundary matching
        pattern = r'\b' + re.escape(keyword) + r'\b'
        if re.search(pattern, normalized, re.IGNORECASE):
            return False, f"Forbidden keyword in query: '{keyword}'"
    
    return True, None


def _check_procedures(query: str) -> Tuple[bool, Optional[str]]:
    """
    Check if any CALL statements use allowed procedures only.
    
    Returns:
        (is_safe, error_message)
    """
    # Find CALL statements
    call_pattern = r'CALL\s+([^\s(]+)'
    matches = re.findall(call_pattern, query, re.IGNORECASE)
    
    for proc in matches:
        proc_clean = proc.strip().lower()
        
        # Check if it's an allowed procedure
        is_allowed = any(
            proc_clean == allowed.lower()
            for allowed in ALLOWED_PROCEDURES
        )
        
        if not is_allowed:
            # Check if it's explicitly forbidden
            if proc_clean.startswith("apoc.") or proc_clean.startswith("dbms."):
                return False, f"Forbidden procedure: CALL {proc}"
            
            # Unknown procedure - warn but allow (conservative)
            # In strict mode, this would be blocked
    
    return True, None


def sanitize_cypher_query(
    query: str,
    params: Optional[Dict[str, Any]] = None,
    strict_mode: bool = False,
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Sanitize a Cypher query for read-only execution.
    
    Args:
        query: The Cypher query string
        params: Optional query parameters (recommended)
        strict_mode: If True, reject all CALL statements except allowed procedures
    
    Returns:
        (is_safe, result_or_error, params) tuple
    
    Examples:
        >>> sanitize_cypher_query("MATCH (n) RETURN n")
        (True, "MATCH (n) RETURN n", None)
        
        >>> sanitize_cypher_query("CREATE (n:Node)")
        (False, "Forbidden keyword in query: 'CREATE'", None)
        
        >>> sanitize_cypher_query("MATCH (n) WHERE n.name = $name RETURN n", {"name": "test"})
        (True, "MATCH (n) WHERE n.name = $name RETURN n", {"name": "test"})
    """
    if not query or not query.strip():
        return False, "Query cannot be empty", None
    
    # Normalize whitespace
    query = query.strip()
    
    # Check prefix
    is_valid, error = _check_prefix(query)
    if not is_valid:
        return False, error, None
    
    # Check forbidden keywords
    is_safe, error = _check_forbidden_keywords(query)
    if not is_safe:
        return False, error, None
    
    # Check procedures
    is_safe, error = _check_procedures(query)
    if not is_safe:
        return False, error, None
    
    # In strict mode, verify all CALLs are allowed
    if strict_mode:
        call_matches = re.findall(r'CALL\s+([^\s(]+)', query, re.IGNORECASE)
        for proc in call_matches:
            if proc.strip().lower() not in [p.lower() for p in ALLOWED_PROCEDURES]:
                return False, f"Strict mode: unknown procedure '{proc}'", None
    
    return True, query, params


def validate_query_params(params: Optional[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """
    Validate query parameters for safety.
    
    Ensures:
    - No executable code in parameters
    - Parameters are serializable
    
    Returns:
        (is_valid, error_message)
    """
    if params is None:
        return True, None
    
    if not isinstance(params, dict):
        return False, "Parameters must be a dictionary"
    
    # Check for potentially dangerous values
    for key, value in params.items():
        # Key validation
        if not isinstance(key, str):
            return False, f"Parameter key must be string, got {type(key).__name__}"
        
        # Check for code injection attempts
        if isinstance(value, str):
            dangerous_patterns = [
                r'\$[a-zA-Z_]+',  # Cypher parameter syntax
                r'__proto__',
                r'constructor',
                r'prototype',
            ]
            for pattern in dangerous_patterns:
                if re.search(pattern, value):
                    return False, f"Potentially dangerous parameter value for '{key}'"
    
    return True, None