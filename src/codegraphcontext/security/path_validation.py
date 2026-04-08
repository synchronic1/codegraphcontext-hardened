"""
Path validation for secure file indexing.

Prevents:
- Path traversal outside allowed directories
- Indexing of sensitive files (.ssh, .env, credentials, etc.)
- Symlink escape attacks
"""

import os
import re
from pathlib import Path
from typing import List, Optional, Tuple

# Blocked path patterns (sensitive files/directories)
# These are checked case-insensitively in the path string
BLOCKED_PATTERNS = [
    # SSH/GPG keys
    ".ssh",
    ".gnupg",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".pem",
    ".key",
    
    # Credentials/secrets
    ".env",
    ".envrc",
    ".env.local",
    ".env.production",
    "credentials",
    "secrets",
    ".secrets",
    ".htpasswd",
    ".netrc",
    
    # Cloud credentials
    ".aws",
    ".config/gcloud",
    ".config/rclone",
    ".kube",
    ".docker",
    ".oci",
    
    # Password managers
    ".password-store",
    ".keepass",
    ".keepassx",
    
    # System sensitive
    "/etc/shadow",
    "/etc/passwd",
    "/etc/hosts",
    "/etc/ssh/",
    
    # Misc sensitive
    ".npmrc",
    ".pypirc",
    ".pgpass",
    ".my.cnf",
    ".gitconfig",
]

# Default allowed roots (can be overridden via environment)
# By default, only allow indexing within current working directory
DEFAULT_ALLOWED_ROOTS_ENV = os.getenv("CGC_ALLOWED_ROOTS", "")

def _get_allowed_roots() -> List[Path]:
    """
    Get allowed root directories from environment or defaults.
    
    Environment: CGC_ALLOWED_ROOTS=/path1:/path2:/path3
    
    If not set, defaults to allowing only the current working directory.
    """
    if DEFAULT_ALLOWED_ROOTS_ENV:
        roots = []
        for root_str in DEFAULT_ALLOWED_ROOTS_ENV.split(":"):
            root = Path(root_str).expanduser().resolve()
            if root.exists():
                roots.append(root)
        return roots if roots else [Path.cwd()]
    return [Path.cwd()]


def _is_path_blocked(path: Path) -> Tuple[bool, Optional[str]]:
    """
    Check if a path matches any blocked pattern.
    
    Returns:
        (is_blocked, reason) tuple
    """
    path_str = str(path)
    path_lower = path_str.lower()
    
    for pattern in BLOCKED_PATTERNS:
        pattern_lower = pattern.lower()
        if pattern_lower in path_lower:
            return True, f"Path contains blocked pattern: '{pattern}'"
    
    # Check for common credential file names
    cred_patterns = [
        r'.*\.pem$',
        r'.*\.key$',
        r'.*\.p12$',
        r'.*\.pfx$',
        r'.*credentials.*',
        r'.*secret.*',
        r'.*password.*',
        r'.*token.*',
        r'.*api[_-]?key.*',
    ]
    
    filename = path.name.lower()
    for pattern in cred_patterns:
        if re.match(pattern, filename):
            return True, f"Path matches blocked credential pattern: {path.name}"
    
    return False, None


def _check_symlink_escape(path: Path, allowed_roots: List[Path]) -> Tuple[bool, Optional[str]]:
    """
    Check if a symlink resolves outside allowed roots.
    
    Returns:
        (is_safe, reason) tuple - False if symlink escapes
    """
    if not path.is_symlink():
        return True, None
    
    try:
        resolved = path.resolve()
        for root in allowed_roots:
            if resolved.is_relative_to(root):
                return True, None
        return False, f"Symlink resolves outside allowed roots: {path} -> {resolved}"
    except Exception as e:
        return False, f"Cannot resolve symlink: {e}"


def validate_path(
    path_str: str,
    allowed_roots: Optional[List[Path]] = None,
    allow_symlinks: bool = False,
) -> Tuple[Optional[Path], Optional[str]]:
    """
    Validate a path for secure indexing.
    
    Args:
        path_str: The path to validate
        allowed_roots: List of allowed root directories (default: from CGC_ALLOWED_ROOTS)
        allow_symlinks: Whether to allow symlink traversal
    
    Returns:
        (resolved_path, error_message) - path is None if validation fails
    
    Examples:
        >>> validate_path("/home/user/project")
        (PosixPath('/home/user/project'), None)
        
        >>> validate_path("~/.ssh/id_rsa")
        (None, "Path contains blocked pattern: '.ssh'")
        
        >>> validate_path("/etc/passwd")
        (None, "Path resolves outside allowed roots: [...]")
    """
    if not path_str:
        return None, "Path cannot be empty"
    
    try:
        path = Path(path_str).expanduser()
        
        # Resolve to absolute path
        if path.exists():
            resolved = path.resolve()
        else:
            # For non-existent paths, still check the resolved form
            resolved = path.resolve()
    except Exception as e:
        return None, f"Invalid path: {e}"
    
    # Check for blocked patterns
    is_blocked, reason = _is_path_blocked(resolved)
    if is_blocked:
        return None, reason
    
    # Get allowed roots
    if allowed_roots is None:
        allowed_roots = _get_allowed_roots()
    
    # Check if path is within allowed roots
    if allowed_roots:
        in_allowed = False
        for root in allowed_roots:
            try:
                if resolved.is_relative_to(root):
                    in_allowed = True
                    break
            except (ValueError, TypeError):
                # is_relative_to may raise on different drives (Windows)
                continue
        
        if not in_allowed:
            allowed_str = ", ".join(str(r) for r in allowed_roots)
            return None, f"Path must be within allowed roots: [{allowed_str}]"
    
    # Check symlinks
    if not allow_symlinks and path.is_symlink():
        is_safe, reason = _check_symlink_escape(path, allowed_roots)
        if not is_safe:
            return None, reason
    
    return resolved, None


def is_path_allowed(path_str: str) -> bool:
    """
    Quick check if a path is allowed for indexing.
    
    Returns:
        True if path is valid, False otherwise
    """
    path, _ = validate_path(path_str)
    return path is not None


# Export for CLI config
def get_allowed_roots_str() -> str:
    """Get the current allowed roots as a colon-separated string."""
    return ":".join(str(r) for r in _get_allowed_roots())