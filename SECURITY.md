# Security Policy

## Hardened Version

This is a **hardened fork** of CodeGraphContext with additional security measures.

### Security Enhancements

#### Path Traversal Protection

The `add_code_to_graph` tool now validates paths to prevent:
- Indexing of sensitive files (`.ssh`, `.env`, credentials, etc.)
- Path traversal outside allowed directories
- Symlink escape attacks

**Configuration:**
```bash
# Allow specific directories (colon-separated)
export CGC_ALLOWED_ROOTS="/home/user/projects:/home/user/workspace"

# Default: current working directory only
```

**Blocked patterns:**
- `.ssh`, `.gnupg`, `.aws`, `.kube` (credentials)
- `.env`, `.envrc`, `credentials`, `secrets`
- `*.pem`, `*.key`, `id_rsa`, `id_ed25519`
- `/etc/shadow`, `/etc/passwd`

#### Cypher Query Sanitization

The `execute_cypher_query` tool now:
- Validates query prefix (MATCH, WITH, RETURN only)
- Blocks write operations (CREATE, MERGE, DELETE, etc.)
- Supports parameterized queries
- Normalizes Unicode to prevent bypass

**Parameterized queries (recommended):**
```python
# Instead of string interpolation
query = "MATCH (n) WHERE n.name = $name RETURN n"
params = {"name": user_input}
result = execute_cypher_query(db, cypher_query=query, params=params)
```

## Reporting Security Issues

For security issues in this hardened fork, open an issue with the `security` label.

For upstream CodeGraphContext security issues, see:
https://github.com/CodeGraphContext/CodeGraphContext/security

## Security Audit

Full security audit: `memory/research/codegraphcontext-security-audit.md`

### Audit Summary (2026-04-08)

| Severity | Count | Key Findings |
|----------|-------|--------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 2 | Cypher injection, path traversal (both mitigated) |
| Low | 3 | Credential storage, no auth, bundle injection |

**Verdict:** Safe for local use with trusted codebases.

---

Original upstream security policy follows below.

---

# Upstream Security Policy

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please report it responsibly.

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please:

1. Email your findings to security@codegraphcontext.dev
2. Include a detailed description of the vulnerability
3. Provide steps to reproduce if possible
4. Allow us 90 days to respond before public disclosure

## Supported Versions

We provide security updates for the latest major version only.

## Security Considerations

### MCP Server Security

- The MCP server listens on stdin/stdout only (no network exposure)
- No authentication is required (local process communication)
- Only run the MCP server from trusted parent processes

### Database Credentials

- Credentials are stored in environment variables or `.env` files
- Never commit credentials to version control
- Use environment-specific credential files

### File System Access

- The indexer can read any file the process has access to
- Only index trusted codebases
- Consider running in a container for untrusted code

### Cypher Queries

- The `execute_cypher_query` tool is restricted to read-only operations
- Write operations (CREATE, MERGE, DELETE) are blocked
- Custom deployments may need additional restrictions