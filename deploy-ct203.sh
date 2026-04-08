#!/bin/bash
# Deploy CodeGraphContext hardened fork to CT203
set -e

CONTAINER_HOST="192.168.1.233"
CONTAINER_ID="203"
REMOTE_PATH="/opt/codegraphcontext"

echo "=== Deploying CodeGraphContext Hardened to CT203 ==="

# Check if already deployed
echo "Checking existing installation..."
ssh root@$CONTAINER_HOST "pct exec $CONTAINER_ID -- test -d $REMOTE_PATH" 2>/dev/null && {
    echo "Found existing installation. Removing..."
    ssh root@$CONTAINER_HOST "pct exec $CONTAINER_ID -- rm -rf $REMOTE_PATH"
}

# Create directory
echo "Creating directory..."
ssh root@$CONTAINER_HOST "pct exec $CONTAINER_ID -- mkdir -p $REMOTE_PATH"

# Copy files from local fork
echo "Copying files..."
LOCAL_PATH="/home/rm/.openclaw/workspace/projects/codegraphcontext-hardened"
cd $LOCAL_PATH

# Sync files (excluding .git to save space)
tar czf - --exclude='.git' . | ssh root@$CONTAINER_HOST "pct exec $CONTAINER_ID -- tar xzf - -C $REMOTE_PATH"

# Install Python dependencies
echo "Installing dependencies..."
ssh root@$CONTAINER_HOST "pct exec $CONTAINER_ID -- bash -c 'cd $REMOTE_PATH && pip install --quiet neo4j watchdog stdlibs typer rich inquirerpy python-dotenv tree-sitter tree-sitter-language-pack tree-sitter-c-sharp pyyaml nbformat nbconvert pathspec falkordb requests fastapi uvicorn 2>&1 | tail -5'"

# Install the package
echo "Installing package..."
ssh root@$CONTAINER_HOST "pct exec $CONTAINER_ID -- bash -c 'cd $REMOTE_PATH && pip install -e . 2>&1 | tail -3'"

# Set environment defaults
echo "Setting environment..."
ssh root@$CONTAINER_HOST "pct exec $CONTAINER_ID -- bash -c 'echo \"DATABASE_TYPE=falkordb\" >> /etc/environment'"
ssh root@$CONTAINER_HOST "pct exec $CONTAINER_ID -- bash -c 'echo \"CGC_STRICT_MODE=true\" >> /etc/environment'"

# Verify installation
echo "Verifying installation..."
ssh root@$CONTAINER_HOST "pct exec $CONTAINER_ID -- python3 -c 'from codegraphcontext.security import validate_path, sanitize_cypher_query; print(\"Security module OK\")'" 2>&1

echo ""
echo "=== Deployment Complete ==="
echo "Location: $REMOTE_PATH"
echo "Environment: DATABASE_TYPE=falkordb, CGC_STRICT_MODE=true"
echo ""
echo "To run MCP server:"
echo "  ssh root@$CONTAINER_HOST \"pct exec $CONTAINER_ID -- cgc mcp start\""
echo ""
echo "To index code:"
echo "  ssh root@$CONTAINER_HOST \"pct exec $CONTAINER_ID -- cgc index /path/to/code\""