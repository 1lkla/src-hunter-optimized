#!/bin/bash
# Installation script for optimized src-hunter skill

set -e

INSTALL_DIR="${HOME}/.claude/skills/src-hunter-optimized"
MCP_CONFIG="${HOME}/.claude/settings.json"

echo "Installing optimized src-hunter skill..."

# Create installation directory
mkdir -p "$INSTALL_DIR"

# Copy skill files
cp SKILL.md "$INSTALL_DIR/"
cp README.md "$INSTALL_DIR/"

# Copy references
cp -r references "$INSTALL_DIR/"

# Install MCP server
mkdir -p "$INSTALL_DIR/mcp_server"
cp mcp_server/src_hunter_mcp.py "$INSTALL_DIR/mcp_server/"

# Add MCP configuration to settings.json
if [ -f "$MCP_CONFIG" ]; then
    # Backup existing config
    cp "$MCP_CONFIG" "${MCP_CONFIG}.backup"

    # Add MCP server configuration if not present
    python3 << EOF
import json
from pathlib import Path

config_path = Path('$MCP_CONFIG')
with open(config_path, 'r') as f:
    config = json.load(f)

# Add MCP server
mcp_servers = {
    "src-hunter": {
        "command": "python3",
        "args": ["${INSTALL_DIR}/mcp_server/src_hunter_mcp.py"],
        "env": {}
    }
}

if "mcpServers" not in config:
    config["mcpServers"] = {}

config["mcpServers"]["src-hunter"] = mcp_servers["src-hunter"]

with open(config_path, 'w') as f:
    json.dump(config, f, indent=2)

print("MCP server added to settings.json")
EOF
else
    echo "Warning: settings.json not found. MCP server not configured."
    echo "Please manually add the MCP server configuration to ~/.claude/settings.json"
fi

echo "✓ Installation complete!"
echo ""
echo "Skill installed to: $INSTALL_DIR"
echo ""
echo "To use the skill:"
echo "  1. Restart Claude Code"
echo "  2. Use /src-hunter-optimized or trigger with 'src挖洞' / 'bug bounty' / 'pentest'"
echo ""
echo "MCP Tools available:"
echo "  - mcp__src_hunter__get_playbook"
echo "  - mcp__src_hunter__get_payloads"
echo "  - mcp__src_hunter__search_reports"
echo "  - mcp__src_hunter__get_waf_bypass"
echo "  - mcp__src_hunter__get_entry_points"
echo "  - mcp__src_hunter__list_categories"