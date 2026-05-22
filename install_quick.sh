#!/bin/bash
# Quick installation script for the optimized src-hunter skill

set -e

INSTALL_DIR="${HOME}/.claude/skills/src-hunter-optimized"
CURRENT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "🎯 Installing optimized src-hunter skill..."
echo ""

# Create installation directory
mkdir -p "$INSTALL_DIR"

# Copy skill files
echo "→ Copying skill files..."
cp "$CURRENT_DIR/SKILL.md" "$INSTALL_DIR/"
cp "$CURRENT_DIR/README.md" "$INSTALL_DIR/"
cp "$CURRENT_DIR/OPTIMIZED_README.md" "$INSTALL_DIR/"

# Copy references
echo "→ Copying references (optimized data)..."
cp -r "$CURRENT_DIR/references" "$INSTALL_DIR/"

# Install MCP server
echo "→ Installing MCP server..."
mkdir -p "$INSTALL_DIR/mcp_server"
cp "$CURRENT_DIR/mcp_server/src_hunter_mcp.py" "$INSTALL_DIR/mcp_server/"

# Update MCP configuration
MCP_CONFIG="${HOME}/.claude/settings.json"
if [ -f "$MCP_CONFIG" ]; then
    echo "→ Updating MCP configuration..."

    # Backup existing config
    cp "$MCP_CONFIG" "${MCP_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"

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

print("  MCP server configured successfully")
EOF
else
    echo "⚠️  Warning: settings.json not found. MCP server not configured."
    echo "   Please manually add the MCP server configuration to ~/.claude/settings.json:"
    echo ""
    echo '   "mcpServers": {'
    echo '     "src-hunter": {'
    echo '       "command": "python3",'
    echo '       "args": ["' "$INSTALL_DIR" '/mcp_server/src_hunter_mcp.py"],'
    echo '       "env": {}'
    echo '     }'
    echo '   }'
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "📍 Skill installed to: $INSTALL_DIR"
echo ""
echo "🚀 To use the skill:"
echo "   1. Restart Claude Code"
echo "   2. Trigger with keywords: 'src挖洞', 'bug bounty', 'pentest', '漏洞赏金'"
echo ""
echo "🔧 Available MCP Tools:"
echo "   • mcp__src_hunter__get_playbook     — Get playbook by vulnerability type"
echo "   • mcp__src_hunter__get_payloads      — Get payloads by attack type"
echo "   • mcp__src_hunter__search_reports    — Search H1 reports by metadata"
echo "   • mcp__src_hunter__get_waf_bypass    — Get WAF/EDR bypass techniques"
echo "   • mcp__src_hunter__get_entry_points  — Get common entry points"
echo "   • mcp__src_hunter__list_categories   — List all available categories"
echo ""
echo "📚 Documentation: $INSTALL_DIR/OPTIMIZED_README.md"