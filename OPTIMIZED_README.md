# SRC Hunter — Optimized Version

A production-ready, optimized version of the original `src-hunter-skill` for bug bounty and penetration testing workflows. This version includes data normalization, semantic indexing, and MCP integration for efficient knowledge retrieval.

## What's New (Optimized)

### Data Improvements
- **Deduplicated H1 Reports:** 2,887 unique reports with normalized metadata
- **Semantic Tagging:** Reports indexed by tech stack, attack vector, severity, CVE, and program
- **Structured JSON:** 57 playbooks and 419 payloads in queryable JSON format
- **Cleaned Markdown:** All playbooks and methodology files standardized with proper formatting
- **Enhanced Indexes:** 5 specialized indexes (tech stack, attack vector, CVE, program, severity)

### Architecture
- **Hybrid Integration:** Works as both a Claude Code skill and MCP server
- **Efficient Lookups:** Use MCP tools for semantic search instead of full-file reads
- **Reduced Context:** Structured JSON enables targeted data retrieval

## Installation

### Option 1: Manual Installation

```bash
# Copy to Claude skills directory
mkdir -p ~/.claude/skills
cp -r /tmp/src-hunter-optimized ~/.claude/skills/src-hunter-optimized

# Add MCP server to settings.json
# Add to ~/.claude/settings.json:
# "mcpServers": {
#   "src-hunter": {
#     "command": "python3",
#     "args": ["~/.claude/skills/src-hunter-optimized/mcp_server/src_hunter_mcp.py"],
#     "env": {}
#   }
# }
```

### Option 2: Automated Installation

```bash
chmod +x /tmp/src-hunter-optimized/install.sh
/tmp/src-hunter-optimized/install.sh
```

## MCP Tools

Once installed, the following tools are available:

| Tool | Description |
|------|-------------|
| `mcp__src_hunter__get_playbook` | Get playbook by vulnerability type |
| `mcp__src_hunter__get_payloads` | Get payloads by attack type |
| `mcp__src_hunter__search_reports` | Search H1 reports by metadata |
| `mcp__src_hunter__get_waf_bypass` | Get WAF/EDR bypass techniques |
| `mcp__src_hunter__get_entry_points` | Get common entry points |
| `mcp__src_hunter__list_categories` | List all available categories |

## Usage Examples

### Search for Java RCE Reports
```
mcp__src_hunter__search_reports(tech_stack="java", attack_vector="rce", severity="critical", limit=5)
```

### Get SQL Injection Payloads
```
mcp__src_hunter__get_payloads(attack_type="sql-nosql注入")
```

### Get XSS Entry Points
```
mcp__src_hunter__get_entry_points(vulnerability="xss")
```

### Get WAF Bypass
```
mcp__src_hunter__get_waf_bypass(attack_type="sqli")
```

## Workflow

The skill follows a 5-phase workflow with enforced checkpoints:

1. **Intake** — Confirm scope, rules, and timebox
2. **Recon** — Passive information gathering
3. **Enum** — Active enumeration of live assets
4. **Hunt** — Vulnerability testing with playbooks
5. **Report** — Structured vulnerability reporting

See `SKILL.md` for complete workflow details.

## Data Structure

```
references/
├── structured/           # Normalized JSON
│   ├── playbooks.json   # 57 playbooks
│   ├── payloads.json    # 419 payloads
│   └── payloads_*.json  # Per-category
├── h1-reports/
│   ├── enhanced/        # Semantically tagged
│   │   ├── reports_enhanced.json
│   │   └── index_*.json # 5 specialized indexes
│   ├── normalized/      # Deduplicated mappings
│   └── by-weakness/     # Original markdown (cleaned)
├── playbooks/           # 19 vulnerability playbooks
├── methodology/         # Testing methodology
├── industry/            # Banking/telecom scenarios
└── dictionaries/        # Fingerprints & credentials
```

## Statistics

- **HackerOne Reports:** 2,887 High/Critical reports
- **Weakness Categories:** 140 types
- **Playbooks:** 19 attack playbooks (57 structured)
- **Payloads:** 419 payloads across 23 categories
- **WAF Bypasses:** 176 techniques
- **Tool Commands:** 114 commands

## Compliance

This skill enforces responsible disclosure and ethical testing boundaries:

- Sample control (1-3 records max)
- Self-testing only (own accounts)
- Read-only operations (no destructive actions)
- No real side effects (proof only)
- Limited DoS testing (≤60s, 5x max)
- No artifact persistence (delete after reporting)
- Credentials verification only (no usage)
- PII redaction (2+2 format)
- Vendor OOB platforms (no public DNSLog)
- Evidence required (no assertions without proof)

## License

MIT — Data compiled from publicly disclosed sources.

## Credits

Based on original `src-hunter-skill` by MyuriKanao. Optimized for production use with enhanced indexing and MCP integration.