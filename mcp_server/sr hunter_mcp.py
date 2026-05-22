#!/usr/bin/env python3
"""MCP server for querying src-hunter knowledge base."""

import json
from pathlib import Path
from typing import Dict, List, Optional
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Base paths
BASE_DIR = Path('/tmp/src-hunter-optimized')
STRUCTURED_DIR = BASE_DIR / 'references/structured'
ENHANCED_DIR = BASE_DIR / 'references/h1-reports/enhanced'

app = Server('src-hunter')

# Cache data
_playbooks = []
_payloads = []
_reports = []

def load_data():
    """Load structured data into memory."""
    global _playbooks, _payloads, _reports

    # Load playbooks
    playbook_file = STRUCTURED_DIR / 'playbooks.json'
    if playbook_file.exists():
        with open(playbook_file, 'r') as f:
            data = json.load(f)
            _playbooks = data.get('playbooks', [])

    # Load payloads
    payload_file = STRUCTURED_DIR / 'payloads.json'
    if payload_file.exists():
        with open(payload_file, 'r') as f:
            data = json.load(f)
            _payloads = data.get('payloads', [])

    # Load enhanced reports
    reports_file = ENHANCED_DIR / 'reports_enhanced.json'
    if reports_file.exists():
        with open(reports_file, 'r') as f:
            data = json.load(f)
            _reports = data.get('reports', [])

@app.on('initialize')
async def on_initialize():
    """Initialize the server."""
    load_data()

@app.list_tools()
async def list_tools() -> List[Tool]:
    """List available MCP tools."""
    return [
        Tool(
            name="get_playbook",
            description="Get a specific playbook by vulnerability type (e.g., sqli, xss, rce, idor, ssrf)",
            inputSchema={
                "type": "object",
                "properties": {
                    "vulnerability": {
                        "type": "string",
                        "description": "Vulnerability type to search for",
                        "enum": ["sqli", "xss", "rce", "idor", "ssrf", "csrf", "path_traversal", "xxe", "file_upload", "auth_bypass", "info_disclosure"]
                    }
                },
                "required": ["vulnerability"]
            }
        ),
        Tool(
            name="get_payloads",
            description="Get payloads for a specific attack type",
            inputSchema={
                "type": "object",
                "properties": {
                    "attack_type": {
                        "type": "string",
                        "description": "Attack type",
                        "enum": ["sql-nosql注入", "xss跨站脚本", "rce远程代码执行", "ssrf服务端请求伪造", "lfi-rfi文件包含", "认证漏洞", "业务逻辑漏洞", "框架漏洞"]
                    }
                },
                "required": ["attack_type"]
            }
        ),
        Tool(
            name="search_reports",
            description="Search HackerOne reports by tech stack, attack vector, severity, or CVE",
            inputSchema={
                "type": "object",
                "properties": {
                    "tech_stack": {
                        "type": "string",
                        "description": "Technology stack (e.g., java, python, php, javascript, dotnet)",
                        "enum": ["java", "python", "php", "javascript", "ruby", "go", "rust", "dotnet", "database", "cloud", "mobile", "container"]
                    },
                    "attack_vector": {
                        "type": "string",
                        "description": "Attack vector",
                        "enum": ["sqli", "xss", "ssrf", "rce", "idor", "csrf", "xxe", "path-traversal", "auth-bypass", "info-disclosure"]
                    },
                    "severity": {
                        "type": "string",
                        "description": "Severity level",
                        "enum": ["critical", "high", "medium", "low"]
                    },
                    "cve": {
                        "type": "string",
                        "description": "CVE identifier"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results to return (default: 5)",
                        "default": 5
                    }
                }
            }
        ),
        Tool(
            name="get_waf_bypass",
            description="Get WAF/EDR bypass techniques for a specific attack type",
            inputSchema={
                "type": "object",
                "properties": {
                    "attack_type": {
                        "type": "string",
                        "description": "Attack type to get bypasses for",
                        "enum": ["sqli", "xss", "rce", "ssrf", "path_traversal", "file_upload", "auth_bypass"]
                    }
                },
                "required": ["attack_type"]
                }
            }
        ),
        Tool(
            name="get_entry_points",
            description="Get common entry points and parameters for a vulnerability type",
            inputSchema={
                "type": "object",
                "properties": {
                    "vulnerability": {
                        "type": "string",
                        "description": "Vulnerability type",
                        "enum": ["sqli", "xss", "rce", "idor", "ssrf", "csrf", "path_traversal", "xxe", "auth_bypass", "info_disclosure"]
                    }
                },
                "required": ["vulnerability"]
            }
        ),
        Tool(
            name="list_categories",
            description="List all available categories (playbooks, payload types, attack vectors)",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> List[TextContent]:
    """Handle tool calls."""

    if name == "get_playbook":
        vuln = arguments.get('vulnerability', '').lower()
        matching = [p for p in _playbooks if vuln in p.get('id', '').lower() or vuln in p.get('title', '').lower()]
        return [TextContent(type='text', text=json.dumps(matching[:3], indent=2))]

    elif name == "get_payloads":
        attack_type = arguments.get('attack_type')
        matching = [p for p in _payloads if attack_type.lower() in p.get('category', '').lower()]
        return [TextContent(type='text', text=json.dumps(matching[:10], indent=2))]

    elif name == "search_reports":
        results = _reports
        tech_stack = arguments.get('tech_stack', '').lower()
        attack_vector = arguments.get('attack_vector', '').lower()
        severity = arguments.get('severity', '').lower()
        cve = arguments.get('cve', '').upper()
        limit = arguments.get('limit', 5)

        if tech_stack:
            results = [r for r in results if tech_stack in [t.lower() for t in r.get('tags', {}).get('tech_stack', [])]]
        if attack_vector:
            results = [r for r in results if attack_vector in [t.lower() for t in r.get('tags', {}).get('attack_vectors', [])]]
        if severity:
            results = [r for r in results if severity in r.get('severity', '').lower()]
        if cve:
            results = [r for r in results if cve in [c.upper() for c in r.get('cve_ids', [])]]

        return [TextContent(type='text', text=json.dumps(results[:limit], indent=2))]

    elif name == "get_waf_bypass":
        # Return bypass techniques from methodology
        bypass_file = BASE_DIR / 'references/methodology/02-bypass-toolkit.md'
        if bypass_file.exists():
            return [TextContent(type='text', text=bypass_file.read_text())]
        return [TextContent(type='text', text='Bypass information not available')]

    elif name == "get_entry_points":
        vuln = arguments.get('vulnerability', '').lower()
        matching = [p for p in _playbooks if vuln in p.get('id', '').lower()]
        if matching and 'entry_points' in matching[0].get('metadata', {}):
            return [TextContent(type='text', text=json.dumps(matching[0]['metadata']['entry_points'], indent=2))]
        return [TextContent(type='text', text='Entry points not found for this vulnerability type')]

    elif name == "list_categories":
        return [TextContent(type='text', text=json.dumps({
            'vulnerability_types': [p['id'] for p in _playbooks],
            'payload_categories': [p.get('category', 'unknown') for p in _payloads],
            'tech_stacks': ['java', 'python', 'php', 'javascript', 'ruby', 'go', 'dotnet', 'database', 'cloud', 'mobile'],
            'attack_vectors': ['sqli', 'xss', 'ssrf', 'rce', 'idor', 'csrf', 'xxe', 'path-traversal', 'auth-bypass', 'info-disclosure']
        }, indent=2))]

    return [TextContent(type='text', text='Unknown tool')]

async def main():
    """Main entry point."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream)

if __name__ == '__main__':
    import asyncio
    asyncio.run(main())