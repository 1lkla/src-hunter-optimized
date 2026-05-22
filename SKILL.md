---
name: src-hunter-optimized
description: Optimized SRC / Bug bounty / Pentest skill with normalized data (2,887 H1 reports, 419 payloads, 57 playbooks). Features: 5-phase workflow (intake → recon → enum → hunt → report), semantic search via MCP, WAF/EDR bypasses, industry-specific playbooks (banking/telecom), and enhanced indexing for efficient lookup. Triggered by "src挖洞 / bug bounty / pentest / 众测 / hackerone / WAF绕过 / 任意X漏洞 / 如何测某API".
argument-hint: "<target-or-program-or-phase>"
level: 2
---

# SRC Hunter — Optimized Bug Bounty Workflow

This is a **checkpoint-driven workflow** with optimized data structures. Each phase requires specific outputs before proceeding. Payloads, playbooks, and H1 cases must be **Read from files or queried via MCP tools** — never generated from memory.

**Data Structure:**
- `references/structured/` — Normalized JSON (playbooks.json, payloads.json)
- `references/h1-reports/enhanced/` — Semantically tagged reports with indexes
- `references/h1-reports/normalized/` — Deduplicated weakness mappings
- `references/playbooks/` — Cleaned, standardized markdown playbooks

**MCP Integration:** Use `mcp__src_hunter__*` tools for semantic search across reports, payloads, and bypasses.

---

## Trigger Conditions

Enter workflow when user mentions:
- "src挖洞 / 漏洞赏金 / bug bounty / 众测 / hackerone / SRC / 渗透测试"
- "如何挖 / 怎么测 / 怎么打 + 目标 / 接口 / 参数"
- "WAF绕过 / 任意账号 / 密码重置 / 未授权访问 / 默认凭据"
- Provides a URL / API endpoint / APK for testing

**Do not trigger for:** White-box code audit (use code-audit skill), fix consulting (general conversation), CTF (general conversation).

---

## Anti-Hallucination Rules (Always Apply)

1. **Never generate payloads from memory**. Before providing SQLi/RCE/SSRF/XSS payloads:
   - Option A: `mcp__src_hunter__get_payloads` with attack_type
   - Option B: Read `references/playbooks/<type>.md`
2. **Never fabricate case numbers**. Before referencing H1 cases:
   - Option A: `mcp__src_hunter__search_reports` with tech_stack/attack_vector
   - Option B: Read `references/h1-reports/by-weakness/<weakness>.md`
3. **No evidence = no conclusion**. Without HTTP packet/screenshot/video, only state "待验证 / 假设", never "已确认 / 发现漏洞"
4. **Stop immediately if out of scope**. If target not in Phase 1 in-scope list → return to Phase 1

---

## Phase 1 · Intake

**Entry:** User provides target/program/URL.

**MUST checkpoint outputs** (all four required):
- [ ] **In-scope:** Domain / IP ranges / apps / endpoints (list each)
- [ ] **Out-of-scope:** Prohibited items (list each)
- [ ] **Rules:** Payout tier / disclosure window / safe-harbor / testing headers (e.g., `X-Bug-Bounty:<handle>`)
- [ ] **Timebox:** 6h / daily / HVV / monthly

**For "which target first" questions:** Read `references/methodology/05-srctimebox-priority.md`

---

## Phase 2 · Recon (Passive)

**Entry:** Phase 1 checkpoint complete.

**Forbidden:** No active packets (port scanning / path brute-forcing / payload testing).

**MUST output:** Asset inventory + historical info from ≥3 sources:
- CT logs (crt.sh / Censys)
- Wayback / CommonCrawl snapshots
- GitHub dorks (`org:target` + `password|api_key|SECRET|.env`)
- FOFA / Shodan favicon hash
- SecurityTrails / DNS history
- ASN / IP ranges (bgp.he.net)

---

## Phase 3 · Enum (Active)

**Entry:** Phase 2 inventory non-empty.

**MUST output:** Live asset matrix: `domain → port → service → fingerprint → JS endpoints`

**Conditional Reads:**

| Signal | MUST Read |
|---|---|
| Fingerprint: `weaver/seeyon/tongda/landray/yongyou/kingdee/hikvision/dahua` | `references/dictionaries/chinese-srcfingerprints.md` + `references/dictionaries/default-credentials-cn.md` |
| Assets: bank/payment/网银/payment aggregator | `references/industry/banking-finance.md` |
| Assets: carrier/BOSS/net management/IoT SIM | `references/industry/telecom-isp.md` |

---

## Phase 4 · Hunt

**Entry:** Phase 3 matrix has ≥1 candidate target.

**Forced workflow per target:**
1. Analyze target signals, select 1 playbook from table
2. **Read playbook file** (mandatory, no shortcuts)
3. Follow playbook's "parameter frequency table" for entry points
4. Use playbook's "payload library" for testing (from files or MCP)
5. If WAF blocks: `mcp__src_hunter__get_waf_bypass` or Read `references/methodology/02-bypass-toolkit.md`
6. On hit: Save HTTP packet/screenshot → proceed to Phase 5

| Entry Signal | MUST Read |
|---|---|
| Actuator / Swagger / default ports / weak passwords | `references/playbooks/unauth-access.md` |
| .git / .svn / .env / heapdump / path enumeration | `references/playbooks/info-disclosure.md` |
| Enumerable user IDs / arbitrary X escalation | `references/playbooks/arbitrary-x-authz.md` |
| Password reset / payment / verification codes / orders / withdrawal | `references/playbooks/logic-flaws/00-index.md` |
| OAuth / SAML / JWT / redirect_uri | `references/playbooks/oauth-saml-jwt/00-index.md` |
| REST API / BOLA / Mass Assignment / rate limiting | `references/playbooks/api-rest/00-index.md` |
| Any user input → DB | `references/playbooks/sqli.md` |
| Deserialization / SSTI / XXE / prototype pollution / framework RCE | `references/playbooks/rce/00-index.md` |
| URL params / cache / Host injection | `references/playbooks/ssrf-cache-host/00-index.md` |
| File path params / LFI / RFI | `references/playbooks/path-traversal/00-index.md` |
| Upload + parsing vulns | `references/playbooks/file-upload/00-index.md` |
| User input reflected in HTML/JS | `references/playbooks/xss/00-index.md` |
| Reverse proxy + Content-Length / TE | `references/playbooks/http-smuggling.md` |
| GraphQL endpoint / introspection | `references/playbooks/graphql.md` |
| Concurrency / TOCTOU | `references/playbooks/race-conditions.md` |
| ReDoS / unlimited resources / algorithm explosion | `references/playbooks/dos.md` |
| APK / IPA / mobile | `references/playbooks/mobile.md` |
| LLM agent / prompt entry / tool calls | `references/playbooks/llm-prompt-injection/00-index.md` |
| Shell / credentials / internal network | `references/playbooks/intranet-postexp/00-index.md` |

**Two-step Read mode (split playbooks):** For directory-based playbooks (`rce/`/`oauth-saml-jwt`/`ssrf-cache-host`/`api-rest`/`logic-flaws`/`file-upload`/`path-traversal`/`xss`/`llm-prompt-injection`/`intranet-postexp`):
1. First read `00-index.md` — contains **sub-file routing** and methodology
2. Then read specific sub-file based on routing (e.g., `rce/14-ssti.md`, `oauth-saml-jwt/12-jwt.md`)

**Generic methodology** (only when stuck, don't preload):
- Don't know next target → `references/methodology/01-attack-priority.md`
- WAF/EDR blocking → `references/methodology/02-bypass-toolkit.md`
- Suspect hallucination / verify evidence chain → `references/methodology/03-evidence-discipline.md`
- Can't find vulnerability → `references/methodology/04-control-gap-hunting.md`

---

## Phase 5 · Report

**Entry:** Phase 4 has ≥1 finding with reproducible HTTP packet/screenshot/video.

**MUST workflow** (sequential):
1. Read `references/compliance.md` to verify compliance red lines (mandatory)
2. Read `references/templates/report-submission.md` for template
3. Three-part output:
   - **Title:** ≤80 chars, precise to endpoint + vulnerability type
   - **Reproduction steps:** Each step executable, with HTTP packet/curl/screenshot
   - **Impact + fix:** CVSS 4.0 vector + business impact

---

## MCP Tools Usage

**Available tools:**
- `mcp__src_hunter__get_playbook` — Get playbook by vulnerability type
- `mcp__src_hunter__get_payloads` — Get payloads by attack type
- `mcp__src_hunter__search_reports` — Search H1 reports by tech_stack/attack_vector/severity/CVE
- `mcp__src_hunter__get_waf_bypass` — Get WAF/EDR bypass techniques
- `mcp__src_hunter__get_entry_points` — Get common entry points for vulnerability type
- `mcp__src_hunter__list_categories` — List all available categories

**Usage patterns:**
```text
# Get payloads for SQL injection
mcp__src_hunter__get_payloads(attack_type="sql-nosql注入")

# Search for Java RCE reports
mcp__src_hunter__search_reports(tech_stack="java", attack_vector="rce", severity="critical", limit=5)

# Get XSS entry points
mcp__src_hunter__get_entry_points(vulnerability="xss")

# Get WAF bypass for SQLi
mcp__src_hunter__get_waf_bypass(attack_type="sqli")
```

---

## File Structure (Optimized)

```
references/
├── structured/           # Normalized JSON data
│   ├── playbooks.json   # 57 playbooks with entry points
│   ├── payloads.json    # 419 payloads with categories
│   └── payloads_*.json  # Per-category payload files
├── h1-reports/
│   ├── enhanced/        # Semantically tagged reports
│   │   ├── reports_enhanced.json
│   │   └── index_*.json # Tech stack, attack vector, CVE, program, severity indexes
│   ├── normalized/      # Deduplicated weakness mappings
│   │   ├── reports_index.json
│   │   └── *.json       # Per-weakness report IDs
│   └── by-weakness/     # Original markdown (cleaned)
├── playbooks/           # Cleaned markdown playbooks
├── methodology/         # Cleaned methodology files
├── industry/            # Industry-specific playbooks
└── dictionaries/        # Fingerprints and credentials
```

---

## Quick Reference

**Top 10 Playbooks by Volume:**
1. arbitrary-x-authz (IDOR/escalation) — 465 H1 cases
2. rce (deserialization/SSTI/XXE/framework) — 385 H1 cases
3. xss — 335 H1 cases
4. info-disclosure — 319 H1 cases
5. oauth-saml-jwt — 240 H1 cases
6. logic-flaws (CSRF/clickjacking/payment) — 234 H1 cases
7. path-traversal/LFI/RFI — 163 H1 cases
8. sqli — 147 H1 cases
9. dos — 138 H1 cases
10. ssrf-cache-host — 108 H1 cases

**Payload Categories:**
- SQL/NoSQL注入, XSS跨站脚本, RCE远程代码执行, SSRF服务端请求伪造, LFI/RFI文件包含, 认证漏洞, 业务逻辑漏洞, 框架漏洞, and 15 more

**Tech Stacks in Reports:**
java, python, php, javascript, dotnet, database, cloud, mobile, container, and more

---

## Compliance Red Lines

Every playbook ends with specific boundaries. Common critical points:

- **Sample control:** SQLi proof with database name/version only; IDOR/Mongo/ES: 1-3 samples maximum
- **Self-testing:** All authorization/password reset/JWT/redirect_uri/XSS testing with your own accounts only
- **Read-only, no write:** RCE: `id`/`whoami`/`uname -a` only; Redis/Mongo: `info`/`ping`/`db.version()` only
- **No real side effects:** No actual SMS/payment/emails/refunds/file changes. Proof of interface + 200 response only
- **DoS/concurrency:** Single reproduction ≤60s, sequential 5 times maximum. Race: 50-100 concurrent, never 1000+
- **No artifacts:** webshells/heapdumps/backups/dumped code → local only, delete after reporting
- **Credentials: don't use:** Leaked AWS/Stripe/DB credentials: `sts get-caller-identity`/banner verification only
- **PII redaction:** Phone/email/username/token/cookie: first 2 + last 2 chars only; sha256 fingerprint for proof
- **OOB verification:** Use vendor SSRF testing platform or self-hosted interactsh/DNSLog; no public DNSLog platforms
- **No packet, no finding:** All assertions need HTTP packet/screenshot/video; no "should be" reports

See specific playbook sections for vulnerability-specific restrictions.