#!/usr/bin/env python3
"""Extract semantic tags and add indexing to H1 reports."""

import json
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict, Counter

BASE_DIR = Path('/tmp/src-hunter-optimized')
RAW_INDEX = BASE_DIR / 'references/h1-reports/raw/index.json'
OUTPUT_DIR = BASE_DIR / 'references/h1-reports/enhanced'

# Tech stack detection patterns
TECH_PATTERNS = {
    'java': ['java', 'spring', 'struts', 'hibernate', 'jboss', 'tomcat', 'jetty', 'weblogic', 'weblogic', 'groovy', 'kotlin', 'scala'],
    'python': ['python', 'django', 'flask', 'fastapi', 'pyramid', 'tornado', 'celery', 'gunicorn'],
    'php': ['php', 'laravel', 'symfony', 'wordpress', 'drupal', 'joomla', 'magento', 'codeigniter', 'yii'],
    'javascript': ['javascript', 'nodejs', 'express', 'koa', 'react', 'angular', 'vue', 'ember', 'backbone', 'meteor', 'nextjs', 'nuxt'],
    'ruby': ['ruby', 'rails', 'sinatra', 'rack', 'puma'],
    'go': ['go', 'golang', 'gin', 'echo', 'fiber'],
    'rust': ['rust', 'actix', 'rocket'],
    'dotnet': ['.net', 'c#', 'asp.net', 'mvc', 'core', 'entity framework'],
    'database': ['sql', 'mysql', 'postgresql', 'postgres', 'mongodb', 'redis', 'elasticsearch', 'sqlite', 'oracle', 'mssql'],
    'cloud': ['aws', 'amazon', 'azure', 'gcp', 'google cloud', 'heroku', 'digitalocean', 'cloudflare'],
    'mobile': ['android', 'ios', 'swift', 'kotlin', 'flutter', 'react native', 'cordova'],
    'container': ['docker', 'kubernetes', 'k8s', 'helm', 'istio', 'containerd'],
}

# Attack vector patterns
ATTACK_PATTERNS = {
    'sqli': ['sql injection', 'sqli', 'sql', 'database injection', 'blind sqli'],
    'xss': ['xss', 'cross-site scripting', 'stored xss', 'reflected xss', 'dom xss'],
    'ssrf': ['ssrf', 'server-side request forgery', 'request forgery'],
    'rce': ['rce', 'remote code execution', 'command injection', 'os command', 'code injection', 'deserialization'],
    'idor': ['idor', 'insecure direct object reference', 'access control', 'authorization', 'privilege escalation'],
    'csrf': ['csrf', 'cross-site request forgery', 'request forgery'],
    'xxe': ['xxe', 'xml external entity', 'xml injection'],
    'path-traversal': ['path traversal', 'directory traversal', 'lfi', 'rfi', 'local file inclusion', 'remote file inclusion'],
    'auth-bypass': ['auth bypass', 'authentication bypass', 'login bypass', 'unauthenticated', 'no auth'],
    'info-disclosure': ['information disclosure', 'info leak', 'data leak', 'exposed', 'sensitive data'],
}

class SemanticTagger:
    def __init__(self):
        self.tech_stack_index: Dict[str, Set[str]] = defaultdict(set)
        self.attack_vector_index: Dict[str, Set[str]] = defaultdict(set)
        self.cve_index: Dict[str, Set[str]] = defaultdict(set)
        self.program_index: Dict[str, Set[str]] = defaultdict(set)
        self.severity_index: Dict[str, Set[str]] = defaultdict(set)

    def detect_tech_stack(self, text: str) -> Set[str]:
        """Detect technology stack from text."""
        techs = set()
        text_lower = text.lower()
        for tech, patterns in TECH_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in text_lower:
                    techs.add(tech)
                    break
        return techs

    def detect_attack_vectors(self, text: str, weakness: str) -> Set[str]:
        """Detect attack vectors from text and weakness field."""
        vectors = set()
        text_lower = text.lower()

        # Check patterns
        for vector, patterns in ATTACK_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in text_lower:
                    vectors.add(vector)
                    break

        # Add weakness-based vector mapping
        weakness_lower = weakness.lower()
        weakness_mappings = {
            'sql-injection': 'sqli',
            'cross-site-scripting': 'xss',
            'server-side-request-forgery': 'ssrf',
            'code-injection': 'rce',
            'command-injection': 'rce',
            'deserialization': 'rce',
            'insecure-direct-object-reference': 'idor',
            'cross-site-request-forgery': 'csrf',
            'xml-external-entities': 'xxe',
            'php-local-file-inclusion': 'path-traversal',
            'authentication-bypass': 'auth-bypass',
            'information-disclosure': 'info-disclosure',
        }

        for w, v in weakness_mappings.items():
            if w in weakness_lower:
                vectors.add(v)

        return vectors

    def process_report(self, report: dict, weakness: str = 'unknown') -> dict:
        """Process a single report and extract semantic tags."""
        report_id = str(report.get('id', report.get('databaseId', '')))
        title = report.get('title', '')
        cwe = report.get('cwe', '')
        cve_ids = report.get('cve_ids', [])
        severity = report.get('severity_rating', report.get('severity', 'unknown')).lower()
        program = report.get('program', {}).get('handle', report.get('program', 'unknown')).lower()

        # Combine text for analysis
        text = f"{title} {cwe}"

        # Extract tags
        tech_stack = self.detect_tech_stack(text)
        attack_vectors = self.detect_attack_vectors(text, weakness)

        # Update indexes
        for tech in tech_stack:
            self.tech_stack_index[tech].add(report_id)

        for vector in attack_vectors:
            self.attack_vector_index[vector].add(report_id)

        for cve in cve_ids:
            self.cve_index[cve].add(report_id)

        self.program_index[program].add(report_id)
        self.severity_index[severity].add(report_id)

        return {
            'id': report_id,
            'title': title,
            'url': report.get('url', ''),
            'severity': severity,
            'cwe': cwe,
            'cve_ids': cve_ids,
            'reporter': report.get('reporter', {}).get('username', 'unknown'),
            'program': program,
            'tags': {
                'tech_stack': list(tech_stack),
                'attack_vectors': list(attack_vectors),
                'weakness': weakness
            }
        }

    def load_and_process(self):
        """Load raw data and process all reports."""
        print("Loading raw reports...")
        with open(RAW_INDEX, 'r') as f:
            data = json.load(f)

        reports = data['nodes']
        print(f"Processing {len(reports)} reports...")

        enhanced_reports = []
        for report in reports:
            enhanced = self.process_report(report)
            enhanced_reports.append(enhanced)

        print(f"Extracted semantic tags from {len(enhanced_reports)} reports")
        return enhanced_reports

    def save_enhanced_data(self, reports: List[dict]):
        """Save enhanced data with semantic tags."""
        print("Saving enhanced data...")
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        # Save enhanced reports
        enhanced_data = {
            'metadata': {
                'total_reports': len(reports),
                'tech_stacks': len(self.tech_stack_index),
                'attack_vectors': len(self.attack_vector_index),
                'programs': len(self.program_index),
                'generated_at': None
            },
            'reports': reports,
            'indexes': {
                'tech_stack': {k: list(v) for k, v in sorted(self.tech_stack_index.items(), key=lambda x: len(x[1]), reverse=True)},
                'attack_vector': {k: list(v) for k, v in sorted(self.attack_vector_index.items(), key=lambda x: len(x[1]), reverse=True)},
                'cve': {k: list(v) for k, v in sorted(self.cve_index.items(), key=lambda x: len(x[1]), reverse=True)},
                'program': {k: list(v) for k, v in sorted(self.program_index.items(), key=lambda x: len(x[1]), reverse=True)},
                'severity': {k: list(v) for k, v in sorted(self.severity_index.items(), key=lambda x: len(x[1]), reverse=True)}
            }
        }

        with open(OUTPUT_DIR / 'reports_enhanced.json', 'w') as f:
            json.dump(enhanced_data, f, indent=2)

        print(f"Saved enhanced reports to {OUTPUT_DIR / 'reports_enhanced.json'}")

        # Save individual index files for quick lookup
        for index_type, index_data in enhanced_data['indexes'].items():
            with open(OUTPUT_DIR / f'index_{index_type}.json', 'w') as f:
                json.dump(index_data, f, indent=2)

        print(f"Saved {len(enhanced_data['indexes'])} index files")

    def run(self):
        """Run the full semantic tagging process."""
        reports = self.load_and_process()
        self.save_enhanced_data(reports)
        print("Semantic tagging complete!")

if __name__ == '__main__':
    tagger = SemanticTagger()
    tagger.run()