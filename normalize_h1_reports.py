#!/usr/bin/env python3
"""Deduplicate and normalize H1 reports data."""

import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set

BASE_DIR = Path('/tmp/src-hunter-optimized')
RAW_INDEX = BASE_DIR / 'references/h1-reports/raw/index.json'
WEAKNESS_DIR = BASE_DIR / 'references/h1-reports/by-weakness'
OUTPUT_DIR = BASE_DIR / 'references/h1-reports/normalized'
OUTPUT_INDEX = OUTPUT_DIR / 'reports_index.json'

class H1ReportNormalizer:
    def __init__(self):
        self.raw_reports = []
        self.weakness_map = defaultdict(list)
        self.normalized_reports = []
        self.all_report_ids: Set[str] = set()

    def load_raw_index(self):
        """Load the raw H1 reports index."""
        print("Loading raw index...")
        with open(RAW_INDEX, 'r') as f:
            data = json.load(f)
        self.raw_reports = data['nodes']
        print(f"Loaded {len(self.raw_reports)} reports from index")

    def extract_report_metadata(self, node: dict) -> dict:
        """Extract key metadata from a report node."""
        report = node['report']
        return {
            'id': report['databaseId'],
            'title': report['title'],
            'url': report['url'],
            'severity': node['severity_rating'],
            'state': report.get('substate', 'unknown'),
            'cwe': node.get('cwe', ''),
            'cve_ids': node.get('cve_ids', []),
            'reporter': node['reporter']['username'],
            'created_at': report.get('created_at', ''),
            'program': node.get('program', {}).get('handle', 'unknown')
        }

    def normalize_reports(self):
        """Normalize and deduplicate all reports."""
        print("Normalizing reports...")

        # Process raw reports first
        for node in self.raw_reports:
            metadata = self.extract_report_metadata(node)
            if metadata['id'] not in self.all_report_ids:
                self.all_report_ids.add(metadata['id'])
                self.normalized_reports.append(metadata)

        print(f"Normalized {len(self.normalized_reports)} unique reports")

    def build_weakness_index(self):
        """Build weakness-to-report index."""
        print("Building weakness index...")
        print(f"Looking for weakness files in: {WEAKNESS_DIR}")
        print(f"Directory exists: {WEAKNESS_DIR.exists()}")

        if not WEAKNESS_DIR.exists():
            print("Warning: weakness directory not found!")
            return

        md_files = list(WEAKNESS_DIR.glob('*.md'))
        print(f"Found {len(md_files)} markdown files")

        for weakness_file in md_files:
            if weakness_file.name == 'index.md':
                continue

            # Extract weakness name from filename
            weakness = weakness_file.stem

            # Parse the markdown file for report IDs
            content = weakness_file.read_text()
            import re
            report_ids = re.findall(r'Report ID:\s*\*\*\s*`(\d+)`', content)

            # Map weakness to report IDs
            for report_id in report_ids:
                self.weakness_map[weakness].append(int(report_id))

        print(f"Found {len(self.weakness_map)} weakness categories")
        print(f"Total weakness mappings: {sum(len(v) for v in self.weakness_map.values())}")

    def save_normalized_data(self):
        """Save normalized data to JSON."""
        print("Saving normalized data...")

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        # Save the main index
        index_data = {
            'metadata': {
                'total_reports': len(self.normalized_reports),
                'total_weaknesses': len(self.weakness_map),
                'generated_at': None  # Will be set later
            },
            'reports': self.normalized_reports,
            'weakness_index': dict(self.weakness_map),
            'weakness_stats': {
                weakness: len(reports)
                for weakness, reports in sorted(self.weakness_map.items(), key=lambda x: len(x[1]), reverse=True)
            }
        }

        with open(OUTPUT_INDEX, 'w') as f:
            json.dump(index_data, f, indent=2)

        print(f"Saved normalized index to {OUTPUT_INDEX}")

        # Also save individual weakness files for quick lookup
        for weakness, report_ids in self.weakness_map.items():
            weakness_data = {
                'weakness': weakness,
                'report_count': len(report_ids),
                'report_ids': report_ids
            }
            weakness_file = OUTPUT_DIR / f"{weakness}.json"
            with open(weakness_file, 'w') as f:
                json.dump(weakness_data, f, indent=2)

        print(f"Saved {len(self.weakness_map)} weakness files")

    def run(self):
        """Run the full normalization process."""
        self.load_raw_index()
        self.normalize_reports()
        self.build_weakness_index()
        self.save_normalized_data()
        print("Normalization complete!")

if __name__ == '__main__':
    normalizer = H1ReportNormalizer()
    normalizer.run()