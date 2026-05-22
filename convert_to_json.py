#!/usr/bin/env python3
"""Convert markdown playbooks and payloads to structured JSON."""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from collections import defaultdict

BASE_DIR = Path('/tmp/src-hunter-optimized')
OUTPUT_DIR = BASE_DIR / 'references/structured'
PLAYBOOKS_DIR = BASE_DIR / 'references/playbooks'
PAYLOADS_DIR = BASE_DIR / 'references/payloader/raw'

class PlaybookConverter:
    """Convert playbook markdown files to structured JSON."""

    def __init__(self):
        self.playbooks = []

    def parse_playbook(self, file_path: Path) -> Optional[dict]:
        """Parse a playbook markdown file into structured data."""
        content = file_path.read_text(encoding='utf-8')

        # Extract title (first H1)
        title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else file_path.stem

        # Extract sections using H2 headers
        sections = re.split(r'^##\s+', content, flags=re.MULTILINE)

        playbook_data = {
            'id': file_path.stem.replace('-', '_'),
            'title': title,
            'file_path': str(file_path.relative_to(BASE_DIR)),
            'type': 'playbook',
            'metadata': {},
            'sections': {}
        }

        for section in sections[1:]:  # Skip first empty section
            lines = section.strip().split('\n')
            if not lines:
                continue

            section_title = lines[0].strip()
            section_content = '\n'.join(lines[1:]).strip()

            playbook_data['sections'][section_title] = section_content

            # Extract metadata from common sections
            if '高频入口' in section_title or 'entry' in section_title.lower():
                self._extract_entry_points(section_content, playbook_data)
            elif 'payload' in section_title.lower() or '探测' in section_title:
                self._extract_payloads(section_content, playbook_data)
            elif '案例' in section_title or 'case' in section_title.lower():
                self._extract_cases(section_content, playbook_data)

        return playbook_data

    def _extract_entry_points(self, content: str, data: dict):
        """Extract entry points from playbook."""
        # Extract parameter frequencies
        params = re.findall(r"'([^']+)':\s*(\d+)", content)
        data['metadata']['entry_points'] = [
            {'parameter': p, 'frequency': int(f)}
            for p, f in params[:10]  # Top 10
        ]

    def _extract_payloads(self, content: str, data: dict):
        """Extract payloads from playbook."""
        # Extract code blocks as payloads
        payloads = re.findall(r'```[a-z]*\n([^`]+)```', content, re.IGNORECASE)
        data['metadata']['payloads'] = [p.strip() for p in payloads if p.strip()][:20]

    def _extract_cases(self, content: str, data: dict):
        """Extract HackerOne case references from playbook."""
        # Extract report IDs
        case_ids = re.findall(r'Report ID:\s*`(\d+)`', content)
        data['metadata']['case_references'] = case_ids[:10]

    def convert_all(self):
        """Convert all playbook files."""
        print("Converting playbooks to JSON...")

        md_files = list(PLAYBOOKS_DIR.rglob('*.md'))
        print(f"Found {len(md_files)} playbook files")

        for file_path in md_files:
            if 'index' in file_path.name.lower():
                continue

            playbook = self.parse_playbook(file_path)
            if playbook:
                self.playbooks.append(playbook)

        print(f"Converted {len(self.playbooks)} playbooks")

class PayloadConverter:
    """Convert payload JSON files to structured format."""

    def __init__(self):
        self.payloads = defaultdict(list)

    def convert_json_payloads(self):
        """Convert payload JSON files to structured format."""
        print("Converting payloads to structured JSON...")

        json_files = list(PAYLOADS_DIR.glob('*.json'))
        print(f"Found {len(json_files)} payload files")

        for json_file in json_files:
            with open(json_file, 'r') as f:
                data = json.load(f)

            if isinstance(data, list):
                category = json_file.stem
                self.payloads[category] = data

            print(f"Converted {json_file.name}: {len(data) if isinstance(data, list) else 1} payloads")

        print(f"Total payload categories: {len(self.payloads)}")

def save_structured_data(playbooks: List[dict], payloads: Dict[str, list]):
    """Save all structured data to JSON files."""
    print("Saving structured data...")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Save playbooks
    playbooks_file = OUTPUT_DIR / 'playbooks.json'
    with open(playbooks_file, 'w') as f:
        json.dump({
            'metadata': {
                'total_playbooks': len(playbooks),
                'generated_at': None
            },
            'playbooks': playbooks
        }, f, indent=2)

    print(f"Saved {len(playbooks)} playbooks to {playbooks_file}")

    # Save payloads
    payloads_file = OUTPUT_DIR / 'payloads.json'
    all_payloads = []
    for category, items in payloads.items():
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    all_payloads.append({
                        **item,
                        'category': category
                    })

    with open(payloads_file, 'w') as f:
        json.dump({
            'metadata': {
                'total_payloads': len(all_payloads),
                'categories': list(payloads.keys()),
                'generated_at': None
            },
            'payloads': all_payloads
        }, f, indent=2)

    print(f"Saved {len(all_payloads)} payloads to {payloads_file}")

    # Save individual categories
    for category, items in payloads.items():
        if isinstance(items, list):
            category_file = OUTPUT_DIR / f'payloads_{category}.json'
            with open(category_file, 'w') as f:
                json.dump({
                    'category': category,
                    'count': len(items),
                    'items': items
                }, f, indent=2)

    print(f"Saved {len(payloads)} category files")

if __name__ == '__main__':
    playbook_converter = PlaybookConverter()
    playbook_converter.convert_all()

    payload_converter = PayloadConverter()
    payload_converter.convert_json_payloads()

    save_structured_data(playbook_converter.playbooks, payload_converter.payloads)
    print("JSON conversion complete!")