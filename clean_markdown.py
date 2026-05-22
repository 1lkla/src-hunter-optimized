#!/usr/bin/env python3
"""Clean and standardize markdown files."""

import re
from pathlib import Path
from typing import Dict, List, Tuple

BASE_DIR = Path('/tmp/src-hunter-optimized')

class MarkdownCleaner:
    def __init__(self):
        self.cleaned_count = 0
        self.issues_found = defaultdict(int)

    def clean_headers(self, content: str) -> str:
        """Clean and standardize markdown headers."""
        # Ensure headers have proper spacing
        content = re.sub(r'^(#{1,6})([^\s#])', r'\1 \2', content, flags=re.MULTILINE)

        # Remove extra spaces after headers
        content = re.sub(r'^(#{1,6})\s{2,}', r'\1 ', content, flags=re.MULTILINE)

        return content

    def clean_code_blocks(self, content: str) -> str:
        """Clean code blocks."""
        # Ensure code blocks have language specifiers
        content = re.sub(r'```(?!\w)', '```text', content)

        return content

    def clean_links(self, content: str) -> str:
        """Clean markdown links."""
        # Fix malformed links
        content = re.sub(r'\[([^\]]+)\]\s*\(\s*([^\)]+)\s*\)', r'[\1](\2)', content)

        return content

    def standardize_lists(self, content: str) -> str:
        """Standardize list formatting."""
        # Ensure consistent spacing in lists
        content = re.sub(r'^(\s*[-*+])\s{2,}', r'\1 ', content, flags=re.MULTILINE)
        content = re.sub(r'^(\s*\d+\.)\s{2,}', r'\1 ', content, flags=re.MULTILINE)

        return content

    def normalize_whitespace(self, content: str) -> str:
        """Normalize whitespace."""
        # Remove trailing whitespace
        content = re.sub(r'[ \t]+$', '', content, flags=re.MULTILINE)

        # Ensure single trailing newline
        content = content.rstrip() + '\n'

        # Remove excessive blank lines (more than 2)
        content = re.sub(r'\n{3,}', '\n\n', content)

        return content

    def detect_language_ratio(self, content: str) -> Tuple[float, str]:
        """Detect the ratio of English vs non-English content."""
        chinese_chars = len(re.findall(r'[一-鿿]', content))
        total_chars = len(content.strip())

        if total_chars == 0:
            return 0.0, 'empty'

        chinese_ratio = chinese_chars / total_chars

        if chinese_ratio > 0.3:
            return chinese_ratio, 'chinese_dominant'
        elif chinese_ratio > 0.1:
            return chinese_ratio, 'mixed'
        else:
            return chinese_ratio, 'english_dominant'

    def clean_file(self, file_path: Path) -> bool:
        """Clean a single markdown file."""
        try:
            content = file_path.read_text(encoding='utf-8')

            # Detect language
            lang_ratio, lang_type = self.detect_language_ratio(content)

            # Apply cleaning
            cleaned = content
            cleaned = self.clean_headers(cleaned)
            cleaned = self.clean_code_blocks(cleaned)
            cleaned = self.clean_links(cleaned)
            cleaned = self.standardize_lists(cleaned)
            cleaned = self.normalize_whitespace(cleaned)

            # Only write if changed
            if cleaned != content:
                file_path.write_text(cleaned, encoding='utf-8')
                self.cleaned_count += 1

            # Add metadata comment at top
            metadata = f"<!-- Language: {lang_type} | Chinese ratio: {lang_ratio:.2%} -->\n"
            if not content.startswith('<!--'):
                file_path.write_text(metadata + cleaned, encoding='utf-8')

            return True

        except Exception as e:
            print(f"Error cleaning {file_path}: {e}")
            self.issues_found['cleaning_errors'] += 1
            return False

    def clean_directory(self, directory: Path, pattern: str = '*.md') -> Dict[str, int]:
        """Clean all markdown files in a directory."""
        print(f"Cleaning markdown files in {directory}...")

        files = list(directory.rglob(pattern))
        print(f"Found {len(files)} files")

        for file_path in files:
            if file_path.is_file():
                self.clean_file(file_path)

        stats = {
            'total_files': len(files),
            'cleaned_files': self.cleaned_count,
            'issues': dict(self.issues_found)
        }

        print(f"Cleaned {self.cleaned_count} files")
        return stats

    def run(self):
        """Run the full cleaning process."""
        # Clean playbooks
        playbooks_dir = BASE_DIR / 'references/playbooks'
        playbook_stats = self.clean_directory(playbooks_dir)

        # Clean methodology
        methodology_dir = BASE_DIR / 'references/methodology'
        methodology_stats = self.clean_directory(methodology_dir)

        # Clean industry
        industry_dir = BASE_DIR / 'references/industry'
        industry_stats = self.clean_directory(industry_dir)

        # Clean templates
        templates_dir = BASE_DIR / 'references/templates'
        template_stats = self.clean_directory(templates_dir)

        print("\nCleaning Summary:")
        print(f"Playbooks: {playbook_stats}")
        print(f"Methodology: {methodology_stats}")
        print(f"Industry: {industry_stats}")
        print(f"Templates: {template_stats}")
        print("Markdown cleaning complete!")

if __name__ == '__main__':
    from collections import defaultdict
    cleaner = MarkdownCleaner()
    cleaner.run()