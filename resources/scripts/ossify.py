#!/usr/bin/env python3
"""
Stalwart SEL code remover

This script removes SEL code from the Stalwart codebase by:
1. Removing entire .rs files that contain "SPDX-License-Identifier: LicenseRef-SEL" in their first comment
2. Removing SEL snippets marked with SPDX-SnippetBegin/End from mixed files

Usage: python ossify.py <stalwart_repository>/crates
"""

# SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
#
# SPDX-License-Identifier: AGPL-3.0-only

import os
import sys
import re
import argparse
from pathlib import Path
from typing import List, Tuple, Optional

def find_first_comment_block(content: str) -> Optional[str]:

    lines = content.strip().split('\n')

    if not lines:
        return None

    first_line = lines[0].strip()

    if first_line.startswith('/*'):
        comment_lines = []
        in_comment = True

        for line in lines:
            if in_comment:
                comment_lines.append(line)
                if '*/' in line:
                    break

        return '\n'.join(comment_lines)

    elif first_line.startswith('//'):
        comment_lines = []

        for line in lines:
            stripped = line.strip()
            if stripped.startswith('//'):
                comment_lines.append(line)
            elif stripped == '':
                comment_lines.append(line)
            else:
                break

        return '\n'.join(comment_lines)

    return None

def should_remove_file(file_path: str) -> bool:

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        first_comment = find_first_comment_block(content)
        if first_comment and 'SPDX-License-Identifier: LicenseRef-SEL' in first_comment:
            return True

    except Exception as e:
        print(f"Error reading file {file_path}: {e}")

    return False

def remove_proprietary_snippets(content: str) -> Tuple[str, int]:

    snippets_removed = 0

    lines = content.split('\n')
    result_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]

        if '// SPDX-SnippetBegin' in line:

            snippet_start = i
            snippet_lines = []
            j = i

            while j < len(lines):
                snippet_lines.append(lines[j])
                if '// SPDX-SnippetEnd' in lines[j]:
                    break
                j += 1

            snippet_content = '\n'.join(snippet_lines)
            if 'SPDX-License-Identifier: LicenseRef-SEL' in snippet_content:

                snippets_removed += 1
                i = j + 1
                continue
            else:

                result_lines.append(line)
                i += 1
        else:
            result_lines.append(line)
            i += 1

    return '\n'.join(result_lines), snippets_removed

def process_rust_file(file_path: str, dry_run: bool = False) -> dict:

    result = {
        'file': file_path,
        'action': 'none',
        'snippets_removed': 0,
        'error': None
    }

    try:

        if should_remove_file(file_path):
            result['action'] = 'file_removed'
            if not dry_run:
                os.remove(file_path)
            return result

        with open(file_path, 'r', encoding='utf-8') as f:
            original_content = f.read()

        modified_content, snippets_removed = remove_proprietary_snippets(original_content)

        if snippets_removed > 0:
            result['action'] = 'snippets_removed'
            result['snippets_removed'] = snippets_removed

            if not dry_run:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(modified_content)

    except Exception as e:
        result['error'] = str(e)

    return result

def find_rust_files(directory: str) -> List[str]:

    rust_files = []

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.rs'):
                rust_files.append(os.path.join(root, file))

    return rust_files

def main():
    parser = argparse.ArgumentParser(
        description='Remove Enterprise licensed code from Stalwart codebase'
    )
    parser.add_argument(
        'directory',
        help='Directory containing Stalwart code to process'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed output for each file'
    )

    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"Error: {args.directory} is not a valid directory")
        sys.exit(1)

    print(f"Processing Rust files in: {args.directory}")
    if args.dry_run:
        print("DRY RUN MODE - No changes will be made")
    print()

    rust_files = find_rust_files(args.directory)

    if not rust_files:
        print("No .rs files found in the specified directory")
        return

    print(f"Found {len(rust_files)} Rust files")
    print()

    files_removed = 0
    files_with_snippets_removed = 0
    total_snippets_removed = 0
    errors = []

    for file_path in rust_files:
        result = process_rust_file(file_path, args.dry_run)

        if result['error']:
            errors.append(f"{file_path}: {result['error']}")
            continue

        if result['action'] == 'file_removed':
            files_removed += 1
            if args.verbose or args.dry_run:
                action_text = "Would remove" if args.dry_run else "Removed"
                print(f"{action_text} file: {file_path}")

        elif result['action'] == 'snippets_removed':
            files_with_snippets_removed += 1
            total_snippets_removed += result['snippets_removed']
            if args.verbose or args.dry_run:
                action_text = "Would remove" if args.dry_run else "Removed"
                print(f"{action_text} {result['snippets_removed']} snippet(s) from: {file_path}")

    print("\nSummary:")
    action_text = "Would be" if args.dry_run else "Were"
    print(f"- {files_removed} files {action_text.lower()} completely removed")
    print(f"- {total_snippets_removed} proprietary snippets {action_text.lower()} removed from {files_with_snippets_removed} files")

    if errors:
        print(f"- {len(errors)} errors occurred:")
        for error in errors:
            print(f"  {error}")

    if args.dry_run:
        print("\nRun without --dry-run to apply changes")

if __name__ == '__main__':
    main()
