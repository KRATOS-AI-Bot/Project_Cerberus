
import os
import re
import json
import argparse
import math
from collections import Counter

def calculate_shannon_entropy(data):
    """Calculate Shannon entropy for a given string"""
    entropy = 0.0
    counter = Counter(data)
    for count in counter.values():
        p = count / len(data)
        entropy -= p * math.log(p, 2)
    return entropy

def load_patterns(patterns_file):
    """Load patterns from JSON file"""
    with open(patterns_file, 'r') as f:
        patterns = json.load(f)
    return patterns['signatures']

def scan_file(file_path, patterns):
    """Scan a single file for patterns"""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            for pattern in patterns:
                if re.search(pattern, content):
                    yield pattern
            entropy = calculate_shannon_entropy(content)
            if entropy > 5.5:  # High entropy threshold
                yield 'High Entropy'
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")

def scan_directory(directory, patterns, exclude_folders, exclude_files):
    """Scan a directory for patterns"""
    for root, dirs, files in os.walk(directory):
        for dir in dirs:
            if dir in exclude_folders:
                dirs.remove(dir)
        for file in files:
            if file.endswith(exclude_files):
                continue
            file_path = os.path.join(root, file)
            yield from scan_file(file_path, patterns)

def main():
    parser = argparse.ArgumentParser(description='Scan for security credentials')
    parser.add_argument('--target', help='Target directory or URL', required=True)
    args = parser.parse_args()

    patterns_file = 'patterns.json'
    patterns = load_patterns(patterns_file)

    exclude_folders = ['.git', 'venv', 'node_modules', '.terraform', '__pycache__']
    exclude_files = ['.jpg', '.png', '.gif', '.zip', '.bin']

    try:
        with open('.cerberusignore', 'r') as f:
            ignore_paths = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        ignore_paths = []

    sarif_file = 'results.sarif'
    with open(sarif_file, 'w') as f:
        f.write('{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Cerberus"}}, "results": []}]}')

    for file_path in scan_directory(args.target, patterns, exclude_folders, exclude_files):
        if os.path.dirname(file_path) in ignore_paths:
            continue
        print(f'[ALERT] {file_path} found in repo {args.target}')
        with open(sarif_file, 'r+') as f:
            data = json.load(f)
            data['runs'][0]['results'].append({
                'ruleId': 'cerberus',
                'level': 'error',
                'message': {'text': f'{file_path} found in repo {args.target}'},
                'locations': [{'physicalLocation': {'address': file_path}}]
            })
            f.seek(0)
            json.dump(data, f)
            f.truncate()

if __name__ == '__main__':
    main()
