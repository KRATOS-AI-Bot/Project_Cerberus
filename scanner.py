
import os
import re
import json
import argparse

def load_patterns(patterns_file):
    with open(patterns_file, 'r') as f:
        patterns = json.load(f)
    return patterns

def scan_folder(folder, patterns):
    for root, dirs, files in os.walk(folder):
        for dir in dirs:
            if dir in ['.git', 'venv', 'node_modules', '.terraform', '__pycache__']:
                dirs.remove(dir)
        for file in files:
            if file.endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.zip', '.bin', '.exe')):
                continue
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")
                continue
            for pattern in patterns['signatures']:
                if re.search(pattern['pattern'], content):
                    print(f"[ALERT] {pattern} found in file {file_path}")

def main():
    parser = argparse.ArgumentParser(description='Scan a folder for security credentials')
    parser.add_argument('--target', help='Folder or URL to scan', required=True)
    args = parser.parse_args()
    patterns = load_patterns('patterns.json')
    scan_folder(args.target, patterns)

if __name__ == '__main__':
    main()
