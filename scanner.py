
import os
import re
import json
import math
import argparse

def shannon_entropy(string):
    """
    Calculate the Shannon entropy of a string.
    """
    # Calculate the frequency of each character
    freq = {}
    for char in string:
        if char in freq:
            freq[char] += 1
        else:
            freq[char] = 1

    # Calculate the entropy
    entropy = 0.0
    for char in freq:
        prob = freq[char] / len(string)
        entropy += prob * math.log2(prob)

    return -entropy

def load_patterns(patterns_file):
    """
    Load the patterns from the JSON file.
    """
    with open(patterns_file, 'r') as f:
        patterns = json.load(f)
    return patterns['signatures']

def scan_folder(target_folder, patterns):
    """
    Scan the target folder for credentials that match the patterns.
    """
    results = []
    for root, dirs, files in os.walk(target_folder):
        # Exclude certain directories
        if '.git' in dirs:
            dirs.remove('.git')
        if 'venv' in dirs:
            dirs.remove('venv')
        if 'node_modules' in dirs:
            dirs.remove('node_modules')
        if '__pycache__' in dirs:
            dirs.remove('__pycache__')

        for file in files:
            # Skip images and zips
            if file.endswith(('.jpg', '.png', '.gif', '.zip', '.gz', '.bz2', '.xz', '.lzma', '.7z')):
                continue

            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")
                continue

            # Check for regex matches
            for pattern in patterns:
                matches = re.findall(pattern, content)
                if matches:
                    for match in matches:
                        results.append({
                            'message': f"Found potential credential: {match}",
                            'locations': [
                                {
                                    'physicalLocation': {
                                        'address': {
                                            'fullyQualifiedName': file_path
                                        }
                                    }
                                }
                            ]
                        })

            # Check for high entropy strings
            for line in content.splitlines():
                entropy = shannon_entropy(line)
                if entropy > 4.5 and len(line) > 20:
                    results.append({
                        'message': f"Found high entropy string: {line}",
                        'locations': [
                            {
                                'physicalLocation': {
                                    'address': {
                                        'fullyQualifiedName': file_path
                                    }
                                }
                            }
                        ]
                    })

    return results

def load_ignore_file(ignore_file):
    """
    Load the ignore file and return a list of paths to ignore.
    """
    try:
        with open(ignore_file, 'r') as f:
            ignore_paths = [line.strip() for line in f.readlines()]
        return ignore_paths
    except FileNotFoundError:
        return []

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', help='Target folder to scan')
    args = parser.parse_args()

    patterns = load_patterns('patterns.json')
    ignore_paths = load_ignore_file('.cerberusignore')

    results = scan_folder(args.target, patterns)

    # Filter out ignored paths
    filtered_results = []
    for result in results:
        file_path = result['locations'][0]['physicalLocation']['address']['fullyQualifiedName']
        if not any(file_path.startswith(ignore_path) for ignore_path in ignore_paths):
            filtered_results.append(result)

    # Print alerts to console
    for result in filtered_results:
        print(f"[ALERT] {result['message']}")

    # Generate SARIF output
    sarif_output = {
        'version': '2.1.0',
        'runs': [
            {
                'tool': {
                    'driver': {
                        'name': 'Cerberus'
                    }
                },
                'results': filtered_results
            }
        ]
    }

    with open('results.sarif', 'w') as f:
        json.dump(sarif_output, f, indent=4)

if __name__ == '__main__':
    main()
