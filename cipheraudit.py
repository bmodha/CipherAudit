#!/usr/bin/env python3
"""
cipheraudit.py
Analyzes nmap SSH scan output and validates algorithms against ciphers.json
Shows violations (algorithms NOT in the allowed list)

Usage:
    python3 cipheraudit.py <nmap_output_file>
    python3 cipheraudit.py -x <nmap_xml_file>
    cat nmap_output.txt | python3 cipheraudit.py -
"""

import sys
import json
import re
import argparse
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple


class Colors:
    """ANSI color codes"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    @staticmethod
    def disable():
        """Disable colors"""
        Colors.RED = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.BLUE = ''
        Colors.CYAN = ''
        Colors.BOLD = ''
        Colors.RESET = ''


def load_ciphers_json(ciphers_file: str) -> Optional[Dict]:
    """Load and parse ciphers.json file"""
    try:
        with open(ciphers_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing {ciphers_file}: {e}", file=sys.stderr)
        return None


def find_ciphers_file() -> Optional[str]:
    """Find ciphers.json in script directory or current directory"""
    script_dir = Path(__file__).parent
    possible_locations = [
        script_dir / "ciphers.json",
        Path(".") / "ciphers.json",
        Path("ciphers.json"),
    ]
    
    for location in possible_locations:
        if location.exists():
            return str(location)
    return None


def parse_nmap_text(nmap_output: str) -> Dict[str, List[str]]:
    """
    Parse nmap text output to extract SSH algorithms
    Returns dict with keys: kex, encryption, mac
    """
    algorithms = {
        'kex': [],
        'encryption': [],
        'mac': []
    }
    
    current_section = None
    
    # Pattern to match section headers
    section_patterns = {
        'kex': re.compile(r'kex_algorithms:\s*\(\d+\)'),
        'encryption': re.compile(r'encryption_algorithms:\s*\(\d+\)'),
        'mac': re.compile(r'mac_algorithms:\s*\(\d+\)')
    }
    
    # Pattern to match algorithm lines (indented with 7 spaces after pipe: "|       algorithm")
    algo_pattern = re.compile(r'^\|\s{7}([a-z0-9@._-]+)$')
    
    # Pattern to detect end of section (next section header or end of ssh2-enum-algos)
    end_pattern = re.compile(r'^\|\s{3}(encryption_algorithms|mac_algorithms|compression_algorithms|server_host_key_algorithms|kex_algorithms):')
    
    lines = nmap_output.split('\n')
    in_ssh2_enum = False
    
    for i, line in enumerate(lines):
        # Check if we're in ssh2-enum-algos section
        if 'ssh2-enum-algos' in line:
            in_ssh2_enum = True
            continue
        
        if not in_ssh2_enum:
            continue
        
        # Check for section start
        for section_name, pattern in section_patterns.items():
            if pattern.search(line):
                current_section = section_name
                continue
        
        # Check for section end - stop current section when we hit any other section header
        if end_pattern.search(line):
            current_section = None
            # Check if this line starts a new section we care about
            for section_name, pattern in section_patterns.items():
                if pattern.search(line):
                    current_section = section_name
                    break
        
        # Check for end of ssh2-enum-algos section (line starting with |_ or non-pipe line)
        if line.strip().startswith('|_') or (line.strip() and not line.startswith('|')):
            # Check if we're still in the ssh2-enum-algos context
            context_lines = '\n'.join(lines[max(0, i-10):i+1])
            if 'ssh2-enum-algos' not in context_lines:
                in_ssh2_enum = False
                current_section = None
                continue
        
        # Extract algorithm if we're in a section
        if current_section:
            match = algo_pattern.match(line)
            if match:
                algo = match.group(1)
                if algo not in algorithms[current_section]:
                    algorithms[current_section].append(algo)
    
    return algorithms


def parse_nmap_xml(nmap_xml: str) -> Dict[str, List[str]]:
    """
    Parse nmap XML output to extract SSH algorithms
    Returns dict with keys: kex, encryption, mac
    """
    try:
        import xml.etree.ElementTree as ET
    except ImportError:
        print("Error: XML parsing requires xml.etree.ElementTree", file=sys.stderr)
        return {'kex': [], 'encryption': [], 'mac': []}
    
    algorithms = {
        'kex': [],
        'encryption': [],
        'mac': []
    }
    
    try:
        root = ET.fromstring(nmap_xml)
        
        # Find ssh2-enum-algos script output
        for host in root.findall('.//host'):
            for port in host.findall('.//port'):
                for script in port.findall('.//script'):
                    if script.get('id') == 'ssh2-enum-algos':
                        # First try to get algorithms from table elements (structured data)
                        for table in script.findall('.//table'):
                            key = table.get('key', '')
                            if key == 'kex_algorithms':
                                for elem in table.findall('.//elem'):
                                    algo = elem.text
                                    if algo and algo not in algorithms['kex']:
                                        algorithms['kex'].append(algo)
                            elif key == 'encryption_algorithms':
                                for elem in table.findall('.//elem'):
                                    algo = elem.text
                                    if algo and algo not in algorithms['encryption']:
                                        algorithms['encryption'].append(algo)
                            elif key == 'mac_algorithms':
                                for elem in table.findall('.//elem'):
                                    algo = elem.text
                                    if algo and algo not in algorithms['mac']:
                                        algorithms['mac'].append(algo)
                        
                        # Fallback: parse the output text if tables weren't found
                        if not any(algorithms.values()):
                            output = script.get('output', '')
                            # XML output has HTML entities, decode them
                            import html
                            output = html.unescape(output)
                            parsed = parse_nmap_text(output)
                            for key in algorithms:
                                algorithms[key].extend(parsed[key])
                                algorithms[key] = list(set(algorithms[key]))  # Remove duplicates
        
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}", file=sys.stderr)
        return {'kex': [], 'encryption': [], 'mac': []}
    
    return algorithms


def validate_algorithms(algorithms: Dict[str, List[str]], ciphers_data: Dict) -> Dict[str, Dict[str, List[str]]]:
    """
    Validate algorithms against ciphers.json
    Returns dict with 'allowed' and 'violations' for each algorithm type
    """
    results = {
        'kex': {'allowed': [], 'violations': []},
        'encryption': {'allowed': [], 'violations': []},
        'mac': {'allowed': [], 'violations': []}
    }
    
    # Map our keys to ciphers.json keys
    ciphers_map = {
        'kex': 'kex',
        'encryption': 'ciphers',
        'mac': 'macs'
    }
    
    ssh_allowed = ciphers_data.get('ssh', {})
    
    for algo_type, algo_list in algorithms.items():
        ciphers_key = ciphers_map[algo_type]
        allowed_list = ssh_allowed.get(ciphers_key, [])
        
        for algo in algo_list:
            if algo in allowed_list:
                results[algo_type]['allowed'].append(algo)
            else:
                results[algo_type]['violations'].append(algo)
    
    return results


def print_results(results: Dict[str, Dict[str, List[str]]], ciphers_file: Optional[str]):
    """Print validation results in a formatted way"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}Algorithm Validation (ciphers.json = allowed list):{Colors.RESET}")
    if ciphers_file:
        print(f"Using ciphers.json: {ciphers_file}\n")
    else:
        print(f"{Colors.YELLOW}Warning: ciphers.json not found - showing all algorithms as violations{Colors.RESET}\n")
    
    total_violations = 0
    
    # Show violations first (most important)
    for algo_type in ['kex', 'encryption', 'mac']:
        type_name = algo_type.capitalize()
        if algo_type == 'kex':
            type_name = 'KEX'
        elif algo_type == 'encryption':
            type_name = 'Encryption Ciphers'
        elif algo_type == 'mac':
            type_name = 'MAC Algorithms'
        
        violations = results[algo_type]['violations']
        allowed = results[algo_type]['allowed']
        
        if violations:
            total_violations += len(violations)
            print(f"{Colors.RED}⚠ VIOLATIONS - {type_name} (NOT in allowed list):{Colors.RESET}")
            for algo in sorted(violations):
                print(f"    {Colors.RED}✗{Colors.RESET} {algo} {Colors.RED}(VIOLATION - not in allowed list){Colors.RESET}")
            print()
        
        if allowed:
            print(f"Allowed {type_name}:")
            for algo in sorted(allowed):
                print(f"    {Colors.GREEN}✓{Colors.RESET} {algo} (allowed)")
            print()
    
    # Summary
    if total_violations > 0:
        print(f"{Colors.RED}⚠ Total Violations: {total_violations} algorithm(s) not in allowed list{Colors.RESET}\n")
    else:
        print(f"{Colors.GREEN}✓ No violations - all algorithms are in allowed list{Colors.RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze nmap SSH scan output and validate algorithms against ciphers.json',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cipheraudit.py nmap_output.txt
  python3 cipheraudit.py -x nmap_output.xml
  cat nmap_output.txt | python3 cipheraudit.py -
  nmap -p 22 --script=ssh2-enum-algos target | python3 cipheraudit.py -
        """
    )
    parser.add_argument('input', nargs='?', default='-',
                       help='Nmap output file (text or XML), or "-" for stdin (default: stdin)')
    parser.add_argument('-x', '--xml', action='store_true',
                       help='Input is XML format (default: auto-detect)')
    parser.add_argument('-c', '--ciphers', type=str,
                       help='Path to ciphers.json file (default: auto-detect)')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')
    
    args = parser.parse_args()
    
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()
    
    # Load ciphers.json
    if args.ciphers:
        ciphers_file = args.ciphers
    else:
        ciphers_file = find_ciphers_file()
    
    if not ciphers_file:
        print(f"{Colors.YELLOW}Warning: ciphers.json not found. Will show all algorithms as violations.{Colors.RESET}", file=sys.stderr)
        ciphers_data = {'ssh': {'kex': [], 'ciphers': [], 'macs': []}}
    else:
        ciphers_data = load_ciphers_json(ciphers_file)
        if not ciphers_data:
            print(f"{Colors.RED}Error: Could not load ciphers.json{Colors.RESET}", file=sys.stderr)
            sys.exit(1)
    
    # Read input
    if args.input == '-' or args.input == '/dev/stdin':
        # Check if stdin is a TTY (interactive terminal)
        if sys.stdin.isatty():
            print(f"{Colors.RED}Error: No input provided and stdin is a terminal.{Colors.RESET}", file=sys.stderr)
            print(f"{Colors.YELLOW}Usage:{Colors.RESET}", file=sys.stderr)
            print(f"  python3 cipheraudit.py <nmap_output_file>", file=sys.stderr)
            print(f"  python3 cipheraudit.py -x <nmap_xml_file>", file=sys.stderr)
            print(f"  cat nmap_output.txt | python3 cipheraudit.py -", file=sys.stderr)
            print(f"  nmap -p 22 --script=ssh2-enum-algos target | python3 cipheraudit.py -", file=sys.stderr)
            print(f"\nUse -h or --help for more information.", file=sys.stderr)
            sys.exit(1)
        nmap_output = sys.stdin.read()
    else:
        try:
            with open(args.input, 'r') as f:
                nmap_output = f.read()
        except FileNotFoundError:
            print(f"{Colors.RED}Error: File not found: {args.input}{Colors.RESET}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}Error reading file: {e}{Colors.RESET}", file=sys.stderr)
            sys.exit(1)
    
    # Parse nmap output
    # Auto-detect format: check if it's XML or if user explicitly requested XML
    is_xml = False
    if args.xml:
        is_xml = True
    elif args.input != '-' and args.input.endswith('.xml'):
        is_xml = True
    elif args.input == '-' or args.input == '/dev/stdin':
        # Check if stdin starts with XML declaration
        if nmap_output.strip().startswith('<?xml'):
            is_xml = True
    else:
        # Check file content
        if nmap_output.strip().startswith('<?xml'):
            is_xml = True
    
    if is_xml:
        algorithms = parse_nmap_xml(nmap_output)
    else:
        algorithms = parse_nmap_text(nmap_output)
    
    # Check if we found any algorithms
    total_algos = sum(len(v) for v in algorithms.values())
    if total_algos == 0:
        print(f"{Colors.YELLOW}Warning: No SSH algorithms found in nmap output.{Colors.RESET}", file=sys.stderr)
        print("Make sure the nmap scan includes --script=ssh2-enum-algos", file=sys.stderr)
        sys.exit(1)
    
    # Validate algorithms
    results = validate_algorithms(algorithms, ciphers_data)
    
    # Print results
    print_results(results, ciphers_file)
    
    # Exit with error code if violations found
    total_violations = sum(len(r['violations']) for r in results.values())
    if total_violations > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()

