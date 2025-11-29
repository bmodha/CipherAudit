#!/usr/bin/env python3
"""
cipheraudit.py
Analyzes nmap SSH and TLS/SSL scan output and validates algorithms against ciphers.json
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


def parse_nmap_text(nmap_output: str) -> Dict[str, Dict[str, List[str]]]:
    """
    Parse nmap text output to extract SSH and TLS algorithms
    Returns dict with keys: 'ssh' (kex, encryption, mac) and 'tls' (tls1_2, tls1_3)
    """
    algorithms = {
        'ssh': {
            'kex': [],
            'encryption': [],
            'mac': []
        },
        'tls': {
            'tls1_2': [],
            'tls1_3': []
        }
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
                if algo not in algorithms['ssh'][current_section]:
                    algorithms['ssh'][current_section].append(algo)
    
    # Parse TLS/SSL cipher information from ssl-enum-ciphers script
    algorithms['tls'] = parse_tls_ciphers_text(nmap_output)
    
    return algorithms


def parse_tls_ciphers_text(nmap_output: str) -> Dict[str, List[str]]:
    """
    Parse nmap text output to extract TLS cipher suites from ssl-enum-ciphers script
    Returns dict with keys: tls1_2, tls1_3
    """
    tls_ciphers = {
        'tls1_2': [],
        'tls1_3': []
    }
    
    lines = nmap_output.split('\n')
    in_ssl_enum = False
    current_tls_version = None
    
    # Pattern to detect ssl-enum-ciphers section
    ssl_enum_pattern = re.compile(r'ssl-enum-ciphers|TLSv\d+\.\d+')
    
    # Pattern to match TLS version headers
    tls_version_pattern = re.compile(r'TLSv(1\.\d+)')
    
    # Pattern to match cipher suite lines (typically indented)
    # Format can vary: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" or similar
    cipher_pattern = re.compile(r'^\s+(TLS_[A-Z0-9_]+|SSL_[A-Z0-9_]+)', re.IGNORECASE)
    
    # Pattern to match cipher suite in various formats
    # Could be: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" or "0x00,0x3D" format
    cipher_suite_pattern = re.compile(r'(TLS_[A-Z0-9_]+|SSL_[A-Z0-9_]+)', re.IGNORECASE)
    
    for i, line in enumerate(lines):
        # Check if we're in ssl-enum-ciphers section
        if 'ssl-enum-ciphers' in line.lower():
            in_ssl_enum = True
            continue
        
        if not in_ssl_enum:
            continue
        
        # Check for TLS version
        tls_match = tls_version_pattern.search(line)
        if tls_match:
            version = tls_match.group(1)
            if version == '1.3':
                current_tls_version = 'tls1_3'
            elif version == '1.2':
                current_tls_version = 'tls1_2'
            elif version in ['1.1', '1.0']:
                # TLS 1.0/1.1 are deprecated, but we can still track them
                current_tls_version = 'tls1_2'  # Group with TLS 1.2 for validation
            continue
        
        # Check for end of ssl-enum-ciphers section
        if line.strip().startswith('|_') or (line.strip() and not line.startswith('|') and 'ssl' not in line.lower()):
            context_lines = '\n'.join(lines[max(0, i-10):i+1])
            if 'ssl-enum-ciphers' not in context_lines.lower() and 'tlsv' not in context_lines.lower():
                in_ssl_enum = False
                current_tls_version = None
                continue
        
        # Extract cipher suites
        if current_tls_version:
            # Look for cipher suite names in the line
            cipher_matches = cipher_suite_pattern.findall(line)
            for cipher in cipher_matches:
                # Normalize cipher name (uppercase)
                cipher_upper = cipher.upper()
                if cipher_upper not in tls_ciphers[current_tls_version]:
                    tls_ciphers[current_tls_version].append(cipher_upper)
    
    return tls_ciphers


def parse_tls_ciphers_xml(script_element) -> Dict[str, List[str]]:
    """
    Parse TLS cipher information from nmap XML script element
    Returns dict with keys: tls1_2, tls1_3
    """
    tls_ciphers = {
        'tls1_2': [],
        'tls1_3': []
    }
    
    try:
        import xml.etree.ElementTree as ET
    except ImportError:
        return tls_ciphers
    
    # Look for table elements with TLS version keys
    for table in script_element.findall('.//table'):
        key = table.get('key', '')
        
        # Check if this is a TLS version table (e.g., "TLSv1.2" or "TLSv1.3")
        if 'TLSv1.3' in key or 'tlsv1.3' in key.lower():
            version_key = 'tls1_3'
        elif 'TLSv1.2' in key or 'tlsv1.2' in key.lower():
            version_key = 'tls1_2'
        elif 'TLSv1.1' in key or 'TLSv1.0' in key:
            # Group TLS 1.0/1.1 with 1.2 for validation
            version_key = 'tls1_2'
        else:
            continue
        
        # Extract cipher suites from this table
        for elem in table.findall('.//elem'):
            cipher = elem.text
            if cipher:
                # Normalize to uppercase
                cipher_upper = cipher.upper()
                if cipher_upper.startswith('TLS_') or cipher_upper.startswith('SSL_'):
                    if cipher_upper not in tls_ciphers[version_key]:
                        tls_ciphers[version_key].append(cipher_upper)
        
        # Also check for nested tables (cipher suites might be in sub-tables)
        for subtable in table.findall('.//table'):
            for elem in subtable.findall('.//elem'):
                cipher = elem.text
                if cipher:
                    cipher_upper = cipher.upper()
                    if cipher_upper.startswith('TLS_') or cipher_upper.startswith('SSL_'):
                        if cipher_upper not in tls_ciphers[version_key]:
                            tls_ciphers[version_key].append(cipher_upper)
    
    # Fallback: parse from output text if structured data not available
    if not any(tls_ciphers.values()):
        output = script_element.get('output', '')
        import html
        output = html.unescape(output)
        parsed = parse_tls_ciphers_text(output)
        for version in ['tls1_2', 'tls1_3']:
            tls_ciphers[version].extend(parsed.get(version, []))
            tls_ciphers[version] = list(set(tls_ciphers[version]))
    
    return tls_ciphers


def parse_nmap_xml(nmap_xml: str) -> Dict[str, Dict[str, List[str]]]:
    """
    Parse nmap XML output to extract SSH and TLS algorithms
    Returns dict with keys: 'ssh' (kex, encryption, mac) and 'tls' (tls1_2, tls1_3)
    """
    try:
        import xml.etree.ElementTree as ET
    except ImportError:
        print("Error: XML parsing requires xml.etree.ElementTree", file=sys.stderr)
        return {
            'ssh': {'kex': [], 'encryption': [], 'mac': []},
            'tls': {'tls1_2': [], 'tls1_3': []}
        }
    
    algorithms = {
        'ssh': {
            'kex': [],
            'encryption': [],
            'mac': []
        },
        'tls': {
            'tls1_2': [],
            'tls1_3': []
        }
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
                                    if algo and algo not in algorithms['ssh']['kex']:
                                        algorithms['ssh']['kex'].append(algo)
                            elif key == 'encryption_algorithms':
                                for elem in table.findall('.//elem'):
                                    algo = elem.text
                                    if algo and algo not in algorithms['ssh']['encryption']:
                                        algorithms['ssh']['encryption'].append(algo)
                            elif key == 'mac_algorithms':
                                for elem in table.findall('.//elem'):
                                    algo = elem.text
                                    if algo and algo not in algorithms['ssh']['mac']:
                                        algorithms['ssh']['mac'].append(algo)
                    
                    # Parse TLS/SSL ciphers from ssl-enum-ciphers script
                    elif script.get('id') == 'ssl-enum-ciphers':
                        # Parse TLS cipher information from XML
                        tls_info = parse_tls_ciphers_xml(script)
                        for version in ['tls1_2', 'tls1_3']:
                            algorithms['tls'][version].extend(tls_info.get(version, []))
                            algorithms['tls'][version] = list(set(algorithms['tls'][version]))
                        
                        # Fallback: parse output text if structured data not found
                        if not any(algorithms['tls'].values()):
                            output = script.get('output', '')
                            import html
                            output = html.unescape(output)
                            parsed_tls = parse_tls_ciphers_text(output)
                            for version in ['tls1_2', 'tls1_3']:
                                algorithms['tls'][version].extend(parsed_tls.get(version, []))
                                algorithms['tls'][version] = list(set(algorithms['tls'][version]))
                        
                        # Fallback for SSH: parse the output text if tables weren't found
                        if not any(algorithms['ssh'].values()):
                            output = script.get('output', '')
                            import html
                            output = html.unescape(output)
                            parsed = parse_nmap_text(output)
                            if 'ssh' in parsed:
                                for key in ['kex', 'encryption', 'mac']:
                                    algorithms['ssh'][key].extend(parsed['ssh'].get(key, []))
                                    algorithms['ssh'][key] = list(set(algorithms['ssh'][key]))
        
        # Parse TLS ciphers from all scripts (in case they're in different ports)
        for host in root.findall('.//host'):
            for port in host.findall('.//port'):
                for script in port.findall('.//script'):
                    if script.get('id') == 'ssl-enum-ciphers':
                        tls_info = parse_tls_ciphers_xml(script)
                        for version in ['tls1_2', 'tls1_3']:
                            algorithms['tls'][version].extend(tls_info.get(version, []))
                            algorithms['tls'][version] = list(set(algorithms['tls'][version]))
        
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}", file=sys.stderr)
        return {
            'ssh': {'kex': [], 'encryption': [], 'mac': []},
            'tls': {'tls1_2': [], 'tls1_3': []}
        }
    
    return algorithms


def validate_algorithms(algorithms: Dict[str, Dict[str, List[str]]], ciphers_data: Dict) -> Dict[str, Dict[str, Dict[str, List[str]]]]:
    """
    Validate algorithms against ciphers.json
    Returns dict with 'ssh' and 'tls' sections, each containing 'allowed' and 'violations' for each algorithm type
    """
    results = {
        'ssh': {
            'kex': {'allowed': [], 'violations': []},
            'encryption': {'allowed': [], 'violations': []},
            'mac': {'allowed': [], 'violations': []}
        },
        'tls': {
            'tls1_2': {'allowed': [], 'violations': []},
            'tls1_3': {'allowed': [], 'violations': []}
        }
    }
    
    # Validate SSH algorithms
    ssh_allowed = ciphers_data.get('ssh', {})
    ciphers_map = {
        'kex': 'kex',
        'encryption': 'ciphers',
        'mac': 'macs'
    }
    
    for algo_type, algo_list in algorithms.get('ssh', {}).items():
        ciphers_key = ciphers_map[algo_type]
        allowed_list = ssh_allowed.get(ciphers_key, [])
        
        for algo in algo_list:
            if algo in allowed_list:
                results['ssh'][algo_type]['allowed'].append(algo)
            else:
                results['ssh'][algo_type]['violations'].append(algo)
    
    # Validate TLS ciphers
    ssl_allowed = ciphers_data.get('ssl', {})
    
    for tls_version in ['tls1_2', 'tls1_3']:
        cipher_list = algorithms.get('tls', {}).get(tls_version, [])
        # Map tls1_2 -> tls1_2, tls1_3 -> tls1_3 in ciphers.json
        allowed_list = ssl_allowed.get(tls_version, [])
        
        for cipher in cipher_list:
            if cipher in allowed_list:
                results['tls'][tls_version]['allowed'].append(cipher)
            else:
                results['tls'][tls_version]['violations'].append(cipher)
    
    return results


def print_results(results: Dict[str, Dict[str, Dict[str, List[str]]]], ciphers_file: Optional[str]):
    """Print validation results in a formatted way"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}Algorithm Validation (ciphers.json = allowed list):{Colors.RESET}")
    if ciphers_file:
        print(f"Using ciphers.json: {ciphers_file}\n")
    else:
        print(f"{Colors.YELLOW}Warning: ciphers.json not found - showing all algorithms as violations{Colors.RESET}\n")
    
    total_violations = 0
    
    # Process SSH results
    ssh_results = results.get('ssh', {})
    if any(ssh_results.values()):
        print(f"{Colors.BOLD}SSH Algorithms:{Colors.RESET}\n")
        
        for algo_type in ['kex', 'encryption', 'mac']:
            type_name = algo_type.capitalize()
            if algo_type == 'kex':
                type_name = 'KEX'
            elif algo_type == 'encryption':
                type_name = 'Encryption Ciphers'
            elif algo_type == 'mac':
                type_name = 'MAC Algorithms'
            
            violations = ssh_results.get(algo_type, {}).get('violations', [])
            allowed = ssh_results.get(algo_type, {}).get('allowed', [])
            
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
    
    # Process TLS results
    tls_results = results.get('tls', {})
    if any(tls_results.values()):
        print(f"{Colors.BOLD}TLS/SSL Ciphers:{Colors.RESET}\n")
        
        for tls_version in ['tls1_2', 'tls1_3']:
            version_name = f"TLS {tls_version.replace('tls', '').replace('_', '.')}"
            violations = tls_results.get(tls_version, {}).get('violations', [])
            allowed = tls_results.get(tls_version, {}).get('allowed', [])
            
            if violations:
                total_violations += len(violations)
                print(f"{Colors.RED}⚠ VIOLATIONS - {version_name} Ciphers (NOT in allowed list):{Colors.RESET}")
                for cipher in sorted(violations):
                    print(f"    {Colors.RED}✗{Colors.RESET} {cipher} {Colors.RED}(VIOLATION - not in allowed list){Colors.RESET}")
                print()
            
            if allowed:
                print(f"Allowed {version_name} Ciphers:")
                for cipher in sorted(allowed):
                    print(f"    {Colors.GREEN}✓{Colors.RESET} {cipher} (allowed)")
                print()
    
    # Summary
    if total_violations > 0:
        print(f"{Colors.RED}⚠ Total Violations: {total_violations} algorithm(s) not in allowed list{Colors.RESET}\n")
    else:
        print(f"{Colors.GREEN}✓ No violations - all algorithms are in allowed list{Colors.RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze nmap SSH and TLS/SSL scan output and validate algorithms against ciphers.json',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cipheraudit.py nmap_output.txt
  python3 cipheraudit.py -x nmap_output.xml
  cat nmap_output.txt | python3 cipheraudit.py -
  nmap -p 22 --script=ssh2-enum-algos target | python3 cipheraudit.py -
  nmap -p 443 --script=ssl-enum-ciphers target | python3 cipheraudit.py -
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
    ssh_algos = sum(len(v) for v in algorithms.get('ssh', {}).values())
    tls_algos = sum(len(v) for v in algorithms.get('tls', {}).values())
    total_algos = ssh_algos + tls_algos
    
    if total_algos == 0:
        print(f"{Colors.YELLOW}Warning: No SSH or TLS algorithms found in nmap output.{Colors.RESET}", file=sys.stderr)
        print("For SSH: Make sure the nmap scan includes --script=ssh2-enum-algos", file=sys.stderr)
        print("For TLS: Make sure the nmap scan includes --script=ssl-enum-ciphers", file=sys.stderr)
        sys.exit(1)
    
    # Validate algorithms
    results = validate_algorithms(algorithms, ciphers_data)
    
    # Print results
    print_results(results, ciphers_file)
    
    # Exit with error code if violations found
    total_violations = 0
    for protocol in results.values():
        for algo_type in protocol.values():
            total_violations += len(algo_type.get('violations', []))
    
    if total_violations > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()

