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

try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False


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


def parse_nmap_text(nmap_output: str) -> Dict[str, Dict[str, Dict[str, List[str]]]]:
    """
    Parse nmap text output to extract SSH and TLS algorithms per host:port
    Returns dict with keys: 'host:port' -> {'ssh': {...}, 'tls': {...}}
    """
    # Dictionary to store algorithms per host:port
    all_algorithms = {}
    
    # Current host:port being processed
    current_host = None
    current_port = None
    current_key = None
    
    def get_or_create_host_port(host, port):
        """Get or create algorithm dict for a host:port"""
        key = f"{host}:{port}"
        if key not in all_algorithms:
            all_algorithms[key] = {
                'ssh': {
                    'kex': [],
                    'encryption': [],
                    'mac': [],
                    'host_keys': []
                },
                'tls': {
                    'tls1_2': [],
                    'tls1_3': []
                }
            }
        return all_algorithms[key]
    
    current_section = None
    
    # Pattern to match "Nmap scan report for" lines
    # Format: "Nmap scan report for hostname (IP)" or "Nmap scan report for IP"
    host_pattern = re.compile(r'Nmap scan report for (.+?)(?:\s+\(([^)]+)\))?$')
    
    # Pattern to match PORT lines (e.g., "22/tcp open  ssh")
    port_pattern = re.compile(r'^(\d+)/(tcp|udp)\s+')
    
    # Pattern to match section headers
    section_patterns = {
        'kex': re.compile(r'kex_algorithms:\s*\(\d+\)'),
        'encryption': re.compile(r'encryption_algorithms:\s*\(\d+\)'),
        'mac': re.compile(r'mac_algorithms:\s*\(\d+\)'),
        'host_keys': re.compile(r'server_host_key_algorithms:\s*\(\d+\)')
    }
    
    # Pattern to match algorithm lines (indented with 7 spaces after pipe: "|       algorithm")
    algo_pattern = re.compile(r'^\|\s{7}([a-z0-9@._-]+)$')
    
    # Pattern to detect end of section (next section header or end of ssh2-enum-algos)
    end_pattern = re.compile(r'^\|\s{3}(encryption_algorithms|mac_algorithms|compression_algorithms|server_host_key_algorithms|kex_algorithms):')
    
    lines = nmap_output.split('\n')
    in_ssh2_enum = False
    in_ssl_enum = False
    
    for i, line in enumerate(lines):
        # Check for new host
        host_match = host_pattern.search(line)
        if host_match:
            hostname = host_match.group(1).strip()
            # Group 2 is the IP in parentheses, if present
            if host_match.group(2):
                ip = host_match.group(2).strip()
            else:
                # If no IP in parentheses, use hostname (might be IP or hostname)
                ip = hostname
            current_host = ip
            current_port = None
            current_key = None
            continue
        
        # Check for port line
        port_match = port_pattern.search(line)
        if port_match and current_host:
            current_port = port_match.group(1)
            current_key = f"{current_host}:{current_port}"
            get_or_create_host_port(current_host, current_port)
            continue
        
        # Check if we're entering ssh2-enum-algos section
        if 'ssh2-enum-algos' in line:
            in_ssh2_enum = True
            current_section = None
            continue
        
        # Check if we're entering ssl-enum-ciphers section
        if 'ssl-enum-ciphers' in line.lower():
            in_ssl_enum = True
            continue
        
        # Process SSH algorithms
        if in_ssh2_enum and current_key:
            algorithms = all_algorithms[current_key]
            
            # Check for section start
            for section_name, pattern in section_patterns.items():
                if pattern.search(line):
                    current_section = section_name
                    break
            
            # Check for section end - stop current section when we hit any other section header
            if end_pattern.search(line):
                current_section = None
                # Check if this line starts a new section we care about
                for section_name, pattern in section_patterns.items():
                    if pattern.search(line):
                        current_section = section_name
                        break
            
            # Check for end of ssh2-enum-algos section
            if line.strip().startswith('|_') or (line.strip() and not line.startswith('|') and 'ssh' not in line.lower()):
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
        
        # Process TLS ciphers (will be handled separately, but track host:port)
        if in_ssl_enum and current_key:
            # TLS parsing will be done in a separate pass
            pass
        
        # Reset flags when we hit a new host or end of scan
        if line.strip().startswith('Nmap done') or (line.strip() and not line.startswith('|') and not line.startswith('PORT') and 'scan report' not in line and current_host and i > 0):
            # Check if we're moving to a new host section
            if i < len(lines) - 1:
                next_lines = '\n'.join(lines[i:min(i+5, len(lines))])
                if 'Nmap scan report' in next_lines:
                    in_ssh2_enum = False
                    in_ssl_enum = False
                    current_section = None
    
    # Parse TLS/SSL cipher information from ssl-enum-ciphers script (per host:port)
    parse_tls_ciphers_text_per_host(nmap_output, all_algorithms)
    
    return all_algorithms


def parse_tls_ciphers_text_per_host(nmap_output: str, all_algorithms: Dict[str, Dict[str, Dict[str, List[str]]]]):
    """
    Parse nmap text output to extract TLS cipher suites from ssl-enum-ciphers script per host:port
    Updates all_algorithms dict in place
    """
    lines = nmap_output.split('\n')
    in_ssl_enum = False
    current_tls_version = None
    current_host = None
    current_port = None
    current_key = None
    
    # Pattern to match "Nmap scan report for" lines
    # Format: "Nmap scan report for hostname (IP)" or "Nmap scan report for IP"
    host_pattern = re.compile(r'Nmap scan report for (.+?)(?:\s+\(([^)]+)\))?$')
    
    # Pattern to match PORT lines (e.g., "443/tcp open  ssl/http")
    port_pattern = re.compile(r'^(\d+)/(tcp|udp)\s+')
    
    # Pattern to match TLS version headers
    tls_version_pattern = re.compile(r'TLSv(1\.\d+)')
    
    # Pattern to match cipher suite in various formats
    cipher_suite_pattern = re.compile(r'(TLS_[A-Z0-9_]+|SSL_[A-Z0-9_]+)', re.IGNORECASE)
    
    for i, line in enumerate(lines):
        # Check for new host
        host_match = host_pattern.search(line)
        if host_match:
            hostname = host_match.group(1).strip()
            ip = host_match.group(2).strip() if host_match.group(2) else hostname
            current_host = ip
            current_port = None
            current_key = None
            in_ssl_enum = False
            current_tls_version = None
            continue
        
        # Check for port line
        port_match = port_pattern.search(line)
        if port_match and current_host:
            current_port = port_match.group(1)
            current_key = f"{current_host}:{current_port}"
            in_ssl_enum = False
            current_tls_version = None
            continue
        
        # Check if we're entering ssl-enum-ciphers section
        if 'ssl-enum-ciphers' in line.lower():
            in_ssl_enum = True
            current_tls_version = None
            continue
        
        if not in_ssl_enum or not current_key:
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
        if line.strip().startswith('|_') or (line.strip() and not line.startswith('|') and 'ssl' not in line.lower() and 'tlsv' not in line.lower()):
            context_lines = '\n'.join(lines[max(0, i-10):i+1])
            if 'ssl-enum-ciphers' not in context_lines.lower() and 'tlsv' not in context_lines.lower():
                in_ssl_enum = False
                current_tls_version = None
                continue
        
        # Extract cipher suites
        if current_tls_version and current_key in all_algorithms:
            # Look for cipher suite names in the line
            cipher_matches = cipher_suite_pattern.findall(line)
            for cipher in cipher_matches:
                # Normalize cipher name (uppercase)
                cipher_upper = cipher.upper()
                if cipher_upper not in all_algorithms[current_key]['tls'][current_tls_version]:
                    all_algorithms[current_key]['tls'][current_tls_version].append(cipher_upper)


def parse_tls_ciphers_text(nmap_output: str) -> Dict[str, List[str]]:
    """
    Parse nmap text output to extract TLS cipher suites from ssl-enum-ciphers script
    Returns dict with keys: tls1_2, tls1_3
    (Legacy function for backward compatibility)
    """
    tls_ciphers = {
        'tls1_2': [],
        'tls1_3': []
    }
    
    lines = nmap_output.split('\n')
    in_ssl_enum = False
    current_tls_version = None
    
    # Pattern to match TLS version headers
    tls_version_pattern = re.compile(r'TLSv(1\.\d+)')
    
    # Pattern to match cipher suite in various formats
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
                current_tls_version = 'tls1_2'
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
            cipher_matches = cipher_suite_pattern.findall(line)
            for cipher in cipher_matches:
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


def parse_nmap_xml(nmap_xml: str) -> Dict[str, Dict[str, Dict[str, List[str]]]]:
    """
    Parse nmap XML output to extract SSH and TLS algorithms per host:port
    Returns dict with keys: 'host:port' -> {'ssh': {...}, 'tls': {...}}
    """
    try:
        import xml.etree.ElementTree as ET
    except ImportError:
        print("Error: XML parsing requires xml.etree.ElementTree", file=sys.stderr)
        return {}
    
    all_algorithms = {}
    
    def get_or_create_host_port(host, port):
        """Get or create algorithm dict for a host:port"""
        key = f"{host}:{port}"
        if key not in all_algorithms:
            all_algorithms[key] = {
                'ssh': {
                    'kex': [],
                    'encryption': [],
                    'mac': [],
                    'host_keys': []
                },
                'tls': {
                    'tls1_2': [],
                    'tls1_3': []
                }
            }
        return all_algorithms[key]
    
    try:
        root = ET.fromstring(nmap_xml)
        
        # Iterate through all hosts and ports
        for host in root.findall('.//host'):
            # Get host address (prefer IPv4, fallback to IPv6 or hostname)
            host_addr = None
            for address in host.findall('.//address'):
                if address.get('addrtype') == 'ipv4':
                    host_addr = address.get('addr')
                    break
            if not host_addr:
                for address in host.findall('.//address'):
                    host_addr = address.get('addr')
                    break
            
            if not host_addr:
                continue
            
            # Process each port
            for port in host.findall('.//port'):
                port_num = port.get('portid')
                if not port_num:
                    continue
                
                key = f"{host_addr}:{port_num}"
                algorithms = get_or_create_host_port(host_addr, port_num)
                
                # Process scripts for this port
                for script in port.findall('.//script'):
                    script_id = script.get('id')
                    
                    # Process SSH algorithms
                    if script_id == 'ssh2-enum-algos':
                        # First try to get algorithms from table elements (structured data)
                        for table in script.findall('.//table'):
                            table_key = table.get('key', '')
                            if table_key == 'kex_algorithms':
                                for elem in table.findall('.//elem'):
                                    algo = elem.text
                                    if algo and algo not in algorithms['ssh']['kex']:
                                        algorithms['ssh']['kex'].append(algo)
                            elif table_key == 'encryption_algorithms':
                                for elem in table.findall('.//elem'):
                                    algo = elem.text
                                    if algo and algo not in algorithms['ssh']['encryption']:
                                        algorithms['ssh']['encryption'].append(algo)
                            elif table_key == 'mac_algorithms':
                                for elem in table.findall('.//elem'):
                                    algo = elem.text
                                    if algo and algo not in algorithms['ssh']['mac']:
                                        algorithms['ssh']['mac'].append(algo)
                            elif table_key == 'server_host_key_algorithms':
                                for elem in table.findall('.//elem'):
                                    algo = elem.text
                                    if algo and algo not in algorithms['ssh']['host_keys']:
                                        algorithms['ssh']['host_keys'].append(algo)
                        
                        # Fallback: parse output text if tables weren't found
                        if not any(algorithms['ssh'].values()):
                            output = script.get('output', '')
                            import html
                            output = html.unescape(output)
                            # Use a simple text parsing approach for fallback
                            for line in output.split('\n'):
                                if 'kex_algorithms' in line or 'encryption_algorithms' in line or 'mac_algorithms' in line:
                                    # Try to extract from output text
                                    pass
                    
                    # Process TLS/SSL ciphers
                    elif script_id == 'ssl-enum-ciphers':
                        # Parse TLS cipher information from XML
                        tls_info = parse_tls_ciphers_xml(script)
                        for version in ['tls1_2', 'tls1_3']:
                            for cipher in tls_info.get(version, []):
                                if cipher not in algorithms['tls'][version]:
                                    algorithms['tls'][version].append(cipher)
                        
                        # Fallback: parse output text if structured data not found
                        if not any(algorithms['tls'].values()):
                            output = script.get('output', '')
                            import html
                            output = html.unescape(output)
                            parsed_tls = parse_tls_ciphers_text(output)
                            for version in ['tls1_2', 'tls1_3']:
                                for cipher in parsed_tls.get(version, []):
                                    if cipher not in algorithms['tls'][version]:
                                        algorithms['tls'][version].append(cipher)
        
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}", file=sys.stderr)
        return {}
    
    return all_algorithms


def validate_algorithms(algorithms: Dict[str, Dict[str, Dict[str, List[str]]]], ciphers_data: Dict) -> Dict[str, Dict[str, Dict[str, Dict[str, List[str]]]]]:
    """
    Validate algorithms against ciphers.json per host:port
    Returns dict with keys: 'host:port' -> {'ssh': {...}, 'tls': {...}} with allowed/violations
    """
    results = {}
    
    # Validate SSH algorithms
    ssh_allowed = ciphers_data.get('ssh', {})
    ciphers_map = {
        'kex': 'kex',
        'encryption': 'ciphers',
        'mac': 'macs',
        'host_keys': 'host_keys'
    }
    
    # Validate TLS ciphers
    ssl_allowed = ciphers_data.get('ssl', {})
    
    # Process each host:port
    for host_port, algo_data in algorithms.items():
        results[host_port] = {
            'ssh': {
                'kex': {'allowed': [], 'violations': []},
                'encryption': {'allowed': [], 'violations': []},
                'mac': {'allowed': [], 'violations': []},
                'host_keys': {'allowed': [], 'violations': []}
            },
            'tls': {
                'tls1_2': {'allowed': [], 'violations': []},
                'tls1_3': {'allowed': [], 'violations': []}
            }
        }
        
        # Validate SSH algorithms for this host:port
        for algo_type, algo_list in algo_data.get('ssh', {}).items():
            # Skip if this algo_type is not in our mapping
            if algo_type not in ciphers_map:
                continue
            ciphers_key = ciphers_map[algo_type]
            allowed_list = ssh_allowed.get(ciphers_key, [])
            
            # Make sure results structure has this algo_type
            if algo_type not in results[host_port]['ssh']:
                results[host_port]['ssh'][algo_type] = {'allowed': [], 'violations': []}
            
            for algo in algo_list:
                if algo in allowed_list:
                    results[host_port]['ssh'][algo_type]['allowed'].append(algo)
                else:
                    results[host_port]['ssh'][algo_type]['violations'].append(algo)
        
        # Validate TLS ciphers for this host:port
        for tls_version in ['tls1_2', 'tls1_3']:
            cipher_list = algo_data.get('tls', {}).get(tls_version, [])
            allowed_list = ssl_allowed.get(tls_version, [])
            
            for cipher in cipher_list:
                if cipher in allowed_list:
                    results[host_port]['tls'][tls_version]['allowed'].append(cipher)
                else:
                    results[host_port]['tls'][tls_version]['violations'].append(cipher)
    
    return results


def print_logo():
    """Print CIPHERAUDIT logo"""
    logo = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗             ║
║    ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗            ║
║    ██║     ██║██████╔╝███████║█████╗  ██████╔╝            ║
║    ██║     ██║██╔══██╗██╔══██║██╔══╝  ██╔══██╗            ║
║    ╚██████╗██║██████╔╝██║  ██║███████╗██║  ██║            ║
║     ╚═════╝╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝            ║
║                                                           ║
║     █████╗ ██╗   ██╗██████╗ ██╗████████╗                 ║
║    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝                 ║
║    ███████║██║   ██║██║  ██║██║   ██║                    ║
║    ██╔══██║██║   ██║██║  ██║██║   ██║                    ║
║    ██║  ██║╚██████╔╝██████╔╝██║   ██║                    ║
║    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝                    ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
    print(logo)


def print_table(title: str, algorithms: List[str], allowed: List[str], violations: List[str], max_width: int = 80):
    """
    Print a table with Algorithm | Allowed | Not Allowed columns using tabulate
    
    Args:
        title: Table title
        algorithms: Combined list of all algorithms (allowed + violations)
        allowed: List of allowed algorithms
        violations: List of violation algorithms
        max_width: Maximum table width
    """
    if not algorithms:
        return
    
    if not TABULATE_AVAILABLE:
        print(f"{Colors.YELLOW}Warning: tabulate not available, falling back to simple format{Colors.RESET}", file=sys.stderr)
        # Fallback to simple format
        print(f"\n{Colors.BOLD}{title}{Colors.RESET}")
        for algo in sorted(set(algorithms)):
            is_allowed = algo in allowed
            is_violation = algo in violations
            allowed_mark = f"{Colors.GREEN}✓{Colors.RESET}" if is_allowed else " "
            violation_mark = f"{Colors.RED}✗{Colors.RESET}" if is_violation else " "
            print(f"  {algo}: {allowed_mark} {violation_mark}")
        print()
        return
    
    # Sort all algorithms for consistent display
    all_sorted = sorted(set(algorithms))
    
    # Prepare table data
    table_data = []
    for algo in all_sorted:
        is_allowed = algo in allowed
        is_violation = algo in violations
        
        allowed_mark = f"{Colors.GREEN}✓{Colors.RESET}" if is_allowed else " "
        violation_mark = f"{Colors.RED}✗{Colors.RESET}" if is_violation else " "
        
        table_data.append([algo, allowed_mark, violation_mark])
    
    # Print title
    print(f"\n{Colors.BOLD}{title}{Colors.RESET}")
    
    # Print table using tabulate with grid format
    headers = ["Algorithm", "Allowed", "Not Allowed"]
    print(tabulate(table_data, headers=headers, tablefmt="grid", stralign="left"))
    print()


def print_summary_table(results: Dict[str, Dict[str, Dict[str, Dict[str, List[str]]]]]):
    """
    Print summary table showing pass/fail status for each host:port
    Columns: IP | Ciphers | KEX Algos | MAC Algos | Host Key Algos
    """
    if not results:
        return
    
    # Collect summary data for each host:port
    summary_data = []
    
    for host_port, host_results in sorted(results.items()):
        ssh_results = host_results.get('ssh', {})
        tls_results = host_results.get('tls', {})
        
        # Check Ciphers (SSH encryption + TLS combined)
        ssh_cipher_violations = len(ssh_results.get('encryption', {}).get('violations', []))
        tls_violations = 0
        for tls_version in ['tls1_2', 'tls1_3']:
            tls_violations += len(tls_results.get(tls_version, {}).get('violations', []))
        ciphers_has_violations = (ssh_cipher_violations + tls_violations) > 0
        
        # Check KEX
        kex_violations = len(ssh_results.get('kex', {}).get('violations', []))
        kex_has_violations = kex_violations > 0
        
        # Check MAC
        mac_violations = len(ssh_results.get('mac', {}).get('violations', []))
        mac_has_violations = mac_violations > 0
        
        # Check Host Keys
        host_key_violations = len(ssh_results.get('host_keys', {}).get('violations', []))
        host_key_has_violations = host_key_violations > 0
        
        summary_data.append({
            'ip': host_port,
            'ciphers': ciphers_has_violations,
            'kex': kex_has_violations,
            'mac': mac_has_violations,
            'host_keys': host_key_has_violations
        })
    
    if not TABULATE_AVAILABLE:
        print(f"{Colors.YELLOW}Warning: tabulate not available, falling back to simple format{Colors.RESET}", file=sys.stderr)
        # Fallback to simple format
        print(f"\n{Colors.BOLD}Summary Table{Colors.RESET}")
        for item in summary_data:
            ciphers_mark = f"{Colors.RED}✗{Colors.RESET}" if item['ciphers'] else f"{Colors.GREEN}✓{Colors.RESET}"
            kex_mark = f"{Colors.RED}✗{Colors.RESET}" if item['kex'] else f"{Colors.GREEN}✓{Colors.RESET}"
            mac_mark = f"{Colors.RED}✗{Colors.RESET}" if item['mac'] else f"{Colors.GREEN}✓{Colors.RESET}"
            host_key_mark = f"{Colors.RED}✗{Colors.RESET}" if item['host_keys'] else f"{Colors.GREEN}✓{Colors.RESET}"
            print(f"  {item['ip']}: Ciphers={ciphers_mark} KEX={kex_mark} MAC={mac_mark} HostKeys={host_key_mark}")
        print()
        return
    
    # Prepare table data for tabulate
    table_data = []
    for item in summary_data:
        ciphers_mark = f"{Colors.RED}✗{Colors.RESET}" if item['ciphers'] else f"{Colors.GREEN}✓{Colors.RESET}"
        kex_mark = f"{Colors.RED}✗{Colors.RESET}" if item['kex'] else f"{Colors.GREEN}✓{Colors.RESET}"
        mac_mark = f"{Colors.RED}✗{Colors.RESET}" if item['mac'] else f"{Colors.GREEN}✓{Colors.RESET}"
        host_key_mark = f"{Colors.RED}✗{Colors.RESET}" if item['host_keys'] else f"{Colors.GREEN}✓{Colors.RESET}"
        
        table_data.append([
            item['ip'],
            ciphers_mark,
            kex_mark,
            mac_mark,
            host_key_mark
        ])
    
    # Print summary table
    print(f"\n{Colors.BOLD}{'═' * 80}{Colors.RESET}")
    print(f"{Colors.BOLD}Summary Table{Colors.RESET}")
    print(f"{Colors.BOLD}{'═' * 80}{Colors.RESET}\n")
    
    # Print table using tabulate with grid format
    headers = ["IP", "Ciphers", "KEX Algos", "MAC Algos", "Host Key Algos"]
    print(tabulate(table_data, headers=headers, tablefmt="grid", stralign="left"))
    print()


def print_results(results: Dict[str, Dict[str, Dict[str, Dict[str, List[str]]]]], ciphers_file: Optional[str]):
    """Print validation results in concise table format"""
    # Print logo
    print_logo()
    
    if ciphers_file:
        print(f"{Colors.CYAN}Using ciphers.json: {ciphers_file}{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}Warning: ciphers.json not found - showing all algorithms as violations{Colors.RESET}")
    print()
    
    total_violations = 0
    total_hosts = len(results)
    
    # Process each host:port
    for host_port, host_results in sorted(results.items()):
        host_violations = 0
        
        print(f"{Colors.BOLD}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.BOLD}IP: {Colors.CYAN}{host_port}{Colors.RESET}")
        print(f"{Colors.BOLD}{'═' * 80}{Colors.RESET}")
        
        # Process SSH results for this host:port
        ssh_results = host_results.get('ssh', {})
        if any(ssh_results.values()):
            # SSH Encryption Ciphers
            if 'encryption' in ssh_results:
                allowed = ssh_results['encryption'].get('allowed', [])
                violations = ssh_results['encryption'].get('violations', [])
                all_algos = allowed + violations
                if all_algos:
                    host_violations += len(violations)
                    total_violations += len(violations)
                    print_table("SSH Encryption Ciphers", all_algos, allowed, violations)
            
            # SSH KEX
            if 'kex' in ssh_results:
                allowed = ssh_results['kex'].get('allowed', [])
                violations = ssh_results['kex'].get('violations', [])
                all_algos = allowed + violations
                if all_algos:
                    host_violations += len(violations)
                    total_violations += len(violations)
                    print_table("SSH KEX Algorithms", all_algos, allowed, violations)
            
            # SSH MAC
            if 'mac' in ssh_results:
                allowed = ssh_results['mac'].get('allowed', [])
                violations = ssh_results['mac'].get('violations', [])
                all_algos = allowed + violations
                if all_algos:
                    host_violations += len(violations)
                    total_violations += len(violations)
                    print_table("SSH MAC Algorithms", all_algos, allowed, violations)
            
            # SSH Host Keys
            if 'host_keys' in ssh_results:
                allowed = ssh_results['host_keys'].get('allowed', [])
                violations = ssh_results['host_keys'].get('violations', [])
                all_algos = allowed + violations
                if all_algos:
                    host_violations += len(violations)
                    total_violations += len(violations)
                    print_table("SSH Host Key Algorithms", all_algos, allowed, violations)
        
        # Process TLS results for this host:port
        tls_results = host_results.get('tls', {})
        if any(tls_results.values()):
            for tls_version in ['tls1_2', 'tls1_3']:
                version_name = f"TLS {tls_version.replace('tls', '').replace('_', '.')}"
                violations = tls_results.get(tls_version, {}).get('violations', [])
                allowed = tls_results.get(tls_version, {}).get('allowed', [])
                all_ciphers = allowed + violations
                
                if all_ciphers:
                    host_violations += len(violations)
                    total_violations += len(violations)
                    print_table(f"{version_name} Ciphers", all_ciphers, allowed, violations)
        
        # Summary for this host:port
        if host_violations > 0:
            print(f"{Colors.RED}⚠ {host_port}: {host_violations} violation(s) found{Colors.RESET}\n")
        else:
            print(f"{Colors.GREEN}✓ {host_port}: No violations - all algorithms are in allowed list{Colors.RESET}\n")
    
    # Overall summary
    print(f"{Colors.BOLD}{'═' * 80}{Colors.RESET}")
    if total_violations > 0:
        print(f"{Colors.RED}⚠ Overall Summary: {total_violations} violation(s) across {total_hosts} host(s){Colors.RESET}\n")
    else:
        print(f"{Colors.GREEN}✓ Overall Summary: No violations found across {total_hosts} host(s){Colors.RESET}\n")
    
    # Print summary table
    print_summary_table(results)


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
        ciphers_data = {
            'ssh': {'kex': [], 'ciphers': [], 'macs': []},
            'ssl': {'tls1_2': [], 'tls1_3': []}
        }
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
    total_algos = 0
    for host_port, algo_data in algorithms.items():
        ssh_algos = sum(len(v) for v in algo_data.get('ssh', {}).values())
        tls_algos = sum(len(v) for v in algo_data.get('tls', {}).values())
        total_algos += ssh_algos + tls_algos
    
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
    for host_port, host_results in results.items():
        for protocol in host_results.values():
            for algo_type in protocol.values():
                total_violations += len(algo_type.get('violations', []))
    
    if total_violations > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()

