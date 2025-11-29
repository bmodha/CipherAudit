# CipherAudit

A Python tool for analyzing SSH and TLS/SSL algorithm configurations from nmap scan output and validating them against an allowed list of ciphers, key exchange algorithms, and MAC algorithms.

## Overview

CipherAudit parses nmap SSH and TLS/SSL scan results and compares the discovered algorithms against a `ciphers.json` file containing your organization's approved/allowed algorithms. It identifies violations (algorithms NOT in the allowed list) and provides a clear, color-coded report for both SSH and TLS protocols.

## Features

- **Parses nmap output**: Supports both text and XML nmap output formats
- **Multi-protocol support**: Validates both SSH and TLS/SSL algorithms
- **Per-host:port breakdown**: Groups results by host and port for easy identification of problematic servers
- **Algorithm validation**: Compares discovered algorithms against an allowed list
- **Violation detection**: Highlights algorithms that are NOT in the allowed list
- **Color-coded output**: Red for violations, green for allowed algorithms
- **Multiple input methods**: File input, stdin, or pipe from nmap
- **Auto-detection**: Automatically detects XML vs text format
- **Multi-host support**: Processes multiple IPs and ports from a single nmap scan file

## Requirements

- Python 3.6+
- `ciphers.json` file (included, or provide your own)

## Installation

1. Copy the `cipheraudit.py` script to your system
2. Ensure `ciphers.json` is in the same directory or provide path with `-c` flag
3. Make the script executable: `chmod +x cipheraudit.py`

## Usage

### Basic Usage

```bash
# Analyze nmap text output
python3 cipheraudit.py nmap_output.txt

# Analyze nmap XML output
python3 cipheraudit.py -x nmap_output.xml

# Pipe directly from nmap (SSH)
nmap -p 22 --script=ssh2-enum-algos target | python3 cipheraudit.py -

# Pipe directly from nmap (TLS/SSL)
nmap -p 443 --script=ssl-enum-ciphers target | python3 cipheraudit.py -

# From stdin
cat nmap_output.txt | python3 cipheraudit.py -
```

### Command Line Options

```
usage: cipheraudit.py [-h] [-x] [-c CIPHERS] [--no-color] [input]

positional arguments:
  input                 Nmap output file (text or XML), or "-" for stdin (default: stdin)

options:
  -h, --help           Show help message and exit
  -x, --xml            Input is XML format (default: auto-detect)
  -c, --ciphers PATH   Path to ciphers.json file (default: auto-detect)
  --no-color           Disable colored output
```

## ciphers.json Format

The `ciphers.json` file defines your allowed algorithms. Any algorithm found in the nmap scan that is NOT in this list will be flagged as a violation.

Example structure:

```json
{
  "ssh": {
    "ciphers": [
      "aes256-gcm",
      "aes256-cbc"
    ],
    "kex": [
      "curve25519-sha256"
    ],
    "macs": [
      "hmac-sha2-256"
    ]
  },
  "ssl": {
    "tls1_3": [
      "TLS_AES_256_GCM_SHA384"
    ],
    "tls1_2": [
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    ]
  }
}
```

**Important**: The `ciphers.json` file contains the **ALLOWED** algorithms. Anything NOT in this list is considered a violation.

## Output Format

The tool provides a color-coded report grouped by host:port, showing:

1. **Per-host:port sections**: Each host:port combination is displayed separately
2. **Violations** (in red): Algorithms found that are NOT in the allowed list
3. **Allowed algorithms** (in green): Algorithms found that ARE in the allowed list
4. **Per-host summary**: Violation count for each host:port
5. **Overall summary**: Total violations across all hosts

Example output:

```
Algorithm Validation (ciphers.json = allowed list):
Using ciphers.json: /path/to/ciphers.json

======================================================================
Host:Port: 192.168.1.100:22
======================================================================

SSH Algorithms:

⚠ VIOLATIONS - KEX (NOT in allowed list):
    ✗ diffie-hellman-group14-sha1 (VIOLATION - not in allowed list)
    ✗ ecdh-sha2-nistp256 (VIOLATION - not in allowed list)

Allowed KEX:
    ✓ curve25519-sha256 (allowed)
    ✓ ecdh-sha2-nistp384 (allowed)

⚠ 192.168.1.100:22: 2 violation(s) found

======================================================================
Host:Port: 192.168.1.100:443
======================================================================

TLS/SSL Ciphers:

⚠ VIOLATIONS - TLS 1.2 Ciphers (NOT in allowed list):
    ✗ TLS_RSA_WITH_AES_256_CBC_SHA (VIOLATION - not in allowed list)

Allowed TLS 1.2 Ciphers:
    ✓ TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (allowed)

⚠ 192.168.1.100:443: 1 violation(s) found

======================================================================
⚠ Overall Summary: 3 violation(s) across 2 host(s)
```

**Note**: When processing multiple hosts and ports, each host:port combination is analyzed separately, making it easy to identify which specific servers need attention.

## Nmap Scan Requirements

### SSH Analysis

The nmap scan must include the `ssh2-enum-algos` script to extract SSH algorithm information:

```bash
nmap -p 22 --script=ssh2-enum-algos target
```

For comprehensive SSH analysis, you can also include other scripts:

```bash
nmap -p 22 --script=ssh-hostkey,ssh-auth-methods,ssh2-enum-algos target
```

### TLS/SSL Analysis

For TLS/SSL cipher analysis, use the `ssl-enum-ciphers` script:

```bash
nmap -p 443 --script=ssl-enum-ciphers target
```

### Combined Analysis

You can analyze both SSH and TLS in a single scan by combining the scripts:

```bash
nmap -p 22,443 --script=ssh2-enum-algos,ssl-enum-ciphers target
```

### Multiple Hosts Analysis

The tool automatically processes multiple hosts and ports from a single nmap scan file. Each host:port combination is analyzed and reported separately:

```bash
# Scan multiple hosts
nmap -p 22,443 --script=ssh2-enum-algos,ssl-enum-ciphers 192.168.1.100 192.168.1.101 192.168.1.102 -oN scan.txt

# Analyze all results
python3 cipheraudit.py scan.txt
```

The output will show results grouped by each `host:port` combination, making it easy to identify which specific servers have violations.

## Exit Codes

- `0`: No violations found (all algorithms are in allowed list)
- `1`: Violations found (one or more algorithms not in allowed list)

This makes it suitable for use in automated scripts and CI/CD pipelines.

## Examples

### Example 1: Analyze SSH on a single host

```bash
nmap -p 22 --script=ssh2-enum-algos 192.168.1.100 -oN scan.txt
python3 cipheraudit.py scan.txt
```

### Example 2: Analyze TLS/SSL on a single host

```bash
nmap -p 443 --script=ssl-enum-ciphers 192.168.1.100 -oN scan.txt
python3 cipheraudit.py scan.txt
```

### Example 3: Analyze both SSH and TLS in one scan

```bash
nmap -p 22,443 --script=ssh2-enum-algos,ssl-enum-ciphers 192.168.1.100 -oN scan.txt
python3 cipheraudit.py scan.txt
```

### Example 4: Analyze multiple hosts in a single scan

```bash
# Scan multiple hosts at once
nmap -p 22,443 --script=ssh2-enum-algos,ssl-enum-ciphers 192.168.1.100 192.168.1.101 192.168.1.102 -oN multi-host-scan.txt

# Analyze all results - each host:port will be shown separately
python3 cipheraudit.py multi-host-scan.txt
```

This will show results for each host:port combination:
- `192.168.1.100:22` (SSH)
- `192.168.1.100:443` (TLS/SSL)
- `192.168.1.101:22` (SSH)
- `192.168.1.101:443` (TLS/SSL)
- etc.

### Example 5: Analyze multiple hosts from a file (individual scans)

```bash
for host in $(cat hosts.txt); do
  echo "=== Scanning $host ==="
  nmap -p 22,443 --script=ssh2-enum-algos,ssl-enum-ciphers $host -oN ${host}.txt
  python3 cipheraudit.py ${host}.txt
done
```

### Example 6: Use in a script with exit code checking

```bash
#!/bin/bash
nmap -p 22,443 --script=ssh2-enum-algos,ssl-enum-ciphers target -oN scan.txt
if python3 cipheraudit.py scan.txt; then
  echo "All algorithms are compliant"
else
  echo "Violations detected!"
  exit 1
fi
```

### Example 7: Batch scan with per-host reporting

```bash
#!/bin/bash
# Scan multiple hosts
hosts="192.168.1.100 192.168.1.101 192.168.1.102"
nmap -p 22,443 --script=ssh2-enum-algos,ssl-enum-ciphers $hosts -oN batch-scan.txt

# Analyze - results will show per host:port
python3 cipheraudit.py batch-scan.txt

# Exit code reflects overall violations across all hosts
if [ $? -eq 0 ]; then
  echo "All hosts are compliant"
else
  echo "Some hosts have violations - check output above"
fi
```

## Per-Host:Port Reporting

CipherAudit automatically groups results by `host:port` combination, making it easy to identify which specific servers have violations. When processing multiple hosts or ports:

- Each `host:port` is analyzed separately
- Violations are clearly attributed to specific servers
- Per-host summaries show violation counts for each server
- Overall summary provides total violations across all hosts

This is especially useful when:
- Scanning multiple servers in a network
- Analyzing different ports on the same host
- Identifying which specific servers need remediation

## Troubleshooting

### "No SSH or TLS algorithms found in nmap output"

- For SSH: Ensure the nmap scan included `--script=ssh2-enum-algos`
- For TLS: Ensure the nmap scan included `--script=ssl-enum-ciphers`
- Check that the target is actually running SSH or TLS services
- Verify the nmap output file contains the appropriate script results

### "ciphers.json not found"

- Place `ciphers.json` in the same directory as the script
- Or use the `-c` flag to specify the path: `python3 cipheraudit.py -c /path/to/ciphers.json input.txt`

### Color codes showing as literal text

- Use `--no-color` flag if your terminal doesn't support colors
- Colors are automatically disabled when output is piped to a file

## License

This tool is part of the Pentest-visualizer project.

## Contributing

Feel free to submit issues or pull requests for improvements.

