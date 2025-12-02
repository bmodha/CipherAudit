# CipherAudit

A Python tool for analyzing SSH and TLS/SSL algorithm configurations from nmap scan output and validating them against an allowed list of ciphers, key exchange algorithms, MAC algorithms, and host key algorithms.

## Overview

CipherAudit parses nmap SSH and TLS/SSL scan results and compares discovered algorithms against a `ciphers.json` file containing approved/allowed algorithms. It identifies violations (algorithms NOT in the allowed list) and provides a clear, table-based report with a summary overview.

## Features

- **Parses nmap output**: Supports both text and XML formats (auto-detected)
- **Multi-protocol support**: Validates SSH (KEX, encryption, MAC, host keys) and TLS/SSL ciphers
- **Table-based output**: Clean, formatted tables using tabulate
- **Summary table**: Quick overview of all targets with pass/fail status per category
- **Per-host:port breakdown**: Results grouped by host and port
- **Color-coded output**: Red (✗) for violations, green (✓) for allowed
- **Multiple input methods**: File input, stdin, or pipe from nmap
- **Exit codes**: Returns 0 for compliance, 1 for violations (CI/CD friendly)

## Requirements

- Python 3.6+
- `tabulate` library (install with: `pip install tabulate`)
- `ciphers.json` file (included, or provide your own)

## Installation

```bash
# Install tabulate
pip install tabulate

# Make script executable (optional)
chmod +x cipheraudit.py
```

## Usage

### Basic Usage

```bash
# Analyze nmap text output
python3 cipheraudit.py nmap_output.txt

# Analyze nmap XML output
python3 cipheraudit.py -x nmap_output.xml

# Pipe directly from nmap
nmap -p 22 --script=ssh2-enum-algos target | python3 cipheraudit.py -
nmap -p 443 --script=ssl-enum-ciphers target | python3 cipheraudit.py -

# From stdin
cat nmap_output.txt | python3 cipheraudit.py -
```

### Command Line Options

```
usage: cipheraudit.py [-h] [-x] [-c CIPHERS] [--no-color] [input]

positional arguments:
  input                 Nmap output file (text or XML), or "-" for stdin

options:
  -h, --help           Show help message
  -x, --xml            Input is XML format (default: auto-detect)
  -c, --ciphers PATH   Path to ciphers.json file (default: auto-detect)
  --no-color           Disable colored output
```

## ciphers.json Format

The `ciphers.json` file defines your **allowed** algorithms. Any algorithm found in the nmap scan that is NOT in this list will be flagged as a violation.

```json
{
  "ssh": {
    "ciphers": ["aes256-gcm", "aes256-ctr", "chacha20-poly1305@openssh.com"],
    "kex": ["curve25519-sha256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521"],
    "macs": ["hmac-sha2-256", "hmac-sha2-512", "hmac-sha2-512-etm@openssh.com"],
    "host_keys": ["ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256"]
  },
  "ssl": {
    "tls1_3": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
    "tls1_2": [
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    ]
  }
}
```

## Output Format

The tool provides:

1. **CIPHERAUDIT logo** at the top
2. **Per-host:port sections** with detailed algorithm tables:
   - SSH Encryption Ciphers
   - SSH KEX Algorithms
   - SSH MAC Algorithms
   - SSH Host Key Algorithms
   - TLS 1.2/1.3 Ciphers
3. **Summary table** at the end showing pass/fail status for all targets:
   ```
   IP               | Ciphers   | KEX Algos   | MAC Algos   | Host Key Algos
   -----------------+-----------+-------------+-------------+----------------
   192.168.1.100:22 | ✗         | ✗           | ✗           | ✓
   ```

Each table shows:
- **Algorithm** column: Algorithm/cipher name
- **Allowed** column: ✓ if in allowed list
- **Not Allowed** column: ✗ if violation

## Nmap Scan Requirements

### SSH Analysis
```bash
nmap -p 22 --script=ssh2-enum-algos target
# Or comprehensive:
nmap -p 22 --script=ssh-hostkey,ssh-auth-methods,ssh2-enum-algos target
```

### TLS/SSL Analysis
```bash
nmap -p 443 --script=ssl-enum-ciphers target
```

### Combined Analysis
```bash
nmap -p 22,443 --script=ssh2-enum-algos,ssl-enum-ciphers target -oN scan.txt
python3 cipheraudit.py scan.txt
```

### Multiple Hosts
```bash
# Scan multiple hosts
nmap -p 22,443 --script=ssh2-enum-algos,ssl-enum-ciphers 192.168.1.100 192.168.1.101 -oN scan.txt

# Analyze - each host:port shown separately with summary table
python3 cipheraudit.py scan.txt
```

## Exit Codes

- `0`: No violations found (all algorithms compliant)
- `1`: Violations found (one or more algorithms not in allowed list)

Suitable for use in automated scripts and CI/CD pipelines.

## Examples

### Example 1: Single host analysis
```bash
nmap -p 22,443 --script=ssh2-enum-algos,ssl-enum-ciphers 192.168.1.100 -oN scan.txt
python3 cipheraudit.py scan.txt
```

### Example 2: Batch scan with exit code checking
```bash
#!/bin/bash
nmap -p 22,443 --script=ssh2-enum-algos,ssl-enum-ciphers 192.168.1.100 192.168.1.101 -oN scan.txt
if python3 cipheraudit.py scan.txt; then
  echo "All hosts compliant"
else
  echo "Violations detected!"
  exit 1
fi
```

### Example 3: Loop through hosts file
```bash
for host in $(cat hosts.txt); do
  nmap -p 22,443 --script=ssh2-enum-algos,ssl-enum-ciphers $host -oN ${host}.txt
  python3 cipheraudit.py ${host}.txt
done
```

## Troubleshooting

**No SSH or TLS algorithms found**
- Ensure nmap scan includes `--script=ssh2-enum-algos` (SSH) or `--script=ssl-enum-ciphers` (TLS)
- Verify target is running SSH/TLS services
- Check nmap output file contains script results

**ciphers.json not found**
- Place `ciphers.json` in script directory, or
- Use `-c` flag: `python3 cipheraudit.py -c /path/to/ciphers.json input.txt`

**Color codes showing as literal text**
- Use `--no-color` flag
- Colors auto-disabled when piped to file

**tabulate not available**
- Install with: `pip install tabulate`
- Tool will fall back to simple format if not available

## License

Part of the Pentest-visualizer project.
