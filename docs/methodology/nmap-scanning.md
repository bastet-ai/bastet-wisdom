# Nmap Scanning Methodologies

Nmap is the gold standard for network discovery and port scanning in security testing. This guide covers systematic approaches to using Nmap for bug bounty hunting and penetration testing.

## 🎯 Scanning Objectives

- **Host Discovery**: Identify live hosts in target networks
- **Port Enumeration**: Find open ports and running services
- **Service Detection**: Identify service versions and technologies
- **OS Fingerprinting**: Determine operating systems
- **Vulnerability Detection**: Discover known vulnerabilities
- **Network Topology**: Map network infrastructure

## 🔍 Host Discovery

### Basic Host Discovery

```bash
# Ping sweep (ICMP)
nmap -sn 192.168.1.0/24

# TCP SYN ping
nmap -PS21,22,23,25,53,80,110,111,135,139,143,443,993,995 -sn 192.168.1.0/24

# UDP ping
nmap -PU53,67,68,69,123,135,137,138,161,631,1434 -sn 192.168.1.0/24

# ARP ping (local network)
nmap -PR 192.168.1.0/24

# Disable ping (useful when ICMP is blocked)
nmap -Pn 192.168.1.1-100
```

### Advanced Host Discovery

```bash
# Multiple ping types
nmap -PE -PP -PM -PS21,22,23,25,53,80,110,111,135,139,143,443,993,995 \
     -PA80,113,443,10042 -PU53,135,137,161 -sn 192.168.1.0/24

# Comprehensive discovery with timing
nmap -sn -T4 --min-parallelism 100 --max-parallelism 256 192.168.1.0/24

# Discovery with custom ports
nmap -PS1-1000 -sn 192.168.1.0/24
```

## 🚪 Port Scanning Techniques

### Basic Port Scans

```bash
# TCP SYN scan (default, stealthy)
nmap -sS target.com

# TCP Connect scan (when SYN scan not possible)
nmap -sT target.com

# UDP scan (slower but important)
nmap -sU target.com

# Top ports scan
nmap --top-ports 1000 target.com

# All ports
nmap -p- target.com
```

### Advanced Port Scanning

```bash
# Comprehensive TCP scan
nmap -sS -sV -O -A -p- target.com

# Fast scan with version detection
nmap -sV -T4 --version-light target.com

# Aggressive scan with scripts
nmap -A -T4 target.com

# Stealth scan with fragmentation
nmap -sS -f -T1 -D RND:10 target.com
```

### Port Range Specifications

```bash
# Specific ports
nmap -p 22,80,443,8080,8443 target.com

# Port ranges
nmap -p 1-1000 target.com

# Mixed specification
nmap -p 22,80,443,1000-2000,8080,8443 target.com

# All TCP and specific UDP
nmap -p- -sS target.com && nmap -sU -p 53,67,68,69,123,135,137,161 target.com

# Common web ports
nmap -p 80,443,8000,8080,8443,8888,9000,9090 target.com
```

## 🔬 Service and Version Detection

### Service Enumeration

```bash
# Basic service detection
nmap -sV target.com

# Aggressive version detection
nmap -sV --version-intensity 9 target.com

# Light version detection (faster)
nmap -sV --version-intensity 0 target.com

# Service detection with OS detection
nmap -sV -O target.com
```

### Banner Grabbing

```bash
# Custom banner grabbing script
nmap --script banner target.com

# HTTP title and methods
nmap --script http-title,http-methods target.com

# SSH version and algorithms
nmap --script ssh-hostkey,ssh2-enum-algos target.com

# SSL/TLS information
nmap --script ssl-cert,ssl-enum-ciphers target.com
```

## 🖥️ Operating System Detection

```bash
# Basic OS detection
nmap -O target.com

# Aggressive OS detection
nmap -O --osscan-guess target.com

# OS detection with version scanning
nmap -sV -O target.com

# Detailed OS fingerprinting
nmap -O --osscan-limit --max-os-tries 3 target.com
```

## 📜 NSE Scripts Usage

### Script Categories

```bash
# Run all default scripts
nmap -sC target.com

# Specific script categories
nmap --script vuln target.com
nmap --script discovery target.com
nmap --script auth target.com
nmap --script brute target.com

# Multiple categories
nmap --script "vuln,discovery,auth" target.com
```

### Popular Security Scripts

**Vulnerability Detection**
```bash
# Common vulnerabilities
nmap --script vuln target.com

# Specific CVEs
nmap --script ms17-010 target.com
nmap --script smb-vuln-* target.com

# Web vulnerabilities
nmap --script http-vuln-* target.com

# Database vulnerabilities
nmap --script mysql-vuln-* target.com
```

**Authentication Testing**
```bash
# Default credentials
nmap --script auth target.com

# Brute force attacks
nmap --script brute target.com
nmap --script ssh-brute target.com
nmap --script ftp-brute target.com
nmap --script mysql-brute target.com
```

**Service Enumeration**
```bash
# SMB enumeration
nmap --script smb-enum-* target.com

# Web enumeration
nmap --script http-enum target.com

# DNS enumeration
nmap --script dns-brute target.com

# SNMP enumeration
nmap --script snmp-* target.com
```

### Custom Script Arguments

```bash
# HTTP enumeration with custom wordlist
nmap --script http-enum --script-args http-enum.basepath='/admin/',http-enum.fingerprintfile='/path/to/wordlist.txt' target.com

# Brute force with custom wordlists
nmap --script ssh-brute --script-args userdb=/path/to/users.txt,passdb=/path/to/passwords.txt target.com

# SSL cipher enumeration
nmap --script ssl-enum-ciphers --script-args vulns.showall target.com
```

## ⚡ Performance Optimization

### Timing Templates

```bash
# Paranoid (very slow, IDS evasion)
nmap -T0 target.com

# Sneaky (slow, some IDS evasion)
nmap -T1 target.com

# Polite (slower, less bandwidth)
nmap -T2 target.com

# Normal (default)
nmap -T3 target.com

# Aggressive (fast, more detectable)
nmap -T4 target.com

# Insane (very fast, very detectable)
nmap -T5 target.com
```

### Custom Timing

```bash
# Fine-tuned timing
nmap --min-parallelism 100 --max-parallelism 300 \
     --min-rate 50 --max-rate 300 \
     --max-retries 2 --host-timeout 5m target.com

# Fast scan with reasonable accuracy
nmap -T4 --min-rate 1000 --max-retries 1 target.com

# Slow and stealthy
nmap -T1 --scan-delay 1s --max-scan-delay 10s target.com
```

## 🕵️ Stealth and Evasion

### Decoy Scanning

```bash
# Random decoys
nmap -D RND:10 target.com

# Specific decoys
nmap -D 192.168.1.5,192.168.1.10,ME,192.168.1.15 target.com

# Idle zombie scan
nmap -sI zombie-host:113 target.com
```

### Fragmentation and Source Manipulation

```bash
# IP fragmentation
nmap -f target.com

# Maximum fragmentation
nmap -ff target.com

# Custom MTU
nmap --mtu 16 target.com

# Source port spoofing
nmap --source-port 53 target.com

# Custom source IP
nmap -S spoofed-ip target.com
```

### Firewall Evasion

```bash
# FIN scan (bypasses some firewalls)
nmap -sF target.com

# Xmas scan
nmap -sX target.com

# Null scan
nmap -sN target.com

# ACK scan (firewall rule testing)
nmap -sA target.com

# Window scan
nmap -sW target.com
```

## 🌐 Scanning Different Services

### Web Services

```bash
# HTTP/HTTPS discovery
nmap -p 80,443,8000-8999 --script http-title,http-server-header target.com

# Web application fingerprinting
nmap --script http-waf-detect,http-waf-fingerprint target.com

# Web vulnerabilities
nmap --script http-vuln-cve2017-5638,http-vuln-cve2014-6271 target.com

# Directory enumeration
nmap --script http-enum --script-args http-enum.basepath='/admin/' target.com
```

### Database Services

```bash
# MySQL enumeration
nmap -p 3306 --script mysql-info,mysql-enum target.com

# PostgreSQL enumeration
nmap -p 5432 --script pgsql-brute target.com

# MSSQL enumeration
nmap -p 1433 --script ms-sql-info,ms-sql-empty-password target.com

# Oracle enumeration
nmap -p 1521 --script oracle-sid-brute target.com
```

### File Sharing Services

```bash
# SMB enumeration
nmap -p 445 --script smb-os-discovery,smb-enum-shares target.com

# FTP enumeration
nmap -p 21 --script ftp-anon,ftp-bounce target.com

# NFS enumeration
nmap -p 2049 --script nfs-ls,nfs-showmount target.com
```

### Remote Access Services

```bash
# SSH enumeration
nmap -p 22 --script ssh-hostkey,ssh2-enum-algos target.com

# RDP enumeration
nmap -p 3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 target.com

# VNC enumeration
nmap -p 5900-5999 --script vnc-info target.com
```

## 📊 Output and Reporting

### Output Formats

```bash
# All output formats
nmap -oA scan_results target.com

# XML output
nmap -oX scan.xml target.com

# Grepable output
nmap -oG scan.grep target.com

# Normal output
nmap -oN scan.txt target.com

# Script kiddie output (just for fun)
nmap -oS scan.skiddie target.com
```

### Advanced Output Options

```bash
# Verbose output
nmap -v target.com

# Very verbose
nmap -vv target.com

# Debug output
nmap -d target.com

# Append to file
nmap --append-output -oN scan.txt target.com

# Resume scan
nmap --resume scan.xml
```

## 🔧 Practical Scanning Strategies

### Network Discovery Workflow

```bash
#!/bin/bash
# Complete network discovery script

TARGET=$1
OUTPUT_DIR="nmap_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR

echo "[+] Starting network discovery for $TARGET"

# 1. Host discovery
echo "[+] Phase 1: Host discovery"
nmap -sn $TARGET > $OUTPUT_DIR/01_host_discovery.txt

# Extract live hosts
LIVE_HOSTS=$(grep "Nmap scan report" $OUTPUT_DIR/01_host_discovery.txt | awk '{print $5}')

# 2. Port discovery
echo "[+] Phase 2: Port discovery"
nmap -sS --top-ports 1000 $LIVE_HOSTS > $OUTPUT_DIR/02_port_discovery.txt

# 3. Service detection
echo "[+] Phase 3: Service detection"
nmap -sV -A $LIVE_HOSTS > $OUTPUT_DIR/03_service_detection.txt

# 4. Vulnerability scanning
echo "[+] Phase 4: Vulnerability scanning"
nmap --script vuln $LIVE_HOSTS > $OUTPUT_DIR/04_vulnerability_scan.txt

echo "[+] Network discovery complete. Results in $OUTPUT_DIR/"
```

### Web Application Discovery

```bash
#!/bin/bash
# Web application focused scanning

TARGET=$1

echo "[+] Web application discovery for $TARGET"

# Discover web services
nmap -p 80,443,8000-8999 --open $TARGET

# HTTP service enumeration
nmap -p 80,443,8000-8999 --script http-title,http-server-header,http-methods $TARGET

# Web application technologies
nmap --script http-waf-detect,http-generator,http-favicon $TARGET

# Common vulnerabilities
nmap --script http-vuln-* $TARGET
```

### Internal Network Scanning

```bash
#!/bin/bash
# Internal network reconnaissance

NETWORK=$1

echo "[+] Internal network scanning for $NETWORK"

# Fast host discovery
nmap -sn -T4 $NETWORK

# Port sweep on live hosts
nmap -sS --top-ports 100 -T4 $NETWORK

# Service detection on open ports
nmap -sV -O -A -T4 $NETWORK

# Internal service enumeration
nmap --script smb-enum-*,ldap-rootdse,dns-brute $NETWORK
```

## ⚠️ Best Practices and Considerations

### Legal and Ethical Guidelines

- **Always get proper authorization** before scanning any network
- **Respect rate limits** and system resources
- **Document everything** for reporting and compliance
- **Follow responsible disclosure** for any findings

### Performance Considerations

```bash
# For large networks, use:
nmap -sS -T4 --min-rate 1000 --max-retries 1 large-network.com

# For stealth requirements:
nmap -sS -T1 --scan-delay 1s sensitive-target.com

# For CI/CD integration:
nmap -sS -T4 --max-retries 1 --host-timeout 5m target.com
```

### Common Pitfalls

- **Port 80/443 tunnel scanning**: Many services run on non-standard ports
- **UDP scanning neglect**: Important services run on UDP
- **Script selection**: Choose appropriate scripts for the environment
- **False positives**: Verify findings manually

## 🔗 Integration with Other Tools

### Feeding Results to Other Scanners

```bash
# Extract open ports for further testing
nmap -oG - target.com | grep "/open" | awk '{print $2}' > live_hosts.txt

# Convert to Burp Suite format
nmap -oX scan.xml target.com
# Use xml2dict or custom parser

# Feed to Nuclei
nmap -p 80,443,8000-8999 --open target.com | grep -oP '\d+\.\d+\.\d+\.\d+' | \
    sed 's/^/http:\/\//' > urls.txt
nuclei -l urls.txt
```

### Database Integration

```bash
# Import XML to database
import xml.etree.ElementTree as ET
# Parse nmap XML and insert into database
```

---

*Remember: Nmap is a powerful tool that can be detected by security systems. Always use it responsibly and within the scope of your authorization. Consider the impact on target systems and networks.*
