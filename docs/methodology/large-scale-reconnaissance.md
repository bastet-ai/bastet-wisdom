# Large-Scale Reconnaissance Methodology

## Overview

Large-scale reconnaissance is essential for analyzing enterprise targets with extensive digital infrastructure. This methodology covers systematic approaches to discovering and analyzing attack surfaces spanning hundreds or thousands of assets.

## Pre-Reconnaissance Planning

### 1. Scope Definition
```bash
# Define primary targets and scope boundaries
echo "Primary Target: nba.com" > scope.txt
echo "Include: *.nba.com, *.wnba.com, *.gleague.nba.com" >> scope.txt
echo "Exclude: Social media accounts, third-party CDNs" >> scope.txt
```

### 2. Resource Planning
- **Time Allocation**: 2-4 hours for initial enumeration
- **Storage Requirements**: 50-100MB for output files per 1000 subdomains
- **Compute Resources**: Parallel processing capabilities
- **Rate Limiting**: Respect target infrastructure limits

### 3. Tool Preparation
```bash
# Ensure all reconnaissance tools are available and updated
export PATH=$PATH:/home/pierce/go/bin
subfinder -version
assetfinder --help
httpx -version
nuclei -version
```

## Phase 1: Subdomain Discovery

### 1. Multi-Source Enumeration
```bash
# Primary subdomain discovery with subfinder
subfinder -d nba.com -all -recursive -o nba_subdomains_subfinder.txt

# Supplementary discovery with assetfinder
assetfinder --subs-only nba.com > nba_subdomains_assetfinder.txt

# Combine and deduplicate results
cat nba_subdomains_*.txt | sort -u > nba_all_subdomains.txt
```

### 2. Advanced Discovery Techniques
```bash
# Certificate transparency logs
curl -s "https://crt.sh/?q=%.nba.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > nba_crt_subdomains.txt

# DNS bruteforcing for additional discovery
amass enum -passive -d nba.com -o nba_amass_subdomains.txt

# Merge all sources
cat nba_*_subdomains.txt | sort -u > nba_final_subdomains.txt
```

### 3. Statistics and Analysis
```bash
# Generate discovery statistics
echo "Total subdomains discovered: $(wc -l < nba_final_subdomains.txt)"
echo "Subfinder results: $(wc -l < nba_subdomains_subfinder.txt)"
echo "Assetfinder results: $(wc -l < nba_subdomains_assetfinder.txt)"
echo "Certificate transparency: $(wc -l < nba_crt_subdomains.txt)"
```

## Phase 2: Service Discovery and Fingerprinting

### 1. HTTP Service Discovery
```bash
# Discover live web services
httpx -l nba_final_subdomains.txt -o nba_live_services.txt

# Enhanced fingerprinting with additional data
httpx -l nba_final_subdomains.txt \
    -title -tech-detect -status-code -content-length \
    -o nba_web_services.json -json
```

### 2. Service Categorization
```bash
# Extract different service types from httpx output
jq -r 'select(.tech != null) | "\(.url) - \(.tech[])"' nba_web_services.json > nba_technology_stack.txt

# Categorize by response codes
jq -r 'select(.status_code == 200) | .url' nba_web_services.json > nba_200_services.txt
jq -r 'select(.status_code == 403) | .url' nba_web_services.json > nba_403_services.txt
jq -r 'select(.status_code == 404) | .url' nba_web_services.json > nba_404_services.txt
```

### 3. Pattern Analysis
```bash
# Identify service patterns
grep -E "(api|dev|staging|test|admin)" nba_live_services.txt > nba_interesting_services.txt
grep -E "(cms|portal|dashboard|admin)" nba_live_services.txt > nba_admin_services.txt
grep -E "(cdn|static|assets|media)" nba_live_services.txt > nba_cdn_services.txt
```

## Phase 3: Detailed Analysis

### 1. Infrastructure Mapping
```bash
# Network analysis
nmap -sn --top-ports 1000 -iL nba_ip_addresses.txt > nba_network_scan.txt

# Service port scanning for critical assets
nmap -sV -sC --top-ports 1000 $(head -20 nba_critical_ips.txt) > nba_detailed_scan.txt
```

### 2. Technology Stack Analysis
```bash
# Extract and analyze technology patterns
grep -i "nginx\|apache\|cloudflare\|akamai" nba_technology_stack.txt | sort | uniq -c
grep -i "react\|angular\|vue\|wordpress\|drupal" nba_technology_stack.txt | sort | uniq -c
```

### 3. Geographic Distribution
```bash
# Analyze IP geolocation (if needed)
while read ip; do
    curl -s "http://ip-api.com/json/$ip" | jq -r '"\(.query) - \(.country) - \(.org)"'
done < nba_unique_ips.txt > nba_geolocation.txt
```

## Phase 4: Vulnerability Discovery

### 1. Automated Vulnerability Scanning
```bash
# Comprehensive nuclei scan
nuclei -l nba_live_services.txt \
    -tags exposure,config,debug,files,logs \
    -severity medium,high,critical \
    -o nba_vulnerabilities.txt

# Specific scans for high-value targets
nuclei -l nba_admin_services.txt \
    -tags auth-bypass,sqli,xss,ssrf \
    -severity low,medium,high,critical \
    -o nba_admin_vulnerabilities.txt
```

### 2. Manual Investigation Priorities
```bash
# Create prioritized target lists
echo "=== HIGH PRIORITY TARGETS ===" > nba_investigation_priorities.txt
grep -E "(admin|api|dev|staging)" nba_live_services.txt >> nba_investigation_priorities.txt

echo -e "\n=== TECHNOLOGY-SPECIFIC TARGETS ===" >> nba_investigation_priorities.txt
grep -E "(graphql|api|cms)" nba_technology_stack.txt >> nba_investigation_priorities.txt

echo -e "\n=== ERROR RESPONSES ===" >> nba_investigation_priorities.txt
head -10 nba_403_services.txt >> nba_investigation_priorities.txt
```

### 3. Client-Side Analysis
```bash
# Extract JavaScript files from live services
while read url; do
    curl -s "$url" | grep -oE "https?://[^\"']*\.js" >> nba_js_files.txt
done < nba_200_services.txt

# Analyze JavaScript files for sensitive information
sort -u nba_js_files.txt | while read js_url; do
    echo "Analyzing: $js_url"
    curl -s "$js_url" | grep -iE "(api|key|secret|token|project.*id)" && echo "FOUND: $js_url"
done > nba_js_analysis.txt
```

## NBA Case Study Results

### Discovery Statistics
- **Total Subdomains**: 1,132 domains discovered
- **Live Services**: 779 active HTTP/HTTPS services
- **Technology Diversity**: 15+ different technology stacks identified
- **Geographic Distribution**: Primary US hosting with global CDN presence

### Critical Findings Distribution
```
Service Category          | Count | High-Value Targets
======================== | ===== | ==================
API Endpoints            |    47 | 12 critical
Admin/CMS Interfaces     |    23 | 8 restricted access
Development Environments |    15 | 7 potentially exposed
Static/CDN Services      |   234 | 3 misconfigurations
Team-Specific Domains    |    78 | 15 worthy investigation
```

### Technology Stack Analysis
```
Technology     | Prevalence | Security Implications
============== | ========== | ====================
Akamai CDN     |      45%   | Bot protection, caching
CloudFront     |      23%   | AWS integration
React.js       |      18%   | Client-side vulnerabilities
WordPress      |       8%   | Plugin vulnerabilities
Custom APIs    |      12%   | Business logic flaws
```

## Automation and Scaling

### 1. Automated Pipeline
```bash
#!/bin/bash
# Large-scale reconnaissance automation script

TARGET_DOMAIN=$1
OUTPUT_DIR="recon_${TARGET_DOMAIN}_$(date +%Y%m%d)"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

# Phase 1: Subdomain Discovery
echo "[+] Starting subdomain discovery..."
subfinder -d "$TARGET_DOMAIN" -all -o subdomains_subfinder.txt
assetfinder --subs-only "$TARGET_DOMAIN" > subdomains_assetfinder.txt
cat subdomains_*.txt | sort -u > all_subdomains.txt

# Phase 2: Service Discovery
echo "[+] Discovering live services..."
httpx -l all_subdomains.txt -o live_services.txt
httpx -l all_subdomains.txt -json -o web_services.json

# Phase 3: Vulnerability Scanning
echo "[+] Running vulnerability scans..."
nuclei -l live_services.txt -tags exposure,config -o vulnerabilities.txt

# Phase 4: Reporting
echo "[+] Generating summary report..."
echo "Reconnaissance Summary for $TARGET_DOMAIN" > summary.txt
echo "=======================================" >> summary.txt
echo "Total subdomains: $(wc -l < all_subdomains.txt)" >> summary.txt
echo "Live services: $(wc -l < live_services.txt)" >> summary.txt
echo "Vulnerabilities found: $(wc -l < vulnerabilities.txt)" >> summary.txt

echo "[+] Reconnaissance complete. Results in $OUTPUT_DIR"
```

### 2. Parallel Processing
```bash
# Split large subdomain lists for parallel processing
split -l 100 all_subdomains.txt subdomain_chunk_

# Process chunks in parallel
for chunk in subdomain_chunk_*; do
    httpx -l "$chunk" -o "results_$(basename $chunk).txt" &
done
wait

# Combine results
cat results_subdomain_chunk_*.txt > all_results.txt
```

### 3. Resource Management
```bash
# Monitor resource usage during large scans
#!/bin/bash
while true; do
    echo "$(date): CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}') Memory: $(free -h | grep Mem | awk '{print $3}')"
    sleep 60
done > resource_usage.log &

# Rate limiting for respectful scanning
export HTTPX_RATE_LIMIT=50  # requests per second
export NUCLEI_RATE_LIMIT=30
```

## Analysis and Reporting

### 1. Statistical Analysis
```bash
# Generate comprehensive statistics
python3 << EOF
import json

# Load httpx results
with open('web_services.json') as f:
    services = [json.loads(line) for line in f]

# Analyze status codes
status_codes = {}
for service in services:
    code = service.get('status_code', 'unknown')
    status_codes[code] = status_codes.get(code, 0) + 1

print("Status Code Distribution:")
for code, count in sorted(status_codes.items()):
    print(f"  {code}: {count}")

# Analyze technologies
technologies = {}
for service in services:
    tech_list = service.get('tech', [])
    for tech in tech_list:
        technologies[tech] = technologies.get(tech, 0) + 1

print("\nTop Technologies:")
for tech, count in sorted(technologies.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f"  {tech}: {count}")
EOF
```

### 2. Visualization
```bash
# Create visual representations of findings
python3 << EOF
import matplotlib.pyplot as plt
import json

# Load data and create charts
# (Implementation depends on specific visualization needs)
EOF
```

### 3. Report Generation
```bash
# Generate markdown report
cat << EOF > reconnaissance_report.md
# Large-Scale Reconnaissance Report
**Target**: $TARGET_DOMAIN
**Date**: $(date)

## Executive Summary
- **Total Subdomains**: $(wc -l < all_subdomains.txt)
- **Live Services**: $(wc -l < live_services.txt)
- **Vulnerabilities**: $(wc -l < vulnerabilities.txt)

## Key Findings
$(head -10 vulnerabilities.txt)

## Technology Stack
$(grep -i "nginx\|apache\|cloudflare" web_services.json | head -5)

## Recommendations
1. Address identified vulnerabilities
2. Review exposed development environments
3. Implement consistent security controls
EOF
```

## Lessons Learned from NBA Analysis

### 1. Scale Considerations
- **Large Attack Surface**: 1,000+ subdomains require systematic approach
- **Resource Management**: Parallel processing essential for efficiency
- **Rate Limiting**: Respectful scanning prevents blocking
- **Storage Planning**: Significant disk space needed for comprehensive logs

### 2. Discovery Effectiveness
- **Multi-Source Enumeration**: Different tools find different assets
- **Certificate Transparency**: Valuable for historical subdomain discovery
- **Technology Fingerprinting**: Essential for prioritizing targets
- **Pattern Recognition**: Automated categorization saves time

### 3. Analysis Priorities
- **Development Environments**: Often have weaker security controls
- **API Endpoints**: High-value targets for business logic flaws
- **Admin Interfaces**: Critical for privilege escalation
- **Third-Party Integrations**: Expanded attack surface

### 4. Automation Benefits
- **Consistency**: Systematic approach prevents missed assets
- **Scalability**: Handles enterprise-level infrastructure
- **Reproducibility**: Can be repeated for monitoring changes
- **Documentation**: Automatic generation of comprehensive reports

## Best Practices

### 1. Ethical Considerations
- Always respect target infrastructure limits
- Use appropriate rate limiting
- Focus on discovery, not exploitation
- Follow responsible disclosure practices

### 2. Technical Excellence
- Validate tool configurations before large scans
- Implement proper error handling
- Monitor resource usage during execution
- Maintain detailed logs for analysis

### 3. Continuous Improvement
- Regular tool updates and capability expansion
- Documentation of lessons learned
- Methodology refinement based on results
- Integration of new discovery techniques

---

**Classification**: Internal Methodology  
**Last Updated**: September 2025  
**Validated Against**: NBA enterprise infrastructure (1,132 subdomains)
