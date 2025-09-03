# Client-Side Security Analysis Methodology

## Overview

Client-side analysis focuses on vulnerabilities and information disclosure in frontend applications, particularly JavaScript files, configuration data, and browser-accessible resources. This methodology proved highly effective during NBA target analysis.

## Discovery Techniques

### 1. JavaScript Bundle Analysis

#### Target Identification
```bash
# Discover main application bundles
curl -s https://target.com | grep -E "\.js[\"']" | grep -oE "https?://[^\"']*\.js"

# Focus on main/chunk bundles (most likely to contain sensitive data)
curl -s https://target.com | grep -E "main\.|chunk\.|bundle\." | grep -oE "https?://[^\"']*\.js"
```

#### Content Extraction
```bash
# Download and analyze JavaScript bundles
curl -s "https://picks.nba.com/nba-bracket/24.39.1-nba-bracket-64/main.1664b9378e032a102d59.js" > analysis.js

# Search for common sensitive patterns
grep -i -E "(api|key|secret|token|password|project.*id|endpoint)" analysis.js
grep -i -E "(mutation|query|graphql)" analysis.js
grep -o -E "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}" analysis.js  # UUIDs
```

#### High-Value Patterns
- **Project IDs**: UUIDs or alphanumeric identifiers for third-party services
- **API Endpoints**: GraphQL schemas, REST endpoints, WebSocket URLs
- **Authentication Tokens**: JWT tokens, API keys, session identifiers
- **Configuration Data**: Environment variables, feature flags, debug settings

### 2. Configuration File Discovery

#### Common Configuration Endpoints
```bash
# Test common configuration patterns
curl -s https://cdn-us.monterosa.cloud/config/enmasse.json
curl -s https://target.com/.env
curl -s https://target.com/config.json
curl -s https://target.com/manifest.json
```

#### Dynamic Configuration Loading
```bash
# Monitor network requests during application load
# Look for config files loaded after initial page load
# Check for environment-specific configurations
```

### 3. GraphQL Schema Discovery

#### Client-Side Schema Exposure
- Minified JavaScript often contains GraphQL queries and mutations
- Look for patterns like `query`, `mutation`, `subscription`
- Extract parameter names and types from client-side code

```javascript
// Common patterns found in NBA analysis:
query getElement($eventId: ID!, $projectId: ID!, $elementId: String!)
mutation addLastReaction($reactionKey: String!, $elementId: String!)
```

#### Schema Reconstruction
1. Extract all GraphQL operations from client-side code
2. Identify parameter types and required fields
3. Reconstruct potential schema structure
4. Test operations against discovered endpoints

## Analysis Techniques

### 1. Source Map Analysis
```bash
# Check for source maps that might expose original code
curl -s https://target.com/main.js | grep "sourceMappingURL"
curl -s https://target.com/main.js.map
```

### 2. Version Control Information
```bash
# Look for build information and version details
grep -i -E "(version|build|commit|branch)" analysis.js
grep -o -E "v[0-9]+\.[0-9]+\.[0-9]+" analysis.js
```

### 3. Third-Party Integration Analysis
- Identify external service integrations
- Extract API endpoints and authentication methods
- Map data flow between services

## Common Vulnerabilities

### 1. Hardcoded Credentials
- **API Keys**: Direct embedding of secret keys
- **Project IDs**: Third-party service identifiers
- **Tokens**: Authentication or session tokens

**Example from NBA Analysis**:
```javascript
PROJECT_ID: "a2a51d7e-bc99-47fd-b720-5e8042c993c2"
```

### 2. GraphQL Schema Exposure
- Complete queries and mutations in client code
- Parameter types and validation rules
- Potential for unauthorized operations

### 3. Configuration Leakage
- Development environment settings in production
- Debug flags and feature toggles
- Internal API endpoints and service URLs

### 4. CORS Misconfigurations
- Development origins allowed in production
- Wildcard or localhost CORS policies
- Credential inclusion with permissive origins

## Exploitation Strategies

### 1. API Enumeration
```bash
# Use discovered PROJECT_IDs for API access
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"query getElement($projectId: ID!) { ... }","variables":{"projectId":"DISCOVERED_ID"}}' \
  https://api-endpoint.com/graphql
```

### 2. Schema Exploration
```bash
# GraphQL introspection with discovered endpoints
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"query IntrospectionQuery{__schema{queryType{name}}}"}' \
  https://graphql-endpoint.com
```

### 3. Configuration Abuse
- Access configuration endpoints with discovered parameters
- Exploit development settings in production
- Bypass authentication using debug flags

## Tools and Automation

### 1. Manual Analysis Tools
```bash
# JavaScript beautification
js-beautify analysis.js > readable.js

# Pattern searching
grep -r -E "(api|key|secret)" ./extracted_js/
```

### 2. Automated Scanning
```bash
# Nuclei templates for client-side issues
nuclei -t exposed-panels,files,config -u https://target.com

# Custom patterns for GraphQL
nuclei -t graphql/ -u https://target.com
```

### 3. Browser Developer Tools
- Network tab for configuration requests
- Sources tab for unminified code inspection
- Application tab for storage analysis

## Verification and Impact Assessment

### 1. Proof of Concept Development
- Test discovered credentials against their intended services
- Verify GraphQL operations work as expected
- Demonstrate unauthorized access or information disclosure

### 2. Impact Calculation
- **Low**: Information disclosure with no direct access
- **Medium**: Unauthorized API access or data enumeration
- **High**: Privilege escalation or sensitive data access
- **Critical**: Full application compromise or data breach

### 3. Remediation Verification
- Confirm fixes address root cause
- Test for similar issues in other parts of application
- Verify no regression in functionality

## Case Study: NBA Bracket Challenge

### Discovery Process
1. **Initial Reconnaissance**: Identified React application at `picks.nba.com`
2. **Bundle Analysis**: Found main JavaScript bundle with minified code
3. **Pattern Matching**: Discovered GraphQL operations and PROJECT_ID
4. **Configuration Discovery**: Found Monterosa Cloud configuration endpoint
5. **Verification**: Confirmed hardcoded values still accessible

### Key Findings
- **PROJECT_ID Exposure**: `a2a51d7e-bc99-47fd-b720-5e8042c993c2`
- **GraphQL Schema**: Complete operations for bracket interactions
- **Third-Party Integration**: Monterosa Cloud platform configuration
- **WebSocket Configuration**: Real-time communication setup exposed

### Lessons Learned
1. **Minified Code**: Still contains searchable patterns and identifiers
2. **Third-Party Services**: Often have weak authentication (PROJECT_ID only)
3. **Configuration Files**: Publicly accessible endpoints common
4. **Build Artifacts**: Production builds may include development artifacts

## Best Practices

### 1. Systematic Approach
- Always analyze main application bundles first
- Look for common configuration patterns
- Map all third-party integrations discovered

### 2. Documentation
- Record all discovered endpoints and identifiers
- Document relationship between services
- Maintain timeline of discovery process

### 3. Verification-First
- Always verify findings before reporting
- Test actual exploitation potential
- Confirm impact assessment accuracy

## Advanced Techniques

### 1. Webpack Bundle Analysis
```bash
# Extract webpack modules and analyze separately
node -e "
const fs = require('fs');
const content = fs.readFileSync('bundle.js', 'utf8');
const modules = content.match(/\/\*\*\*\/ \(function\([\s\S]*?\}\)/g);
modules.forEach((mod, i) => fs.writeFileSync(\`module_\${i}.js\`, mod));
"
```

### 2. AST-Based Analysis
- Use JavaScript parsers to extract meaningful structures
- Identify function calls to external APIs
- Map data flow through application

### 3. Dynamic Analysis
- Monitor runtime behavior for additional endpoints
- Use browser automation to trigger configuration loads
- Capture WebSocket messages and API calls

---

**Classification**: Internal Methodology  
**Last Updated**: September 2025  
**Effectiveness**: High (confirmed findings in NBA analysis)
