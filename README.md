# Spoofaloof

A Python tool that checks domains for email spoofing vulnerabilities by analyzing SPF, DKIM, and DMARC records.

## Installation

1. Clone or download this project
2. Create a virtual environment and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Basic usage (text report):
```bash
python3 spoofaloof.py example.com
```

### JSON output:
```bash
python3 spoofaloof.py example.com --json
```

### Include remediation instructions:
```bash
python3 spoofaloof.py example.com --remediate
```

### Disable colored output:
```bash
python3 spoofaloof.py example.com --no-color
```

### Skip open relay testing:
```bash
python3 spoofaloof.py example.com --skip-open-relay
```

## What it checks

### Core Email Authentication
1. **SPF (Sender Policy Framework)**: Verifies SPF records, analyzes configuration, and counts DNS lookups
2. **DKIM (DomainKeys Identified Mail)**: Checks for DKIM records using 60+ common selectors
3. **DMARC (Domain-based Message Authentication)**: Verifies DMARC policy configuration and alignment

### Additional Security Checks
4. **MX Records**: Validates mail server configuration
5. **MTA-STS**: Checks for Mail Transfer Agent Strict Transport Security
6. **DNSSEC**: Verifies domain name security extensions
7. **BIMI**: Checks for Brand Indicators for Message Identification
8. **TLS-RPT**: Checks for TLS reporting configuration
9. **Wildcard Records**: Detects potentially dangerous wildcard DNS entries
10. **Subdomain Analysis**: Scans common subdomains for missing email authentication
11. **Open Relay Testing**: Tests mail servers for open relay vulnerabilities that could be abused for spam

## Vulnerability Scoring

The tool provides a vulnerability score from 0.0 to 10.0:
- **0.0-2.0**: Low risk - Well configured email authentication
- **2.1-4.0**: Medium risk - Minor configuration issues
- **4.1-7.0**: High risk - Significant vulnerabilities allowing spoofing
- **7.1-10.0**: Critical risk - Little to no protection against spoofing

## Example Output

```
Email Spoofing Vulnerability Report for example.com
============================================================

Vulnerability Score: 6.5/10.0
Risk Level: High

SPF (Sender Policy Framework) Analysis:
----------------------------------------
✓ SPF record found: v=spf1 include:_spf.google.com ~all

DKIM (DomainKeys Identified Mail) Analysis:
----------------------------------------
✓ DKIM records found for 2 selector(s)
  • Selector 'google' configured
  • Selector 'selector1' configured

DMARC (Domain-based Message Authentication) Analysis:
----------------------------------------
✗ No DMARC record found
Issues:
  • No DMARC record found

Additional Security Analysis:
----------------------------------------
✓ MX records found (5 server(s))
✗ No MTA-STS policy found
✗ Domain is not DNSSEC signed
◯ No BIMI record found (optional)
◯ No TLS-RPT record found (optional)
⚠ 3 vulnerable subdomain(s) found

Identified Vulnerabilities:
----------------------------------------
  • Missing DMARC record - no policy for handling spoofed emails
  • No MTA-STS policy - emails vulnerable to downgrade attacks
  • Domain not signed with DNSSEC - DNS responses can be forged
  • 3 subdomain(s) found without email authentication
```

## JSON Output Example

```json
{
  "domain": "example.com",
  "vulnerability_score": 6.5,
  "risk_level": "High",
  "spf": {
    "found": true,
    "record": "v=spf1 include:_spf.google.com ~all",
    "issues": [],
    "lookup_count": 1
  },
  "dkim": {
    "found": true,
    "selectors_checked": [
      {"selector": "google", "record": "v=DKIM1; k=rsa; p=..."},
      {"selector": "selector1", "record": "v=DKIM1; k=rsa; p=..."}
    ],
    "issues": []
  },
  "dmarc": {
    "found": false,
    "record": null,
    "issues": ["No DMARC record found"]
  },
  "vulnerabilities": [
    "Missing DMARC record - no policy for handling spoofed emails",
    "No MTA-STS policy - emails vulnerable to downgrade attacks",
    "Domain not signed with DNSSEC - DNS responses can be forged",
    "3 subdomain(s) found without email authentication"
  ]
}
```

## Testing

Run the test suite to verify functionality:

```bash
python3 run_tests.py
```

Or run tests directly with unittest:

```bash
python3 -m unittest test_spoofaloof.py -v
```

The test suite covers:
- SPF record parsing and validation
- DKIM selector checking
- DMARC policy analysis
- Vulnerability scoring algorithm
- Additional security checks (MTA-STS, DNSSEC, etc.)
- Report generation
- Integration testing

## License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](LICENSE) file for details.