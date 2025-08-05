#!/usr/bin/env python3

import argparse
import json
import sys
import socket
import smtplib
import dns.resolver
import dns.exception
import dns.dnssec
import dns.rdatatype
import re
from typing import Dict, List, Optional, Tuple


# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Spoofaloof:
    def __init__(self, domain: str):
        self.domain = domain
        self.results = {
            'domain': domain,
            'spf': {'found': False, 'record': None, 'issues': [], 'lookup_count': 0},
            'dkim': {'selectors_checked': [], 'found': False, 'issues': []},
            'dmarc': {'found': False, 'record': None, 'issues': []},
            'mta_sts': {'found': False, 'policy': None, 'issues': []},
            'bimi': {'found': False, 'record': None, 'issues': []},
            'dnssec': {'signed': False, 'validated': False, 'issues': []},
            'mx': {'found': False, 'records': [], 'issues': []},
            'wildcards': {'found': False, 'issues': []},
            'null_mx': {'found': False},
            'tls_rpt': {'found': False, 'record': None},
            'open_relay': {'tested': False, 'vulnerable': False, 'tested_servers': [], 'issues': []},
            'subdomains': {'vulnerable': [], 'checked': []},
            'vulnerabilities': [],
            'risk_level': 'Unknown',
            'vulnerability_score': 0.0
        }
        
    def check_spf(self) -> None:
        """Check SPF records for the domain"""
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            spf_records = []
            
            for rdata in answers:
                txt_string = ''.join([s.decode('utf-8') for s in rdata.strings])
                if txt_string.startswith('v=spf1'):
                    spf_records.append(txt_string)
            
            if spf_records:
                self.results['spf']['found'] = True
                self.results['spf']['record'] = spf_records[0]
                
                # Analyze SPF record
                record = spf_records[0].lower()
                
                if len(spf_records) > 1:
                    self.results['spf']['issues'].append('Multiple SPF records found (only one allowed)')
                
                if record.endswith('+all'):
                    self.results['spf']['issues'].append('SPF record allows any server to send email (+all)')
                elif record.endswith('?all'):
                    self.results['spf']['issues'].append('SPF record is neutral - not enforcing restrictions (?all)')
                elif not (record.endswith('-all') or record.endswith('~all')):
                    self.results['spf']['issues'].append('SPF record does not specify all mechanism')
                    
                if 'redirect=' in record:
                    self.results['spf']['issues'].append('SPF record uses redirect mechanism')
                
                # Count DNS lookups (SPF has a limit of 10)
                lookup_count = 0
                lookup_count += record.count('include:')
                lookup_count += record.count('a ')
                lookup_count += record.count('mx ')
                lookup_count += record.count('ptr ')
                lookup_count += record.count('exists:')
                lookup_count += record.count('redirect=')
                
                self.results['spf']['lookup_count'] = lookup_count
                if lookup_count > 10:
                    self.results['spf']['issues'].append(f'SPF record has {lookup_count} DNS lookups (limit is 10)')
                elif lookup_count > 6:
                    self.results['spf']['issues'].append(f'SPF record has {lookup_count} DNS lookups (approaching limit of 10)')
                    
            else:
                self.results['spf']['issues'].append('No SPF record found')
                
        except dns.exception.DNSException:
            self.results['spf']['issues'].append('DNS lookup failed for SPF record')
    
    def check_dkim(self) -> None:
        """Check DKIM records using common selectors"""
        common_selectors = [
            'default', 'selector1', 'selector2', 'google', 'k1', 'k2', 
            'dkim', 'mail', 's1', 's2', 'email', 'key1', 'key2',
            'mandrill', 'mailgun', 'sendgrid', 'sparkpost', 'postmark',
            'amazonses', 'ses', 'mx', 'mailjet', 'sendpulse',
            'zoho', 'zimbra', 'yandex', 'yahoo', 'outlook', 'office365',
            'protonmail', 'pm-bounces', 'mxvault', 'dyn', 'smtp',
            'mailo', 'cm', 'mc', 'e1', 'e2', 'e3', 'mta',
            'scph0923', 'scph1223', 'scph0324', 'scph0624',
            '1', '2', '3', '4', '5', 'a', 'b', 'c',
            'brevo', 'sendinblue', 'mailchimp', 'k3', 'k4',
            'sig1', 'sig2', 'sig3', 'campaign', 'marketing',
            'transactional', 'notification', 'support', 'sales'
        ]
        
        dkim_found = False
        
        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{self.domain}"
                answers = dns.resolver.resolve(dkim_domain, 'TXT')
                
                for rdata in answers:
                    txt_string = ''.join([s.decode('utf-8') for s in rdata.strings])
                    if 'v=DKIM1' in txt_string or 'k=rsa' in txt_string:
                        self.results['dkim']['selectors_checked'].append({
                            'selector': selector,
                            'record': txt_string
                        })
                        dkim_found = True
                        
            except dns.exception.DNSException:
                continue
        
        if dkim_found:
            self.results['dkim']['found'] = True
        else:
            self.results['dkim']['issues'].append('No DKIM records found for common selectors')
    
    def check_dmarc(self) -> None:
        """Check DMARC record for the domain"""
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            
            for rdata in answers:
                txt_string = ''.join([s.decode('utf-8') for s in rdata.strings])
                if txt_string.startswith('v=DMARC1'):
                    self.results['dmarc']['found'] = True
                    self.results['dmarc']['record'] = txt_string
                    
                    # Analyze DMARC record
                    record = txt_string.lower()
                    
                    if 'p=none' in record:
                        self.results['dmarc']['issues'].append('DMARC policy is set to none (monitoring only)')
                    elif 'p=quarantine' not in record and 'p=reject' not in record:
                        self.results['dmarc']['issues'].append('DMARC policy not properly configured')
                    
                    if 'sp=' not in record:
                        self.results['dmarc']['issues'].append('No subdomain policy specified')
                    elif 'sp=none' in record:
                        self.results['dmarc']['issues'].append('Subdomain policy is set to none')
                    
                    if 'pct=' in record:
                        import re
                        pct_match = re.search(r'pct=(\d+)', record)
                        if pct_match and int(pct_match.group(1)) < 100:
                            self.results['dmarc']['issues'].append(f'DMARC only applies to {pct_match.group(1)}% of emails')
                    
                    break
            
            if not self.results['dmarc']['found']:
                self.results['dmarc']['issues'].append('No DMARC record found')
                
        except dns.exception.DNSException:
            self.results['dmarc']['issues'].append('DNS lookup failed for DMARC record')
    
    def check_mx(self) -> None:
        """Check MX records for the domain"""
        try:
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            self.results['mx']['found'] = True
            
            for mx in mx_records:
                mx_host = str(mx.exchange).rstrip('.')
                self.results['mx']['records'].append({
                    'priority': mx.preference,
                    'host': mx_host
                })
            
            # Check for suspicious MX records
            for mx_info in self.results['mx']['records']:
                mx_host = mx_info['host'].lower()
                if mx_host == self.domain or mx_host.endswith(f'.{self.domain}'):
                    # Self-hosted email might be more vulnerable
                    self.results['mx']['issues'].append(f'MX record points to same domain ({mx_host}) - may indicate self-hosted email')
                
        except dns.resolver.NXDOMAIN:
            self.results['mx']['issues'].append('No MX records found - domain may not handle email')
        except dns.exception.DNSException:
            self.results['mx']['issues'].append('DNS lookup failed for MX records')
    
    def check_null_mx(self) -> None:
        """Check for null MX record (RFC 7505)"""
        try:
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            for mx in mx_records:
                if mx.preference == 0 and str(mx.exchange) == '.':
                    self.results['null_mx']['found'] = True
                    break
        except:
            pass
    
    def check_mta_sts(self) -> None:
        """Check MTA-STS policy"""
        try:
            # Check for MTA-STS DNS record
            mta_sts_domain = f"_mta-sts.{self.domain}"
            answers = dns.resolver.resolve(mta_sts_domain, 'TXT')
            
            for rdata in answers:
                txt_string = ''.join([s.decode('utf-8') for s in rdata.strings])
                if txt_string.startswith('v=STSv1'):
                    self.results['mta_sts']['found'] = True
                    self.results['mta_sts']['policy'] = txt_string
                    
                    # Basic validation
                    if 'id=' not in txt_string:
                        self.results['mta_sts']['issues'].append('MTA-STS record missing ID field')
                    break
                    
        except dns.exception.DNSException:
            pass  # Handle "not found" in vulnerability assessment, not here
    
    def check_tls_rpt(self) -> None:
        """Check TLS-RPT record"""
        try:
            tls_rpt_domain = f"_smtp._tls.{self.domain}"
            answers = dns.resolver.resolve(tls_rpt_domain, 'TXT')
            
            for rdata in answers:
                txt_string = ''.join([s.decode('utf-8') for s in rdata.strings])
                if 'v=TLSRPTv1' in txt_string:
                    self.results['tls_rpt']['found'] = True
                    self.results['tls_rpt']['record'] = txt_string
                    break
        except:
            pass
    
    def check_bimi(self) -> None:
        """Check BIMI record"""
        try:
            bimi_domains = [f"default._bimi.{self.domain}", f"_bimi.{self.domain}"]
            
            for bimi_domain in bimi_domains:
                try:
                    answers = dns.resolver.resolve(bimi_domain, 'TXT')
                    for rdata in answers:
                        txt_string = ''.join([s.decode('utf-8') for s in rdata.strings])
                        if txt_string.startswith('v=BIMI1'):
                            self.results['bimi']['found'] = True
                            self.results['bimi']['record'] = txt_string
                            
                            # Check for required fields
                            if 'l=' not in txt_string:
                                self.results['bimi']['issues'].append('BIMI record missing logo location')
                            if 'a=' not in txt_string:
                                self.results['bimi']['issues'].append('BIMI record missing authority evidence')
                            return
                except:
                    continue
                    
        except:
            pass
    
    def check_dnssec(self) -> None:
        """Check DNSSEC status"""
        try:
            # Check if domain has DNSKEY records
            dns.resolver.resolve(self.domain, 'DNSKEY')
            self.results['dnssec']['signed'] = True
            
            # Try to validate
            try:
                dns.resolver.resolve(self.domain, 'A', raise_on_no_answer=False)
                self.results['dnssec']['validated'] = True
            except dns.exception.DNSException:
                self.results['dnssec']['issues'].append('DNSSEC validation failed')
                
        except dns.resolver.NoAnswer:
            self.results['dnssec']['issues'].append('Domain not signed with DNSSEC')
        except dns.exception.DNSException:
            self.results['dnssec']['issues'].append('DNSSEC check failed')
    
    def check_wildcards(self) -> None:
        """Check for wildcard DNS records"""
        try:
            # Check for wildcard A record
            wildcard_domain = f"*.{self.domain}"
            try:
                dns.resolver.resolve(wildcard_domain, 'A')
                self.results['wildcards']['found'] = True
                self.results['wildcards']['issues'].append('Wildcard A record found - subdomains can be easily created')
            except:
                pass
                
            # Check for wildcard MX
            try:
                dns.resolver.resolve(wildcard_domain, 'MX')
                self.results['wildcards']['found'] = True
                self.results['wildcards']['issues'].append('Wildcard MX record found - any subdomain can receive email')
            except:
                pass
                
        except:
            pass
    
    def check_subdomains(self) -> None:
        """Check common subdomains for email authentication"""
        common_subdomains = ['mail', 'email', 'smtp', 'mx', 'webmail', 'autodiscover', 
                           'cpanel', 'webdisk', 'ftp', 'cpcalendars', 'cpcontacts']
        
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{self.domain}"
            self.results['subdomains']['checked'].append(full_domain)
            
            try:
                # Check if subdomain exists
                dns.resolver.resolve(full_domain, 'A')
                
                # Check if it has SPF
                has_spf = False
                try:
                    spf_answers = dns.resolver.resolve(full_domain, 'TXT')
                    for rdata in spf_answers:
                        txt_string = ''.join([s.decode('utf-8') for s in rdata.strings])
                        if txt_string.startswith('v=spf1'):
                            has_spf = True
                            break
                except:
                    pass
                
                # Check if it has DMARC
                has_dmarc = False
                try:
                    dmarc_answers = dns.resolver.resolve(f"_dmarc.{full_domain}", 'TXT')
                    for rdata in dmarc_answers:
                        txt_string = ''.join([s.decode('utf-8') for s in rdata.strings])
                        if txt_string.startswith('v=DMARC1'):
                            has_dmarc = True
                            break
                except:
                    pass
                
                if not has_spf and not has_dmarc:
                    self.results['subdomains']['vulnerable'].append({
                        'subdomain': full_domain,
                        'reason': 'No SPF or DMARC protection'
                    })
                    
            except:
                continue
    
    def check_open_relay(self) -> None:
        """Check for open mail relay vulnerabilities"""
        if not self.results['mx']['found'] or not self.results['mx']['records']:
            self.results['open_relay']['issues'].append('No MX records to test for open relay')
            return
        
        self.results['open_relay']['tested'] = True
        
        # Test common open relay techniques on MX servers
        test_cases = [
            # External to external relay test
            ('external@malicious.com', 'victim@target.com'),
            # Percent hack
            ('test%victim@target.com@malicious.com', 'victim@target.com'),
            # Double at sign
            ('test@victim@target.com', 'victim@target.com'),
            # Source routing
            ('@malicious.com:victim@target.com', 'victim@target.com'),
        ]
        
        for mx_info in self.results['mx']['records'][:3]:  # Test up to 3 MX servers
            mx_host = mx_info['host']
            
            try:
                # Test SMTP connection with timeout
                server = smtplib.SMTP(timeout=10)
                server.set_debuglevel(0)  # Disable debug output
                
                try:
                    server.connect(mx_host, 25)
                    server.helo('spoofaloof-scanner.example.com')
                    
                    relay_vulnerable = False
                    test_results = []
                    
                    for mail_from, rcpt_to in test_cases:
                        try:
                            server.mail(mail_from)
                            code, response = server.rcpt(rcpt_to)
                            
                            # If the server accepts the recipient (2xx response),
                            # it might be an open relay
                            if 200 <= code < 300:
                                relay_vulnerable = True
                                test_results.append(f"Accepted relay: {mail_from} -> {rcpt_to}")
                            else:
                                test_results.append(f"Rejected relay: {mail_from} -> {rcpt_to} ({code})")
                                
                        except smtplib.SMTPRecipientsRefused:
                            test_results.append(f"Rejected relay: {mail_from} -> {rcpt_to}")
                        except smtplib.SMTPException as e:
                            test_results.append(f"SMTP error for {mail_from} -> {rcpt_to}: {str(e)}")
                        
                        # Reset for next test
                        try:
                            server.rset()
                        except:
                            pass
                    
                    self.results['open_relay']['tested_servers'].append({
                        'server': mx_host,
                        'vulnerable': relay_vulnerable,
                        'test_results': test_results
                    })
                    
                    if relay_vulnerable:
                        self.results['open_relay']['vulnerable'] = True
                        self.results['open_relay']['issues'].append(f'Open relay detected on {mx_host}')
                    
                except (smtplib.SMTPException, OSError, socket.error) as e:
                    self.results['open_relay']['tested_servers'].append({
                        'server': mx_host,
                        'vulnerable': False,
                        'test_results': [f'Connection failed: {str(e)}']
                    })
                    
                finally:
                    try:
                        server.quit()
                    except:
                        pass
                        
            except (socket.error, OSError) as e:
                self.results['open_relay']['tested_servers'].append({
                    'server': mx_host,
                    'vulnerable': False,
                    'test_results': [f'Connection failed: {str(e)}']
                })
                continue
        
        if not self.results['open_relay']['vulnerable'] and self.results['open_relay']['tested_servers']:
            # All servers tested, none vulnerable
            tested_count = len(self.results['open_relay']['tested_servers'])
            self.results['open_relay']['issues'].append(f'Open relay test completed on {tested_count} server(s) - no relays detected')
    
    def assess_vulnerabilities(self) -> None:
        """Assess overall vulnerabilities based on findings"""
        vulnerabilities = []
        
        # Define severity levels for each vulnerability type
        # Level 1: Minor issues (0.5-1.5 points)
        # Level 2: Moderate issues (2.0-3.5 points)  
        # Level 3: Severe issues (4.0-6.0 points)
        # Level 4: Critical issues (7.0-9.0 points)
        
        vulnerability_scores = []
        
        # SPF vulnerabilities
        if not self.results['spf']['found']:
            vulnerabilities.append('Missing SPF record - domain can be easily spoofed')
            vulnerability_scores.append(7.0)  # Critical - no sender verification
        elif self.results['spf']['issues']:
            for issue in self.results['spf']['issues']:
                if '+all' in issue:
                    vulnerabilities.append('SPF allows any server to send email')
                    vulnerability_scores.append(8.5)  # Critical - SPF is useless
                elif '?all' in issue:
                    vulnerabilities.append('SPF not enforcing restrictions')
                    vulnerability_scores.append(6.0)  # Severe - weak enforcement
                elif 'Multiple SPF' in issue:
                    vulnerabilities.append('Multiple SPF records can cause delivery issues')
                    vulnerability_scores.append(3.0)  # Moderate - breaks SPF
                elif 'DNS lookup' in issue and 'limit' in issue:
                    vulnerabilities.append('SPF record exceeds DNS lookup limit')
                    vulnerability_scores.append(4.0)  # Severe - SPF may fail
                elif 'approaching limit' in issue:
                    vulnerability_scores.append(2.0)  # Moderate - future risk
        
        # DKIM vulnerabilities
        if not self.results['dkim']['found']:
            vulnerabilities.append('No DKIM records found - emails cannot be cryptographically verified')
            vulnerability_scores.append(4.0)  # Severe - no signature verification
        
        # DMARC vulnerabilities
        if not self.results['dmarc']['found']:
            vulnerabilities.append('Missing DMARC record - no policy for handling spoofed emails')
            vulnerability_scores.append(7.5)  # Critical - no spoofing protection
        elif self.results['dmarc']['issues']:
            for issue in self.results['dmarc']['issues']:
                if 'p=none' in issue:
                    vulnerabilities.append('DMARC in monitoring mode only - not protecting against spoofing')
                    vulnerability_scores.append(6.5)  # Severe - no enforcement
                elif 'subdomain policy' in issue and 'none' in issue:
                    vulnerabilities.append('Subdomains not protected by DMARC')
                    vulnerability_scores.append(5.0)  # Severe - subdomain spoofing
                elif 'pct=' in issue:
                    vulnerabilities.append('DMARC not applied to all emails')
                    vulnerability_scores.append(4.0)  # Severe - partial protection
        
        # Critical combinations
        if not self.results['spf']['found'] and not self.results['dmarc']['found']:
            # Override individual scores - this is catastrophic
            vulnerability_scores.append(9.5)  # Nearly maximum vulnerability
        
        if (self.results['spf']['found'] and any('+all' in issue for issue in self.results['spf']['issues']) 
            and not self.results['dmarc']['found']):
            # SPF +all with no DMARC is effectively no protection
            vulnerability_scores.append(9.0)
        
        # Critical combination: SPF record exists but DMARC is p=none
        if (self.results['spf']['found'] and self.results['dmarc']['found'] and 
            self.results['dmarc']['record'] and 'p=none' in self.results['dmarc']['record'].lower()):
            vulnerabilities.append('SPF record exists but DMARC policy is "none" - creates false security impression while providing no enforcement')
            vulnerability_scores.append(7.5)  # Critical - false sense of security
        
        # MX vulnerabilities
        if not self.results['mx']['found']:
            if not self.results['null_mx']['found']:
                vulnerabilities.append('No MX records found - unclear email handling')
                vulnerability_scores.append(1.5)  # Minor - confusing but not critical
        elif self.results['mx']['issues']:
            for issue in self.results['mx']['issues']:
                if 'self-hosted' in issue:
                    vulnerabilities.append('Self-hosted email may lack advanced anti-spoofing features')
                    vulnerability_scores.append(2.0)  # Moderate - potential weakness
        
        # MTA-STS vulnerabilities
        if not self.results['mta_sts']['found']:
            vulnerabilities.append('No MTA-STS policy - emails vulnerable to downgrade attacks')
            vulnerability_scores.append(3.5)  # Moderate to severe
        
        # DNSSEC vulnerabilities
        if not self.results['dnssec']['signed']:
            vulnerabilities.append('Domain not signed with DNSSEC - DNS responses can be forged')
            vulnerability_scores.append(4.0)  # Severe - DNS hijacking possible
        elif not self.results['dnssec']['validated']:
            vulnerabilities.append('DNSSEC validation failed - may not be properly configured')
            vulnerability_scores.append(3.0)  # Moderate - broken DNSSEC
        
        # Wildcard vulnerabilities
        if self.results['wildcards']['found']:
            for issue in self.results['wildcards']['issues']:
                if 'MX' in issue:
                    vulnerabilities.append('Wildcard MX allows any subdomain to receive email')
                    vulnerability_scores.append(7.0)  # Critical - unlimited subdomain spoofing
                else:
                    vulnerabilities.append('Wildcard DNS records enable easy subdomain creation')
                    vulnerability_scores.append(3.0)  # Moderate - potential for abuse
        
        # Subdomain vulnerabilities
        if self.results['subdomains']['vulnerable']:
            vuln_count = len(self.results['subdomains']['vulnerable'])
            vulnerabilities.append(f'{vuln_count} subdomain(s) found without email authentication')
            if vuln_count >= 5:
                vulnerability_scores.append(5.0)  # Severe - many vulnerable subdomains
            elif vuln_count >= 3:
                vulnerability_scores.append(3.5)  # Moderate to severe
            else:
                vulnerability_scores.append(2.5)  # Moderate
        
        # Open relay vulnerabilities
        if self.results['open_relay']['tested'] and self.results['open_relay']['vulnerable']:
            vulnerabilities.append('Open mail relay detected - server can be abused for spam and spoofing')
            vulnerability_scores.append(8.0)  # Critical - allows direct mail abuse
        
        # BIMI consideration (informational only)
        # Don't add BIMI to vulnerabilities since it's optional
        
        self.results['vulnerabilities'] = vulnerabilities
        
        # Calculate final vulnerability score using intelligent approach
        if vulnerability_scores:
            # Use a combination of maximum severity and average
            max_score = max(vulnerability_scores)
            avg_score = sum(vulnerability_scores) / len(vulnerability_scores)
            
            # Weight heavily toward the maximum (weakest link principle)
            # but consider overall security posture
            vulnerability_score = (max_score * 0.7) + (avg_score * 0.3)
            
            # Ensure critical vulnerabilities always result in high scores
            if max_score >= 8.0:
                vulnerability_score = max(vulnerability_score, 8.0)
            elif max_score >= 7.0:
                vulnerability_score = max(vulnerability_score, 7.0)
            
            # Cap at 10.0
            vulnerability_score = min(10.0, vulnerability_score)
        else:
            # No vulnerabilities found
            vulnerability_score = 0.0
        
        # Round to 1 decimal place
        self.results['vulnerability_score'] = round(vulnerability_score, 1)
        
        # Determine risk level based on score
        if self.results['vulnerability_score'] <= 2.0:
            self.results['risk_level'] = 'Low'
        elif self.results['vulnerability_score'] <= 4.0:
            self.results['risk_level'] = 'Medium'
        elif self.results['vulnerability_score'] <= 7.0:
            self.results['risk_level'] = 'High'
        else:
            self.results['risk_level'] = 'Critical'
    
    def generate_text_report(self, include_remediation: bool = False) -> str:
        """Generate a human-readable text report"""
        report = []
        report.append(f"Email Spoofing Vulnerability Report for {self.domain}")
        report.append("=" * 60)
        report.append("")
        
        # Risk Summary with color based on severity
        score = self.results['vulnerability_score']
        if score <= 2.0:
            score_color = Colors.GREEN
        elif score <= 4.0:
            score_color = Colors.YELLOW
        elif score <= 7.0:
            score_color = Colors.YELLOW + Colors.BOLD
        else:
            score_color = Colors.RED + Colors.BOLD
            
        report.append(f"Vulnerability Score: {score_color}{self.results['vulnerability_score']}/10.0{Colors.ENDC}")
        report.append(f"Risk Level: {score_color}{self.results['risk_level']}{Colors.ENDC}")
        report.append("")
        
        # SPF Section
        report.append("SPF (Sender Policy Framework) Analysis:")
        report.append("-" * 40)
        if self.results['spf']['found']:
            report.append(f"{Colors.GREEN}✓{Colors.ENDC} SPF record found: {self.results['spf']['record']}")
        else:
            report.append(f"{Colors.RED}✗{Colors.ENDC} No SPF record found")
        
        if self.results['spf']['issues']:
            report.append("Issues:")
            for issue in self.results['spf']['issues']:
                report.append(f"  • {issue}")
        report.append("")
        
        # DKIM Section
        report.append("DKIM (DomainKeys Identified Mail) Analysis:")
        report.append("-" * 40)
        if self.results['dkim']['found']:
            report.append(f"{Colors.GREEN}✓{Colors.ENDC} DKIM records found for {len(self.results['dkim']['selectors_checked'])} selector(s)")
            for selector_info in self.results['dkim']['selectors_checked']:
                report.append(f"  • Selector '{selector_info['selector']}' configured")
        else:
            report.append(f"{Colors.RED}✗{Colors.ENDC} No DKIM records found")
        
        if self.results['dkim']['issues']:
            report.append("Issues:")
            for issue in self.results['dkim']['issues']:
                report.append(f"  • {issue}")
        report.append("")
        
        # DMARC Section
        report.append("DMARC (Domain-based Message Authentication) Analysis:")
        report.append("-" * 40)
        if self.results['dmarc']['found']:
            report.append(f"{Colors.GREEN}✓{Colors.ENDC} DMARC record found: {self.results['dmarc']['record']}")
        else:
            report.append(f"{Colors.RED}✗{Colors.ENDC} No DMARC record found")
        
        if self.results['dmarc']['issues']:
            report.append("Issues:")
            for issue in self.results['dmarc']['issues']:
                report.append(f"  • {issue}")
        report.append("")
        
        # Additional Security Checks
        report.append("Additional Security Analysis:")
        report.append("-" * 40)
        
        # MX Records
        if self.results['mx']['found']:
            report.append(f"{Colors.GREEN}✓{Colors.ENDC} MX records found ({len(self.results['mx']['records'])} server(s))")
        elif self.results['null_mx']['found']:
            report.append(f"{Colors.GREEN}✓{Colors.ENDC} Null MX record configured (domain does not accept email)")
        else:
            report.append(f"{Colors.RED}✗{Colors.ENDC} No MX records found")
        
        # MTA-STS
        if self.results['mta_sts']['found']:
            report.append(f"{Colors.GREEN}✓{Colors.ENDC} MTA-STS policy configured (enforces TLS for email)")
        else:
            report.append(f"{Colors.RED}✗{Colors.ENDC} No MTA-STS policy found")
        
        # DNSSEC
        if self.results['dnssec']['signed'] and self.results['dnssec']['validated']:
            report.append(f"{Colors.GREEN}✓{Colors.ENDC} DNSSEC is properly configured")
        elif self.results['dnssec']['signed']:
            report.append(f"{Colors.YELLOW}⚠{Colors.ENDC} DNSSEC is signed but validation failed")
        else:
            report.append(f"{Colors.RED}✗{Colors.ENDC} Domain is not DNSSEC signed")
        
        # BIMI
        if self.results['bimi']['found']:
            report.append(f"{Colors.GREEN}✓{Colors.ENDC} BIMI record configured (brand indicators)")
        else:
            report.append(f"{Colors.BLUE}◯{Colors.ENDC} No BIMI record found (optional)")
        
        # TLS-RPT
        if self.results['tls_rpt']['found']:
            report.append(f"{Colors.GREEN}✓{Colors.ENDC} TLS-RPT configured (TLS reporting)")
        else:
            report.append(f"{Colors.BLUE}◯{Colors.ENDC} No TLS-RPT record found (optional)")
        
        # Wildcards
        if self.results['wildcards']['found']:
            report.append(f"{Colors.YELLOW}⚠{Colors.ENDC} Wildcard DNS records detected")
        
        # Subdomains
        if self.results['subdomains']['vulnerable']:
            report.append(f"{Colors.YELLOW}⚠{Colors.ENDC} {len(self.results['subdomains']['vulnerable'])} vulnerable subdomain(s) found")
        
        # Open Relay
        if self.results['open_relay']['tested']:
            if self.results['open_relay']['vulnerable']:
                report.append(f"{Colors.RED}✗{Colors.ENDC} Open mail relay detected - server vulnerable to abuse")
            else:
                tested_count = len(self.results['open_relay']['tested_servers'])
                report.append(f"{Colors.GREEN}✓{Colors.ENDC} No open relays detected ({tested_count} server(s) tested)")
        else:
            report.append(f"{Colors.BLUE}◯{Colors.ENDC} Open relay test skipped (no MX records)")
        
        report.append("")
        
        # Vulnerabilities Summary
        if self.results['vulnerabilities']:
            report.append("Identified Vulnerabilities:")
            report.append("-" * 40)
            for vuln in self.results['vulnerabilities']:
                report.append(f"  • {vuln}")
            report.append("")
        
        # Remediation section if requested
        if include_remediation and self.results['vulnerabilities']:
            report.append("Basic Remediation Instructions:")
            report.append("-" * 40)
            
            remediation_shown = set()
            
            # SPF remediation
            if not self.results['spf']['found'] and 'spf_missing' not in remediation_shown:
                report.append("\nMissing SPF Record:")
                report.append("Add a TXT record to your DNS:")
                report.append(f"  Name: {self.domain}")
                report.append("  Type: TXT")
                report.append("  Value: \"v=spf1 include:_spf.google.com ~all\"")
                report.append("  (Replace with your email provider's SPF include)")
                remediation_shown.add('spf_missing')
            elif self.results['spf']['found'] and any('+all' in issue for issue in self.results['spf']['issues']):
                report.append("\nSPF +all Issue:")
                report.append("Change your SPF record's +all to -all or ~all:")
                report.append("  Current: v=spf1 ... +all")
                report.append("  Change to: v=spf1 ... -all")
                remediation_shown.add('spf_all')
            
            # DKIM remediation
            if not self.results['dkim']['found'] and 'dkim_missing' not in remediation_shown:
                report.append("\nMissing DKIM:")
                report.append("DKIM setup varies by email provider:")
                report.append("  • Google Workspace: Admin Console → Apps → Gmail → Authenticate email")
                report.append("  • Office 365: Admin Center → Setup → Domains → DNS records")
                report.append("  • Self-hosted: Configure your MTA (Postfix/Exim) for DKIM signing")
                remediation_shown.add('dkim_missing')
            
            # DMARC remediation
            if not self.results['dmarc']['found'] and 'dmarc_missing' not in remediation_shown:
                report.append("\nMissing DMARC Record:")
                report.append("Add a TXT record to your DNS:")
                report.append(f"  Name: _dmarc.{self.domain}")
                report.append("  Type: TXT")
                report.append("  Value: \"v=DMARC1; p=quarantine; rua=mailto:dmarc@{self.domain}\"")
                report.append("  (Start with p=none for monitoring, then quarantine, then reject)")
                remediation_shown.add('dmarc_missing')
            elif any('p=none' in issue for issue in self.results['dmarc']['issues']):
                report.append("\nDMARC Policy Too Weak:")
                report.append("Update your DMARC policy from 'none' to 'quarantine' or 'reject':")
                report.append("  Current: v=DMARC1; p=none; ...")
                report.append("  Change to: v=DMARC1; p=quarantine; ...")
                if self.results['spf']['found']:
                    report.append("  WARNING: Having SPF with DMARC p=none creates false security!")
                    report.append("  Recipients may think emails are authenticated when they're not enforced.")
                remediation_shown.add('dmarc_weak')
            
            # Special case: SPF exists with DMARC p=none (dangerous combination)
            if (self.results['spf']['found'] and self.results['dmarc']['found'] and 
                self.results['dmarc']['record'] and 'p=none' in self.results['dmarc']['record'].lower() and
                'spf_dmarc_none_combo' not in remediation_shown):
                report.append("\nDANGEROUS: SPF + DMARC p=none Combination:")
                report.append("Your domain has SPF records but DMARC is set to 'none' - this is misleading!")
                report.append("  • Recipients see SPF authentication and may trust emails")
                report.append("  • But DMARC p=none means no action is taken on failures")
                report.append("  • Attackers can spoof your domain and still get delivered")
                report.append("  • This creates a FALSE SENSE OF SECURITY")
                report.append("Immediate action required:")
                report.append("  • Change DMARC policy to 'quarantine' to start blocking spoofed emails")
                report.append("  • Monitor DMARC reports for legitimate email failures")
                report.append("  • Gradually move to 'reject' policy for maximum protection")
                remediation_shown.add('spf_dmarc_none_combo')
            
            # MTA-STS remediation
            if not self.results['mta_sts']['found'] and 'mta_sts_missing' not in remediation_shown:
                report.append("\nMissing MTA-STS:")
                report.append("1. Add DNS TXT record:")
                report.append(f"   Name: _mta-sts.{self.domain}")
                report.append("   Value: \"v=STSv1; id=20240101000000\"")
                report.append(f"2. Host policy file at: https://mta-sts.{self.domain}/.well-known/mta-sts.txt")
                report.append("   With content:")
                report.append("   version: STSv1")
                report.append("   mode: enforce")
                report.append("   mx: mail.{self.domain}")
                report.append("   max_age: 86400")
                remediation_shown.add('mta_sts_missing')
            
            # DNSSEC remediation
            if not self.results['dnssec']['signed'] and 'dnssec_missing' not in remediation_shown:
                report.append("\nMissing DNSSEC:")
                report.append("Enable DNSSEC through your domain registrar:")
                report.append("  • Most registrars have a 'Enable DNSSEC' option in DNS settings")
                report.append("  • May require DS records from your DNS provider")
                report.append("  • Contact your registrar's support for specific steps")
                remediation_shown.add('dnssec_missing')
            
            # Wildcard MX remediation
            if self.results['wildcards']['found'] and any('MX' in issue for issue in self.results['wildcards']['issues']):
                report.append("\nWildcard MX Record:")
                report.append("Remove the wildcard MX record (*.{self.domain}):")
                report.append("  • Delete any MX records for *.{self.domain}")
                report.append("  • Only keep specific MX records for {self.domain}")
                report.append("  • This prevents subdomain email spoofing")
                remediation_shown.add('wildcard_mx')
            
            # SPF lookup limit remediation
            if self.results['spf']['lookup_count'] > 10:
                report.append("\nSPF Lookup Limit Exceeded:")
                report.append("Reduce DNS lookups in your SPF record:")
                report.append("  • Consolidate multiple include: statements")
                report.append("  • Use IP addresses instead of A/MX lookups where possible")
                report.append("  • Consider using SPF flattening services")
                report.append(f"  Current lookups: {self.results['spf']['lookup_count']} (limit: 10)")
                remediation_shown.add('spf_lookups')
            
            # BIMI remediation
            if not self.results['bimi']['found'] and self.results['dmarc']['found'] and 'bimi_missing' not in remediation_shown:
                # Only suggest BIMI if DMARC is already configured
                dmarc_policy = self.results['dmarc']['record'] or ""
                if 'p=quarantine' in dmarc_policy or 'p=reject' in dmarc_policy:
                    report.append("\nMissing BIMI (Optional):")
                    report.append("BIMI requires DMARC with quarantine/reject policy (✓ already configured):")
                    report.append("1. Add DNS TXT record:")
                    report.append(f"   Name: default._bimi.{self.domain}")
                    report.append("   Type: TXT")
                    report.append(f"   Value: \"v=BIMI1; l=https://{self.domain}/logo.svg\"")
                    report.append("2. Host your brand logo as an SVG file at the specified URL")
                    report.append("3. Consider getting a Verified Mark Certificate (VMC) for enhanced trust")
                    remediation_shown.add('bimi_missing')
            
            # Open relay remediation
            if self.results['open_relay']['vulnerable'] and 'open_relay' not in remediation_shown:
                report.append("\nOpen Mail Relay Detected:")
                report.append("Immediately secure your mail server configuration:")
                report.append("  • Configure the mail server to reject external-to-external relaying")
                report.append("  • Restrict relay permissions to authenticated users only")
                report.append("  • Review SMTP server configuration (Postfix, Sendmail, Exchange, etc.)")
                report.append("  • Consider implementing SMTP authentication (SASL)")
                report.append("  • Test configuration using external relay testing tools")
                report.append("  • Monitor mail server logs for abuse attempts")
                remediation_shown.add('open_relay')
            
            report.append("")
        
        return "\n".join(report)
    
    def run(self, skip_open_relay: bool = False) -> Dict:
        """Run all checks and return results"""
        self.check_spf()
        self.check_dkim()
        self.check_dmarc()
        self.check_mx()
        self.check_null_mx()
        self.check_mta_sts()
        self.check_tls_rpt()
        self.check_bimi()
        self.check_dnssec()
        self.check_wildcards()
        self.check_subdomains()
        if not skip_open_relay:
            self.check_open_relay()
        self.assess_vulnerabilities()
        return self.results


def main():
    parser = argparse.ArgumentParser(
        description='Spoofaloof - Check a domain for email spoofing vulnerabilities'
    )
    parser.add_argument('domain', help='Domain to check for spoofing vulnerabilities')
    parser.add_argument('--json', action='store_true', help='Output results as JSON')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--remediate', action='store_true', help='Include basic remediation instructions')
    parser.add_argument('--skip-open-relay', action='store_true', help='Skip open relay testing (faster, less intrusive)')
    
    args = parser.parse_args()
    
    # Disable colors if requested or if output is not a terminal
    if args.no_color or not sys.stdout.isatty():
        Colors.HEADER = ''
        Colors.BLUE = ''
        Colors.CYAN = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.RED = ''
        Colors.FAIL = ''
        Colors.ENDC = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''
    
    # Create checker instance
    checker = Spoofaloof(args.domain)
    
    try:
        # Run checks
        results = checker.run(skip_open_relay=args.skip_open_relay)
        
        # Output results
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(checker.generate_text_report(include_remediation=args.remediate))
            
    except Exception as e:
        error_msg = f"Error checking domain {args.domain}: {str(e)}"
        if args.json:
            print(json.dumps({'error': error_msg}, indent=2))
        else:
            print(error_msg)
        sys.exit(1)


if __name__ == '__main__':
    main()