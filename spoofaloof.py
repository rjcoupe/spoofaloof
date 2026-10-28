#!/usr/bin/env python3

import argparse
import json
import sys
import socket
import smtplib
import dns.resolver
import dns.exception
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
    def __init__(self, domain: str, dkim_selectors: Optional[List[str]] = None):
        self.domain = domain
        self.dkim_selectors = dkim_selectors
        if dkim_selectors is not None:
            if not dkim_selectors or any(not self.valid_selector(x) for x in dkim_selectors):
                raise ValueError('DKIM selectors must be nonempty DNS names with valid labels')
            self.dkim_selectors = list(dict.fromkeys(dkim_selectors))
        self.results = {
            'domain': domain,
            'spf': {'found': False, 'record': None, 'issues': [], 'lookup_count': 0},
            'dkim': {'selectors_checked': [], 'found': False, 'issues': []},
            'dmarc': {'found': False, 'record': None, 'issues': []},
            'mta_sts': {'found': False, 'policy': None, 'issues': []},
            'bimi': {'found': False, 'record': None, 'issues': []},
            'dnssec': {'signed': None, 'validated': None, 'issues': []},
            'mx': {'found': False, 'records': [], 'issues': []},
            'wildcards': {'found': False, 'issues': []},
            'null_mx': {'found': False},
            'tls_rpt': {'found': False, 'record': None},
            'open_relay': {'status': 'skipped', 'tested': False, 'vulnerable': None, 'tested_servers': [], 'issues': []},
            'subdomains': {'vulnerable': [], 'checked': []},
            'vulnerabilities': [],
            'risk_level': 'Unknown',
            'vulnerability_score': None
        }
        for name, result in self.results.items():
            if isinstance(result, dict) and name != 'open_relay':
                result['status'] = 'not_checked'

    @staticmethod
    def valid_selector(selector: str) -> bool:
        return len(selector) <= 253 and all(
            re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
            for label in selector.split('.'))

    @staticmethod
    def tags(record: str) -> Dict[str, str]:
        return {key.strip().lower(): value.strip() for part in record.split(';')
                if '=' in part for key, value in [part.split('=', 1)]}

    def query(self, check: str, name: str, kind: str):
        """Preserve DNS absence separately from operational failure."""
        result = self.results[check]
        try:
            answer = dns.resolver.resolve(name, kind)
            result['status'] = 'ok'
            return answer
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            result['status'] = 'absent'
            return []
        except dns.exception.DNSException as exc:
            result['status'] = 'error'
            result.setdefault('errors', []).append(f'{name} {kind}: {type(exc).__name__}')
            return []

    def check_spf(self) -> None:
        """Check SPF records for the domain"""
        try:
            answers = self.query('spf', self.domain, 'TXT')
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
                    
            elif self.results['spf']['status'] != 'error':
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
        
        result = self.results['dkim']
        result.update(found=False, selectors_checked=[], selectors_attempted=[],
                      coverage_complete=False, errors=[], issues=[])
        for selector in self.dkim_selectors or common_selectors:
            result['selectors_attempted'].append(selector)
            answers = self.query('dkim', f'{selector}._domainkey.{self.domain}', 'TXT')
            for rdata in answers:
                record = ''.join(s.decode('utf-8') for s in rdata.strings)
                tags = self.tags(record)
                if tags.get('v', 'DKIM1') != 'DKIM1' or tags.get('k', 'rsa') not in ('rsa', 'ed25519'):
                    continue
                if 'p' in tags and tags['p']:
                    result['selectors_checked'].append({'selector': selector, 'record': record})
                    result['found'] = True
                elif 'p' in tags:
                    result['issues'].append(f'Selector {selector} has a revoked (empty) key')
        result['status'] = ('partial' if result['errors'] else 'ok') if result['found'] else (
            'error' if result['errors'] else 'no_match')
        if not result['found']:
            result['issues'].append('No usable key discovered at queried selectors; DKIM deployment is unknown')

    def check_dmarc(self) -> None:
        """Check DMARC record for the domain"""
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = self.query('dmarc', dmarc_domain, 'TXT')
            
            for rdata in answers:
                txt_string = ''.join([s.decode('utf-8') for s in rdata.strings])
                if txt_string.startswith('v=DMARC1'):
                    self.results['dmarc']['found'] = True
                    self.results['dmarc']['record'] = txt_string
                    
                    tags = self.tags(txt_string)
                    self.results['dmarc']['tags'] = tags
                    if tags.get('p') == 'none':
                        self.results['dmarc']['issues'].append('DMARC policy is set to none (monitoring only)')
                    elif tags.get('p') not in ('quarantine', 'reject'):
                        self.results['dmarc']['issues'].append('DMARC policy not properly configured')
                    if tags.get('sp') == 'none':
                        self.results['dmarc']['issues'].append('Subdomain policy is set to none')
                    pct = tags.get('pct', '100')
                    if not pct.isdigit() or not 0 <= int(pct) <= 100:
                        self.results['dmarc']['issues'].append('Invalid DMARC percentage')
                    elif int(pct) < 100:
                        self.results['dmarc']['issues'].append(f'DMARC only applies to {pct}% of emails')
                    break
            
            if not self.results['dmarc']['found'] and self.results['dmarc']['status'] != 'error':
                self.results['dmarc']['issues'].append('No DMARC record found')
                
        except dns.exception.DNSException:
            self.results['dmarc']['issues'].append('DNS lookup failed for DMARC record')
    
    def check_mx(self) -> None:
        """Check MX records for the domain"""
        try:
            mx_records = self.query('mx', self.domain, 'MX')
            self.results['mx']['found'] = bool(mx_records)
            
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
            mx_records = self.query('null_mx', self.domain, 'MX')
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
            answers = self.query('mta_sts', mta_sts_domain, 'TXT')
            
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
            answers = self.query('tls_rpt', tls_rpt_domain, 'TXT')
            
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
                    answers = self.query('bimi', bimi_domain, 'TXT')
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
        """Discover DNSKEY only; no trust-chain or signature validation."""
        result = self.results['dnssec']
        answer = self.query('dnssec', self.domain, 'DNSKEY')
        result['signed'] = None if result['status'] == 'error' else bool(answer)
        result['validated'] = None
        result['issues'] = ['DNSSEC signatures and chain of trust were not validated']

    def check_wildcards(self) -> None:
        """Sample literal wildcard records; preserve lookup failures."""
        result = self.results['wildcards']
        for kind in ('A', 'MX'):
            if self.query('wildcards', f'*.{self.domain}', kind):
                result['found'] = True
                result['issues'].append(f'Wildcard {kind} record discovered')
        result['status'] = 'partial' if result.get('errors') else 'ok'

    def check_subdomains(self) -> None:
        """Sample local records only; never treat a lookup error as absence."""
        common_subdomains = ['mail', 'email', 'smtp', 'mx', 'webmail', 'autodiscover',
                             'cpanel', 'webdisk', 'ftp', 'cpcalendars', 'cpcontacts']
        result = self.results['subdomains']
        for subdomain in common_subdomains:
            name = f'{subdomain}.{self.domain}'
            result['checked'].append(name)
            if not self.query('subdomains', name, 'A'):
                continue
            before_errors = len(result.get('errors', []))
            spf = self.query('subdomains', name, 'TXT')
            dmarc = self.query('subdomains', f'_dmarc.{name}', 'TXT')
            if len(result.get('errors', [])) > before_errors:
                continue
            has_spf = any(b''.join(record.strings).startswith(b'v=spf1') for record in spf)
            has_dmarc = any(b''.join(record.strings).startswith(b'v=DMARC1') for record in dmarc)
            if not has_spf and not has_dmarc:
                result['vulnerable'].append({
                    'subdomain': name,
                    'reason': 'No local SPF or DMARC discovered; parent DMARC policy not assessed',
                })
        result['status'] = 'partial' if result.get('errors') else 'ok'

    def check_open_relay(self) -> None:
        """Probe envelope acceptance only, never submit DATA."""
        result = self.results['open_relay']
        hosts = [mx['host'] for mx in self.results['mx']['records'] if mx['host']]
        if not hosts:
            result['status'] = 'unavailable'
            result['issues'].append('No usable MX hosts; relay behavior is unknown')
            return
        result['tested'] = True
        test_cases = [
            ('external@malicious.com', 'victim@target.com'),
            ('test%victim@target.com@malicious.com', 'victim@target.com'),
            ('test@victim@target.com', 'victim@target.com'),
            ('@malicious.com:victim@target.com', 'victim@target.com'),
        ]
        accepted = False
        incomplete = False
        for host in hosts[:3]:
            entry = {'server': host, 'vulnerable': None, 'test_results': []}
            result['tested_servers'].append(entry)
            server = None
            host_accepted = False
            host_incomplete = False
            try:
                server = smtplib.SMTP(timeout=10)
                code, _ = server.connect(host, 25)
                if code != 220:
                    raise smtplib.SMTPException('Server did not greet successfully')
                code, _ = server.helo('spoofaloof-scanner.example.com')
                if not 200 <= code < 300:
                    raise smtplib.SMTPException('HELO rejected')
                for sender, recipient in test_cases:
                    code, _ = server.mail(sender)
                    if not 200 <= code < 300:
                        host_incomplete = True
                        entry['test_results'].append(f'MAIL FROM not accepted ({code}); RCPT not tested')
                    else:
                        code, _ = server.rcpt(recipient)
                        if 200 <= code < 300:
                            host_accepted = True
                            entry['test_results'].append('Potential relay: RCPT accepted; delivery not tested')
                        elif 500 <= code < 600:
                            entry['test_results'].append(f'RCPT rejected ({code})')
                        else:
                            host_incomplete = True
                            entry['test_results'].append(f'Inconclusive RCPT response ({code})')
                    code, _ = server.rset()
                    if not 200 <= code < 300:
                        raise smtplib.SMTPException('RSET rejected')
            except (smtplib.SMTPException, OSError) as exc:
                host_incomplete = True
                entry['test_results'].append(f'Probe incomplete: {exc}')
            finally:
                if server is not None:
                    try:
                        server.quit()
                    except (smtplib.SMTPException, OSError):
                        server.close()
            entry['vulnerable'] = True if host_accepted else (None if host_incomplete else False)
            entry['status'] = 'potential_relay' if host_accepted else ('error' if host_incomplete else 'not_observed')
            accepted |= host_accepted
            incomplete |= host_incomplete
        result['vulnerable'] = True if accepted else (None if incomplete else False)
        result['status'] = 'potential_relay' if accepted else ('error' if incomplete else 'not_observed')
        if incomplete:
            result['issues'].append('Some SMTP probes were inconclusive')

    def assess_vulnerabilities(self) -> None:
        """Score observed configuration signals, never failed or unrun checks."""
        signals = []
        r = self.results

        def known(check):
            return r[check].get('status') in ('ok', 'absent')

        def add(check, weight, evidence):
            signals.append({'check': check, 'weight': weight, 'evidence': evidence})

        if known('spf'):
            if not r['spf']['found']:
                add('spf', 7.0, 'No SPF record discovered')
            else:
                for issue in r['spf']['issues']:
                    if '+all' in issue:
                        add('spf', 8.5, 'SPF permits all senders (+all)')
                    elif '?all' in issue:
                        add('spf', 6.0, 'SPF neutral all mechanism (?all)')
                    elif 'Multiple SPF' in issue:
                        add('spf', 3.0, 'Multiple SPF records')
                count = r['spf']['lookup_count']
                if count > 10:
                    add('spf', 4.0, 'Estimated SPF DNS lookups exceed 10')
                elif count > 6:
                    add('spf', 2.0, 'Estimated SPF DNS lookups approaching 10')
        tags = self.tags(r['dmarc']['record'] or '')
        if known('dmarc'):
            if not r['dmarc']['found']:
                add('dmarc', 7.5, 'No local DMARC record discovered; parent policy not assessed')
            else:
                if tags.get('p') == 'none':
                    add('dmarc', 6.5, 'DMARC monitoring policy (p=none)')
                if tags.get('sp') == 'none':
                    add('dmarc', 5.0, 'DMARC subdomain monitoring policy (sp=none)')
                pct = tags.get('pct', '100')
                if pct.isdigit() and 0 <= int(pct) < 100:
                    add('dmarc', 4.0, 'DMARC percentage below 100')
        if known('spf') and known('dmarc'):
            if not r['spf']['found'] and not r['dmarc']['found']:
                add('combination', 9.5, 'Neither SPF nor local DMARC discovered')
            if r['spf']['found'] and not r['dmarc']['found'] and any('+all' in x for x in r['spf']['issues']):
                add('combination', 9.0, 'SPF +all and no local DMARC')
            if r['spf']['found'] and r['dmarc']['found'] and tags.get('p') == 'none':
                add('combination', 7.5, 'SPF with DMARC monitoring policy')
        if known('mx'):
            if not r['mx']['found'] and not r['null_mx']['found']:
                add('mx', 1.5, 'No MX record discovered')
            for issue in r['mx']['issues']:
                if 'self-hosted' in issue:
                    add('mx', 2.0, issue)
        if known('mta_sts') and not r['mta_sts']['found']:
            add('mta_sts', 3.5, 'No MTA-STS TXT record discovered')
        if known('dnssec') and r['dnssec']['signed'] is False:
            add('dnssec', 4.0, 'No DNSKEY discovered at queried name; chain not validated')
        for issue in r['wildcards']['issues']:
            add('wildcards', 7.0 if 'MX' in issue else 3.0, issue)
        count = len(r['subdomains']['vulnerable'])
        if count:
            add('subdomains', 5.0 if count >= 5 else 3.5 if count >= 3 else 2.5,
                f'{count} sampled subdomains without local SPF/DMARC; parent policy not assessed')
        if r['open_relay']['vulnerable'] is True:
            add('open_relay', 8.0, 'Potential relay: RCPT accepted; delivery not tested')
        weights = [s['weight'] for s in signals]
        if weights:
            highest = max(weights)
            score = 0.7 * highest + 0.3 * sum(weights) / len(weights)
            score = max(score, 8.0 if highest >= 8 else 7.0 if highest >= 7 else 0.0)
            score = round(min(10.0, score), 1)
        else:
            score = 0.0 if any(known(c) for c in ('spf', 'dmarc', 'mx', 'mta_sts', 'dnssec')) else None
        r['score_signals'] = signals
        r['vulnerabilities'] = [s['evidence'] for s in signals]
        r['vulnerability_score'] = score
        r['risk_level'] = ('Unknown' if score is None else 'Low' if score <= 2 else
                           'Medium' if score <= 4 else 'High' if score <= 7 else 'Critical')
        r['assessment_incomplete'] = True
        r['score_method'] = 'heuristic-v2-observed-signals'
        r['limitations'] = [
            'Score covers observed configuration signals, not delivery or exploitability; unknowns are unscored.',
            'DKIM selector discovery is incomplete; keys and message signatures are not validated.',
            'DNSSEC chain/signatures and MTA-STS HTTPS policy/TLS enforcement are not validated.',
            'SPF evaluation and DMARC parsing are limited; parent DMARC policy is not discovered.',
            'SMTP is envelope-only when opted in; no message delivery is tested.',
        ]

    def generate_text_report(self, include_remediation: bool = False) -> str:
        r = self.results
        score = r['vulnerability_score']
        lines = [f'Spoofaloof report: {self.domain}',
                 f'Heuristic score: {score if score is not None else "Unknown"} / 10',
                 f'Risk band: {r["risk_level"]}',
                 'Assessment is incomplete. A low score is not proof of protection.', '']
        for name in ('spf', 'dkim', 'dmarc', 'mx', 'null_mx', 'mta_sts', 'dnssec',
                     'bimi', 'tls_rpt', 'wildcards', 'subdomains', 'open_relay'):
            result = r[name]
            status = result.get('status', 'not_checked')
            if status == 'ok' and 'found' in result:
                status = 'record discovered' if result['found'] else 'record not discovered'
            lines.append(f'{name.upper()}: {status}')
            for issue in result.get('issues', []) + result.get('errors', []):
                lines.append(f'  {issue}')
            record = result.get('record') or result.get('policy')
            if record:
                lines.append(f'  {record}')
            for match in result.get('selectors_checked', []):
                lines.append(f'  Selector {match["selector"]}: {match["record"]}')
            for mx in result.get('records', []):
                lines.append(f'  MX {mx["priority"]} {mx["host"] or "."}')
            for server in result.get('tested_servers', []):
                lines.append(f'  {server["server"]}: {server["status"]}')
                lines.extend(f'    {detail}' for detail in server['test_results'])
        lines.append(f'DNSKEY discovered: {r["dnssec"]["signed"]}; DNSSEC validation: not performed')
        lines.append('MTA-STS: TXT discovery only; HTTPS policy and TLS enforcement not tested')
        lines.append('SMTP: skipped unless explicitly enabled; RCPT acceptance does not prove relay delivery')
        lines.append('')
        for signal in r.get('score_signals', []):
            lines.append(f'  [{signal["weight"]}] {signal["evidence"]}')
        lines.extend(r.get('limitations', []))
        if include_remediation:
            lines.append('')
            lines.append('Remediation guidance: validate findings against authorized DNS evidence and actual mail flows.')
            for name in ('spf', 'dmarc', 'mta_sts'):
                if r[name].get('status') in ('ok', 'absent') and not r[name]['found']:
                    lines.append(f'  Review missing {name.upper()} configuration with the domain/mail administrator.')
            if r['dmarc']['found']:
                lines.append('  Validate legitimate sender alignment and review reports before tightening DMARC policy.')
            if r['open_relay']['vulnerable'] is True:
                lines.append('  Corroborate potential relay behavior in an owned lab before changing relay permissions.')
        return '\n'.join(lines)

    def run(self, skip_open_relay: bool = True, *, probe_smtp: bool = False) -> Dict:
        """Run checks; SMTP requires explicit opt-in (including legacy skip=False)."""
        self.__init__(self.domain, self.dkim_selectors)
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
        if probe_smtp or not skip_open_relay:
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
    smtp_flags = parser.add_mutually_exclusive_group()
    smtp_flags.add_argument('--probe-smtp', action='store_true', help='Opt in to active SMTP envelope probes on up to three MX hosts')
    smtp_flags.add_argument('--skip-open-relay', action='store_true', help='Explicit DNS-only mode (the default)')
    parser.add_argument('--dkim-selector', action='append', help='Query this known DKIM selector instead of common guesses; repeat for multiple selectors')
    
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
    try:
        checker = Spoofaloof(args.domain, dkim_selectors=args.dkim_selector)
    except ValueError as exc:
        parser.error(str(exc))
    
    try:
        # Run checks
        results = checker.run(probe_smtp=args.probe_smtp)
        
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