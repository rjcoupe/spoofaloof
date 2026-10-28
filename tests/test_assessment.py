import contextlib
import io
import json
import unittest
from unittest.mock import patch

import dns.exception
import dns.resolver
import dns.rrset
import spoofaloof


def txt(value):
    return dns.rrset.from_text('lab.test.', 60, 'IN', 'TXT', '"' + value + '"')


def fixture(name, kind, **kwargs):
    records = {
        ('lab.test', 'TXT'): txt('v=spf1 ip4:192.0.2.10 -all'),
        ('lab.test', 'MX'): dns.rrset.from_text('lab.test.', 60, 'IN', 'MX', '10 mx.other.test.'),
        ('default._domainkey.lab.test', 'TXT'): txt('v=DKIM1; p=example'),
    }
    if (name, kind) in records:
        return records[name, kind]
    raise dns.resolver.NoAnswer()


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        # No test may reach a real DNS resolver or SMTP server.
        self.dns = patch('spoofaloof.dns.resolver.resolve', side_effect=fixture).start()
        self.smtp = patch('spoofaloof.smtplib.SMTP', side_effect=AssertionError('Unexpected SMTP')).start()
        self.addCleanup(patch.stopall)

    def test_default_run_never_connects_smtp(self):
        result = spoofaloof.Spoofaloof('lab.test').run()
        self.assertFalse(result['open_relay']['tested'])
        self.assertEqual(result['open_relay']['status'], 'skipped')

    def test_cli_default_and_explicit_skip_are_dns_only(self):
        for flags in ([], ['--skip-open-relay']):
            with self.subTest(flags=flags), patch('sys.argv', ['spoofaloof', 'lab.test', '--json'] + flags), contextlib.redirect_stdout(io.StringIO()) as output:
                spoofaloof.main()
                self.assertEqual(json.loads(output.getvalue())['open_relay']['status'], 'skipped')

    def test_dnskey_is_not_validation_and_does_not_query_a(self):
        self.dns.return_value = [object()]
        self.dns.side_effect = None
        s = spoofaloof.Spoofaloof('lab.test')
        s.check_dnssec()
        self.assertIsNone(s.results['dnssec']['validated'])
        self.assertTrue(s.results['dnssec']['signed'])
        self.dns.assert_called_once_with('lab.test', 'DNSKEY')
        self.assertNotIn('properly configured', s.generate_text_report())

    def test_all_timeouts_are_unknown_not_critical_or_clean(self):
        self.dns.side_effect = dns.exception.Timeout()
        s = spoofaloof.Spoofaloof('lab.test')
        r = s.run()
        self.assertIsNone(r['vulnerability_score'])
        self.assertEqual(r['risk_level'], 'Unknown')
        self.assertFalse(r['subdomains']['vulnerable'])
        self.assertFalse(r['score_signals'])
        self.assertIn('unknown', s.generate_text_report().lower())
        self.assertNotIn('Missing SPF Record:', s.generate_text_report(True))

    def test_absence_and_timeout_are_distinct(self):
        for exc, status in ((dns.resolver.NoAnswer(), 'absent'), (dns.resolver.NXDOMAIN(), 'absent'), (dns.exception.Timeout(), 'error')):
            with self.subTest(status=status):
                self.dns.side_effect = exc
                s = spoofaloof.Spoofaloof('lab.test')
                s.check_spf()
                self.assertEqual(s.results['spf']['status'], status)

    def test_custom_selector_recognizes_optional_version_and_ed25519(self):
        self.dns.side_effect = lambda name, kind: txt('k=ed25519; p=YWJj')
        s = spoofaloof.Spoofaloof('lab.test', dkim_selectors=['rotated.2026'])
        s.check_dkim()
        self.assertTrue(s.results['dkim']['found'])
        self.assertEqual(s.results['dkim']['selectors_attempted'], ['rotated.2026'])
        self.dns.assert_called_once_with('rotated.2026._domainkey.lab.test', 'TXT')

    def test_dkim_no_match_is_incomplete_and_unscored(self):
        self.dns.side_effect = dns.resolver.NoAnswer()
        s = spoofaloof.Spoofaloof('lab.test')
        s.check_dkim()
        s.assess_vulnerabilities()
        self.assertEqual(len(s.results['dkim']['selectors_attempted']), 67)
        self.assertEqual(s.results['dkim']['status'], 'no_match')
        self.assertFalse(s.results['dkim']['coverage_complete'])
        self.assertFalse(s.results['score_signals'])

    def test_revoked_dkim_is_not_a_usable_match(self):
        self.dns.side_effect = lambda *args: txt('v=DKIM1; p=')
        s = spoofaloof.Spoofaloof('lab.test', dkim_selectors=['default'])
        s.check_dkim()
        self.assertFalse(s.results['dkim']['found'])
        self.assertTrue(s.results['dkim']['issues'])

    def test_invalid_selector_rejected_before_dns(self):
        for selector in ('', 'bad..name', '-bad', 'bad/name', 'x' * 64):
            with self.subTest(selector=selector), self.assertRaises(ValueError):
                spoofaloof.Spoofaloof('lab.test', dkim_selectors=[selector])
        self.dns.assert_not_called()

    def test_synthetic_before_after_scores_and_evidence(self):
        s = spoofaloof.Spoofaloof('lab.test')
        r = s.run()
        self.assertEqual((r['vulnerability_score'], r['risk_level']), (7.0, 'High'))
        self.assertEqual(sorted(x['weight'] for x in r['score_signals']), [3.5, 4.0, 7.5])
        self.dns.side_effect = lambda name, kind, **kw: txt('v=DMARC1; p=reject; sp=reject; pct=100') if name == '_dmarc.lab.test' else fixture(name, kind, **kw)
        r = spoofaloof.Spoofaloof('lab.test').run()
        self.assertEqual((r['vulnerability_score'], r['risk_level']), (3.9, 'Medium'))
        self.assertTrue(r['assessment_incomplete'])

    def test_sp_none_is_not_parent_none_combination(self):
        self.dns.side_effect = lambda name, kind, **kw: txt('v=DMARC1; p=reject; sp=none') if name == '_dmarc.lab.test' else fixture(name, kind, **kw)
        r = spoofaloof.Spoofaloof('lab.test').run()
        weights = [x['weight'] for x in r['score_signals']]
        self.assertIn(5.0, weights)
        self.assertNotIn(7.5, weights)

    def test_dmarc_none_and_partial_policy_are_scored(self):
        self.dns.side_effect = lambda name, kind, **kw: txt('v=DMARC1; p=none; pct=50') if name == '_dmarc.lab.test' else fixture(name, kind, **kw)
        r = spoofaloof.Spoofaloof('lab.test').run()
        weights = [x['weight'] for x in r['score_signals']]
        self.assertIn(6.5, weights)
        self.assertIn(7.5, weights)
        self.assertIn(4.0, weights)

    def test_spf_approaching_limit_has_lower_weight(self):
        self.dns.side_effect = lambda name, kind, **kw: txt('v=spf1 ' + 'include:sender.test ' * 7 + '-all') if (name, kind) == ('lab.test', 'TXT') else fixture(name, kind, **kw)
        r = spoofaloof.Spoofaloof('lab.test').run()
        self.assertIn(2.0, [x['weight'] for x in r['score_signals'] if x['check'] == 'spf'])
        self.assertFalse(any('exceeds' in x for x in r['vulnerabilities']))

    def test_mta_sts_txt_does_not_claim_tls_enforcement(self):
        self.dns.side_effect = lambda name, kind, **kw: txt('v=STSv1; id=1') if name == '_mta-sts.lab.test' else fixture(name, kind, **kw)
        s = spoofaloof.Spoofaloof('lab.test')
        s.run()
        self.assertNotIn('enforces TLS', s.generate_text_report())

    def test_smtp_connection_failure_is_unknown(self):
        self.smtp.side_effect = OSError('offline refusal')
        s = spoofaloof.Spoofaloof('lab.test')
        r = s.run(probe_smtp=True)
        self.assertEqual(r['open_relay']['status'], 'error')
        self.assertIsNone(r['open_relay']['vulnerable'])
        self.assertNotIn('no relays detected', s.generate_text_report().lower())


class EdgeCaseTests(unittest.TestCase):
    setUp = AssessmentTests.setUp

    def test_reusing_checker_drops_old_observations(self):
        s = spoofaloof.Spoofaloof('lab.test')
        before = s.run()
        self.dns.side_effect = dns.exception.Timeout()
        after = s.run()
        self.assertIsNone(after['vulnerability_score'])
        self.assertFalse(after['spf']['found'])
        self.assertEqual(before['vulnerability_score'], 7.0)

    def test_timeout_report_does_not_call_spf_or_dmarc_missing(self):
        self.dns.side_effect = dns.exception.Timeout()
        s = spoofaloof.Spoofaloof('lab.test')
        s.run()
        report = s.generate_text_report()
        self.assertNotIn('No SPF record found', report)
        self.assertNotIn('No DMARC record found', report)

    def test_subdomain_dns_failure_is_recorded_not_scored(self):
        def resolve(name, kind, **kw):
            if name == 'mail.lab.test' and kind == 'A':
                return dns.rrset.from_text(name, 60, 'IN', 'A', '192.0.2.10')
            if name in ('mail.lab.test', '_dmarc.mail.lab.test'):
                raise dns.exception.Timeout()
            return fixture(name, kind, **kw)
        self.dns.side_effect = resolve
        r = spoofaloof.Spoofaloof('lab.test').run()
        self.assertFalse(r['subdomains']['vulnerable'])
        self.assertTrue(r['subdomains']['errors'])

    def test_score_floors_and_no_signals(self):
        for spf, expected in (('v=spf1 +all', (8.5, 'Critical')), ('v=spf1 -all', (0.0, 'Low'))):
            with self.subTest(spf=spf):
                def resolve(name, kind, **kw):
                    overrides = {
                        ('lab.test', 'TXT'): txt(spf),
                        ('_dmarc.lab.test', 'TXT'): txt('v=DMARC1; p=reject'),
                        ('_mta-sts.lab.test', 'TXT'): txt('v=STSv1; id=1'),
                        ('lab.test', 'DNSKEY'): [object()],
                    }
                    if (name, kind) in overrides:
                        return overrides[name, kind]
                    return fixture(name, kind, **kw)
                self.dns.side_effect = resolve
                r = spoofaloof.Spoofaloof('lab.test').run()
                self.assertEqual((r['vulnerability_score'], r['risk_level']), expected)
                self.assertTrue(r['assessment_incomplete'])

    def test_smtp_transactions_and_no_data(self):
        for mail_code, rcpt_code, status, vulnerable in ((250, 250, 'potential_relay', True), (250, 550, 'not_observed', False), (250, 450, 'error', None), (550, 250, 'error', None)):
            with self.subTest(mail=mail_code, rcpt=rcpt_code):
                server = FakeSMTP(mail_code, rcpt_code)
                self.smtp.side_effect = None
                self.smtp.return_value = server
                r = spoofaloof.Spoofaloof('lab.test').run(probe_smtp=True)
                self.assertEqual(r['open_relay']['status'], status)
                self.assertIs(r['open_relay']['vulnerable'], vulnerable)
                self.assertEqual(server.recipients, 4 if mail_code == 250 else 0)
                self.assertTrue(server.closed)

    def test_cli_opt_in_and_selector(self):
        self.smtp.side_effect = None
        self.smtp.return_value = FakeSMTP(250, 550)
        with patch('sys.argv', ['spoofaloof', 'lab.test', '--json', '--probe-smtp', '--dkim-selector', 'known']), contextlib.redirect_stdout(io.StringIO()) as out:
            spoofaloof.main()
        r = json.loads(out.getvalue())
        self.assertTrue(r['open_relay']['tested'])
        self.assertEqual(r['dkim']['selectors_attempted'], ['known'])

    def test_cli_conflicting_flags_rejected(self):
        with patch('sys.argv', ['spoofaloof', 'lab.test', '--probe-smtp', '--skip-open-relay']), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
            spoofaloof.main()
        self.assertEqual(exc.exception.code, 2)
        self.dns.assert_not_called()

    def test_partial_dkim_errors_preserve_match_and_uncertainty(self):
        def resolve(name, kind, **kw):
            if name == 'default._domainkey.lab.test':
                return txt('v=DKIM1; p=example')
            raise dns.exception.Timeout()
        self.dns.side_effect = resolve
        s = spoofaloof.Spoofaloof('lab.test', dkim_selectors=['default', 'other'])
        s.check_dkim()
        self.assertTrue(s.results['dkim']['found'])
        self.assertEqual(s.results['dkim']['status'], 'partial')
        self.assertEqual(len(s.results['dkim']['errors']), 1)

    def test_null_mx_is_not_probed(self):
        self.dns.side_effect = lambda name, kind, **kw: dns.rrset.from_text('lab.test.', 60, 'IN', 'MX', '0 .') if (name, kind) == ('lab.test', 'MX') else fixture(name, kind, **kw)
        r = spoofaloof.Spoofaloof('lab.test').run(probe_smtp=True)
        self.assertFalse(r['open_relay']['tested'])
        self.assertEqual(r['open_relay']['status'], 'unavailable')
        self.assertTrue(r['null_mx']['found'])

    def test_lookup_failure_does_not_mask_other_findings(self):
        self.dns.side_effect = lambda name, kind, **kw: (_ for _ in ()).throw(dns.exception.Timeout()) if name == '_dmarc.lab.test' else fixture(name, kind, **kw)
        r = spoofaloof.Spoofaloof('lab.test').run()
        self.assertEqual(r['vulnerability_score'], 3.9)
        self.assertFalse(any(x['check'] in ('dmarc', 'combination') for x in r['score_signals']))

    def test_dnskey_presence_is_not_scored_as_failed_validation(self):
        self.dns.side_effect = lambda *args, **kwargs: [object()]
        s = spoofaloof.Spoofaloof('lab.test')
        s.check_dnssec()
        s.assess_vulnerabilities()
        self.assertFalse(s.results['score_signals'])
        self.assertIsNone(s.results['dnssec']['validated'])

    def test_all_optional_timeouts_preserved(self):
        self.dns.side_effect = dns.exception.Timeout()
        r = spoofaloof.Spoofaloof('lab.test').run()
        for check in ('bimi', 'tls_rpt', 'wildcards', 'subdomains'):
            self.assertTrue(r[check]['errors'])
            self.assertIn(r[check]['status'], ('error', 'partial'))



class FakeSMTP:
    """Only envelope commands exist: DATA/sendmail calls fail the test."""
    def __init__(self, mail_code, rcpt_code):
        self.mail_code, self.rcpt_code = mail_code, rcpt_code
        self.recipients = 0
        self.closed = False

    def connect(self, host, port):
        assert host == 'mx.other.test' and port == 25
        return 220, b'ready'

    def helo(self, name):
        return 250, b'ok'

    def mail(self, sender):
        return self.mail_code, b'mail'

    def rcpt(self, recipient):
        self.recipients += 1
        return self.rcpt_code, b'rcpt'

    def rset(self):
        return 250, b'reset'

    def quit(self):
        self.closed = True


if __name__ == '__main__':
    unittest.main()
