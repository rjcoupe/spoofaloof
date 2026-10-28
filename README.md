# Spoofaloof

A Python command-line tool for triaging email-authentication configuration. Spoofaloof inspects SPF, DKIM and DMARC DNS records, collects related mail-security signals, and produces a text or JSON report with a heuristic score.

Use it to identify configuration questions for an authorized assessment, plan remediation and compare retests. A finding is a lead to validate, not proof that a spoofed message will be delivered.

## Installation

1. Clone or download this project.
2. Create a Python 3 virtual environment and install the dependency:

```bash
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Scope and network activity

Only assess domains and infrastructure you own or have permission to test. Include third-party mail hosting in the agreed scope; permission to inspect a domain does not automatically cover its provider's SMTP servers.

**SMTP probing is enabled by default.** Alongside DNS queries, the tool connects to TCP port 25 on up to the first three returned MX hosts, with a 10-second socket timeout. It sends `HELO`, `MAIL FROM`, `RCPT TO`, `RSET` and `QUIT` commands using four hard-coded envelope-address cases. These include external addresses that are not configurable through the CLI. It does **not** issue `DATA` or submit a message body, but it does actively contact mail servers and may trigger logging or alerts.

Use `--skip-open-relay` for DNS-only checks. This disables SMTP connections, not DNS traffic. Omit the flag only when active SMTP testing is explicitly in scope.

## Usage

The examples use a placeholder for an owned lab domain. Replace it with your authorized domain and ensure your resolver can resolve it:

```bash
DOMAIN='mail-lab.test'

# Text report, without SMTP probing
python3 spoofaloof.py "$DOMAIN" --skip-open-relay

# JSON report for evidence capture or comparison
python3 spoofaloof.py "$DOMAIN" --skip-open-relay --json > report.json

# Text report with basic remediation suggestions and no ANSI colors
python3 spoofaloof.py "$DOMAIN" --skip-open-relay --remediate --no-color

# All available options (does not run checks)
python3 spoofaloof.py --help
```

`--remediate` adds suggestions to the text report; it does not change DNS or server configuration, and does not add remediation fields to JSON. Review suggestions against your actual mail flows before applying them.

## What it checks

| Check | Current implementation |
| --- | --- |
| SPF | Finds `v=spf1` TXT records; flags selected policy patterns and multiple records; estimates DNS lookups from strings in the first record. |
| DKIM | Queries 67 fixed common selectors at `<selector>._domainkey.<domain>` and recognizes TXT records containing `v=DKIM1` or `k=rsa`. |
| DMARC | Looks for `v=DMARC1` at `_dmarc.<domain>` and checks policy, subdomain-policy and percentage strings. |
| MX / null MX | Lists MX hosts, flags hosts within the assessed domain, and separately checks for a null MX record. |
| MTA-STS | Looks for a `v=STSv1` TXT record at `_mta-sts.<domain>` and an `id=` field. |
| DNSSEC | Looks for DNSKEY records, then performs an ordinary A lookup. This is not cryptographic DNSSEC validation. |
| BIMI / TLS-RPT | Looks for BIMI TXT records at `default._bimi` and `_bimi`, and TLS-RPT at `_smtp._tls`. These do not contribute to the score. |
| Wildcards | Queries the literal `*.<domain>` for A and MX records. |
| Subdomains | Tries 11 fixed names; flags those with an A response and neither a local SPF nor a local DMARC record. |
| SMTP relay | Unless skipped, treats a 2xx response to any tested `RCPT TO` as a potential relay finding. No end-to-end relay delivery is attempted. |

### Selector and subdomain coverage

DKIM selectors include `default`, `selector1`, `selector2`, `google` and provider-specific guesses. The complete list is in `check_dkim()` in [spoofaloof.py](spoofaloof.py). There is no custom-selector CLI option. Custom, rotated or otherwise unlisted selectors can be missed; **no common-selector match does not mean DKIM is absent**. Obtain the actual selector from the mail provider or a legitimate message's `DKIM-Signature` header, then verify that record and the signature separately. The JSON field `dkim.selectors_checked` contains successful matches, not every attempted selector.

Subdomain coverage is limited to `mail`, `email`, `smtp`, `mx`, `webmail`, `autodiscover`, `cpanel`, `webdisk`, `ftp`, `cpcalendars` and `cpcontacts`. It is not asset discovery, and A-only existence checks can miss other mail-relevant names.

## Scoring methodology

The `vulnerability_score` is a project-specific **triage heuristic**, not CVSS, an exploitability probability or a measure of message-delivery success. It combines email-authentication and broader mail/DNS configuration signals. The risk labels describe the tool's score bands only.

`assess_vulnerabilities()` in [spoofaloof.py](spoofaloof.py) builds a list of signal weights and calculates:

```text
raw score = 0.7 × highest weight + 0.3 × mean of all weights
if highest weight >= 8.0: apply a minimum score of 8.0
else if highest weight >= 7.0: apply a minimum score of 7.0
cap at 10.0, then round to one decimal place
no scored signals: 0.0
```

Selected weights in the current implementation:

| Signal | Weight |
| --- | ---: |
| SPF not found / SPF `+all` / SPF `?all` | 7.0 / 8.5 / 6.0 |
| Multiple SPF records | 3.0 |
| No DKIM match among common selectors | 4.0 |
| DMARC not found | 7.5 |
| SPF and DMARC both not found | Additional 9.5 |
| SPF `+all` with no DMARC | Additional 9.0 |
| SPF found and DMARC record contains `p=none` | Additional 7.5 |
| MX host within the assessed domain | 2.0 per flagged host |
| MTA-STS TXT record not found | 3.5 |
| DNSKEY not found | 4.0 |
| Wildcard A / MX record | 3.0 / 7.0 |
| Flagged subdomains: 1–2 / 3–4 / 5 or more | 2.5 / 3.5 / 5.0 |
| Potential relay acceptance | 8.0 |

Combination weights are appended alongside individual weights, not substituted or summed into the final score. The mean depends on the detected signal set, so score changes need to be interpreted alongside the underlying evidence.

| Score | Label |
| --- | --- |
| 0.0–2.0 | Low |
| 2.1–4.0 | Medium |
| 4.1–7.0 | High |
| 7.1–10.0 | Critical |

### Current scoring caveats

Issue-to-score mapping uses string matching rather than structured findings. In particular:

- An SPF estimate of 7–10 lookups produces an “approaching limit” issue, but currently receives the same 4.0 weight and “exceeds” summary as an estimate above 10.
- The normal DMARC `p=none`, `sp=none` and partial-percentage warning text does not match its corresponding scoring branches. The separate SPF-plus-`p=none` combination still applies; its substring check can also match `sp=none`.
- Some issues are unscored. A lower score or an empty vulnerability list does not mean every check passed. Skipping SMTP adds no score penalty and leaves relay behavior unknown.

Review the per-check records and `issues`, not only the score or generated vulnerability wording.

## Limitations and interpretation

- **DNS observations are a snapshot.** Resolver failures can be reported as missing configuration or silently skipped by some checks. Record the resolver, time and raw responses when validating a finding; distinguish absence from lookup failure.
- **SPF analysis is approximate.** It does not evaluate a sender IP or recursively follow `include` / `redirect` records, and its string-based lookup count is not an RFC-complete evaluation. See [SPF DNS lookup limits](https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.4).
- **Record discovery is not message authentication.** DKIM key validity, actual signing, signature verification and SPF/DKIM alignment with the visible From domain are not tested. DMARC checks are simple string checks, not a full policy parser or organizational-domain discovery process. Parent DMARC policy may apply to a subdomain; a missing local record or `sp` tag alone does not establish lack of protection. See [DMARC policy discovery](https://www.rfc-editor.org/rfc/rfc7489.html#section-6.6.3).
- **Transport and DNS checks are limited.** MTA-STS checks do not fetch the HTTPS policy or test TLS/certificates; `mta_sts.policy` holds the DNS TXT string. DNSSEC's `validated` field does not establish a validated signature chain. In particular, the text report's “enforces TLS” and “DNSSEC is properly configured” wording exceeds what these checks establish. See [MTA-STS policy validation](https://www.rfc-editor.org/rfc/rfc8461.html#section-4).
- **Relay results need corroboration.** RCPT acceptance alone does not prove that a server will relay a completed message. Conversely, connection failure is not a clean result: inspect `open_relay.tested_servers[].test_results`, even if `tested` is true and `vulnerable` is false. When explicitly skipped, the text report still says “no MX records”; use the command flags and JSON `tested` field to establish test scope.
- **Context matters.** Self-hosted MX, wildcard DNS or a missing optional control does not by itself prove spoofability. The tool does not assess display-name spoofing, lookalike domains, receiver-specific filtering or successful delivery. Treat generated remediation as a starting point, not a deployment plan.

## Worked example: finding, remediation and retest

> **Illustrative owned-lab scenario, not an observed engagement or live test.** `mail-lab.test`, the documentation IP and all outcomes below are synthetic. The scores follow the current scoring function. This example demonstrates a reporting workflow, not evidence that a real domain was exploited or remediated.

### 1. Scope and initial finding

Assume an isolated, owned mail lab with these inputs:

- SPF: `v=spf1 ip4:192.0.2.10 -all` (documentation address; use the lab's real authorized sender in an actual test).
- A recognized DKIM record at the `default` selector. Its signing behavior remains a separate validation step.
- An owned MX host elsewhere in the isolated lab, outside `mail-lab.test`, with no MX issues; no wildcard or flagged subdomain results.
- No DMARC TXT record, no MTA-STS TXT record and no DNSKEY response.
- SMTP probing explicitly skipped.

**Finding:** No DMARC policy was discovered at `_dmarc.mail-lab.test` in this synthetic scenario. SPF and a discoverable DKIM record alone do not establish how a receiving system handles messages that fail DMARC. Delivery impact has not been demonstrated.

Illustrative JSON excerpt (selected fields only):

```json
{
  "domain": "mail-lab.test",
  "vulnerability_score": 7.0,
  "risk_level": "High",
  "dmarc": {
    "found": false,
    "record": null,
    "issues": ["DNS lookup failed for DMARC record"]
  },
  "open_relay": {
    "tested": false,
    "vulnerable": false,
    "tested_servers": [],
    "issues": []
  }
}
```

For an absent TXT answer, the current checker emits the generic DNS-lookup issue shown above. In a real assessment, distinguish confirmed record absence from a resolver problem before raising this finding; this scenario assumes the owned lab zone confirms absence.

The contributing weights are `[7.5, 3.5, 4.0]`: the weighted calculation is 6.75, raised to the 7.0 floor. `vulnerable: false` here does not mean relay testing passed; `tested: false` means it was not performed.

### 2. Remediation plan

Inventory legitimate senders, confirm SPF and DKIM alignment using messages sent only within the authorized lab, and review DMARC reports before tightening policy. A real rollout can begin with monitoring and progress to quarantine/reject after legitimate mail flows are accounted for; do not copy a reject policy into production without that validation.

For this hypothetical lab, the intended final TXT record at `_dmarc.mail-lab.test` is:

```text
v=DMARC1; p=reject; sp=reject; pct=100
```

Configure reporting to an approved mailbox you control when conducting a real rollout. This short illustrative record omits reporting destinations.

### 3. Retest and closure criteria

After the authorized DNS change has propagated, rerun the same scope and save both reports:

```bash
# Run before making the authorized change
python3 spoofaloof.py "$DOMAIN" --skip-open-relay --json > before.json

# Run after the change and DNS propagation
python3 spoofaloof.py "$DOMAIN" --skip-open-relay --json > after.json
```

| Evidence | Illustrative before | Expected after, with all other inputs unchanged |
| --- | --- | --- |
| DMARC record | Not found | `v=DMARC1; p=reject; sp=reject; pct=100` |
| DMARC issues | `DNS lookup failed for DMARC record` | Empty list |
| Scoring weights | `[7.5, 3.5, 4.0]` | `[3.5, 4.0]` |
| Tool score / label | **7.0 / High** | **3.9 / Medium** |
| SMTP relay coverage | Skipped | Skipped |

The expected 3.9 score reflects remaining MTA-STS and DNSSEC signals, not a failed DMARC fix. Close the configuration finding only after confirming the intended DNS policy and independently checking legitimate-mail authentication plus handling of controlled, failing messages at owned receivers. Preserve timestamps, tool revision, command flags, raw DNS evidence and relevant receiver headers/logs. A changed score alone is not proof of enforcement or successful remediation.

## License

This project is licensed under the BSD 3-Clause License. See [LICENSE](LICENSE) for details.
