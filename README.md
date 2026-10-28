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

**SMTP probing is disabled by default.** Normal runs perform DNS queries only. Use `--probe-smtp` only when active SMTP testing is explicitly in scope. The legacy `--skip-open-relay` flag remains accepted as an explicit DNS-only choice and cannot be combined with `--probe-smtp`.

When enabled, the tool connects to TCP port 25 on up to the first three usable returned MX hosts, with a 10-second socket timeout. It sends `HELO`, `MAIL FROM`, `RCPT TO`, `RSET` and `QUIT` commands using four hard-coded envelope-address cases. These include external addresses that are not configurable through the CLI. It does **not** issue `DATA` or submit a message body, but it actively contacts mail servers and may trigger logging or alerts.

The Python API also defaults to DNS-only: `checker.run()`. Explicit `checker.run(probe_smtp=True)` opts in. For compatibility, explicitly passing `skip_open_relay=False` also opts in; existing callers using that argument should review their scope.

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

# Query known selectors instead of the common-selector guesses (repeatable)
python3 spoofaloof.py "$DOMAIN" --dkim-selector rotated.2026 --dkim-selector other

# Active SMTP envelope testing, only with explicit authorization
python3 spoofaloof.py "$DOMAIN" --probe-smtp

# All available options (does not run checks)
python3 spoofaloof.py --help
```

`--remediate` adds evidence-aware review guidance to the text report; it does not change DNS or server configuration, and does not add remediation fields to JSON. Review suggestions against your actual mail flows before applying them.

## What it checks

| Check | Current implementation |
| --- | --- |
| SPF | Finds `v=spf1` TXT records; flags selected policy patterns and multiple records; estimates DNS lookups from strings in the first record. |
| DKIM | Queries supplied selectors or 67 common guesses at `<selector>._domainkey.<domain>`. Discovers nonempty `p=` records for RSA/Ed25519, including an omitted optional version tag; key validity is not tested. |
| DMARC | Looks for `v=DMARC1` at `_dmarc.<domain>` and checks policy, subdomain-policy and percentage strings. |
| MX / null MX | Lists MX hosts, flags hosts within the assessed domain, and separately checks for a null MX record. |
| MTA-STS | Looks for a `v=STSv1` TXT record at `_mta-sts.<domain>` and an `id=` field. |
| DNSSEC | Discovers DNSKEY records only. `validated` is always `null`; no signature or trust-chain validation is performed. |
| BIMI / TLS-RPT | Looks for BIMI TXT records at `default._bimi` and `_bimi`, and TLS-RPT at `_smtp._tls`. These do not contribute to the score. |
| Wildcards | Queries the literal `*.<domain>` for A and MX records. |
| Subdomains | Tries 11 fixed names; flags those with an A response and neither a local SPF nor a local DMARC record. |
| SMTP relay | Only with explicit opt-in, treats a 2xx `RCPT TO` response after accepted `MAIL FROM` as a potential relay finding. Connection failures and temporary errors remain inconclusive; no delivery is attempted. |

### Selector and subdomain coverage

The default guesses include `default`, `selector1`, `selector2`, `google` and provider-specific names; see `check_dkim()` in [spoofaloof.py](spoofaloof.py). Repeat `--dkim-selector` to query known selectors **instead of** those guesses. Dotted selectors are supported; invalid or empty DNS labels are rejected before queries run.

Selectors cannot generally be enumerated. Custom, rotated or otherwise unlisted selectors can be missed; **no selector match does not mean DKIM is absent** and adds no score penalty. Obtain actual selectors from the provider or a legitimate message's `DKIM-Signature` header, then verify the keys and signatures separately. Empty `p=` values are reported as revoked keys, not usable matches.

For compatibility, `dkim.selectors_checked` retains successful record matches. `selectors_attempted` lists every queried selector; `errors` preserves lookup failures; `status` distinguishes `ok`, `partial`, `no_match` and `error`. `coverage_complete` stays false even when a key is discovered.

Subdomain coverage is limited to `mail`, `email`, `smtp`, `mx`, `webmail`, `autodiscover`, `cpanel`, `webdisk`, `ftp`, `cpcalendars` and `cpcontacts`. It is not asset discovery, and A-only existence checks can miss other mail-relevant names.

## Scoring methodology

The `vulnerability_score` is a project-specific **triage heuristic**, not CVSS, an exploitability probability or a measure of message-delivery success. It combines email-authentication and broader mail/DNS configuration signals. The risk labels describe the tool's score bands only.

`assess_vulnerabilities()` in [spoofaloof.py](spoofaloof.py) builds a list of signal weights and calculates:

```text
raw score = 0.7 × highest weight + 0.3 × mean of all weights
if highest weight >= 8.0: apply a minimum score of 8.0
else if highest weight >= 7.0: apply a minimum score of 7.0
cap at 10.0, then round to one decimal place
no scored signals with at least one completed core observation: 0.0
no completed core observation and no scored signals: null / Unknown
```

Selected weights in the current implementation:

| Signal | Weight |
| --- | ---: |
| SPF not found / SPF `+all` / SPF `?all` | 7.0 / 8.5 / 6.0 |
| Multiple SPF records | 3.0 |
| No DKIM match among queried selectors | Unscored: deployment unknown |
| DMARC not found | 7.5 |
| SPF and DMARC both not found | Additional 9.5 |
| SPF `+all` with no DMARC | Additional 9.0 |
| SPF found and exact DMARC `p` tag is `none` | Additional 7.5 |
| DMARC `p=none` / `sp=none` / valid `pct` below 100 | 6.5 / 5.0 / 4.0 |
| Estimated SPF lookups: 7–10 / above 10 | 2.0 / 4.0 |
| MX host within the assessed domain | 2.0 per flagged host |
| MTA-STS TXT record not found | 3.5 |
| DNSKEY not found after a completed lookup | 4.0 (discovery heuristic only) |
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

### Evidence, unknowns and compatibility

`score_method` is `heuristic-v2-observed-signals`. `score_signals` exposes each contributing check, weight and evidence, so the result can be audited. The formula and bands are retained, but signal handling changed: DKIM discovery misses and unperformed DNSSEC validation are unscored, DNS errors do not become missing-control penalties, SPF estimates of 7–10 receive 2.0 rather than 4.0, and exact DMARC tags drive the policy weights. `sp=none` no longer triggers the separate `p=none` combination.

Core DNS checks distinguish a completed query (`ok`), negative answer (`absent`), lookup failure (`error`) and an unrun check (`not_checked`). A completed TXT query can still contain no relevant policy; inspect `found` with `status`. Multi-query checks preserve failures in `errors`. Unknowns are unscored, so **incomplete evidence can lower a score**. `assessment_incomplete` is always true because this tool never verifies end-to-end authentication or delivery; read `limitations`, per-check `issues`, and `errors` alongside the score.

JSON consumers must handle `vulnerability_score: null` and `risk_level: "Unknown"` when no core scored checks completed and no signals were observed. `dnssec.validated` is always `null`; `dnssec.signed` is only a legacy DNSKEY-discovery flag and is `null` on lookup error. `open_relay.vulnerable` is `null` when skipped or inconclusive, `true` for potential acceptance, and `false` only when all sampled envelope cases were rejected. Neither boolean proves message-delivery behavior. The text report mirrors these states and provides review guidance rather than unsupported enforcement assurances.

Compare scores only with the tool revision, method, queried selectors and scope recorded. Results from the prior scoring implementation are not directly comparable without reviewing the signal set.

## Limitations and interpretation

- **DNS observations are a snapshot.** Core lookup failures are recorded separately from negative answers; even negative answers depend on the resolver and queried name. Record the resolver, time and raw responses when validating a finding; distinguish absence from lookup failure.
- **SPF analysis is approximate.** It does not evaluate a sender IP or recursively follow `include` / `redirect` records, and its string-based lookup count is not an RFC-complete evaluation. See [SPF DNS lookup limits](https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.4).
- **Record discovery is not message authentication.** DKIM key validity, actual signing, signature verification and SPF/DKIM alignment with the visible From domain are not tested. DMARC scoring uses exact semicolon-delimited tags, but this is not a full policy validator or organizational-domain discovery process. Parent DMARC policy may apply to a subdomain; a missing local record or `sp` tag alone does not establish lack of protection. See [DMARC policy discovery](https://www.rfc-editor.org/rfc/rfc7489.html#section-6.6.3).
- **Transport and DNS checks are limited.** MTA-STS checks do not fetch the HTTPS policy or test TLS/certificates; `mta_sts.policy` holds the DNS TXT string. DNSSEC's `validated` field remains `null`; neither DNSKEY presence nor absence at the queried name establishes a validated chain or a zone's security. See [MTA-STS policy validation](https://www.rfc-editor.org/rfc/rfc8461.html#section-4).
- **Relay results need corroboration.** RCPT acceptance alone does not prove that a server will relay a completed message. Connection failures, failed SMTP preconditions and temporary replies are inconclusive. Inspect `status`, `tested` and `open_relay.tested_servers[].test_results`. `not_observed` describes only the sampled envelope cases; no server receives a message body.
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
    "status": "absent",
    "issues": ["No DMARC record found"]
  },
  "open_relay": {
    "tested": false,
    "vulnerable": null,
    "status": "skipped",
    "tested_servers": [],
    "issues": []
  }
}
```

An absent TXT answer is distinct from a resolver failure (`status: "error"`). This scenario assumes a negative answer corroborated by the owned lab zone.

The contributing weights are `[7.5, 3.5, 4.0]`: the weighted calculation is 6.75, raised to the 7.0 floor. `vulnerable: null` and `tested: false` mean relay testing was not performed.

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
| DMARC issues | `No DMARC record found` | Empty list |
| Scoring weights | `[7.5, 3.5, 4.0]` | `[3.5, 4.0]` |
| Tool score / label | **7.0 / High** | **3.9 / Medium** |
| SMTP relay coverage | Skipped | Skipped |

The expected 3.9 score reflects remaining MTA-STS and DNSSEC signals, not a failed DMARC fix. Close the configuration finding only after confirming the intended DNS policy and independently checking legitimate-mail authentication plus handling of controlled, failing messages at owned receivers. Preserve timestamps, tool revision, command flags, raw DNS evidence and relevant receiver headers/logs. A changed score alone is not proof of enforcement or successful remediation.

## Offline tests

After installing the dependency, run:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile spoofaloof.py
```

Tests replace the DNS resolver and SMTP transport with controlled fixtures. They never probe external domains or mail servers. Coverage includes default/opt-in CLI behavior, custom and revoked DKIM selectors, DNS failures versus absence, truthful DNSSEC/MTA-STS output, SMTP transaction outcomes, scoring evidence and synthetic before/after scores.

## License

This project is licensed under the BSD 3-Clause License. See [LICENSE](LICENSE) for details.
