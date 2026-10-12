# Security tool research and adoption — 2026-10-12

[한국어](ko/TOOL_RESEARCH.md) · [Documentation index](README.md)

This comparison uses official documentation. Guard adopts design and operational
ideas; it does not claim protocol or rule compatibility with these tools.

| Tool | Relevant capabilities | Adoption in hangang-guard |
| --- | --- | --- |
| CrowdSec | Conditional filters, source buckets, distinct events, separation of detection/remediation, allowlisting | Per-IP window scores, threshold/BCL, observe/enforce, allowlist precedence; distinct patterns and multiple scenarios remain future work |
| Fail2Ban | findtime/maxretry/bantime, configurable filters/actions | Window/threshold/TTL policies, immediate admin policy changes, expiration/unblocking |
| BunkerWeb | IP/ASN/country blacklists, bad behavior detection, administration | IPv4/IPv6 CIDRs, GeoIP/ASN, dynamic network/country/ASN rules, inspection/scoring UI; bot challenges/CAPTCHA remain future work |
| OWASP Coraza/CRS | Rule IDs/priorities, observation mode, anomaly scores, phase-based inspection | Rule ID/priority/reason, risk scores/suspicion stages, validation and atomic application; full request/body WAF compatibility is separate work |
| MaxMind | Offline MMDB, country/city/ASN, metadata/accuracy radius | Local lookup, database status, last-good reload, admin inspection |

Primary sources:

- [CrowdSec scenarios](https://docs.crowdsec.net/docs/log_processor/scenarios/intro/)
- [CrowdSec whitelists](https://docs.crowdsec.net/u/getting_started/post_installation/whitelists/)
- [Fail2Ban client manual](https://github.com/fail2ban/fail2ban/blob/master/man/fail2ban-client.1)
- [BunkerWeb features](https://docs.bunkerweb.io/latest/features/)
- [BunkerWeb security tuning](https://docs.bunkerweb.io/security-tuning/)
- [Coraza actions](https://coraza.io/docs/seclang/actions/)
- [Coraza internals](https://www.coraza.io/docs/reference/internals/)
- [MaxMind accuracy](https://support.maxmind.com/knowledge-base/articles/maxmind-geolocation-accuracy)

GeoIP estimates network geography, not exact personal location. Handle unknown
metadata separately. Country or ASN alone is not automatic proof of maliciousness.

## Rule runtime decision

Embed Lua 5.4 in Rust, executing only when administrators apply configuration.
Lua returns a RuleSet table, validated and compiled into internal decision indexes.
No Lua VM is created and no script executes per query. JSON RuleSets use the same
validation/publication path.

Limits: 32 KiB script, 4 MiB Lua memory, approximately 100,000 instructions and a
50 ms execution hook budget; no filesystem/network/process APIs. Rules contain
ID, priority, conditions (CIDR/country/ASN), score, action and optional expiration.
See [RULES.md](RULES.md) for the implemented schema, precedence and suspicion stages.

Keep per-IP and CIDR aggregate scores distinct. Suspicion of some IPs must not
silently cause automatic blocking of their whole network. CIDR inspection shows
unique IP count, sum and maximum per-IP signal score to inform scope review.
