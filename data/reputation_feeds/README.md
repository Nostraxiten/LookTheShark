# Local reputation feeds

Drop indicator lists in this folder and the `reputation` module will cross them
against every capture you analyze. **Nothing is ever queried online** — see
"Why offline" below.

## Format

Any `.txt`, `.csv`, `.list` or `.ioc` file. One indicator per line:

```
# Lines starting with # or ; are ignored.
# An optional label after a comma, semicolon or tab shows up in the report.

185.220.101.5,Tor exit node
45.33.0.0/16,Scanning range seen in the March incident
malicious.example.com,C2 from ticket INC-2026-0142
*.phishing-domain.tld,Phishing campaign
d41d8cd98f00b204e9800998ecf8427e,Sample hash
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,SHA-256 of the dropper
```

Supported indicator types:

| Type | Example | Matching |
|---|---|---|
| IPv4 address | `185.220.101.5` | Exact |
| CIDR range | `45.33.0.0/16` | Any address inside the range |
| Domain | `malicious.example.com` | The domain and all its subdomains |
| MD5 hash | 32 hex characters | Against reconstructed files |
| SHA-256 hash | 64 hex characters | Against reconstructed files |

If a line carries no label, the filename is used as the label — so naming files
after their source (`abuse-ch-feodo.txt`, `internal-blocklist.csv`) makes the
reports self-documenting.

## Where to get lists

Any threat-intelligence feed you already have works. Public ones commonly used:

* **abuse.ch** — Feodo Tracker, URLhaus, ThreatFox
* **Spamhaus DROP** — hijacked and criminal-controlled netblocks
* **Emerging Threats** — compromised IP list
* **Tor Project** — exit node list
* **Your own incident history** — usually the highest-value list you have

Download them however you like; they're read from disk, never fetched.

## Why offline

Two concrete reasons, both of which matter during a real incident:

1. **Querying an indicator warns whoever controls it.** Many services log
   lookups, and some are watched by the operators themselves. Checking an IP in
   the middle of an investigation can be the thing that tells the intruder
   they've been noticed.

2. **It leaks your client's data to a third party.** Domains, IPs and file
   hashes from a customer's network are sensitive, and submitting a file hash to
   a public service can expose the existence of an incident.

## Note

These files are excluded from version control on purpose: an organization's
indicator lists are private, and some are licensed. Only this README is
tracked.

A finding from here is exactly as reliable as the list it came from. Verify the
source of an indicator before acting on it in production.
