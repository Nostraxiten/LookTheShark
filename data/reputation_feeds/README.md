# Offline Reputation Feeds

LookingTheShark does not query external services live. Reputation feeds
are downloaded **manually** and placed in this folder as `.txt` files
(one IP or domain per line).

## Recommended feeds

| Feed | Download URL | Type | Suggested Frequency |
|---|---|---|---|
| Abuse.ch Feodo Tracker | https://feodotracker.abuse.ch/downloads/ipblocklist.txt | C2 IPs | Daily |
| Abuse.ch URLhaus | https://urlhaus.abuse.ch/downloads/text/ | Malicious domains | Daily |
| Abuse.ch SSL Blacklist | https://sslbl.abuse.ch/blacklist/sslipblacklist.txt | IPs with malicious certs | Daily |
| Emerging Threats (IPs) | https://rules.emergingthreats.net/blockrules/compromised-ips.txt | Compromised IPs | Weekly |
| Spamhaus DROP | https://www.spamhaus.org/drop/drop.txt | Hijacked IP ranges | Weekly |
| TOR Exit Nodes | https://check.torproject.org/torbulkexitlist | TOR exit nodes | Daily |
| Alienvault OTX (IPs) | https://reputation.alienvault.com/reputation.data | IP reputation | Daily |

## Expected format

Each file must have one IP or domain per line. Empty lines and lines
starting with `#` are ignored.

```
# Example: malicious_ips.txt
192.168.1.100
10.0.0.5
evil-domain.example.com
```

## How to download

```bash
# Example with curl (run manually, LookingTheShark never does it on its own):
curl -o feodo_ips.txt https://feodotracker.abuse.ch/downloads/ipblocklist.txt
curl -o urlhaus_domains.txt https://urlhaus.abuse.ch/downloads/text/
```

> **Note**: Never automate downloading from LookingTheShark. The decision
> of which feeds to use and when to update them belongs to the analyst.
