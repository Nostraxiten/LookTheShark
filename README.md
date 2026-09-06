# LookTheShark

**Forensic network capture translator — turns a `.pcap` into an explanation of what happened.**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-2%20pure--python-brightgreen.svg?style=for-the-badge)](#installation)
[![No Wireshark](https://img.shields.io/badge/tshark-not%20required-success.svg?style=for-the-badge&logo=wireshark)](#no-wireshark-required)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg?style=for-the-badge)](https://attack.mitre.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg?style=for-the-badge)](#installation)

<img width="585" height="357" alt="Captura de pantalla 2026-08-27 183132" src="https://github.com/user-attachments/assets/43edec5e-d043-429f-a6f1-986043dac539" />

## Overview

Reading packets is tedious and rarely answers the question you actually have.
LookingTheShark reconstructs the conversations inside a capture and reports them
the way an analyst would explain them:

```
GET    http://cdn.example.com/downloads/holiday.jpg
        200  image/jpeg  2.1 KB
        from 192.168.1.50 (Windows 10/11) · Chrome 121
        ⚠ downloaded as .jpg but the content is a Windows executable
```

Every finding says **what happened**, **what it means**, and **what to do next**.

---

## What's new in 2.0

Version 2.0 is a rewrite of the engine. Three things changed that affect
everyone:

### No Wireshark required

The capture reader, the packet dissectors and every protocol parser are now
native Python (the `core/` package). `tshark` is gone as a dependency.

* **Installation is two pure-Python wheels.** No system packages, no `sudo`, no
  Administrator prompt, no compiler, no PATH surgery.
* **Identical on Windows and Linux.** Same code path, same results.
* Works on locked-down machines where you can't install Wireshark at all.

### One pass instead of thirty

Previously each module iterated the full packet list independently — with
eleven modules enabled that meant the capture was walked more than thirty
times, with every packet held in RAM simultaneously.

Now a single streaming pass feeds every accumulator, and the modules read the
finished analysis object. Memory is bounded rather than proportional to capture
size, and analysis is roughly an order of magnitude faster.

### Built to be read

New modules focused on comprehension rather than statistics: full HTTP
transaction reconstruction with OS attribution, sensitive-material scanning
inside transferred content, device profiling, and a chronological narrative of
the incident.

---

## Installation

### Linux / macOS

```bash
git clone https://github.com/Nostraxiten/LookTheShark.git
cd LookTheShark
bash install.sh
```

### Windows

```powershell
git clone https://github.com/Nostraxiten/LookTheShark.git
cd LookTheShark
.\install.bat
```

`install.bat` is double-clickable — it handles the PowerShell execution policy
for that one script without changing any system setting.

Both installers take a few seconds, need no elevated privileges, and are
idempotent: run them again and they reuse what's already there.

**Installer options**

| Flag | PowerShell equivalent | Effect |
|---|---|---|
| `--con-extras` | `-ConExtras` | Also install GeoIP, Brotli and Zstandard support |
| `--recrear` | `-Recrear` | Delete `.venv` and start over |
| `--sin-red` | `-SinRed` | Install from pip's local cache only |

**Manual installation**, if you'd rather not run a script:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt        # Linux / macOS
.venv\Scripts\pip install -r requirements.txt    # Windows
```

**Verify the installation** at any time:

```bash
./run.sh --check      # Linux / macOS
.\run.bat --check     # Windows
```

`--check` inspects Python, dependencies, data files and templates, then runs
the engine end to end against a capture it generates on the fly.

### Requirements

* Python 3.9 or newer
* `rich` and `jinja2` — both pure Python, installed by the installer

Optional extras (`requirements-optional.txt`), none of them needed:

| Package | Adds |
|---|---|
| `geoip2` | IP geolocation (also needs a GeoLite2 database in `data/geoip/`) |
| `brotli` | Reading HTTP bodies sent with `Content-Encoding: br` |
| `zstandard` | Reading zstd-compressed captures (`.pcapng.zst`) |

---

## Usage

```bash
./run.sh                                          # interactive mode
./run.sh -f capture.pcapng                        # full analysis
./run.sh -f capture.pcapng --deep --mitre --format html
./run.sh -f capture.pcapng -m http,creds,secrets  # selected modules only
./run.sh --diff before.pcap after.pcap            # compare two captures
./run.sh --list                                   # list available modules
```

On Windows replace `./run.sh` with `.\run.bat` — the arguments are identical.

No capture at hand? Generate a synthetic one that contains a bit of everything:

```bash
.venv/bin/python tests/generar_pcap_demo.py
./run.sh -f tests/sample_pcaps/demo.pcap --deep --mitre --format html
```

### Key options

| Option | Purpose |
|---|---|
| `-f`, `--file` | Capture to analyze — `.pcap`, `.pcapng`, also gzip-compressed |
| `-m`, `--modules` | Comma-separated module list (see `--list`) |
| `--deep` | Enable behavioural heuristics (scanning, beaconing, exfiltration) |
| `--mitre` | Map findings to MITRE ATT&CK techniques |
| `--format` | `md`, `html`, `json`, `csv` — combinable with commas |
| `-o`, `--output` | Report base path, without extension |
| `--extract-dir` | Write reconstructed files to disk |
| `--anonymize` | Replace IPs with stable aliases throughout the report |
| `--whitelist-ips` | Exclude known-good addresses from the analysis |
| `--time-range` | Restrict analysis to a time window (`HH:MM-HH:MM`) |
| `--confidence-threshold` | Drop findings below a confidence level |
| `--baseline` | Normal-behaviour profile to suppress expected findings |
| `--quiet` | Only the verdict and the reports |
| `--check` | Verify the installation and exit |

### Exit codes

Useful for scripting and CI:

| Code | Meaning |
|---|---|
| `0` | Analysis completed, nothing critical or high |
| `2` | At least one **critical** finding |
| `3` | At least one **high** finding |
| `1` | The capture could not be analyzed |

---

## Modules

| ID | Module | What it answers |
|---|---|---|
| `ip_hosts` | Devices | Who is on the network, running what, talking to whom |
| `protocols` | Protocols | What's spoken, how much travels unencrypted, what shouldn't be there |
| `dns` | DNS | Which names were resolved, and which ones don't add up |
| `http` | HTTP | Every request and response, and which machine issued it |
| `files` | Files | What was downloaded, and whether it was what it claimed to be |
| `tls` | TLS | Where encrypted traffic goes, and which client produced it (JA3) |
| `creds` | Credentials | Which accounts are already compromised |
| `secrets` | Sensitive material | Keys, tokens and personal data that travelled in the clear |
| `os_fp` | Operating systems | What each device is, and the evidence behind that call |
| `layer2` | Local network | ARP, DHCP, and who could be sitting in the middle |
| `heuristics` | Behaviour | Scans, beaconing, exfiltration, unusual hours |
| `reputation` | Offline reputation | Matches against your own local indicator lists |
| `timeline` | Chronology | What happened, in what order |
| `mitre` | MITRE ATT&CK | Which stage of an attack each finding belongs to |

---

## How OS attribution works

Knowing *who* made a request changes how you read it. A Windows workstation
downloading an `.exe` is a very different story from the update server doing so.

Six independent sources are combined, weighted by how hard each is to forge:

| Source | Reliability | Notes |
|---|---|---|
| DHCP option 55 | Very high | The requested-parameter list is distinctive per OS and awkward to fake |
| User-Agent | High when present | Exact, but trivially forged and absent from encrypted traffic |
| TCP SYN fingerprint | High | TTL, window size, MSS and TCP option order — needs kernel changes to alter |
| JA3 | Identifies the program | Tells you the TLS client, not the OS |
| mDNS / NetBIOS | Contextual | Gives the machine's advertised name |
| MAC OUI | Low | Only the NIC vendor; useless past a router |

Sources agreeing raises confidence. Sources disagreeing is reported as a
finding in itself — that pattern means NAT, a proxy, containers, or a forged
User-Agent.

The `os_fp` module shows the full reasoning per host, so the conclusion can be
checked rather than taken on trust.

---

## What gets found inside the traffic

The `secrets` module scans HTTP headers and bodies, reconstructed files and any
plaintext protocol payload for material that should never have travelled
unencrypted:

Cloud credentials (AWS, Google, Azure SAS) · service tokens (GitHub, GitLab,
Slack, Stripe, npm, SendGrid, Twilio, OpenAI-style keys) · JWTs, with their
claims decoded so you can see the privileges they carried · private keys in PEM
and PuTTY formats · database connection strings · session cookies · plaintext
password fields · payment card numbers, Luhn-validated · IBANs and national ID
numbers, checksum-validated.

**Values are always masked.** Enough of each secret is shown to locate and
rotate it, never enough to reuse it. A forensic report shouldn't be the place a
credential leaks for the second time.

---

## Offline reputation

The `reputation` module never queries an online service. Two reasons: looking up
an indicator tells the operator behind it that they've been spotted, and it
sends your client's data to a third party.

Drop any `.txt`, `.csv`, `.list` or `.ioc` file into `data/reputation_feeds/`:

```
# One indicator per line. An optional label after a comma appears in the report.
185.220.101.5,Tor exit node
45.33.0.0/16,Known scanning range
malicious.example.com,C2 from incident 2026-03
d41d8cd98f00b204e9800998ecf8427e,Sample from the March campaign
```

IPs, CIDR ranges, domains (parent domains cover their subdomains) and MD5/SHA-256
hashes are all matched.

---

## Reports

`--format` accepts `md`, `html`, `json` and `csv`, combinable.

* **HTML** — self-contained, light and dark aware, no external resources. The
  most readable option, and the one to hand to someone who wasn't there.
* **Markdown** — for tickets, wikis and pull requests.
* **JSON** — full structured output for further processing.
* **CSV** — findings as rows, for a spreadsheet or a SIEM.

Every report opens with an executive summary in plain language, followed by a
prioritized "where to start" list, the device inventory, the findings, the
reconstructed HTTP transactions and the timeline.

`--anonymize` replaces every address with a stable alias (`equipo-A`,
`equipo-B`…) consistently across the whole document, including the structured
data blocks — so a report can be shared without exposing the real addressing.

---

## Supported formats

| | |
|---|---|
| Capture files | `libpcap` (both endiannesses, µs and ns timestamps), `pcapng` (multi-interface), transparently gzip-compressed, zstd with the optional extra |
| Link layers | Ethernet, 802.1Q and QinQ VLANs, Linux SLL and SLL2, raw IP, NULL/loopback, PPP, MPLS, PPPoE |
| Network | IPv4 with options and fragmentation, IPv6 with extension headers, ARP, ICMP, ICMPv6 |
| Transport | TCP with full stream reassembly, UDP, SCTP (headers) |
| Application | HTTP/1.x (chunked, gzip/deflate/brotli), TLS handshakes with JA3/JA3S, DNS/mDNS/LLMNR, DHCP, FTP, SMTP, POP3, IMAP, Telnet, IRC, TFTP, NetBIOS, service banners |

Damaged captures are handled rather than rejected: truncated files, malformed
headers and impossible lengths produce a partial analysis with a warning, never
a traceback.

---

## Performance and limits

A single streaming pass, with `__slots__` on the hot path and precompiled
struct parsers. Reassembly budgets are set per service — a TLS connection only
needs its handshake retained, not the megabytes of ciphertext that follow.

When a capture is large enough that a limit truncates the analysis, the tool
**says so** and names the flag that raises it. An incomplete report presented as
complete is worse than no report:

```
⚠ La captura supera algunos limites y el analisis es parcial:
    · 1,204 conexiones TCP no se siguieron al superarse el limite de 200,000 flujos
```

| Flag | Default | Controls |
|---|---|---|
| `--max-flows` | 200,000 | TCP connections tracked |
| `--max-stream-mb` | 4 | Memory per direction of a flow |
| `--max-memory-mb` | 512 | Global reassembly ceiling |
| `--full-reassembly` | off | Reassemble every flow, not just known service ports |

---

## Testing

```bash
.venv/bin/python tests/test_lookingtheshark.py
```

122 checks with no external test dependencies, across three levels: parsers in
isolation, the full engine against a synthetic capture, and verification that
each detector finds what that capture deliberately hides — a disguised
executable, three plaintext logins, a leaked AWS key, a DGA domain, a DNS
tunnel, ARP spoofing, a port scan and C2 beaconing.

The generator itself is a usable tool:

```bash
python tests/generar_pcap_demo.py my_capture.pcap
```

---

## Project layout

```
lookingtheshark.py     Entry point and CLI
core/                  Native engine — no external dependencies
  pcap_reader.py         .pcap / .pcapng reader, streaming
  decoders.py            Layer 2/3/4 dissectors
  streams.py             TCP reassembly with memory budgets
  http.py                HTTP/1.x transactions
  tls.py                 TLS handshake, JA3 / JA3S, certificates
  dns.py                 DNS messages with name decompression
  plaintext.py           FTP, SMTP, POP3, IMAP, Telnet, IRC
  carving.py             File identification and hashing
  secrets.py             Sensitive-material detection
  fingerprint.py         Passive OS fingerprinting
  services.py            Ports, services and their risk reading
  session.py             Single-pass analysis
modules/               Interpretation and presentation
ui/                    Theme, banner, interactive menu
templates/             Jinja2 report templates
data/                  Signatures, JA3, MITRE map, OUI, feeds
tests/                 Test suite and capture generator
```

---

## Legal notice

Analyze only captures you own or are expressly authorized to examine.
Intercepting third-party network traffic without authorization is a criminal
offence in most jurisdictions.

Findings are **indicators requiring manual verification**, not conclusions. The
tool is deliberately explicit about the confidence behind each one, and about
what would explain it legitimately. A network capture only ever shows what
happened during the capture.



WARNING
-------

LookTheShark is an analysis and forensic assistance tool, not a definitive
network-security detection system.

The results produced by this tool may contain false positives or false
negatives. Some detection methods, heuristics, parsers, or other functions
may be incomplete, inaccurate, experimental, or malfunction under certain
conditions. Network captures can also contain missing, malformed, encrypted,
or otherwise insufficient information, which may affect the accuracy of the
analysis.

Do NOT treat a finding, alert, classification, or absence of a finding as
conclusive evidence of malicious or benign activity. Results should always
be reviewed and validated manually using appropriate forensic and network
analysis tools, including Wireshark or other specialized software when
appropriate.

The developer has personally tested LookTheShark in controlled environments,
including analyzing a Wireshark capture of an ARP spoofing scenario, where
the tool successfully detected the spoofing activity. However, successful
results in testing do not guarantee correct detection in every real-world
environment or capture.

Use this tool as an additional source of evidence and investigation aid,
not as the sole basis for security decisions, incident-response conclusions,
or forensic findings.

Use at your own discretion and always verify important results independently.



---

## Credits

Built by [@nostraxiten](https://github.com/Nostraxiten).
MIT licensed.
