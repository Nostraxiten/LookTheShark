# Sample captures

Put your own `.pcap` / `.pcapng` files here. This folder is excluded from
version control: **network captures routinely contain credentials, session
cookies, personal data and sometimes live malware.** Never commit one.

## Generating a demo capture

If you have no capture at hand, generate a synthetic one — no root, no network
interface, no permissions needed:

```bash
python tests/generar_pcap_demo.py
```

That writes `demo.pcap` here. Then:

```bash
./run.sh -f tests/sample_pcaps/demo.pcap --deep --mitre --format html
```

The generated capture deliberately contains, so every detector has something to
find:

| Scenario | Which module reports it |
|---|---|
| Windows executable downloaded as `vacaciones.jpg` | `files` |
| FTP login in cleartext | `creds` |
| Telnet session with login and commands | `creds`, `timeline` |
| HTTP login form over plain HTTP | `creds`, `secrets` |
| AWS key and JWT in an API request | `secrets` |
| Session cookie over plain HTTP | `secrets` |
| DGA-looking domain | `dns` |
| DNS tunnel with a 50-character label | `dns` |
| TLS handshake with SNI and a weak cipher suite | `tls` |
| 21-port scan from an Nmap-fingerprinted host | `heuristics`, `os_fp` |
| C2 beaconing every 30 seconds | `heuristics` |
| ARP spoofing of the gateway | `layer2` |
| DHCP request revealing the machine name | `layer2`, `os_fp` |
| Bulk upload to an external host | `heuristics` |

The generator is also useful as a reference for building test captures of your
own: it constructs frames byte by byte with no external dependencies.

## Where to find real captures

Public, legal to analyze, and good for exercising the tool:

* **Wireshark sample captures** — <https://wiki.wireshark.org/SampleCaptures>
* **Malware Traffic Analysis** — <https://malware-traffic-analysis.net> — real
  infection traffic with write-ups. Handle in a VM: the reconstructed files are
  live malware.
* **NETRESEC** — <https://netresec.com/?page=PcapFiles>
* **CTF captures** — most forensics CTFs publish theirs afterwards

## Warning about extracted files

`--extract-dir` writes reconstructed files to disk. From a real malware capture
**those files are the malware itself.** Extract only inside an isolated VM, and
never on the machine you're investigating from.
