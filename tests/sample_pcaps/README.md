# Test Files (PCAPs)

This directory is intended to store sample network captures for testing `LookingTheShark`.

**Important**: For security and size reasons, real captures are not included in the repository by default.

## Recommended sources for test PCAPs:

- **Malware Traffic Analysis**: https://www.malware-traffic-analysis.net/
- **Wireshark Sample Captures**: https://wiki.wireshark.org/SampleCaptures
- **Netresec Public PCAP files**: https://www.netresec.com/?page=MACCDC

## How to test

Download a pcap (for example `test.pcap`) and place it here. Then run:

```bash
cd ..
python lookingtheshark.py --file tests/sample_pcaps/test.pcap --deep --mitre
```
