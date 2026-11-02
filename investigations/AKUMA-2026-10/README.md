# AKUMA-2026-10: ADB Botnet Activity and Polygon-Based C2 Configuration

**Original honeypot research | October 27–30, 2026**

**Status:** Technical investigation completed for the documented scope. Publicly released on November 2, 2026 (UTC).

**Full technical report:** [Read the complete AKUMA-2026-10 investigation](./REPORT_EN.md).

## Overview

Akuma is a Linux/IoT botnet associated with the compromise of exposed devices and network services.

This investigation examines an Akuma x86_64 sample associated with **Android Debug Bridge (ADB) infection attempts** observed by a T-Pot honeypot.

Our analysis documents a command-and-control (C2) configuration mechanism in which the malware retrieves an IPv6-formatted string from a Polygon smart contract and decodes it into an IPv4 destination using an obfuscated key embedded in its executable.

The investigation combines original honeypot telemetry, static reverse engineering, Polygon transaction records, isolated behavioral analysis, and Suricata detection testing.

## Key findings

### 1. ADB infection attempts

- 12 ADB command sessions observed on TCP/5555.
- Two source IP addresses identified.
- Identical installation commands across all 12 sessions.
- Loader scripts referencing 19 executable architecture variants.

These observations establish attempted infection commands against the honeypot, **not successful compromise of a real device**.

### 2. Polygon-based C2 configuration

The analyzed sample references the following Polygon contract:

`0x084a379b1E18c153212015bCCD60295C948EaAe2`

Two successful configuration transactions were identified.

| Date (UTC) | Decoded IPv4 destination | Port |
|---|---|---|
| October 18, 2026 | `45.205.1.121` | TCP/25565 |
| October 23, 2026 | `191.217.203.232` | TCP/25565 |

The stored values use the documentation IPv6 prefix `2001:db8` as part of an encoded data representation.

**Important:** These are destinations reconstructed from malware configuration data. Their operational availability was not verified.

### 3. Independent key reconstruction

Static reverse engineering identified four routines responsible for reconstructing a 32-byte decryption key.

The original forensic decoder recovered this key directly from the ELF and successfully reproduced both configured IPv4 destinations.

A simplified public decoder is provided in this repository. It uses the already recovered key and validates the published transaction inputs without executing malware or making network requests.

### 4. Isolated behavioral analysis

On October 29, 2026, the sample was executed in a restricted laboratory environment using simulated DNS, Polygon RPC, and C2 services.

Observed behavior included:

- Requests to three Polygon RPC providers.
- A table containing nine RPC endpoints identified through static analysis.
- A 26-byte initial C2 registration message.
- The identifiers `x86_64` and `akuma.adb`.
- Five heartbeat messages at approximately 60-second intervals.
- Reconnection attempts targeting the same C2 port.

**No real attacker-controlled C2 infrastructure was contacted during these tests.**

### 5. Suricata detection

A candidate signature was developed for the observed `akuma.adb` x86_64 registration sequence.

**Suricata SID:** `9001001`

Testing with Suricata 7.0.10 produced:

| Test | Result |
|---|---|
| Original Ethernet PCAP, 334 packets, checksum checks disabled for offline replay | 1 alert |
| Derived internal control, 27 packets without the C2 flow | 0 alerts |
| Anonymized public C2 capture, 17 packets | Not yet retested with the Suricata engine |

This validates detection of the observed registration sequence in the original laboratory capture.

It does **not** establish a measured false-positive rate or detection coverage across the entire Akuma family.

## Research artifacts

| File | Description |
|---|---|
| [Full technical report](./REPORT_EN.md) | Complete investigation, evidence analysis, methodology and limitations |
| [Public evidence](./AKUMA_PUBLIC_EVIDENCE_2026-10-28.json) | Curated ADB events, Polygon transaction data and laboratory observations |
| [Offline decoder](./AKUMA_PUBLIC_DECODE_20261030.py) | Standalone Python tool for reproducing the published C2 decoding results |
| [Suricata rule](./akuma-adb-x64.rules) | Candidate signature for the observed x86_64 registration |
| [Anonymized PCAP](./AKUMA_C2_ANONYMIZED_20261030.pcap) | 17 packets captured during communication with the simulated C2 |
| [Evidence documentation](./AKUMA_PUBLIC_RELEASE_README_20261030.md) | Detailed provenance, methodology and limitations |
| [SHA256 checksums](./AKUMA_PUBLIC_SHA256SUMS_20261030.txt) | Integrity verification for the distributed artifacts |

### Reproduce the decoding

Python 3 is required. No external dependencies or network connectivity are needed.

```bash
python3 AKUMA_PUBLIC_DECODE_20261030.py AKUMA_PUBLIC_EVIDENCE_2026-10-28.json
```

Verify the distributed files:

```bash
sha256sum -c AKUMA_PUBLIC_SHA256SUMS_20261030.txt
```

The public decoder checks the consistency of the published records. Independent extraction of the decryption key from the original ELF requires the separate forensic workflow and original malware sample, which are not distributed here.

## Research limitations

- No successful infection of a real device was demonstrated.
- No direct connections to the decoded public C2 destinations were performed.
- No DDoS attack was triggered or observed during testing.
- Historical Polygon contract state was not exhaustively reconstructed.
- The Suricata signature was not evaluated against an independent benign traffic corpus.
- The anonymized PCAP contains traffic from a **simulated C2**, not an attacker-operated server.

## Data handling and safety

All publicly distributed network evidence has been selected or anonymized to exclude administrative SSH traffic and private laboratory network addresses.

The original malware executable, complete laboratory captures, administrative logs, and other sensitive evidence are retained privately.

This repository is intended for **defensive security research, reproducibility, and threat intelligence sharing**.

## Related research

- [KSI Digital — Akuma Botnet Loader](https://www.ksi-digital.com/en/blog/akuma-botnet-loader/) — Earlier analysis of Akuma activity involving a different sample and delivery mechanism.
- [ThreatFox](https://threatfox.abuse.ch/ioc/1977508/) — Independent reporting of an associated distribution artifact.

Our contribution concerns the specific ADB campaign, Polygon configuration mechanism, independently reconstructed key, and isolated behavioral observations documented here.

---

*Research conducted in October 2026. All timestamps are UTC. Findings are limited to the evidence and test conditions described above.*
