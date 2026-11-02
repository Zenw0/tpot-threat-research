# AKUMA ADB / Polygon — Curated Public Evidence Release

**Prepared: October 30, 2026 (UTC). Publicly released: November 2, 2026 (UTC).**

This set of supporting materials accompanies our investigation of a Linux x86_64 Akuma sample with SHA-256:

`d5de7f84a8547f8ef0213890850aaac5840f168ffeb6bca34cb0870fc9854817`

The public release contains **no malware executable, infection loader, administrative SSH capture, or private lab credentials**. All scripts and captures in this folder are provided for **offline defensive analysis**.

## Included files

| File | Content | Important limitation |
| --- | --- | --- |
| `AKUMA_PUBLIC_EVIDENCE_2026-10-28.json` | Curated set of 12 ADB events, two raw Polygon transaction inputs, bounded lab observations and Suricata results. | Editorial selection, **not** full original logs or independently authenticated blockchain responses. |
| `AKUMA_PUBLIC_DECODE_20261030.py` | Standard-library Python decoder for the two public transaction inputs, without malware execution or network access. | Uses an **already recovered, published 32-byte key**; does **not** extract the key from the ELF. |
| `akuma-adb-x64.rules` | Suricata candidate signature, `sid:9001001`, revision 1. | Specific to this `akuma.adb` x86_64 check-in; no measured false-positive rate on independent traffic. |
| `AKUMA_C2_ANONYMIZED_20261030.pcap` | **17 real captured packets** from communication with a **private simulated C2**, with identifying headers anonymized. | **Not** traffic with a live malicious C2. TCP payloads and packet segmentation were preserved, but IP/MAC/TCP timestamp fields were changed. |
| `AKUMA_PUBLIC_SHA256SUMS_20261030.txt` | SHA-256 hashes of the four evidence artifacts above. | Verifies local integrity only; a checksum alone does not authenticate the investigation. |

See [REPORT_EN.md](REPORT_EN.md) for the full English investigation and [README.md](README.md) for its case overview.

## Provenance and privacy safeguards

- The selected traffic originated from the **17-packet TCP/25565 subset** of an Ethernet capture on the **private fake-C2 server**. The private source subset has SHA-256 `26c947551f9ff74c7993ce5c8bc0a4c1ad54d0a163743bf43f199673d143d7bd`.
- Both exposed endpoint IPs are documentation addresses: **`192.0.2.10`** (simulated victim) and **`192.0.2.20`** (simulated C2). Public packet MAC addresses were replaced with demonstration locally administered values; IPv4/TCP checksums were recomputed and independently checked for **all 17 packets**.
- Packets outside the targeted TCP/25565 flow were excluded. **No administrative SSH, ARP, DNS, Polygon RPC or other sessions** are included in this PCAP.
- The **original laboratory event times were retained** because the delay between registration and keepalive messages is relevant to the research. The Ethernet subset captures **34 application bytes**, while the fake-C2 server log records **36 bytes**; its fifth two-byte heartbeat falls beyond the Ethernet capture window.
- The original complete PCAP, NFLOG data, service logs, Suricata validation archive, malware ELF and primary hash manifests are archived separately **and privately**.

## Offline reproduction without executing malware

Run from the case directory with Python 3 and its standard library:

```bash
python3 AKUMA_PUBLIC_DECODE_20261030.py AKUMA_PUBLIC_EVIDENCE_2026-10-28.json
sha256sum -c AKUMA_PUBLIC_SHA256SUMS_20261030.txt
```

Expected decoder results include decoded configured destinations **`45.205.1.121:25565`** and **`191.217.203.232:25565`**, the threefold repetition of each IPv4 value, validation of the 21-byte `akuma.adb` registration prefix, and **`PASS`**.

The public decoder validates the consistency of the published inputs and algorithm. It **does not independently prove the ELF key-extraction process or perform fresh Polygon queries**. The original forensic decoder (kept private) additionally reconstructed the key from the ELF and checked the original blockchain evidence archive; its full-input verification passed.

## Suricata replay: accurately scoped claims

On October 30, 2026, **Suricata 7.0.10 generated one alert** on the **original 334-packet Ethernet PCAP** when replayed offline with `-k none`, and **zero alerts** on a **27-packet derived control** without the C2 or administrative SSH stream. Invalid checksums in the primary capture had caused the original replay with checksum verification enabled to produce zero alerts. The primary 17-packet C2 subset also generated one alert in its original form.

The public **anonymized** 17-packet PCAP **has not yet been retested with the Suricata engine after its header rewrites**. A separate integrity check validated all its IPv4/TCP checksums, but this is **not a substitute for engine replay**. Therefore, do not describe this transformed file as an independently engine-validated positive sample until that test is performed.

The control traffic was derived from the same laboratory capture, **not** an independent benign-data evaluation. We have **no measured real-world false-positive rate**, no other-architecture sensitivity results and no family-wide detection claim. The victim-side NFLOG capture was rejected by Suricata 7.0.10 due to unsupported linktype 239; that is **not** a negative detection result.

## Interpretation limits

1. The observed malware registration and heartbeats occurred **only against a private simulated C2**; neither decoded public IP address was contacted by the malware in our tests.
2. ADBHoney recorded **attempted installation commands**, not proven successful HTTP delivery or execution on any actual victim.
3. Two Polygon setter transactions had `status=0x1`, and an archived `latest` getter response matched the second configuration. **Successful historical getter state responses are not preserved**; the public dataset should not be interpreted as a complete transaction-by-transaction storage audit.
4. The released JSON is a **curated selection**, not a native explorer export or a third-party-signed attestation.
5. A successful public decoder run replays the **published key and values**; independently reconstructing the key from the original malicious binary requires private source evidence and forensic tooling.
6. The decoded IPv4:port pairs are **configured destinations with unverified live service status**, not authenticated active botnet-C2 sightings.
7. Viewing these files requires **no malware execution and no external network access**.

**Release status:** The research owner authorized public repository publication on November 2, 2026 (UTC). External media outreach and threat-intelligence submissions are separate actions; these artifacts do not automatically submit data to any third party.
