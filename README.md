# T-Pot Threat Research

**Independent honeypot investigations, Linux malware analysis, and reproducible threat intelligence.**

This repository documents selected attacks observed by a T-Pot honeypot and the technical investigations that follow. The goal is to turn original network telemetry and malware artifacts into useful, verifiable findings for defenders and fellow researchers.

We prioritize **evidence over speculation**, clearly separate observed behavior from inference, and publish sanitized supporting material whenever it can be shared safely.

## Investigations

| Case | Focus | Research status | Resources |
| --- | --- | --- | --- |
| **AKUMA-2026-10** | ADB-delivered Linux/IoT bot sample with C2 configuration retrieved from a Polygon smart contract | Technical investigation completed for the documented scope | [Case overview](investigations/AKUMA-2026-10/README.md) · [Full report](investigations/AKUMA-2026-10/REPORT_EN.md) · [Evidence](investigations/AKUMA-2026-10/AKUMA_PUBLIC_RELEASE_README_20261030.md) |

Additional investigations will be added when their findings and evidence meet our publication criteria. Not every attack observed by a honeypot warrants a public report.

## Featured research: AKUMA-2026-10

In October 2026, our ADBHoney sensor recorded **12 identical installation attempts against TCP/5555**. An associated Linux x86_64 Akuma sample led us to investigate an unusual configuration mechanism: an **IPv6-formatted value stored in a Polygon smart contract** is decoded into an IPv4 C2 destination using an obfuscated key embedded in the executable.

The investigation connects:

1. Original ADB honeypot events and associated distribution scripts.
2. Static recovery of a **32-byte decryption key** from the ELF.
3. Two accepted Polygon configuration transactions and their **decoded IPv4:port values**.
4. Isolated behavioral analysis against **simulated** DNS, Polygon RPC and C2 services.
5. A candidate **Suricata** detection rule tested against the original laboratory packet capture.

**Important boundaries:** The ADB events demonstrate *attempted installation*, not a proven compromise of a real device. The decoded IPv4 addresses are *configured destinations*, not confirmed live criminal C2 servers. The dynamic experiment contacted only a private simulated C2. The candidate detection rule has not been evaluated against an independent benign traffic corpus.

**Read the investigation:** [AKUMA-2026-10 — ADB Botnet Activity and Polygon-Based C2 Configuration](investigations/AKUMA-2026-10/REPORT_EN.md).

## Research approach

Each case follows a documented chain of evidence:

- **Collection:** Record relevant honeypot events, timestamps, payload references and hashes.
- **Static analysis:** Inspect captured artifacts without executing untrusted code on production or shared networks.
- **Corroboration:** Compare observed indicators with primary third-party research and, when applicable, blockchain records.
- **Controlled experiments:** Run malware only in appropriately isolated environments with a tightly constrained scope and simulated infrastructure when practical.
- **Detection and reproduction:** Develop candidate detection logic, preserve test outcomes and provide offline verification tools where feasible.
- **Publication review:** Remove private addressing, credentials, administrative traffic and other unnecessary sensitive material before sharing.

We label findings according to their evidentiary basis:

| Label | Meaning |
| --- | --- |
| **Observed** | Directly supported by an archived log, binary, packet capture, transaction or test result. |
| **Corroborated** | Independently reported by a relevant outside source. |
| **Inference** | A reasoned interpretation, with its assumptions and limitations stated. |
| **Unverified** | An untested hypothesis or a fact that available evidence does not establish. |

## Available materials

Depending on the case, a published investigation may include:

- An English-language technical report and a concise case overview.
- Curated indicators, transaction references and evidence manifests.
- Offline analysis scripts or decoders designed **not** to execute malicious samples.
- Candidate IDS detection rules and explicitly scoped validation results.
- Anonymized packet captures from controlled experiments.

**Raw malware executables, infection loaders, administrative captures and private laboratory data are not included in the AKUMA public evidence package.** Availability and sharing conditions may differ for future cases; consult each investigation's documentation.

## Responsible use and interpretation

- Indicators have **different confidence levels and lifetimes**. Do not automatically label a decoded configuration address as a confirmed active C2.
- Public shared-service endpoints, including blockchain RPC providers, are **not** malicious merely because malware queried them.
- Detection rules are research artifacts unless their documentation explicitly establishes broader validation. Test them against your own environment before deployment.
- Source IP addresses, hosting providers, ASNs and transaction wallets do **not** establish individual or organizational attribution by themselves.
- Prior work is credited in each report. Publication of an additional case study does not imply discovery of a malware family or technique for the first time.

## Feedback and contributions

Corrections, independent reproduction results, relevant prior research and suggestions for improving the evidence are welcome through **GitHub Issues**.

Please **do not post credentials, private victim data, live malware payloads or other sensitive material in public issues**.

Maintained by **[Zenw0](https://github.com/Zenw0)**. Research is conducted independently; findings reflect the data and test conditions described in each case.
