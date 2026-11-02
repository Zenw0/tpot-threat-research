# AKUMA-2026-10: ADB Botnet Activity and Polygon-Based C2 Configuration

**Original T-Pot honeypot research | October 27–30, 2026 (UTC)**  
**Author:** Zenw0 / T-Pot Threat Research  
**Status:** Pre-publication technical review; public evidence package prepared, not yet independently audited by a third party.

## Executive summary

Between October 27 and 28, 2026, an ADBHoney sensor in our T-Pot laboratory recorded **12 identical installation attempts against Android Debug Bridge (ADB), TCP/5555**, from two source IP addresses. The commands referenced a script distribution server and led us to a Linux x86_64 Akuma bot sample. The sample was acquired **manually by the analyst** from a URL referenced in the scripts; successful malware execution by the honeypot or a real device was **not** established.

Our static analysis found a C2 configuration mechanism that retrieves an **IPv6-formatted string from a Polygon smart contract** and decodes its last 12 bytes using a 32-byte key assembled by obfuscated routines in the ELF. The `2001:db8` prefix is a documentation prefix, **not an IPv6 destination used by the bot**. We recovered the key independently from the sample and reproduced two configured IPv4 destinations from on-chain transaction inputs:

| Polygon setter transaction (UTC) | Decoded configured destination | TCP port |
| --- | --- | --- |
| 2026-10-18 08:01:00 | `45.205.1.121` | 25565 |
| 2026-10-23 17:22:48 | `191.217.203.232` | 25565 |

These are **decoded configuration values, not confirmed live C2 services**. We made **no direct connections to either address**.

On October 29 we ran a **bounded, isolated experiment using two private VMs**, with simulated DNS, Polygon JSON-RPC, and a fake TCP C2. The sample sent a **26-byte registration message** identifying itself as `akuma.adb` on `x86_64`, followed by two-byte heartbeat messages approximately 60 seconds apart. A candidate Suricata signature derived from the registration produced **one alert in an offline replay of the original 334-packet Ethernet capture**, with checksum validation disabled for that replay because the original capture contained invalid checksums. A **27-packet control derived from the same capture** generated zero alerts. This is **not** an independent false-positive assessment.

**Scope of the contribution:** original ADB telemetry, a specific ELF's independently reconstructed key, two Polygon configuration transactions, constrained behavioral corroboration, and a traceable detection test. Akuma and its use of TCP/25565 had already been reported by other researchers; we do **not** claim discovery of the family.

## Evidence classification

- **[OBSERVED]** Directly supported by an archived sensor log, binary, capture, analysis output, or blockchain transaction record.
- **[CORROBORATED]** An independently published observation that specifically supports the claim.
- **[INFERENCE]** A reasoned interpretation with stated limits.
- **[UNVERIFIED]** A hypothesis, an unavailable historical record, or a property not tested in this investigation.

All times below are in UTC. The [curated public evidence JSON](AKUMA_PUBLIC_EVIDENCE_2026-10-28.json) exposes selected observations rather than original private logs. Primary logs, binary samples, and unredacted administrative traffic remain in private, hashed archives.

## 1. Initial access attempts: what ADBHoney actually recorded

**[OBSERVED]** ADBHoney logged 12 `adbhoney.command.input` events between **2026-10-27 09:09:48** and **2026-10-28 10:08:37**. All 12 submitted the same attempted installation sequence: change directory to `/data/local/tmp/`, download and invoke `w.sh` using BusyBox `wget`, invoke `curl` to request `c.sh`, and attempt to execute the latter. We have defanged the associated URLs.

| ADBHoney source IP | Sessions | Confidence |
| --- | ---: | --- |
| `154.80.128.124` | 8 | [OBSERVED] source of submitted commands |
| `154.80.128.121` | 4 | [OBSERVED] source of submitted commands |

The referenced distribution URLs were:

- `hxxp://45[.]9[.]2[.]239:24381/bins/payloads/w.sh`
- `hxxp://45[.]9[.]2[.]239:24381/bins/payloads/c.sh`

**[OBSERVED]** Two scripts were subsequently preserved and hashed:

| Evidence file | Bytes | SHA-256 |
| --- | ---: | --- |
| `adb_w.sample` | 1,817 | `4890d90dd5eedd73f37ba627da8d1487114db5f5366772a9a464defc493c6943` |
| `adb_c.sample` | 1,665 | `ec0a0374513a93cd3f34e6b0ce57fc7408706dfd687bd608c385ac8da54ce047` |

**[OBSERVED]** Both refer to 19 `akuma.<architecture>` payload names under `/bins/adb/`, covering ARM, x86, MIPS, RISC-V, PowerPC, and other targets. **[UNVERIFIED]** Their presence in scripts does not demonstrate that all 19 binaries were actually available at the distribution endpoint.

**[INFERENCE]** A likely defect exists in the `c.sh` execution path: it issues `curl URL` without `-O`, `-o`, or shell redirection, then invokes `chmod` and attempts to run a file that would not ordinarily have been written. This is a static observation and was **not** validated as a failure on an infected device.

### Sample acquisition and provenance

**[OBSERVED]** After obtaining the scripts, the analyst manually requested the exact x64 payload path referenced by them:

`hxxp://45[.]9[.]2[.]239:24381/bins/adb/akuma.x64`

The lab's Bash history records a `curl` invocation with IPv4, failure checking, a 20 MiB transfer limit, and an output file named `akuma.x64.sample`. TCP/24381 egress was temporarily allowed for that acquisition. **The historical HTTP response status and transferred byte count were not preserved**; we do not invent them. In particular, a later manual acquisition must not be conflated with a successful payload download or execution during any of the 12 ADBHoney interactions.

The resulting examined ELF is a **540,768-byte, statically linked, stripped Linux x86_64 executable**, SHA-256:

`d5de7f84a8547f8ef0213890850aaac5840f168ffeb6bca34cb0870fc9854817`

## 2. Polygon as a C2 configuration source

**[OBSERVED]** The sample includes a routine that prepares Polygon JSON-RPC `eth_call` requests to retrieve configuration from this contract:

`0x084a379b1E18c153212015bCCD60295C948EaAe2`

The read selector observed in the ELF and in the controlled execution is **`0xc5a56599`**; two successful configuration-setting transactions use **`0x9846adc5`**. Polygon's chain identifier is `0x89`. The public RPC providers are legitimate shared infrastructure, **not C2 endpoints**.

**[OBSERVED]** The archived setter calls and receipts contain the following values:

| Block | Transaction hash | IPv6-formatted value in calldata | Receipt |
| --- | --- | --- | --- |
| `95736742` | `0xd0191ebc33189b0cb5a31a9e08d87c4fa4e6df9e26994336c65d833cc51d3d58` | `2001:db8:b9ed:e89b:9925:35d4:1af2:5855` | `status=0x1` |
| `96047198` | `0xd3f178dd5ce75c8d97a856ceb0c3847987d715ad3999b3cf8de0f1151af116f4` | `2001:db8:2d4d:b21f:2585:ff50:8e52:2d9` | `status=0x1` |

The first transaction was recorded at **2026-10-18 08:01:00 UTC** and the second at **2026-10-23 17:22:48 UTC**. An archived `eth_call` at `latest` on October 28 returned the **second** value.

**Important limitation:** Historical *successful getter responses* for the blocks surrounding those transactions were not archived. Available RPC attempts returned archive-state/access errors. We therefore report accepted setter transactions plus a consistent later getter result, **not a complete state-by-state reconstruction of Polygon storage**. Further auditing of setter bytecode would add confidence in its exact storage semantics.

## 3. Independent recovery of the obfuscated decryption key

**[OBSERVED]** Reverse engineering located IPv6 parsing and decryption near sample code addresses `0x40a2de` and `0x40a315`. A key assembly routine at `0x40a2d9` invokes four functions that reconstruct eight bytes each from obfuscated constants in `.rodata`:

| ELF routine | Independently reconstructed output, hex |
| --- | --- |
| `0x409fff` | `1a7e92513795dbd1` |
| `0x40a0a5` | `ab8afdeea8a1d8b9` |
| `0x40a14b` | `dd56100601f7a1fc` |
| `0x40a1f1` | `7b0021ea81a5d662` |

Together these produce this **32-byte key**:

```text
1a7e92513795dbd1ab8afdeea8a1d8b9dd56100601f7a1fc7b0021ea81a5d662
```

The program parses an IPv6-formatted string and transforms the **last 12 bytes** (`i = 0 ... 11`) as follows:

```python
t = (ciphertext[i] - 13 * i) & 0xff
plaintext[i] = (((t << 5) | (t >> 3)) & 0xff) ^ key[(7 * i) % 32]
```

The first four decrypted bytes repeat **three times**, yielding one IPv4 destination:

| Transaction date | Encrypted final 12 bytes | Decrypted 12 bytes | Recovered IPv4 |
| --- | --- | --- | --- |
| October 18 | `b9ede89b992535d41af25855` | `2dcd01792dcd01792dcd0179` | `45.205.1.121` |
| October 23 | `2d4db21f2585ff508e5202d9` | `bfd9cbe8bfd9cbe8bfd9cbe8` | `191.217.203.232` |

**[OBSERVED]** A private forensic decoder reconstructed this key directly from the archived ELF, verified the relevant raw Polygon transaction inputs and receipts, and reproduced both IPv4 values without assuming either IP in advance. Its full original-input run passed integrity and decoding checks.

**[OBSERVED, public reproducibility limit]** Our separate [public decoder](AKUMA_PUBLIC_DECODE_20261030.py) embeds the **already recovered key**. It independently applies the published transformation to the curated [transaction data](AKUMA_PUBLIC_EVIDENCE_2026-10-28.json), verifies the triple repetition and check-in prefix, and requires neither network access nor executing malware. It **does not re-extract the key from the ELF**, nor independently query blockchain history. Those are distinct verification levels, and the original ELF is deliberately not distributed in this release.

**Avoid a common parsing error:** The last four *raw* bytes of these IPv6-formatted strings are **ciphertext**, not an IPv4 C2 indicator. Treating them as direct IP addresses produces false indicators.

## 4. Why this mechanism matters

**[INFERENCE, high confidence]** The bot can obtain a changeable C2 configuration from public blockchain data while keeping the intended IPv4 address out of cleartext in its executable. The byte string's `2001:db8` prefix provides an IPv6-looking container for transformed data; it is not a routable C2 IPv6 address.

**[UNVERIFIED]** Neither decoded IPv4 is demonstrated to have accepted a malware connection during our investigation. A transaction sender, the funding provenance of a contract deployment, a hosting ASN, and an IP address do **not** establish the identity of the botnet operator. We make no personal or organizational attribution.

## 5. Controlled behavioral analysis — October 29, 2026

The ELF was launched only in a **restricted victim VM** communicating with a **separate private simulation VM**. This server simulated DNS, an HTTPS Polygon RPC service, and TCP C2 on port 25565. Outbound traffic from the malware's unprivileged UID was restricted to the private simulation host; other network destinations and outbound IPv6 for that UID were blocked. The experiment used NFLOG on the victim and Ethernet capture on the simulation server. Processes were stopped and restrictive controls restored after testing. **No real attacker C2 was contacted**.

### Nine Polygon RPC candidates, three observed

**[OBSERVED, static]** A provider/path table near `0x467680` contains **nine Polygon RPC candidates**. A selection routine near `0x40de32` chooses a pseudo-random starting entry and attempts candidates in circular order until an acceptable response is obtained.

**[OBSERVED, dynamic]** Across three bounded runs, the sample requested three different legitimate providers:

- `polygon.drpc.org`
- `poly.api.pocket.network`
- `rpc.solidrpc.io`

The simulation received JSON-RPC `eth_call` requests for the expected contract, selector and `latest` block. We returned **synthetic, valid ABI data** designed to make the program calculate the private simulation endpoint instead of an external C2. The nine candidates represent **Polygon data-access services, not nine criminal C2 servers**; blanket blocking of these services is unwarranted.

### Exact 26-byte C2 registration and heartbeats

**[OBSERVED]** When the sample reached the **fake** C2 over TCP/25565, the first application message was 26 bytes:

```text
00 00 00 01 06 78 38 36 5f 36 34 09 61 6b 75 6d 61 2e 61 64 62 01 00 00 07 43
```

The `06` and `09` length bytes introduce `x86_64` and `akuma.adb`. The last five bytes describe the test system: **one online CPU** and **1,859 MiB of RAM**, rather than an IP address. The fake server's logs record five `00 00` heartbeats approximately **60 seconds** apart. No application-level attack command was sent back by the simulation server; **no DDoS activity was exercised or observed**.

### Bounded reconnection and port observations

**[OBSERVED]** During a 360-second test blocking TCP/25565, the network capture recorded five connection SYN attempts to the **same port** and no alternative-port attempt. In a separate restricted all-ports trial toward only the simulation host, the malware initiated TCP connections only to **443 and 25565**, with DNS on UDP/53. On the examined reconnect path, static analysis indicates the program retained its previously decoded IPv4 rather than immediately calling Polygon again.

**[UNVERIFIED]** A six-minute window and one code path cannot exclude all possible fallback strategies, other bot variants, or behavior after a longer period.

### Capture composition and evidence protection

The original simulation-server capture contains **334 Ethernet frames**: **290 administrative SSH frames**, **10 ARP frames**, and **34 relevant IPv4 packets**. A derived TCP/25565 subset contains **17 packets**. Its TCP stream carries **34 application bytes** (the registration plus four heartbeats); the private fake-C2 log records **36 bytes** because its fifth heartbeat fell outside the Ethernet capture window.

Only the 17-packet subset was adapted for public release: source/destination addresses were replaced with reserved documentation addresses **`192.0.2.10` and `192.0.2.20`**; MAC addresses and internal TCP timestamps were also replaced, and IPv4/TCP checksums recalculated and verified for all 17 packets. TCP payload bytes and segmentation were preserved. **The unredacted source with administrative SSH is not published.**

## 6. Detection: candidate Suricata rule and measured results

**[OBSERVED]** The 26-byte registration is split in the original capture into TCP segments carrying **4 + 7 + 15 bytes**. The first 21 bytes provide a useful registration prefix covering the architecture and bot label, while excluding the variable CPU/RAM suffix:

```text
00 00 00 01 06 78 38 36 5f 36 34 09 61 6b 75 6d 61 2e 61 64 62
```

The following candidate rule was tested on **Suricata 7.0.10** on October 30:

```suricata
alert tcp any any -> any any (msg:"MALWARE Akuma ADB x86_64 C2 registration"; flow:established,to_server; content:"|00 00 00 01 06 78 38 36 5f 36 34 09 61 6b 75 6d 61 2e 61 64 62|"; depth:21; classtype:trojan-activity; sid:9001001; rev:1;)
```

| Offline corpus | Replay conditions | Alerts on `sid:9001001` | Interpretation |
| --- | --- | ---: | --- |
| Original reduced 17-packet C2 stream | Rule-only replay | **1** | The target registration is detectable in the test stream. |
| Original 334-frame Ethernet capture | Normal checksum checks | **0** | **Inconclusive:** Suricata reported many invalid capture checksums. |
| Same original 334-frame capture | `-k none` for this offline replay | **1** | Detection verified after checksum checks were disabled for the test file. |
| Derived 27-packet control, excluding C2 flow and SSH | `-k none` | **0** | Internal sanity check only; **not** an independent benign corpus. |
| Victim-side NFLOG capture, linktype 239 | Suricata 7.0.10 PCAP reader | **Not analyzed** | The engine rejected the unsupported link type; no negative result can be claimed. |

**Timestamp caveat:** Suricata emitted an alert timestamp of **2026-10-29 12:21:51.606630 UTC**, matching the capture's initial frame. The actual registration segments occur near **12:24:07.386 UTC**, and EVE records `pkt_src="stream (flow timeout)"`. For the communication timeline we use the original packet/flow timestamps; the precise cause of the alert timestamp discrepancy has not been established.

The public [Suricata rule](akuma-adb-x64.rules) is specifically a **candidate signature for this `akuma.adb` x86_64 check-in**. **No independent benign dataset, cross-architecture validation, or measured false-positive rate exists**. Disabling checksum verification was needed for *this archived PCAP replay only*, **not** a recommendation for production sensors. **The publicly anonymized 17-packet PCAP has not yet been replayed through Suricata after rewriting its headers**; the engine-positive claims above apply to the original capture and its original reduced subset.

## 7. Public reproduction without malware execution

The public package contains a minimal, curated evidence set:

| File | Purpose and limitation |
| --- | --- |
| [AKUMA_PUBLIC_EVIDENCE_2026-10-28.json](AKUMA_PUBLIC_EVIDENCE_2026-10-28.json) | Selected ADB events, raw Polygon setter calldata, reconstructed configuration, private-lab observations and detection results; **not** full native logs. |
| [AKUMA_PUBLIC_DECODE_20261030.py](AKUMA_PUBLIC_DECODE_20261030.py) | Offline Python 3 decoder using the **published key**; **not** an independent ELF key extractor. |
| [akuma-adb-x64.rules](akuma-adb-x64.rules) | Candidate Suricata signature for the observed 21-byte registration prefix. |
| [AKUMA_C2_ANONYMIZED_20261030.pcap](AKUMA_C2_ANONYMIZED_20261030.pcap) | Seventeen anonymized *real capture packets from the simulated-C2 trial*; **not** packets from a live criminal C2. |
| [AKUMA_PUBLIC_SHA256SUMS_20261030.txt](AKUMA_PUBLIC_SHA256SUMS_20261030.txt) | Integrity manifest for the four files above; a checksum is **not** third-party authentication. |
| [AKUMA_PUBLIC_RELEASE_README_20261030.md](AKUMA_PUBLIC_RELEASE_README_20261030.md) | Release description, provenance, data-handling and scope limits. |

To check consistency and hashes locally **without network access or executing an ELF**:

```bash
python3 AKUMA_PUBLIC_DECODE_20261030.py AKUMA_PUBLIC_EVIDENCE_2026-10-28.json
sha256sum -c AKUMA_PUBLIC_SHA256SUMS_20261030.txt
```

Expected decoder output includes `45.205.1.121:25565`, `191.217.203.232:25565`, threefold repetition of each decoded IPv4, registration-prefix verification and `PASS`. The public Python utility uses only the standard library.

The original forensic validation (kept private) also independently reconstructs the embedded key from the sampled ELF and checks the archived transaction inputs, receipts and SHA-256 values. That deeper verification requires the private malware archive and forensic evidence; it is not implied by successful execution of the **public** decoder.

## 8. Indicators, confidence, and suggested use

The categories below are intentionally distinct. **Configured C2 destinations are not labelled "confirmed live".** Public RPC provider domains should not be blocked as malware infrastructure merely because the sample queried them.

| Observable | Role | Evidence and caveat |
| --- | --- | --- |
| `hxxp://45[.]9[.]2[.]239:24381/bins/payloads/w.sh` | ADB installation script URL | **[OBSERVED]** in submitted command; not proof of an HTTP success during ADBHoney sessions. |
| `hxxp://45[.]9[.]2[.]239:24381/bins/payloads/c.sh` | Second installation script URL | **[OBSERVED]** in submitted command, same execution caveat. |
| `154.80.128.124`, `154.80.128.121` | Sources of ADB attempts | **[OBSERVED]** as source IPs; not an attribution of the responsible actor. |
| `45.205.1.121:25565` | Decoded October 18 C2 configuration | **[OBSERVED]** algorithm/transaction; **[UNVERIFIED]** live service. |
| `191.217.203.232:25565` | Decoded October 23 C2 configuration | **[OBSERVED]** algorithm/transaction; **[UNVERIFIED]** live service. |
| `0x084a379b1E18c153212015bCCD60295C948EaAe2` | Polygon configuration contract | **[OBSERVED]** referenced by ELF and relevant transactions. |
| `d5de7f84a8547f8ef0213890850aaac5840f168ffeb6bca34cb0870fc9854817` | Exact x86_64 ELF sample hash | **[OBSERVED]** identity of examined specimen; sample itself withheld from this public package. |
| `4890d90dd5eedd73f37ba627da8d1487114db5f5366772a9a464defc493c6943` | Archived `w.sh` SHA-256 | **[OBSERVED]** file identity; script not included in public package. |
| `ec0a0374513a93cd3f34e6b0ce57fc7408706dfd687bd608c385ac8da54ce047` | Archived `c.sh` SHA-256 | **[OBSERVED]** file identity; script not included in public package. |

Defenders can monitor **unauthorized ADB exposure on TCP/5555**, correlate the particular file hashes and observed delivery URLs, investigate outbound **TCP/25565** associated with the check-in pattern, and assess the proposed rule against their own benign traffic before deployment. A generic rule blocking **all Polygon RPC access** would be overbroad and is not recommended.

## 9. What our evidence does not establish

1. **Successful compromise or execution on a real ADB device.** Honeypot logs demonstrate commands delivered to an emulator; the x64 specimen was fetched later by the analyst.
2. **Live criminal C2 infrastructure.** Both IPv4s were derived from configuration values; our dynamic TCP connections reached a **private fake C2 only**.
3. **Complete historical Polygon contract state.** Two accepted setter transaction records and a consistent `latest` getter response are present; successful historical getter results and independent bytecode-state validation are not archived.
4. **Exhaustive DDoS capabilities or an observed attack.** The binary contains network-task dispatch structures, including a 24-entry dispatcher, but not a fully mapped set of 24 distinct, exercised functions. No DDoS command or attack traffic was observed.
5. **Universal Akuma detection.** Rule `9001001` matched one relevant original test flow; false-positive behavior in unrelated benign traffic and efficacy on other architectures remain unmeasured.
6. **Universal reconnect behavior.** A 360-second test did not show alternate ports; this does not exclude other paths, timeouts, or variants.
7. **Threat-actor attribution.** IP ownership, an ASN, a funding wallet, a contract transaction sender, or shared tooling alone does not identify an operator.

## 10. Relation to earlier research

**[CORROBORATED]** [KSI Digital's October 11–12, 2026 Akuma analysis](https://www.ksi-digital.com/en/blog/akuma-botnet-loader/) documents **earlier** Akuma activity through Telnet, another loader/distribution environment, an `akuma_x64` build, TCP/25565, check-in labels including `telnet.akuma` and later `akuma.dvr`, direct/network-tunnel C2 behavior, and previously published detection rules. These are material prior findings. Our sample's `akuma.adb` label, original ADBHoney delivery observations, independently recovered Polygon-based configuration key, two decoded transaction inputs and controlled test provide a **distinct, documented evidence chain**; they do **not** prove a distinct operator or that the overall technique was previously unknown.

**[CORROBORATED]** The referenced script host's `w.sh` had already appeared in [ThreatFox](https://threatfox.abuse.ch/ioc/1977508/) on October 21 under an initial *unknown malware* classification. Our analysis may help contextualize the observed indicator, but should not be presented as its first identification. We have not completed an exact byte-level comparison of the prior Suricata signatures and our new rule; **we therefore make no originality claim for the signature itself**.

The specific contribution of this report is the **combined primary-evidence chain for this sample**, rather than the discovery of Akuma as a family or a claim to be first to identify blockchain-based concealment.

## 11. Research ethics, disclosure and acknowledgements

The private experiment was designed to eliminate contact with real attacker infrastructure and not to transmit DDoS commands. The public package excludes the malicious executable, loader scripts, private administrative SSH, original lab addressing and secrets. The derived PCAP preserves lab-event times for timing analysis and consists of **fake-C2 communications only**. Original sources and hash manifests are archived for provenance but are **not public**.

The authors welcome independent verification and corrections. Any subsequent IOC submission should clearly distinguish **directly observed delivery infrastructure**, **sample hashes**, and **unverified live status of decoded destinations**. Reproduction of the public decoder requires no malware execution.

Prior research credit: **KSI Digital** for its independently published Akuma analysis and detection work. External passive context: **abuse.ch ThreatFox**. Network detection testing used **Suricata 7.0.10**.

---

*Prepared October 30, 2026. All timestamps in UTC. The repository was private at drafting time; this document is a proposed English public release, subject to final editorial and privacy review. No claim of independently confirmed live C2s or real-device compromise is made.*
