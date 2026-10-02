# 10 · Test data, the lab, and verification

Teams lose more hours to "we have no realistic traffic to test against" than to any algorithm.
This project has two sources of traffic: a **generator** that works everywhere, and a **Docker
lab** for real Postfix/Dovecot traffic.

## 1. The demo capture generator (`samples.py`)

```bash
python -m securemailscope samples samples
```

It writes byte-accurate captures: real TCP handshakes with checksums, real SMTP/IMAP/POP3
dialogues, and real TLS ClientHello/ServerHello/Certificate/ServerKeyExchange bytes. The
certificates are generated with pyca/cryptography under a demo CA. All names and addresses are
fictitious: `example.com`/`example.net` and the RFC 5737/3849 documentation ranges.

| File | Format | Contents |
|---|---|---|
| `demo-ca.pem` | PEM | the demo root CA: pass it as `--trust-store` |
| `healthy_baseline.pcap` | PCAP, Ethernet | a clean week earlier: 5 relay sessions, 3 submission, 2 IMAPS. Use it to seed `--baseline-db` |
| `demo_enterprise.pcap` | PCAP, Ethernet | the scenarios below, 687 frames |
| `starttls_stripping.pcapng` | PCAPNG, **Linux SLL**, ns timestamps | 3 healthy submission sessions and 1 stripped |

### Scenarios in `demo_enterprise.pcap`

| Client | Scenario | Expected findings |
|---|---|---|
| 198.51.100.40 | relay STARTTLS → TLS 1.2, with **reordering, a retransmission and an overlap** | none (tests reassembly) |
| 198.51.100.41 | same, **ISN 0xFFFFFF00** (sequence wrap) | none |
| 198.51.100.42 | same, **802.1Q VLAN 120** | none |
| 198.51.100.43 | same, plain | none |
| 10.20.0.10–12 | submission 587 STARTTLS → **TLS 1.3** | `CERT-010` info |
| 10.20.0.32 | IMAPS 993 TLS 1.3 | `CERT-010` info |
| 2001:db8:20::31 | **IPv6** IMAP STARTTLS → TLS 1.2 | none |
| 10.20.0.23 | submission: capability rewritten to `XXXXXXXX`, `AUTH LOGIN` + mail in cleartext | `STRIP-001`, `CRED-001`, `DATA-001`, `BASE-001` |
| 198.51.100.52 | relay: `454 TLS not available`, mail in cleartext | `STRIP-001`, `DATA-001`, `BASE-001` |
| 198.51.100.51 | relay: **self-signed** cert for mx.example.com | `CERT-002` (medium → **critical**), `BASE-002`, `TLS-012` |
| 10.20.0.26 | submission: `STARTTLS\r\nRSET\r\nMAIL FROM…` in one segment | `INJ-001` |
| 10.20.0.25 | submission: TLS 1.2 + DOWNGRD sentinel, client offered 1.3 | `TLS-010`, `BASE-003` |
| 10.20.0.27 | SMTPS 465: DHE-**1024**, CBC | `TLS-005`, `TLS-004`, `TLS-012` |
| 10.20.0.28 | SMTPS 465: SNI `mail.corp.example.com` vs `*.example.com` | + `CERT-003` (wildcard = one label) |
| 10.20.0.31 | IMAP 143, no STARTTLS, `LOGIN`, `FETCH` body | `PLAIN-001`, `CRED-001`, `DATA-001` |
| 10.20.0.40 | POP3 STLS → **TLS 1.0**, 3DES, RSA kx; RSA-1024 **SHA-1** expired cert, private CA | `TLS-001/002/003/006/009`, `CERT-001/004/005/007`, `ML-001` |
| 10.20.0.60 | Sendmail on **port 2525**, offers STARTTLS, client ignores it | `PORT-001`, `PLAIN-002`, `DATA-001` |
| 10.20.0.23 → :443 | HTTPS | ignored (not mail) |
| — | one UDP packet, one IP fragment | counted, skipped |

`tests/test_pipeline.py::test_scenario_findings` asserts every row.

## 2. The Docker lab (`lab/`)

A deliberately misconfigured mail server, a stripping proxy, and a client that generates traffic
and captures it with tcpdump. Everything is on an **internal** Docker network.

| Container | Role |
|---|---|
| `mailserver` | Debian + Postfix + Dovecot: TLS optional, AUTH before TLS allowed, TLS 1.0 and `@SECLEVEL=0` ciphers, a self-signed RSA-1024 SHA-1 cert with the wrong CN, plaintext IMAP/POP3 login allowed |
| `stripper` | `lab/strip_proxy.py`: forwards 25/587/143/110 to the mail server and rewrites `STARTTLS` → `XXXXXXXX`, `STLS` → `XXXX` (same length, as real devices do) |
| `client` | swaks, openssl, curl, tcpdump. `lab/traffic.sh` runs one of each pattern and writes `lab/captures/lab.pcap` |

```bash
cd lab
docker compose up -d --build
docker compose exec client sh /lab/traffic.sh
docker compose down
cd ..
python -m securemailscope analyze lab/captures/lab.pcap -o reports
```

> **Status:** the lab files are written, but they were not run in the development environment,
> because the Docker daemon wasn't running there. The stripping proxy's rewrite logic *is*
> unit-tested (`tests/test_lab_proxy.py`), including feeding its output through the protocol parser.
> Expect to adjust package or config details the first time you bring it up. The lab credential in
> `entrypoint.sh`/`traffic.sh` is a lab-only fixture.

To make stripping by hand without the proxy, use mitmproxy in TCP mode with a replacement rule,
or any 30-line socket relay. The key property is that the rewrite keeps the same length.

## 3. Verification: treat these as ground truth

Your parser will be wrong before it's right. Verify against independent tools:

| Tool | Check |
|---|---|
| **Wireshark / tshark** | conversations, followed streams, TLS fields: `tshark -r X.pcap -Y tls.handshake.type==2 -T fields -e tls.handshake.version -e tls.handshake.extensions.supported_version -e tls.handshake.ciphersuite` |
| **Wireshark JA3** | `-e tls.handshake.ja3` (and `ja3s`) to compare with the JSON report |
| **openssl** | `openssl s_client -starttls smtp -connect host:25 -showcerts`, then `openssl x509 -text -noout` |
| **testssl.sh / SSLyze** | active scans of the lab server: the versions, ciphers and certificate problems should agree with what the passive analysis saw |
| **Qualys SSL Labs** | the same, for internet-facing HTTPS on the same certificates |
| **Zeek** | `ssl.log` / `x509.log` as an independent passive oracle; also the fallback preprocessor if time runs short |

Example cross-check of the demo capture's negotiated versions:

```bash
tshark -r samples/demo_enterprise.pcap -Y "tls.handshake.type==2" -T fields -e ip.src -e tls.handshake.extensions.supported_version -e tls.handshake.ciphersuite
```

Sessions with `0x0304` in the second column must be TLS 1.3 in the SecureMailScope report, even
though their legacy version field says `0x0303`.

**Cross-check done during development (TShark 4.6.4):** all three sample captures open with **zero
expert errors**. The TCP conversation counts match SecureMailScope's flow counts (20 and 4). Every
negotiated version and cipher suite matches. Every server **JA3S matches Wireshark's** hash exactly.
The first run of this check found a real generator bug: DHE and RSA ClientKeyExchange messages used
the ECDHE length prefix, and Wireshark flagged them as malformed. That's gotcha #10 earning its place.

## Third-party corpora

The lab and `samples.py` produce captures we control, which is what makes the
attack cases possible — no public dataset contains STARTTLS stripping, because
collecting one against a real server is either illegal or too sensitive to
publish. What they cannot produce is traffic nobody built for us.

The best mail-specific corpus is **Zeek's own protocol test suite**, at
`testing/btest/Traces/` in `github.com/zeek/zeek`:

| Path | What it gives us |
|---|---|
| `tls/smtp-starttls.pcap`, `tls/imap-starttls.pcap`, `tls/pop3-starttls.pcap` | All three STARTTLS upgrades, real servers, real certificates |
| `tls/xmpp-starttls.pcap`, `tls/irc-starttls.pcap`, `ldap/ldap-starttls.pcap` | STARTTLS on protocols we must *not* claim — negative cases |
| `smtp/rfc3030-bdat-*.pcap` | BDAT chunking: the DATA alternative our state machine also has to follow |
| `smtp/smtp-bdat-cmd-*.pcap` | Malformed and hostile length fields |
| `smtp-one-side-only.pcap` | A capture with one direction missing |
| `smtp/smtp-bdat-gap.pcap` | A reassembly gap mid-transaction |
| `pop3/pop3.pcap`, `pop3-unknown-commands.pcap` | POP3 sessions and unknown verbs |

Fetch just that directory rather than the whole repository:

```sh
git clone --filter=blob:none --no-checkout --depth 1 https://github.com/zeek/zeek.git
cd zeek && git sparse-checkout set testing/btest/Traces && git checkout
```

Sweep a corpus with `tools/corpus.py`, which runs each capture in its own
process so a hang cannot take the run down:

```sh
python tools/corpus.py ~/captures --csv results.csv
```

It reports parsed / crashed / timed out, throughput and what was found. It is a
robustness harness, not a detection test: third-party captures carry no ground
truth, so the only assertion it can make is that the pipeline survives them.

Two bugs came out of the first sweep, both from Zeek's deliberately malformed
SMTP traces, and both are now regression tests in `tests/test_mailproto.py`:

- `BDAT -100` reached `math.log1p()` through the feature vector and raised
  `ValueError: math domain error`, aborting the analysis. A negative count also
  made `Cursor.take()` slice backwards and rewind the parser.
- `BDAT 999999999` over five real bytes was counted as 999999999 bytes of
  cleartext exposure. The declared size is attacker-controlled; only bytes
  actually observed on the wire are evidence, and the parser now counts what
  `take()` returned rather than what the client announced.
