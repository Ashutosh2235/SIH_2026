# SecureMailScope public-derived mail TLS dataset

Built by SecureMailScope 1.0.0 with seed 2026. **4043 sessions.** Rebuild with `python -m securemailscope dataset build -o <dir>`.

## Why it exists

No public corpus of SMTP / IMAP / POP3 sessions labelled by cryptographic risk exists, and public captures containing mail are rare. This dataset is assembled from public captures, and every row records where it came from.

## Composition

| Origin | Rows | What it is | Label |
|---|---|---|---|
| real | 21 | every mail session found in the public captures | rules engine (weak) |
| transplant | 210 | a real mail STARTTLS prologue + a real TLS handshake from another capture: real versions, ciphers, key exchange and certificates in a mail context | rules engine (weak) |
| augmented | 3710 | real and transplanted upgrades edited to carry known issues: STARTTLS stripping and injection; TLS 1.0 / 1.1, 3DES, RC4, no forward secrecy, compression, downgrade sentinel, handshake failure; self-signed, expired, 1024-bit, SHA-1, mismatched and untrusted certificates; cleartext credentials; non-standard ports; and 2-3-issue combinations | **by construction** (`issues`, `expected_rules`) |

Splits: {'test': 606, 'train': 2830, 'val': 607}. Whole groups (`group` = source + server endpoint) are assigned to one split, greedily toward 70/15/15, and variants stay in their parent's group, so no server appears in two splits. Use `group` for group-aware cross-validation.

Protocols: {'SMTP': 2011, 'IMAP': 1109, 'POP3': 923}

TLS versions: {'none': 1050, 'TLS 1.2': 1752, 'TLS 1.3': 794, 'TLS 1.0': 257, 'TLS 1.3 (draft 20)': 37, 'TLS 1.1': 153}

Rule-risk classes: {'high': 1038, 'critical': 2029, 'minimal': 180, 'medium': 355, 'low': 441}

## Sources

| Source | Provides | Rows | SHA-256 used | Licence / terms |
|---|---|---|---|---|
| [weber-ultimate](https://weberblog.net/wp-content/uploads/2020/02/The-Ultimate-PCAP.pcapng.gz) | real SMTP/IMAP/POP3 (cleartext, STARTTLS, implicit TLS) and ~60 real TLS handshakes | {'real': 17, 'transplant': 162, 'augmented': 2381} | `ecbca543fbe011a8…` | Johannes Weber, weberblog.net/the-ultimate-pcap (no licence stated; versioned, may change) |
| [ws-smtp](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/smtp.pcap) | real cleartext SMTP | {'real': 1} | `17ad230db1b6fd5d…` | Wireshark wiki SampleCaptures; check the wiki's terms before redistributing the raw file |
| [ws-imf](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/sample-imf.pcap.gz) | real cleartext SMTP with MIME | {'real': 1} | `7e1e5deec73e2e57…` | Wireshark wiki SampleCaptures; check the wiki's terms before redistributing the raw file |
| [ws-tnef](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/sample-TNEF.pcap.gz) | real cleartext SMTP with attachments | {'real': 1} | `4d89c204e785e4a7…` | Wireshark wiki SampleCaptures; check the wiki's terms before redistributing the raw file |
| [ws-imap](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/imap.cap) | real cleartext IMAP | {'real': 1} | `fa9a9bcca7b7f294…` | Wireshark wiki SampleCaptures; check the wiki's terms before redistributing the raw file |
| [ws-tls12-aes128ccm](https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures/tls12-aes128ccm.pcap) | TLS 1.2 AES-CCM | {'transplant': 3, 'augmented': 51} | `175e4e1186aa0602…` | Wireshark source tree test/captures (GPL-2.0-or-later project) |
| [ws-tls12-aes256gcm](https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures/tls12-aes256gcm.pcap) | TLS 1.2 AES-256-GCM | {'transplant': 3, 'augmented': 51} | `24d95f17af5b0b6a…` | Wireshark source tree test/captures (GPL-2.0-or-later project) |
| [ws-tls12-chacha20poly1305](https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures/tls12-chacha20poly1305.pcap) | TLS 1.2 ChaCha20-Poly1305, several key exchanges | {'transplant': 21, 'augmented': 423} | `fc69b8b1bf484729…` | Wireshark source tree test/captures (GPL-2.0-or-later project) |
| [ws-tls12-dsb](https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures/tls12-dsb.pcapng) | TLS 1.2 | {'transplant': 6, 'augmented': 138} | `d6034147bd02a206…` | Wireshark source tree test/captures (GPL-2.0-or-later project) |
| [ws-tls13-rfc8446](https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures/tls13-rfc8446.pcap) | TLS 1.3 (RFC 8446) | {'transplant': 6, 'augmented': 47} | `e24aaedb2912f9ea…` | Wireshark source tree test/captures (GPL-2.0-or-later project) |
| [ws-tls13-20-chacha20poly1305](https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures/tls13-20-chacha20poly1305.pcap) | TLS 1.3 draft 20 | {'transplant': 6, 'augmented': 53} | `0fcafe42260b12a2…` | Wireshark source tree test/captures (GPL-2.0-or-later project) |
| [ws-tls-renegotiation](https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures/tls-renegotiation.pcap) | TLS 1.2 with renegotiation | {'transplant': 3, 'augmented': 68} | `a3472920f5080ac3…` | Wireshark source tree test/captures (GPL-2.0-or-later project) |
| [lab-r1-good-relay]() | lab healthy server: relay, STARTTLS, TLS >= 1.2 | {'lab': 1, 'augmented': 9} | `b6dd644d80d1ddda…` | generated by this project's lab (lab/) |
| [lab-r1-good-submission]() | lab healthy server: submission, STARTTLS then AUTH | {'lab': 1, 'augmented': 8} | `c5bbffad6581ca90…` | generated by this project's lab (lab/) |
| [lab-r1-good-imap]() | lab healthy server: IMAP STARTTLS then LOGIN | {'lab': 1, 'augmented': 8} | `c19693285d0a0ee6…` | generated by this project's lab (lab/) |
| [lab-r1-good-pop3]() | lab healthy server: POP3 STLS then USER/PASS | {'lab': 1, 'augmented': 8} | `ce7c18e363c3e542…` | generated by this project's lab (lab/) |
| [lab-r1-good-imaps]() | lab healthy server: IMAPS (implicit TLS) | {'lab': 1} | `bff8c6ac5f0af31c…` | generated by this project's lab (lab/) |
| [lab-r1-good-smtps]() | lab healthy server: SMTPS (implicit TLS) | {'lab': 1} | `20be1fafedc2b662…` | generated by this project's lab (lab/) |
| [lab-r1-strip-submission]() | lab healthy server: submission through the stripping proxy | {'lab': 1} | `bbc6b31dfe992ff4…` | generated by this project's lab (lab/) |
| [lab-r1-strip-imap]() | lab healthy server: IMAP through the stripping proxy | {'lab': 1} | `666df815c7bacf98…` | generated by this project's lab (lab/) |
| [lab-r1-strip-pop3]() | lab healthy server: POP3 through the stripping proxy | {'lab': 1} | `c4c2bbbbc10d8191…` | generated by this project's lab (lab/) |
| [lab-r1-weak-relay]() | lab weak server: relay, STARTTLS, TLS 1.2 | {'lab': 1, 'augmented': 23} | `0cc1ee0b2b1f11d4…` | generated by this project's lab (lab/) |
| [lab-r1-weak-imaps]() | lab weak server: IMAPS, TLS 1.2 | {'lab': 1} | `e3ca8c9e79a3d5d7…` | generated by this project's lab (lab/) |
| [lab-r1-weak-submission]() | lab weak server: submission, AUTH LOGIN in cleartext | {'lab': 1} | `a1b4a6611e223018…` | generated by this project's lab (lab/) |
| [lab-r1-weak-imap]() | lab weak server: IMAP LOGIN in cleartext | {'lab': 1} | `afb9bc94f04c0aa1…` | generated by this project's lab (lab/) |
| [lab-r1-weak-pop3]() | lab weak server: POP3 USER/PASS in cleartext | {'lab': 1} | `2111f9d41a41ea9d…` | generated by this project's lab (lab/) |
| [lab-r1-old-relay]() | lab legacy server: relay, STARTTLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 9} | `acc9fd1b2a37978e…` | generated by this project's lab (lab/) |
| [lab-r1-old-imap]() | lab legacy server: IMAP STARTTLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 9} | `0c09a64b02bd6f5b…` | generated by this project's lab (lab/) |
| [lab-r1-old-pop3]() | lab legacy server: POP3 STLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 8} | `7a4e2532ecfccce8…` | generated by this project's lab (lab/) |
| [lab-r2-good-relay]() | lab healthy server: relay, STARTTLS, TLS >= 1.2 | {'lab': 1, 'augmented': 8} | `dae7c851347a45a0…` | generated by this project's lab (lab/) |
| [lab-r2-good-submission]() | lab healthy server: submission, STARTTLS then AUTH | {'lab': 1, 'augmented': 8} | `15bfe8f8c816b8c8…` | generated by this project's lab (lab/) |
| [lab-r2-good-imap]() | lab healthy server: IMAP STARTTLS then LOGIN | {'lab': 1, 'augmented': 9} | `bd3f012667720a64…` | generated by this project's lab (lab/) |
| [lab-r2-good-pop3]() | lab healthy server: POP3 STLS then USER/PASS | {'lab': 1, 'augmented': 8} | `155b9081684da36e…` | generated by this project's lab (lab/) |
| [lab-r2-good-imaps]() | lab healthy server: IMAPS (implicit TLS) | {'lab': 1} | `ef2a900f67c4642a…` | generated by this project's lab (lab/) |
| [lab-r2-good-smtps]() | lab healthy server: SMTPS (implicit TLS) | {'lab': 1} | `84d76621c4fd2cde…` | generated by this project's lab (lab/) |
| [lab-r2-strip-submission]() | lab healthy server: submission through the stripping proxy | {'lab': 1} | `21e8d0c5b8ee759e…` | generated by this project's lab (lab/) |
| [lab-r2-strip-imap]() | lab healthy server: IMAP through the stripping proxy | {'lab': 1} | `0eb7cd9ee4da4e68…` | generated by this project's lab (lab/) |
| [lab-r2-strip-pop3]() | lab healthy server: POP3 through the stripping proxy | {'lab': 1} | `7f354cf0f55110ee…` | generated by this project's lab (lab/) |
| [lab-r2-weak-relay]() | lab weak server: relay, STARTTLS, TLS 1.2 | {'lab': 1, 'augmented': 23} | `28be9ff38b3705c2…` | generated by this project's lab (lab/) |
| [lab-r2-weak-imaps]() | lab weak server: IMAPS, TLS 1.2 | {'lab': 1} | `226e014b8f6e63cb…` | generated by this project's lab (lab/) |
| [lab-r2-weak-submission]() | lab weak server: submission, AUTH LOGIN in cleartext | {'lab': 1} | `a3ec9d3253fe5fcd…` | generated by this project's lab (lab/) |
| [lab-r2-weak-imap]() | lab weak server: IMAP LOGIN in cleartext | {'lab': 1} | `c2572cffa515316a…` | generated by this project's lab (lab/) |
| [lab-r2-weak-pop3]() | lab weak server: POP3 USER/PASS in cleartext | {'lab': 1} | `d5e79d0822ecf7d8…` | generated by this project's lab (lab/) |
| [lab-r2-old-relay]() | lab legacy server: relay, STARTTLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 8} | `43867b07d67f6618…` | generated by this project's lab (lab/) |
| [lab-r2-old-imap]() | lab legacy server: IMAP STARTTLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 8} | `c3fc91431dd420e7…` | generated by this project's lab (lab/) |
| [lab-r2-old-pop3]() | lab legacy server: POP3 STLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 7} | `f854dfe93f3d9a40…` | generated by this project's lab (lab/) |
| [lab-r3-good-relay]() | lab healthy server: relay, STARTTLS, TLS >= 1.2 | {'lab': 1, 'augmented': 10} | `b4476cd0acecc8b1…` | generated by this project's lab (lab/) |
| [lab-r3-good-submission]() | lab healthy server: submission, STARTTLS then AUTH | {'lab': 1, 'augmented': 9} | `4e66e8880f460ee4…` | generated by this project's lab (lab/) |
| [lab-r3-good-imap]() | lab healthy server: IMAP STARTTLS then LOGIN | {'lab': 1, 'augmented': 8} | `55c86a4279df3159…` | generated by this project's lab (lab/) |
| [lab-r3-good-pop3]() | lab healthy server: POP3 STLS then USER/PASS | {'lab': 1, 'augmented': 10} | `5e7c90b018d38a62…` | generated by this project's lab (lab/) |
| [lab-r3-good-imaps]() | lab healthy server: IMAPS (implicit TLS) | {'lab': 1} | `87f60b4b03f53e25…` | generated by this project's lab (lab/) |
| [lab-r3-good-smtps]() | lab healthy server: SMTPS (implicit TLS) | {'lab': 1} | `2c149ceb399c928d…` | generated by this project's lab (lab/) |
| [lab-r3-strip-submission]() | lab healthy server: submission through the stripping proxy | {'lab': 1} | `0aa68a9de8c00b00…` | generated by this project's lab (lab/) |
| [lab-r3-strip-imap]() | lab healthy server: IMAP through the stripping proxy | {'lab': 1} | `9f99f7d1faa2a2ba…` | generated by this project's lab (lab/) |
| [lab-r3-strip-pop3]() | lab healthy server: POP3 through the stripping proxy | {'lab': 1} | `b1540aabfed92388…` | generated by this project's lab (lab/) |
| [lab-r3-weak-relay]() | lab weak server: relay, STARTTLS, TLS 1.2 | {'lab': 1, 'augmented': 23} | `a174c48ff4ad5fe7…` | generated by this project's lab (lab/) |
| [lab-r3-weak-imaps]() | lab weak server: IMAPS, TLS 1.2 | {'lab': 1} | `0ebfa245f48f7044…` | generated by this project's lab (lab/) |
| [lab-r3-weak-submission]() | lab weak server: submission, AUTH LOGIN in cleartext | {'lab': 1} | `de3cac02eafc2107…` | generated by this project's lab (lab/) |
| [lab-r3-weak-imap]() | lab weak server: IMAP LOGIN in cleartext | {'lab': 1} | `bb4f9071c4a939b2…` | generated by this project's lab (lab/) |
| [lab-r3-weak-pop3]() | lab weak server: POP3 USER/PASS in cleartext | {'lab': 1} | `3d00dd802d216d72…` | generated by this project's lab (lab/) |
| [lab-r3-old-relay]() | lab legacy server: relay, STARTTLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 10} | `4dfd6c9ee4e662f9…` | generated by this project's lab (lab/) |
| [lab-r3-old-imap]() | lab legacy server: IMAP STARTTLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 10} | `471cc5cd3f08a8f1…` | generated by this project's lab (lab/) |
| [lab-r3-old-pop3]() | lab legacy server: POP3 STLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 8} | `10170e2cff88235f…` | generated by this project's lab (lab/) |
| [lab-r4-good-relay]() | lab healthy server: relay, STARTTLS, TLS >= 1.2 | {'lab': 1, 'augmented': 8} | `4d86217f4be045a4…` | generated by this project's lab (lab/) |
| [lab-r4-good-submission]() | lab healthy server: submission, STARTTLS then AUTH | {'lab': 1, 'augmented': 8} | `838668844d121a0d…` | generated by this project's lab (lab/) |
| [lab-r4-good-imap]() | lab healthy server: IMAP STARTTLS then LOGIN | {'lab': 1, 'augmented': 9} | `62f20b806d3925f1…` | generated by this project's lab (lab/) |
| [lab-r4-good-pop3]() | lab healthy server: POP3 STLS then USER/PASS | {'lab': 1, 'augmented': 10} | `3e9d4540a63861cd…` | generated by this project's lab (lab/) |
| [lab-r4-good-imaps]() | lab healthy server: IMAPS (implicit TLS) | {'lab': 1} | `9f6cc1b2e50f089f…` | generated by this project's lab (lab/) |
| [lab-r4-good-smtps]() | lab healthy server: SMTPS (implicit TLS) | {'lab': 1} | `7f4aa6311beaee59…` | generated by this project's lab (lab/) |
| [lab-r4-strip-submission]() | lab healthy server: submission through the stripping proxy | {'lab': 1} | `557df4584200bdfd…` | generated by this project's lab (lab/) |
| [lab-r4-strip-imap]() | lab healthy server: IMAP through the stripping proxy | {'lab': 1} | `7d4da60573eca219…` | generated by this project's lab (lab/) |
| [lab-r4-strip-pop3]() | lab healthy server: POP3 through the stripping proxy | {'lab': 1} | `971b5bfdd4ed38c3…` | generated by this project's lab (lab/) |
| [lab-r4-weak-relay]() | lab weak server: relay, STARTTLS, TLS 1.2 | {'lab': 1, 'augmented': 23} | `33b4a43f58ca8c0f…` | generated by this project's lab (lab/) |
| [lab-r4-weak-imaps]() | lab weak server: IMAPS, TLS 1.2 | {'lab': 1} | `4562ef482900b0cb…` | generated by this project's lab (lab/) |
| [lab-r4-weak-submission]() | lab weak server: submission, AUTH LOGIN in cleartext | {'lab': 1} | `f9f49d0adff5a3d4…` | generated by this project's lab (lab/) |
| [lab-r4-weak-imap]() | lab weak server: IMAP LOGIN in cleartext | {'lab': 1} | `b4caae88567a23c2…` | generated by this project's lab (lab/) |
| [lab-r4-weak-pop3]() | lab weak server: POP3 USER/PASS in cleartext | {'lab': 1} | `4f298789299f1c95…` | generated by this project's lab (lab/) |
| [lab-r4-old-relay]() | lab legacy server: relay, STARTTLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 9} | `f3dcd145259e3dca…` | generated by this project's lab (lab/) |
| [lab-r4-old-imap]() | lab legacy server: IMAP STARTTLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 9} | `df695ecf2f6380e1…` | generated by this project's lab (lab/) |
| [lab-r4-old-pop3]() | lab legacy server: POP3 STLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 7} | `b6acad5331b8183d…` | generated by this project's lab (lab/) |
| [lab-r5-good-relay]() | lab healthy server: relay, STARTTLS, TLS >= 1.2 | {'lab': 1, 'augmented': 9} | `9c3989e2bc461500…` | generated by this project's lab (lab/) |
| [lab-r5-good-submission]() | lab healthy server: submission, STARTTLS then AUTH | {'lab': 1, 'augmented': 8} | `c8e35c0196fc6bb7…` | generated by this project's lab (lab/) |
| [lab-r5-good-imap]() | lab healthy server: IMAP STARTTLS then LOGIN | {'lab': 1, 'augmented': 9} | `4e436fb4c081a035…` | generated by this project's lab (lab/) |
| [lab-r5-good-pop3]() | lab healthy server: POP3 STLS then USER/PASS | {'lab': 1, 'augmented': 10} | `ff634282afeb58fc…` | generated by this project's lab (lab/) |
| [lab-r5-good-imaps]() | lab healthy server: IMAPS (implicit TLS) | {'lab': 1} | `ebccdd99254f438e…` | generated by this project's lab (lab/) |
| [lab-r5-good-smtps]() | lab healthy server: SMTPS (implicit TLS) | {'lab': 1} | `daa23056374f487c…` | generated by this project's lab (lab/) |
| [lab-r5-strip-submission]() | lab healthy server: submission through the stripping proxy | {'lab': 1} | `43f407b30a52f890…` | generated by this project's lab (lab/) |
| [lab-r5-strip-imap]() | lab healthy server: IMAP through the stripping proxy | {'lab': 1} | `394a5726cb176bca…` | generated by this project's lab (lab/) |
| [lab-r5-strip-pop3]() | lab healthy server: POP3 through the stripping proxy | {'lab': 1} | `a21619de9769e879…` | generated by this project's lab (lab/) |
| [lab-r5-weak-relay]() | lab weak server: relay, STARTTLS, TLS 1.2 | {'lab': 1, 'augmented': 23} | `56e41cba10ea998d…` | generated by this project's lab (lab/) |
| [lab-r5-weak-imaps]() | lab weak server: IMAPS, TLS 1.2 | {'lab': 1} | `56e354abcf3b55fa…` | generated by this project's lab (lab/) |
| [lab-r5-weak-submission]() | lab weak server: submission, AUTH LOGIN in cleartext | {'lab': 1} | `293df47a43074599…` | generated by this project's lab (lab/) |
| [lab-r5-weak-imap]() | lab weak server: IMAP LOGIN in cleartext | {'lab': 1} | `0fe67232b184709b…` | generated by this project's lab (lab/) |
| [lab-r5-weak-pop3]() | lab weak server: POP3 USER/PASS in cleartext | {'lab': 1} | `08814726e930c555…` | generated by this project's lab (lab/) |
| [lab-r5-old-relay]() | lab legacy server: relay, STARTTLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 10} | `fe7603b5c0077f50…` | generated by this project's lab (lab/) |
| [lab-r5-old-imap]() | lab legacy server: IMAP STARTTLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 9} | `c1fe0f86fee93ff9…` | generated by this project's lab (lab/) |
| [lab-r5-old-pop3]() | lab legacy server: POP3 STLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 6} | `58c08345f08be660…` | generated by this project's lab (lab/) |
| [lab-r6-good-relay]() | lab healthy server: relay, STARTTLS, TLS >= 1.2 | {'lab': 1, 'augmented': 9} | `aba6ff7ba3f02dcb…` | generated by this project's lab (lab/) |
| [lab-r6-good-submission]() | lab healthy server: submission, STARTTLS then AUTH | {'lab': 1, 'augmented': 9} | `3ef6c919efe37eff…` | generated by this project's lab (lab/) |
| [lab-r6-good-imap]() | lab healthy server: IMAP STARTTLS then LOGIN | {'lab': 1, 'augmented': 9} | `a84606b47a9a2bd5…` | generated by this project's lab (lab/) |
| [lab-r6-good-pop3]() | lab healthy server: POP3 STLS then USER/PASS | {'lab': 1, 'augmented': 9} | `51dfc402b9b532ab…` | generated by this project's lab (lab/) |
| [lab-r6-good-imaps]() | lab healthy server: IMAPS (implicit TLS) | {'lab': 1} | `656df80aabd737f0…` | generated by this project's lab (lab/) |
| [lab-r6-good-smtps]() | lab healthy server: SMTPS (implicit TLS) | {'lab': 1} | `227f02e5cba7cb71…` | generated by this project's lab (lab/) |
| [lab-r6-strip-submission]() | lab healthy server: submission through the stripping proxy | {'lab': 1} | `8a45bf3b5cb40c60…` | generated by this project's lab (lab/) |
| [lab-r6-strip-imap]() | lab healthy server: IMAP through the stripping proxy | {'lab': 1} | `d9e2224588c0ca7e…` | generated by this project's lab (lab/) |
| [lab-r6-strip-pop3]() | lab healthy server: POP3 through the stripping proxy | {'lab': 1} | `42c335c2dd7257a8…` | generated by this project's lab (lab/) |
| [lab-r6-weak-relay]() | lab weak server: relay, STARTTLS, TLS 1.2 | {'lab': 1, 'augmented': 23} | `0888041c7ff0c132…` | generated by this project's lab (lab/) |
| [lab-r6-weak-imaps]() | lab weak server: IMAPS, TLS 1.2 | {'lab': 1} | `47004969faf71fba…` | generated by this project's lab (lab/) |
| [lab-r6-weak-submission]() | lab weak server: submission, AUTH LOGIN in cleartext | {'lab': 1} | `b9fe6ca2e6f04cdb…` | generated by this project's lab (lab/) |
| [lab-r6-weak-imap]() | lab weak server: IMAP LOGIN in cleartext | {'lab': 1} | `1c9589c3805f460d…` | generated by this project's lab (lab/) |
| [lab-r6-weak-pop3]() | lab weak server: POP3 USER/PASS in cleartext | {'lab': 1} | `5534b6dd23f4177c…` | generated by this project's lab (lab/) |
| [lab-r6-old-relay]() | lab legacy server: relay, STARTTLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 8} | `6d8f45434d057d2e…` | generated by this project's lab (lab/) |
| [lab-r6-old-imap]() | lab legacy server: IMAP STARTTLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 8} | `a63bf28f7fae0889…` | generated by this project's lab (lab/) |
| [lab-r6-old-pop3]() | lab legacy server: POP3 STLS, TLS 1.0 RSA AES-CBC | {'lab': 1, 'augmented': 7} | `a4cb0c9a824df316…` | generated by this project's lab (lab/) |

## Detection on constructed attacks (ground truth)

*Per session* judges each session alone. *Full pipeline* runs the real pipeline as intended: it learns each server's baseline from the real and transplant sessions, then analyses each attack against it, with at most one attack per server per capture. `strip_remove` leaves nothing wrong inside the session itself, so only the baseline can catch it; where a server has fewer than 3 learned clean sessions the baseline abstains by design, and those sessions are counted as *abstained*, not as detections or misses.

| Variant | n | Per session | Full pipeline |
|---|---|---|---|
| cert_expired | 82 | 82 (100%) | 82 (100%) |
| cert_hostname_mismatch | 70 | 70 (100%) | 70 (100%) |
| cert_self_signed | 82 | 82 (100%) | 82 (100%) |
| cert_sha1 | 82 | 82 (100%) | 82 (100%) |
| cert_untrusted | 82 | 82 (100%) | 82 (100%) |
| cert_weak_key | 82 | 82 (100%) | 82 (100%) |
| cipher_3des | 112 | 112 (100%) | 112 (100%) |
| cipher_rc4 | 112 | 112 (100%) | 112 (100%) |
| cleartext_credentials | 266 | 266 (100%) | 266 (100%) |
| combo | 376 | 376 (100%) | 376 (100%) |
| downgrade_sentinel | 112 | 112 (100%) | 112 (100%) |
| handshake_failure | 266 | 266 (100%) | 266 (100%) |
| inject_client | 266 | 266 (100%) | 266 (100%) |
| inject_server | 266 | 266 (100%) | 266 (100%) |
| no_forward_secrecy | 112 | 112 (100%) | 112 (100%) |
| nonstandard_port | 266 | 266 (100%) | 266 (100%) |
| strip_refuse | 266 | 266 (100%) | 266 (100%) |
| strip_remove | 237 | 0 (0%) | 230 of 230 (100%, 7 abstained) |
| strip_rewrite | 237 | 237 (100%) | 237 (100%) |
| tls_1_0 | 112 | 112 (100%) | 112 (100%) |
| tls_1_1 | 112 | 112 (100%) | 112 (100%) |
| tls_compression | 112 | 112 (100%) | 112 (100%) |

Per issue, counting issues inside combos (the rule named must fire):

| Issue | Rule | n | Per session | Full pipeline |
|---|---|---|---|---|
| cert_expired | `SMS-CERT-001` | 108 | 108 (100%) | 108 (100%) |
| cert_hostname_mismatch | `SMS-CERT-003` | 92 | 92 (100%) | 92 (100%) |
| cert_self_signed | `SMS-CERT-002` | 116 | 116 (100%) | 116 (100%) |
| cert_sha1 | `SMS-CERT-005` | 101 | 101 (100%) | 101 (100%) |
| cert_untrusted | `SMS-CERT-007` | 115 | 115 (100%) | 115 (100%) |
| cert_weak_key | `SMS-CERT-004` | 112 | 112 (100%) | 112 (100%) |
| cipher_3des | `SMS-TLS-002` | 139 | 139 (100%) | 139 (100%) |
| cipher_rc4 | `SMS-TLS-002` | 150 | 150 (100%) | 150 (100%) |
| cleartext_credentials | `SMS-CRED-001` | 550 | 550 (100%) | 550 (100%) |
| downgrade_sentinel | `SMS-TLS-010` | 139 | 139 (100%) | 139 (100%) |
| handshake_failure | `SMS-TLS-007` | 266 | 266 (100%) | 266 (100%) |
| inject_client | `SMS-INJ-001` | 266 | 266 (100%) | 266 (100%) |
| inject_server | `SMS-INJ-001` | 266 | 266 (100%) | 266 (100%) |
| no_forward_secrecy | `SMS-TLS-003` | 136 | 136 (100%) | 136 (100%) |
| nonstandard_port | `SMS-PORT-001` | 544 | 544 (100%) | 544 (100%) |
| strip_refuse | `SMS-STRIP-001` | 266 | 266 (100%) | 266 (100%) |
| strip_remove | `SMS-BASE-001` | 237 | 0 (0%) | 230 of 230 (100%, 7 abstained) |
| strip_rewrite | `SMS-STRIP-001` | 237 | 237 (100%) | 237 (100%) |
| tls_1_0 | `SMS-TLS-001` | 149 | 149 (100%) | 149 (100%) |
| tls_1_1 | `SMS-TLS-001` | 153 | 153 (100%) | 153 (100%) |
| tls_compression | `SMS-TLS-008` | 142 | 142 (100%) | 142 (100%) |

Worst case for `strip_remove`: every session in one capture, with no stored history, so attacks outnumber normal sessions at each server. It is still flagged in 230 of 230 (100%) of the sessions at servers the baseline can judge, as vanished (`SMS-BASE-001`) or as inconsistent (`SMS-BASE-005`).

Real mail servers from the Docker lab (`lab/`). Labels come from the servers' configuration, not from SecureMailScope. A *clean* step passes only if there is no finding of medium severity or above.

| Lab step | Expected | Sessions | Pass |
|---|---|---|---|
| good-imap | (clean) | 6 | 6 |
| good-imaps | (clean) | 6 | 6 |
| good-pop3 | (clean) | 6 | 6 |
| good-relay | (clean) | 6 | 6 |
| good-smtps | (clean) | 6 | 6 |
| good-submission | (clean) | 6 | 6 |
| old-imap | SMS-TLS-001, SMS-TLS-003, SMS-TLS-004 | 6 | 6 |
| old-pop3 | SMS-TLS-001, SMS-TLS-003, SMS-TLS-004 | 6 | 6 |
| old-relay | SMS-TLS-001, SMS-TLS-003, SMS-TLS-004 | 6 | 6 |
| strip-imap | SMS-STRIP-001 | 6 | 6 |
| strip-pop3 | SMS-STRIP-001 | 6 | 6 |
| strip-submission | SMS-STRIP-001 | 6 | 6 |
| weak-imap | SMS-CRED-001 | 6 | 6 |
| weak-imaps | SMS-CERT-002, SMS-CERT-003, SMS-CERT-004, SMS-CERT-005 | 6 | 6 |
| weak-pop3 | SMS-CRED-001 | 6 | 6 |
| weak-relay | SMS-CERT-002, SMS-CERT-003, SMS-CERT-004, SMS-CERT-005 | 6 | 6 |
| weak-submission | SMS-CRED-001 | 6 | 6 |

| Protocol | n | Per session | Full pipeline |
|---|---|---|---|
| IMAP | 1010 | 939 (93%) | 1010 (100%) |
| POP3 | 838 | 798 (95%) | 838 (100%) |
| SMTP | 1862 | 1736 (93%) | 1855 of 1855 (100%, 7 abstained) |

## Independent check against Wireshark

Our labels come from our own rules, but the facts they judge can be verified independently. `tshark` (Wireshark's own TCP reassembly, STARTTLS tracking and TLS dissector) re-read `augmented.pcap`: both decoded a handshake in 2993 of 2993 TLS sessions.

| Field | Compared | Agree |
|---|---|---|
| version | 2993 | 2993 (100.0%) |
| cipher_code | 2993 | 2993 (100.0%) |
| compression | 2993 | 2993 (100.0%) |
| sni | 2231 | 2231 (100.0%) |
| cert_sha256 | 1742 | 1742 (100.0%) |

## Files

- `sessions.csv`: one row per session. Provenance, labels, negotiated crypto, certificate facts, rule IDs, rule risk and class, and the 34 model features (`f_*`).
- `sessions.jsonl`: the same, plus each finding and SHA-256-truncated usernames.
- `augmented.pcap`: every session (real, transplant, augmented) as real TCP, for re-running the full pipeline. Byte streams are exact; timing between the two directions is not, and IPv6 servers are mapped to one IPv4 address.
- `summary.json`: counts, sources and the evaluation above.
- `prototype-tests/`: real PCAPs for testing the whole prototype, cut from the **test split**: one capture per issue, a clean history capture, a self-contained `mixed-scenario.pcap`, and `expected.json` with the findings each session must produce. Run `python -m securemailscope dataset check <dir>/prototype-tests`.

## Limits

- Small: public mail captures are scarce. The real rows are what exists publicly.
- Weak labels on real and transplant rows come from our own rules. Use them to train the risk model's shape, not as independent ground truth. Only augmented rows have ground-truth attack labels.
- Rows are judged on their own, so baseline features (`f_base_*`) are always 0.
- Found by this dataset and fixed: when attacks made up more than about 20% of one server's sessions in a capture with no stored history, silently removed STARTTLS offers outvoted the in-capture baseline. `SMS-BASE-005` now flags an endpoint offering STARTTLS in 20-80% of sessions (see the worst-case line above). A capture in which every session is stripped still needs stored history (`--baseline-db`): no baseline can learn normal behaviour that it has never seen.
- Transplants pair a mail prologue with a TLS handshake from a different server, so a certificate hostname can mismatch the mail banner. The certificate is judged against the handshake's SNI where present.
- Metadata only: no payload bytes in the CSV / JSONL, and usernames are hashed. `augmented.pcap` contains bytes from the source captures, so treat it under their terms and do not redistribute it blindly.
