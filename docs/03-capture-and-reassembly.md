# 03 · Capture and TCP reassembly (stages 00–02)

Nothing downstream produces output until this layer is right. The PDF calls TCP reassembly "the
hardest correctness problem in the build". It isn't glamorous, but a parser fed a wrongly
reassembled stream reports confident nonsense.

Code: [`pcapio.py`](../securemailscope/pcapio.py), [`flows.py`](../securemailscope/flows.py) ·
Tests: [`test_pcapio.py`](../tests/test_pcapio.py), [`test_flows.py`](../tests/test_flows.py)

## 1. Container formats

### Classic PCAP

A 24-byte global header, then `[16-byte record header][frame bytes]` repeated.

| Magic (as read) | Byte order | Timestamp resolution |
|---|---|---|
| `d4 c3 b2 a1` | little-endian | microseconds |
| `a1 b2 c3 d4` | big-endian | microseconds |
| `4d 3c b2 a1` | little-endian | **nanoseconds** |
| `a1 b2 3c 4d` | big-endian | nanoseconds |

The global header carries **one** link type for the whole file. Its upper bits can carry FCS
information, so we mask with `0x0FFFFFFF`.

### PCAPNG

A sequence of typed blocks: `[type:4][total length:4][body][total length:4]`.

| Block | Type | What we take from it |
|---|---|---|
| Section Header | `0x0A0D0D0A` | **byte order** for the whole section (from the magic `1A2B3C4D`); resets interfaces |
| Interface Description | 1 | link type **per interface**, and `if_tsresol` (option 9) |
| Enhanced Packet | 6 | interface id, 64-bit timestamp, frame |
| Simple Packet | 3 | frame only (no timestamp) |
| Packet (obsolete) | 2 | same as EPB, older layout |

Two traps. **Timestamps are in interface ticks, not microseconds**: `if_tsresol` gives
`10^-n` (high bit clear) or `2^-n` (high bit set), and tcpdump on Linux usually writes nanoseconds.
And **each interface can have a different link type**, so a single file can mix Ethernet and Linux
cooked captures.

## 2. Link layers

Real captures arrive in all of these:

| Link type | Name | How we reach IP |
|---|---|---|
| 1 | Ethernet | 14-byte header. **Loop** while EtherType is `0x8100`/`0x88A8`/`0x9100`, because VLAN tags stack (QinQ) |
| 113 | Linux cooked (SLL) | 16-byte header, protocol at offset 14 (what `tcpdump -i any` writes) |
| 276 | Linux cooked v2 (SLL2) | 20-byte header, protocol at offset 0 |
| 0 | BSD null/loopback | 4-byte address family in **host** byte order; AF_INET6 is 10, 24, 28 or 30 depending on OS |
| 101 / 228 / 229 | raw IP | no link header; the IP version nibble decides |

## 3. IP

**IPv4:** header length from IHL, total length to trim Ethernet padding, protocol 6 for TCP.

**Fragments:** if the MF flag is set or the fragment offset is non-zero, the packet is skipped and
**counted** (`fragments_skipped`). A non-first fragment has no TCP header at all. A first fragment
holds only part of a segment, and reassembling IP fragments is out of scope. The count appears in
the report, so an analyst knows if it mattered.

**IPv6:** walk the extension-header chain (hop-by-hop 0, routing 43, destination options 60,
AH 51 which uses a different length formula, mobility, HIP, shim6) until next-header is TCP. A
Fragment header (44) is skipped and counted, like IPv4.

## 4. Grouping into conversations

Segments are grouped by the **canonical 5-tuple**: the two `(ip, port)` endpoints sorted, so both
directions land in the same bucket. Within a bucket, a fresh SYN after a FIN/RST starts a new
conversation, which handles port reuse.

**Which side is the client?** In order of confidence:

1. whoever sent **SYN without ACK**
2. otherwise, whoever *received* the SYN/ACK
3. otherwise (the capture started mid-connection), the side on a well-known mail port, then the
   lower port. The flow records this as `"no handshake captured; inferred from ports (low confidence)"`

## 5. Reassembly, one direction at a time

The algorithm in `flows.reassemble()`:

```
base   = ISN + 1                       (first data byte after the SYN)
         or, with no SYN, the earliest seq in circular order
offset = (seq - base) mod 2^32, as a signed 32-bit distance
sort segments by (offset, longest first)
cursor = 0
for each segment:
    end = offset + len
    if end <= cursor:            retransmission → drop
                                 (and if its bytes disagree with what we kept: overlap conflict)
    if offset > cursor:          gap → pad with zeros so offsets stay stable, count it
    if offset < cursor:          partial overlap → trim the first (cursor - offset) bytes
                                 (and compare the overlapping bytes: conflict?)
    append, advance cursor
```

### Why `(seq − isn) mod 2³²`

Sequence numbers are 32-bit and **wrap**. A connection whose ISN is `0xFFFFFF00` crosses zero
after 256 bytes. Sorting raw sequence numbers would put the post-wrap bytes first. Sorting by the
offset from the ISN, modulo 2³², is correct everywhere. The demo capture includes a session with
exactly this ISN, and `test_sequence_wraparound` checks it.

### Worked example

```
segments arrive:  seq=107 "world"   seq=101 "hello "   seq=101 "hello "   seq=104 "lo world"
isn=100 → base=101
offsets:          6                  0                   0                   3
sorted:           (0,"hello ") (0,"hello ") (3,"lo world") (6,"world")
                   append        retransmit   trim 3 → "world"  retransmit (end 11 ≤ cursor 11)
result:           "hello world"   out_of_order=1  retransmissions=2  overlaps_trimmed=1
```

### Overlap conflicts: an evasion signal

When an overlapping or retransmitted segment carries **different bytes** from the ones already
kept, the policy is first-arrival-wins, and `overlap_conflicts` is incremented. Honest stacks never
do this. Attackers use it to make an IDS and the endpoint see different data. A non-zero count
raises `SMS-TCP-001`.

### Stream quality travels with the session

Every `MailSession` carries `stream_quality`: retransmissions, out-of-order, overlaps trimmed,
conflicts, gaps and how the client was identified. The HTML report shows it per session, so an
analyst can tell a clean parse from a best-effort one.

## Verifying against Wireshark

Wireshark is the only cheap oracle. For any sample:

```bash
tshark -r samples/demo_enterprise.pcap -q -z conv,tcp
```

```bash
tshark -r samples/demo_enterprise.pcap -q -z follow,tcp,ascii,0
```

Compare the conversation count with `flows` in the report, and the followed stream with the
session's banner and commands.

## Compressed captures

Public corpora are published compressed — the Ultimate PCAP ships as
`.pcapng.gz`, malware-traffic-analysis.net ships password-protected `.zip`,
CIC and Stratosphere ship `.gz` and `.tar.gz`. A reader that only accepts a
bare `.pcap` fails on nearly every capture worth testing against, so
`open_capture()` sniffs the first eight bytes and transparently unwraps gzip,
bzip2, xz and zstd (zstd needs the optional `zstandard` package).

Three details matter:

- **The evidence hash is still taken over the file as received**, not over the
  decompressed stream. The chain of custody covers what the analyst was handed.
- **Nothing is written to disk.** The decompressing stream is read forward once;
  a 6 MB `.gz` never becomes a 60 MB temp file.
- **Archives are refused, not guessed at.** A `.zip`, `.7z` or `.rar` may hold
  several files, so the reader names the format and says to extract it rather
  than picking one and hoping. The error also mentions the `infected` password,
  because that is what the next step usually needs.

Anything else is reported by what it actually is — a PDF, a PNG, a text hex
dump (with the `text2pcap` invocation that converts it) — rather than as
`magic 1f8b0808`. The reader's error message is the first thing a user sees
when their capture will not load; it should tell them what to do next.

## Frame provenance

Reassembly is where the link from protocol back to packet is normally lost:
retransmissions disappear, overlaps are trimmed, gaps are padded, and what the
parser reads is a byte stream with no frame numbers in it. So `reassemble()`
returns a third value — a provenance map, one `(stream_offset, length, frame,
ts)` entry per span of bytes that *survived into the stream*. Only surviving
bytes are listed: a retransmitted segment the analyser discarded is not evidence
for anything the parser saw.

`mailproto` then records, for each transcript entry, the byte range it consumed
in its own direction. Entries in one direction tile that direction's stream
without overlapping, so `frames_for_span()` can resolve each entry to the frames
that carried it. The relationship is deliberately many-to-many: one protocol
line can straddle two segments, and one segment can carry several lines.

Two consequences are visible in the UI and are worth understanding before
reading it:

- **The frame list for a step is in stream order, not arrival order.** The EHLO
  response in the demo capture resolves to frames 42, 8, 10, 9, 11 — the server
  sent those chunks out of order, and 42 is an overlapping retransmission that
  won the race for the first six bytes. Sorting them numerically for display
  would hide that; the packet list shows true arrival order alongside.
- **A segment does not respect line boundaries.** The packet list's Info column
  therefore reads the line out of the reassembled stream at that segment's
  offset, not out of the segment's own payload. A segment starting mid-line is
  labelled with a leading ellipsis rather than being shown as if its first bytes
  began a command.

The same redaction rules apply here as everywhere else: the Info column keeps the
verb and the SASL mechanism and drops the argument, and a bare base64 blob is
replaced outright. A packet list that printed `PASS hunter2` would undo the
promise the rest of the tool makes.
