"""Stage 00-01: read PCAP / PCAPNG and walk link -> IP -> TCP.

Hand-rolled with `struct`: no dependencies, runs on an air-gapped forensic box.

Containers: classic pcap (both endiannesses, microsecond and nanosecond) and
pcapng (multiple sections, multiple interfaces, per-interface tsresol).
Captures published on the internet are almost always compressed, so gzip,
bzip2, xz and zstd are unwrapped transparently — the file is never rewritten
to disk, and the evidence hash is still taken over the file exactly as it was
received.

Supported link types:
    0   BSD null / loopback      (4-byte address family, host byte order)
    1   Ethernet                 (with stacked 802.1Q / 802.1ad VLAN tags)
    101 raw IP                   (also 228 = raw IPv4, 229 = raw IPv6)
    113 Linux cooked (SLL)       (also 276 = SLL2)
"""
from __future__ import annotations

import bz2
import gzip
import ipaddress
import lzma
import struct
from dataclasses import dataclass, field
from typing import BinaryIO, Iterator, Optional

from .models import Packet

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}
ETH_IPV4, ETH_IPV6 = 0x0800, 0x86DD
IPV6_EXT_HEADERS = {0, 43, 60, 51, 135, 139, 140}  # hop-by-hop, routing, dest opts, AH, mobility, HIP, shim6
IPV6_FRAGMENT = 44
PROTO_TCP = 6


MAX_RECORD = 1 << 26      # 64 MiB: larger than any real frame, small enough to stop a runaway read
MAX_BLOCK = 1 << 27       # 128 MiB: pcapng blocks (a decryption-secrets block can be big)


class PcapError(Exception):
    pass


@dataclass
class ReadStats:
    format: str = ""
    compression: str = ""
    frames: int = 0
    tcp_segments: int = 0
    non_ip: int = 0
    non_tcp: int = 0
    fragments_skipped: int = 0
    truncated: int = 0
    sections: int = 0
    interfaces: int = 0
    blocks_skipped: int = 0
    link_types: set = field(default_factory=set)
    unsupported_link_types: set = field(default_factory=set)
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["link_types"] = sorted(self.link_types)
        d["unsupported_link_types"] = sorted(self.unsupported_link_types)
        return d


# --------------------------------------------------------------------------- compression

class _Exact:
    """Guarantees read(n) returns n bytes unless the stream really ended.

    Decompressing streams (and zstandard's reader in particular) are allowed to
    return short reads. Every parser below assumes a short read means EOF, so
    that assumption is made true here once instead of at forty call sites.
    """

    def __init__(self, raw):
        self._raw = raw

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            return self._raw.read()
        out = bytearray()
        while len(out) < n:
            chunk = self._raw.read(n - len(out))
            if not chunk:
                break
            out += chunk
        return bytes(out)

    def close(self) -> None:
        try:
            self._raw.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"PK\x03\x04", "zip"),
    (b"\x37\x7a\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!", "rar"),
)


def detect_compression(head: bytes) -> str:
    for signature, name in _SIGNATURES:
        if head.startswith(signature):
            return name
    return ""


def open_capture(path: str) -> tuple[_Exact, str]:
    """Open a capture for reading, unwrapping a compression layer if present."""
    with open(path, "rb") as probe:
        head = probe.read(8)
    if not head:
        raise PcapError("the file is empty")

    kind = detect_compression(head)

    if kind in ("zip", "7z", "rar"):
        raise PcapError(
            f"this is a .{kind} archive, not a capture — extract it first and upload the "
            ".pcap/.pcapng inside (archives from malware-traffic-analysis.net use the "
            "password 'infected')"
        )
    if kind == "zstd":
        try:
            import zstandard
        except ImportError:
            raise PcapError(
                "this capture is zstd-compressed — install the 'zstandard' package, "
                "or decompress it first with: zstd -d <file>"
            ) from None
        return _Exact(zstandard.ZstdDecompressor().stream_reader(open(path, "rb"))), "zstd"
    if kind == "gzip":
        return _Exact(gzip.open(path, "rb")), "gzip"
    if kind == "bzip2":
        return _Exact(bz2.open(path, "rb")), "bzip2"
    if kind == "xz":
        return _Exact(lzma.open(path, "rb")), "xz"
    return _Exact(open(path, "rb")), ""


# --------------------------------------------------------------------------- container formats

def _iter_pcap(f: BinaryIO, magic: bytes,
               stats: Optional["ReadStats"] = None) -> Iterator[tuple[float, int, bytes]]:
    table = {
        b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
        b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9),
    }
    endian, resolution = table[magic]
    rest = f.read(20)
    if len(rest) < 20:
        raise PcapError("truncated pcap global header — the file stops after 4 bytes")
    _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(endian + "HHiIII", rest)
    linktype &= 0x0FFFFFFF  # upper bits carry FCS info
    if stats:
        stats.sections = 1
        stats.interfaces = 1
    rec = struct.Struct(endian + "IIII")
    while True:
        hdr = f.read(16)
        if len(hdr) < 16:
            if hdr and stats:
                stats.notes.append("file ends mid-record header; trailing bytes ignored")
            return
        sec, frac, incl, _orig = rec.unpack(hdr)
        if incl > MAX_RECORD:
            # Either the file is damaged or it is not really a pcap. Stop cleanly
            # with what was parsed rather than attempting a multi-gigabyte read.
            if stats:
                stats.notes.append(
                    f"record claims {incl:,} bytes at frame {stats.frames + 1}; "
                    "stopped reading (file is truncated or corrupt)")
            return
        data = f.read(incl)
        if len(data) < incl:
            if stats:
                stats.notes.append("file ends mid-record; final partial frame ignored")
            return
        yield sec + frac * resolution, linktype, data


def _iter_pcapng(f: BinaryIO, first: bytes,
                 stats: Optional["ReadStats"] = None) -> Iterator[tuple[float, int, bytes]]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, seconds-per-tick)
    buf = first
    while True:
        if len(buf) < 8:
            buf += f.read(8 - len(buf))
            if len(buf) < 8:
                return
        btype_raw, blen_raw = buf[:4], buf[4:8]
        if btype_raw == b"\x0a\x0d\x0d\x0a":
            # Section header: byte-order magic decides endianness for the whole section.
            # A merged capture (mergecap, or a tool appending sessions) contains several,
            # and each one resets the interface table.
            bom = f.read(4)
            if len(bom) < 4:
                return
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", blen_raw)[0]
            if not 12 <= blen <= MAX_BLOCK:
                raise PcapError(f"corrupt pcapng section header (length {blen})")
            f.read(blen - 12)
            interfaces = []
            buf = b""
            if stats:
                stats.sections += 1
            continue
        btype, blen = struct.unpack(endian + "II", buf[:8])
        if blen < 12 or blen > MAX_BLOCK:
            if stats:
                stats.notes.append(
                    f"implausible pcapng block length ({blen:,} bytes) after "
                    f"{stats.frames:,} frames; stopped reading")
            return
        body = f.read(blen - 8)
        buf = b""
        if len(body) < blen - 8:
            if stats:
                stats.notes.append("file ends mid-block; final partial block ignored")
            return
        body = body[:-4]  # trailing block length
        if btype == 1:  # Interface Description Block
            if len(body) < 8:
                continue
            linktype = struct.unpack(endian + "H", body[:2])[0]
            tick = 1e-6
            opts = body[8:]
            while len(opts) >= 4:
                code, olen = struct.unpack(endian + "HH", opts[:4])
                if code == 0:
                    break
                val = opts[4:4 + olen]
                if code == 9 and val:  # if_tsresol
                    v = val[0]
                    tick = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                opts = opts[4 + ((olen + 3) & ~3):]
            interfaces.append((linktype, tick))
            if stats:
                stats.interfaces += 1
        elif btype == 6:  # Enhanced Packet Block
            if len(body) < 20:
                continue
            iface, ts_hi, ts_lo, incl, _orig = struct.unpack(endian + "IIIII", body[:20])
            linktype, tick = interfaces[iface] if iface < len(interfaces) else (LINKTYPE_ETHERNET, 1e-6)
            yield ((ts_hi << 32) | ts_lo) * tick, linktype, body[20:20 + incl]
        elif btype == 3:  # Simple Packet Block (no timestamp)
            linktype = interfaces[0][0] if interfaces else LINKTYPE_ETHERNET
            yield 0.0, linktype, body[4:]
        elif btype == 2:  # obsolete Packet Block
            if len(body) < 20:
                continue
            iface, _drops, ts_hi, ts_lo, incl, _orig = struct.unpack(endian + "HHIIII", body[:20])
            linktype, tick = interfaces[iface] if iface < len(interfaces) else (LINKTYPE_ETHERNET, 1e-6)
            yield ((ts_hi << 32) | ts_lo) * tick, linktype, body[20:20 + incl]
        elif stats:
            # name resolution (4), interface statistics (5), decryption secrets (10),
            # custom (0x0BAD/0x40000BAD) — all legal, none carry frames.
            stats.blocks_skipped += 1


def _describe_foreign(magic: bytes) -> str:
    """Say what the file actually is, so the user knows what to do next."""
    kind = detect_compression(magic)
    if kind:
        return (f"the stream is {kind}-compressed but could not be unwrapped "
                f"(magic {magic.hex()})")
    known = {
        b"\x4d\x3c\xb2\xa1": "pcap", b"\xa1\xb2\x3c\x4d": "pcap",
        b"%PDF": "a PDF", b"\x89PNG": "a PNG image", b"\x50\x4b\x03\x04": "a ZIP archive",
        b"SQLi": "an SQLite database", b"\x7fELF": "an ELF binary",
        b"ETSI": "an ETSI/ER trace", b"TRSN": "a Sniffer trace",
    }
    for prefix, name in known.items():
        if magic.startswith(prefix):
            return f"this looks like {name}, not a pcap"
    text = magic[:4].decode("ascii", "ignore")
    if len(text) == len(magic[:4]) and text.isprintable():
        return (f"the file starts with text ({text!r}) — if this is a hex dump or a "
                "text export, convert it first with: text2pcap dump.txt out.pcap")
    return f"unrecognised container (magic {magic.hex()})"


def iter_frames(f: BinaryIO, stats: Optional[ReadStats] = None) -> Iterator[tuple[float, int, bytes]]:
    magic = f.read(4)
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        if stats: stats.format = "pcap"
        yield from _iter_pcap(f, magic, stats)
    elif magic == b"\x0a\x0d\x0d\x0a":
        if stats: stats.format = "pcapng"
        yield from _iter_pcapng(f, magic + f.read(4), stats)
    else:
        raise PcapError(f"not a pcap or pcapng capture: {_describe_foreign(magic)}")


# --------------------------------------------------------------------------- layer walk

def _link_to_ip(linktype: int, data: bytes) -> tuple[Optional[int], bytes]:
    """Return (ip_version, ip_packet) or (None, b'')."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None, b""
        etype = struct.unpack("!H", data[12:14])[0]
        off = 14
        while etype in VLAN_ETHERTYPES:  # tags stack (QinQ), so loop
            if len(data) < off + 4:
                return None, b""
            etype = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        payload = data[off:]
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None, b""
        etype = struct.unpack("!H", data[14:16])[0]
        payload = data[16:]
    elif linktype == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            return None, b""
        etype = struct.unpack("!H", data[0:2])[0]
        payload = data[20:]
    elif linktype == LINKTYPE_NULL:
        if len(data) < 4:
            return None, b""
        fam_le = struct.unpack("<I", data[:4])[0]
        fam_be = struct.unpack(">I", data[:4])[0]
        fam = fam_le if fam_le < 256 else fam_be
        payload = data[4:]
        if fam == 2:
            return 4, payload
        if fam in (10, 24, 28, 30):  # AF_INET6 differs per OS
            return 6, payload
        return None, b""
    elif linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        if not data:
            return None, b""
        v = data[0] >> 4
        return (v, data) if v in (4, 6) else (None, b"")
    else:
        return None, b""
    if etype == ETH_IPV4:
        return 4, payload
    if etype == ETH_IPV6:
        return 6, payload
    return None, b""


def _ip_to_tcp(version: int, pkt: bytes, stats: ReadStats) -> Optional[tuple[str, str, bytes]]:
    if version == 4:
        if len(pkt) < 20:
            stats.truncated += 1
            return None
        ihl = (pkt[0] & 0x0F) * 4
        total_len = struct.unpack("!H", pkt[2:4])[0]
        flags_frag = struct.unpack("!H", pkt[6:8])[0]
        more_frags = flags_frag & 0x2000
        frag_off = flags_frag & 0x1FFF
        if frag_off or more_frags:
            # Non-first fragments carry no TCP header; first fragments carry a partial
            # segment. Reassembling IP fragments is out of scope, so skip and count.
            stats.fragments_skipped += 1
            return None
        if pkt[9] != PROTO_TCP:
            stats.non_tcp += 1
            return None
        end = total_len if 0 < total_len <= len(pkt) else len(pkt)
        src = str(ipaddress.IPv4Address(pkt[12:16]))
        dst = str(ipaddress.IPv4Address(pkt[16:20]))
        return src, dst, pkt[ihl:end]
    if version == 6:
        if len(pkt) < 40:
            stats.truncated += 1
            return None
        plen = struct.unpack("!H", pkt[4:6])[0]
        nxt = pkt[6]
        src = str(ipaddress.IPv6Address(pkt[8:24]))
        dst = str(ipaddress.IPv6Address(pkt[24:40]))
        body = pkt[40:40 + plen] if plen else pkt[40:]
        while nxt in IPV6_EXT_HEADERS or nxt == IPV6_FRAGMENT:
            if len(body) < 8:
                stats.truncated += 1
                return None
            if nxt == IPV6_FRAGMENT:
                stats.fragments_skipped += 1
                return None
            hdr_len = (body[1] + 2) * 4 if nxt == 51 else (body[1] + 1) * 8
            nxt, body = body[0], body[hdr_len:]
        if nxt != PROTO_TCP:
            stats.non_tcp += 1
            return None
        return src, dst, body
    return None


_SUPPORTED_LINKTYPES = frozenset({
    LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW,
    LINKTYPE_LINUX_SLL, LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_LINUX_SLL2,
})


def read_packets(path: str, stats: Optional[ReadStats] = None) -> tuple[list[Packet], ReadStats]:
    stats = stats or ReadStats()
    packets: list[Packet] = []
    handle, compression = open_capture(path)
    stats.compression = compression
    with handle as f:
        for ts, linktype, frame in iter_frames(f, stats):
            stats.frames += 1
            stats.link_types.add(linktype)
            if linktype not in _SUPPORTED_LINKTYPES:
                stats.unsupported_link_types.add(linktype)
            version, ip = _link_to_ip(linktype, frame)
            if version is None:
                stats.non_ip += 1
                continue
            res = _ip_to_tcp(version, ip, stats)
            if res is None:
                continue
            src, dst, seg = res
            if len(seg) < 20:
                stats.truncated += 1
                continue
            sport, dport, seq, ack, off_flags = struct.unpack("!HHIIH", seg[:14])
            data_off = (off_flags >> 12) * 4
            flags = off_flags & 0x01FF
            if data_off < 20 or data_off > len(seg):
                stats.truncated += 1
                continue
            stats.tcp_segments += 1
            packets.append(Packet(stats.frames, ts, src, dst, sport, dport, seq, ack, flags, bytes(seg[data_off:])))
    return packets, stats
