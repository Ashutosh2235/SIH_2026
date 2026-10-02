"""Stage 00-01 against the shapes real-world captures actually arrive in.

Public captures are published compressed and merged; a reader that only accepts
a bare, single-section .pcap fails on almost everything worth testing against.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import pathlib
import struct
import zipfile

import pytest

from securemailscope.pcapio import (
    PcapError, ReadStats, detect_compression, iter_frames, open_capture, read_packets,
)

FRAME = b"\xff" * 6 + b"\x00" * 6 + b"\x08\x00" + b"\x45" + b"\x00" * 19


# --------------------------------------------------------------- pcapng builder

def _blk(btype, body):
    total = 12 + len(body) + (-len(body) % 4)
    return struct.pack("<II", btype, total) + body + b"\x00" * (-len(body) % 4) + struct.pack("<I", total)


def _shb():
    body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    body += struct.pack("<HH", 3, 5) + b"linux" + b"\x00" * 3
    body += struct.pack("<HH", 0, 0)
    return _blk(0x0A0D0D0A, body)


def _idb(linktype=1, tsresol=6):
    body = struct.pack("<HHI", linktype, 0, 262144)
    body += struct.pack("<HH", 9, 1) + bytes([tsresol]) + b"\x00" * 3
    body += struct.pack("<HH", 2, 4) + b"eth0"
    body += struct.pack("<HH", 0, 0)
    return _blk(1, body)


def _epb(iface, ts, data=FRAME):
    body = struct.pack("<IIIII", iface, ts >> 32, ts & 0xFFFFFFFF, len(data), len(data)) + data
    return _blk(6, body + b"\x00" * (-len(data) % 4))


def _frames(blob):
    return list(iter_frames(io.BytesIO(blob), ReadStats()))


# --------------------------------------------------------------- compression

@pytest.fixture(scope="module")
def demo_capture(sample_paths):
    return pathlib.Path(sample_paths["demo"])


def test_signatures_are_recognised():
    assert detect_compression(b"\x1f\x8b\x08\x00") == "gzip"
    assert detect_compression(b"BZh9") == "bzip2"
    assert detect_compression(b"\xfd7zXZ\x00\x00") == "xz"
    assert detect_compression(b"\x28\xb5\x2f\xfd\x00") == "zstd"
    assert detect_compression(b"PK\x03\x04") == "zip"
    assert detect_compression(b"\xd4\xc3\xb2\xa1") == ""


@pytest.mark.parametrize("name,wrap", [
    ("gzip", gzip.compress),
    ("bzip2", bz2.compress),
    ("xz", lzma.compress),
])
def test_compressed_captures_read_identically(tmp_path, demo_capture, name, wrap):
    """The Ultimate PCAP and most public corpora ship compressed."""
    reference, ref_stats = read_packets(str(demo_capture))

    packed = tmp_path / f"c.pcap.{name}"
    packed.write_bytes(wrap(demo_capture.read_bytes()))

    got, stats = read_packets(str(packed))
    assert stats.compression == name
    assert stats.format == ref_stats.format
    assert len(got) == len(reference)
    assert [p.payload for p in got] == [p.payload for p in reference]


def test_uncompressed_is_still_reported_as_uncompressed(demo_capture):
    _, stats = read_packets(str(demo_capture))
    assert stats.compression == ""


def test_open_capture_closes_cleanly(tmp_path, demo_capture):
    packed = tmp_path / "c.pcap.gz"
    packed.write_bytes(gzip.compress(demo_capture.read_bytes()))
    handle, kind = open_capture(str(packed))
    assert kind == "gzip"
    with handle as f:
        assert f.read(4) == b"\xd4\xc3\xb2\xa1"


# --------------------------------------------------------------- honest errors

def test_zip_archive_is_named_not_just_rejected(tmp_path):
    path = tmp_path / "traffic.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("a.pcap", b"\xd4\xc3\xb2\xa1")
    with pytest.raises(PcapError, match="archive"):
        read_packets(str(path))


def test_empty_file(tmp_path):
    path = tmp_path / "e.pcap"
    path.write_bytes(b"")
    with pytest.raises(PcapError, match="empty"):
        read_packets(str(path))


def test_text_file_suggests_text2pcap(tmp_path):
    path = tmp_path / "dump.txt"
    path.write_text("0000  45 00 00 28 ...")
    with pytest.raises(PcapError, match="text2pcap"):
        read_packets(str(path))


def test_binary_junk_reports_the_magic(tmp_path):
    path = tmp_path / "x.pcap"
    path.write_bytes(b"\x01\x02\x03\x04" * 40)
    with pytest.raises(PcapError, match="unrecognised container"):
        read_packets(str(path))


# --------------------------------------------------------------- pcapng shapes

def test_multiple_sections_each_reset_the_interface_table():
    blob = _shb() + _idb() + _epb(0, 1_000_000) + _shb() + _idb() + _epb(0, 2_000_000)
    stats = ReadStats()
    got = list(iter_frames(io.BytesIO(blob), stats))
    assert len(got) == 2
    assert stats.sections == 2


def test_nanosecond_tsresol():
    got = _frames(_shb() + _idb(tsresol=9) + _epb(0, 1_500_000_000))
    assert got[0][0] == pytest.approx(1.5)


def test_microsecond_tsresol():
    got = _frames(_shb() + _idb(tsresol=6) + _epb(0, 1_500_000))
    assert got[0][0] == pytest.approx(1.5)


def test_per_interface_link_types():
    blob = _shb() + _idb(1) + _idb(101) + _idb(113) + _epb(2, 1_000_000)
    assert _frames(blob)[0][1] == 113


def test_unknown_blocks_are_skipped_not_fatal():
    blob = (_shb() + _idb()
            + _blk(4, b"\x00" * 16)      # name resolution
            + _blk(10, b"\x00" * 40)     # decryption secrets
            + _blk(5, b"\x00" * 60)      # interface statistics
            + _epb(0, 1_000_000))
    stats = ReadStats()
    assert len(list(iter_frames(io.BytesIO(blob), stats))) == 1
    assert stats.blocks_skipped == 3


def test_interface_described_after_first_packets():
    blob = _shb() + _idb() + _epb(0, 1_000_000) + _idb() + _epb(1, 2_000_000)
    assert len(_frames(blob)) == 2


def test_truncated_final_block_yields_what_it_can():
    whole = _shb() + _idb() + _epb(0, 1_000_000) + _epb(0, 2_000_000)
    assert len(_frames(whole[:-6])) == 1


def test_trailing_garbage_is_tolerated():
    assert len(_frames(_shb() + _idb() + _epb(0, 1_000_000) + b"\x99\x99")) == 1


def test_absurd_block_length_stops_instead_of_allocating(tmp_path):
    blob = _shb() + _idb() + _epb(0, 1_000_000) + struct.pack("<II", 6, 0xF0000000)
    stats = ReadStats()
    assert len(list(iter_frames(io.BytesIO(blob), stats))) == 1
    assert any("implausible" in n for n in stats.notes)


def test_absurd_pcap_record_length_stops(tmp_path):
    path = tmp_path / "bad.pcap"
    path.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
                     + struct.pack("<IIII", 1, 0, 0xF0000000, 0xF0000000))
    packets, stats = read_packets(str(path))
    assert packets == []
    assert any("corrupt" in n for n in stats.notes)


def test_unsupported_link_type_is_counted_not_crashed():
    blob = _shb() + _idb(105) + _epb(0, 1_000_000)   # 105 = 802.11
    stats = ReadStats()
    frames = list(iter_frames(io.BytesIO(blob), stats))
    assert stats.format == "pcapng"
    assert frames and frames[0][1] == 105


# --------------------------------------------------------------- honest verdict

def test_capture_without_mail_is_not_graded_A(tmp_path):
    """An absence of mail is an absence of evidence, not a clean bill of health."""
    from securemailscope.pipeline import Options, analyze

    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for i, (sp, dp) in enumerate([(40000, 443), (40001, 80)]):
        for flags, payload in ((0x02, b""), (0x12, b""), (0x18, b"GET / HTTP/1.1\r\n\r\n")):
            tcp = struct.pack("!HHIIBBHHH", sp, dp, 1000, 1, 5 << 4, flags, 64240, 0, 0) + payload
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), i, 0x4000, 64, 6, 0,
                             bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + tcp
            frame = b"\x00" * 12 + b"\x08\x00" + ip
            out.append(struct.pack("<IIII", 1700000000 + i, 0, len(frame), len(frame)) + frame)
    path = tmp_path / "web-only.pcap"
    path.write_bytes(b"".join(out))

    a = analyze(str(path), Options(use_ml=False))
    assert a.meta["mail_sessions"] == 0
    assert a.posture["assessed"] is False
    assert a.posture["score"] is None
    assert a.posture["grade"] != "A"
    assert "no SMTP, IMAP or POP3" in a.posture["note"]

    from securemailscope import report
    html = report.to_html(a)
    assert "Nothing to assess" in html
    assert "not assessed" in html
