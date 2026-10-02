"""Regressions for the issues found in the September 2026 security assessment.

Each test names the finding it closes and the real capture or attack that
motivated it, so a future change that reintroduces the behaviour fails loudly.
"""
from __future__ import annotations

import random

import pytest

from securemailscope import mailproto, samples, scoring
from securemailscope.pipeline import Options, analyze
from tests.conftest import make_flow

L = samples._lines


def _cap(build, tmp_path, name="c.pcap"):
    cap = samples.Capture()
    build(cap, random.Random(7))
    p = tmp_path / name
    cap.write_pcap(str(p))
    return str(p)


def _conv(cap, rng, port=25):
    return samples.Conv(cap, samples.DEMO_T0, ("10.0.0.5", 50000), ("203.0.113.9", port), rng).open()


# ------------------------------------------------- F2: malformed DER must not crash

def test_non_canonical_der_is_a_finding_not_a_crash():
    """A real Go Daddy leaf served by Lavabit encodes BasicConstraints.ca as an
    explicit DEFAULT: legal BER, illegal DER. cryptography parses extensions
    lazily, so this raised from deep inside cert_info and killed the capture."""
    from cryptography import x509
    from securemailscope.certs import _ext, _extensions_parse_error

    class Exploding:
        @property
        def extensions(self):
            raise ValueError("error parsing asn1 value: ParseError { kind: EncodedDefault }")

    assert _ext(Exploding(), x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME) is None
    assert "EncodedDefault" in (_extensions_parse_error(Exploding()) or "")


# ------------------------------------------------- F1: cleartext mail cannot pass

def test_cleartext_message_content_caps_the_capture_at_D(tmp_path):
    """Before: 400 KB of unencrypted mail scored A/90 because the relay discount
    was applied three times over."""
    def build(cap, rng):
        c = _conv(cap, rng)
        c.s(L("220 mx.example.com ESMTP"))
        c.c(L("EHLO relay.example.net")); c.s(L("250-mx.example.com", "250 8BITMIME"))
        c.c(L("MAIL FROM:<a@b.c>")); c.s(L("250 Ok"))
        c.c(L("DATA")); c.s(L("354 go"))
        c.c(b"Subject: x\r\n\r\n" + b"secret " * 2000 + b"\r\n.\r\n"); c.s(L("250 queued"))
        c.c(L("QUIT")); c.s(L("221 bye")); c.close()

    a = analyze(_cap(build, tmp_path), Options(use_ml=False))
    assert a.posture["score"] <= scoring.CONFIDENTIALITY_FLOOR
    assert a.posture["grade"] in ("D", "F")
    assert any("unencrypted" in f["reason"] for f in a.posture["floors"])
    data = next(f for f in a.findings if f.rule_id == "SMS-DATA-001")
    assert data.severity == "high", "the relay discount belongs in exposure, not in the severity"


def test_encrypted_capture_is_not_penalised(tmp_path):
    def build(cap, rng):
        c = _conv(cap, rng, port=465)
        samples.tls13_exchange(c, rng, "mx.example.com"); c.close()

    a = analyze(_cap(build, tmp_path), Options(use_ml=False))
    assert a.posture["grade"] == "A"
    assert not any("unencrypted" in f["reason"] for f in a.posture["floors"])


def test_unverified_tls_cannot_score_100(tmp_path):
    """A session whose certificate was never observed has not been verified;
    scoring it 100 claims a check that did not run."""
    def build(cap, rng):
        c = _conv(cap, rng, port=465)
        samples.tls13_exchange(c, rng, "mx.example.com"); c.close()

    a = analyze(_cap(build, tmp_path), Options(use_ml=False))
    assert a.posture["score"] <= scoring.UNVERIFIED_FLOOR


# ------------------------------------------------- F3: coverage of partial captures

def test_one_sided_capture_is_analysed_not_dropped():
    """zeek_smtp-one-side-only.pcap: 18 KB of visible cleartext SMTP that used
    to produce 'no SMTP, IMAP or POP3 session was found in this capture'."""
    client = (L("EHLO relay.example.net") + L("MAIL FROM:<a@b.c>") + L("RCPT TO:<d@e.f>")
              + L("DATA") + b"Subject: x\r\n\r\n" + b"body " * 400 + b"\r\n.\r\n" + L("QUIT"))
    sess = mailproto.parse_session(make_flow(client, b""), "S001")
    assert sess is not None
    assert sess.protocol == "SMTP"
    assert sess.identified_by == "client-verbs"
    assert sess.one_sided
    assert sess.cleartext_message_bytes > 1000
    assert any("server side" in n for n in sess.notes)


def test_midstream_capture_is_analysed():
    client = L("MAIL FROM:<a@b.c>") + L("RCPT TO:<d@e.f>") + L("DATA") + b"Subject: x\r\n\r\nbody\r\n.\r\n"
    sess = mailproto.parse_session(make_flow(client, L("250 Ok", "250 Ok", "354 go", "250 queued")), "S001")
    assert sess is not None and sess.protocol == "SMTP"
    assert sess.cleartext_message_bytes > 0


def test_client_identification_needs_two_distinct_verbs():
    """One line that happens to start with LIST is not evidence of a protocol.
    suricata's imap-on-ftp confusion test must stay unidentified."""
    assert mailproto.parse_session(make_flow(b"USER CAPABILITY\r\n", b""), "S") is None
    assert mailproto.parse_session(make_flow(b"QUIT\r\n", b""), "S") is None


def test_unclassified_mail_port_flows_are_reported(tmp_path):
    """A flow on port 25 we cannot parse must appear in the report, not vanish."""
    def build(cap, rng):
        c = _conv(cap, rng)
        c.c(b"\x00\x01\x02\x03binary rubbish\r\n"); c.s(b"\xff\xfe nonsense\r\n"); c.close()

    a = analyze(_cap(build, tmp_path), Options(use_ml=False))
    assert a.meta["unclassified_mail_flows"], "a mail-port flow was dropped silently"
    u = a.meta["unclassified_mail_flows"][0]
    assert u["server"].endswith(":25") and u["reason"]


def test_no_session_wording_is_honest():
    assert "could be parsed" in scoring.posture([], 0)["note"]


# ------------------------------------------------- F4: absent chains are not equal

@pytest.mark.parametrize("kind,expect_rule", [
    ("resumed", "SMS-CERT-012"),
    ("anonymous", "SMS-CERT-014"),
])
def test_absent_certificate_reasons_are_distinguished(tmp_path, kind, expect_rule):
    def build(cap, rng):
        c = _conv(cap, rng, port=465)
        c.c(samples.client_hello(rng, "mx.example.com", tls13=False))
        if kind == "resumed":
            flight = samples.server_hello(rng, 0x0303, 0xC030)
        else:
            flight = samples.server_hello(rng, 0x0303, 0x0034) + samples.ske_dhe(rng, 1024) + samples._hs(14, b"")
        c.s(samples.record(22, flight, 0x0303) + samples.record(20, b"\x01", 0x0303)
            + samples.record(22, rng.randbytes(40), 0x0303))
        c.c(samples.record(20, b"\x01", 0x0303) + samples.record(22, rng.randbytes(40), 0x0303))
        c.close()

    a = analyze(_cap(build, tmp_path), Options(use_ml=False))
    assert a.results[0].chain.absent_kind == kind
    assert expect_rule in {f.rule_id for f in a.findings}


# ------------------------------------------------- F5: HELO downgrade

def test_helo_downgrade_is_detected(tmp_path):
    """Rewriting EHLO to HELO suppresses the STARTTLS offer without touching
    the capability line, so capability comparison cannot see it."""
    def build(cap, rng):
        for i, verb in enumerate(("EHLO", "EHLO", "HELO")):
            c = samples.Conv(cap, samples.DEMO_T0 + i * 3, ("10.0.0.%d" % (5 + i), 50000 + i),
                             ("203.0.113.9", 25), rng).open()
            c.s(L("220 mx.example.com ESMTP"))
            c.c(L(f"{verb} relay.example.net"))
            c.s(L("250 mx.example.com") if verb == "HELO"
                else L("250-mx.example.com", "250-STARTTLS", "250 8BITMIME"))
            if verb == "EHLO":
                c.c(L("STARTTLS")); c.s(L("220 ready")); c.c(samples.record(23, rng.randbytes(120)))
            else:
                c.c(L("MAIL FROM:<a@b.c>")); c.s(L("250 Ok"))
            c.c(L("QUIT")); c.s(L("221 bye")); c.close()

    a = analyze(_cap(build, tmp_path), Options(use_ml=False))
    strip = [f for f in a.findings if f.rule_id == "SMS-STRIP-002"]
    assert len(strip) == 1
    # the endpoint answered EHLO elsewhere, so this is suspicious, not merely odd
    assert strip[0].severity == "high"


def test_helo_without_an_ehlo_baseline_is_only_medium(tmp_path):
    def build(cap, rng):
        c = _conv(cap, rng)
        c.s(L("220 mx.example.com ESMTP"))
        c.c(L("HELO relay.example.net")); c.s(L("250 mx.example.com"))
        c.c(L("MAIL FROM:<a@b.c>")); c.s(L("250 Ok"))
        c.c(L("QUIT")); c.s(L("221 bye")); c.close()

    a = analyze(_cap(build, tmp_path), Options(use_ml=False))
    strip = [f for f in a.findings if f.rule_id == "SMS-STRIP-002"]
    assert len(strip) == 1 and strip[0].severity == "medium"


# ------------------------------------------------- F6: server answered outside the offer

def test_server_choosing_an_unoffered_cipher_is_flagged(tmp_path):
    """RFC 5246 s7.4.1.3: a conforming server cannot do this, so the ServerHello
    did not come from the client's peer."""
    def build(cap, rng):
        c = _conv(cap, rng, port=465)
        c.c(samples.client_hello(rng, "mx.example.com", tls13=False))
        pki = samples.build_pki()
        flight = (samples.server_hello(rng, 0x0303, 0x000A)
                  + samples.certificate_msg(pki.chain_der("mx")) + samples._hs(14, b""))
        c.s(samples.records(22, flight, 0x0303))
        c.c(samples.record(20, b"\x01", 0x0303) + samples.record(22, rng.randbytes(40), 0x0303))
        c.s(samples.record(20, b"\x01", 0x0303) + samples.record(22, rng.randbytes(40), 0x0303))
        c.close()

    a = analyze(_cap(build, tmp_path), Options(use_ml=False))
    f = next(f for f in a.findings if f.rule_id == "SMS-TLS-013")
    assert f.severity == "high"


def test_negotiation_rules_do_not_fire_on_a_normal_handshake(tmp_path):
    def build(cap, rng):
        c = _conv(cap, rng, port=465)
        samples.tls12_exchange(c, rng, "mx.example.com", 0xC030, samples.build_pki().chain_der("mx"))
        c.close()

    a = analyze(_cap(build, tmp_path), Options(use_ml=False))
    ids = {f.rule_id for f in a.findings}
    assert not ({"SMS-TLS-013", "SMS-TLS-014", "SMS-TLS-015"} & ids)


# ------------------------------------------------- F7: caveats reach the report

def test_read_notes_and_floors_are_in_the_report(tmp_path):
    def build(cap, rng):
        c = _conv(cap, rng)
        c.s(L("220 mx ESMTP")); c.c(L("EHLO x")); c.s(L("250 mx"))
        c.c(L("MAIL FROM:<a@b.c>")); c.s(L("250 Ok"))
        c.c(L("DATA")); c.s(L("354 go")); c.c(b"Subject: x\r\n\r\nbody\r\n.\r\n"); c.s(L("250 queued"))
        c.c(L("QUIT")); c.s(L("221 bye")); c.close()

    from securemailscope import report
    a = analyze(_cap(build, tmp_path), Options(use_ml=False))
    assert a.posture["floors"]
    assert "floors" in report.to_dict(a)["posture"]


# ------------------------------------------------- floors must not overstate

def _crit():
    from securemailscope.models import Finding
    return Finding(rule_id="SMS-CRED-001", title="x", severity="critical", category="credential",
                   session_id="S001", endpoint="a:587", evidence=[], remediation="", compliance=[])


def test_only_the_binding_floor_claims_the_cap():
    """A capture with a critical finding AND cleartext mail is capped at F by the
    critical rule. Reporting 'capping the capture at D' beside a grade of F,
    which is what sequential application produced, is simply wrong."""
    p = scoring.posture([_crit()], 1, cleartext_content=True)
    assert p["grade"] == "F"
    binding = [f for f in p["floors"] if f["binding"]]
    assert len(binding) == 1 and binding[0]["grade"] == "F"
    soft = [f for f in p["floors"] if not f["binding"]]
    assert soft and soft[0]["grade"] == "D"
    text = " ".join(p["floor_reasons"])
    assert "this caps the capture at F" in text
    assert "on its own that would cap the capture at D" in text
    assert "capping the capture at D" not in text


def test_a_floor_above_the_earned_score_is_not_reported():
    """Penalties already put this capture below every floor, so nothing was
    capped and claiming otherwise would misattribute the grade."""
    findings = [_crit()] + [
        scoring.Finding(rule_id=f"R{i}", title="x", severity="high", category="tls",
                        session_id="S001", endpoint="a:587", evidence=[], remediation="", compliance=[])
        for i in range(4)
    ]
    p = scoring.posture(findings, 1, cleartext_content=True)
    assert p["earned_score"] < scoring.CRITICAL_FLOOR
    assert p["floors"] == []
    assert p["score"] == p["earned_score"]


def test_floor_order_does_not_change_the_outcome():
    """The previous implementation suppressed the unverified floor only because
    the critical check happened to run first and append to the list."""
    a = scoring.posture([_crit()], 1, cleartext_content=True, unverified_tls=True)
    b = scoring.posture([_crit()], 1, unverified_tls=True, cleartext_content=True)
    assert a["score"] == b["score"]
    assert [f["cap"] for f in a["floors"]] == [f["cap"] for f in b["floors"]]
    # the 95 floor cannot bite when the score is already 59
    assert scoring.UNVERIFIED_FLOOR not in [f["cap"] for f in a["floors"]]


def test_earned_score_is_reported_alongside_the_capped_one():
    p = scoring.posture([_crit()], 1)
    assert p["earned_score"] == 70 and p["score"] == scoring.CRITICAL_FLOOR
