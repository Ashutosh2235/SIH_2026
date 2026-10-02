"""The whole pipeline, stage 00 to 12, as one function.

    00-01 pcapio     read container, walk link/IP/TCP
    02    flows      TCP reassembly, client/server roles
    03-04 mailproto  banner protocol ID, STARTTLS state machine, TLS slicing
    05    tls        handshake parsing, JA3/JA3S
    06    certs      X.509 analysis
    07    rules      findings with evidence, fix, compliance
    08    features   feature vectors
    09    baseline   per-endpoint profile, deviations, escalation
    10    ml         risk model + isolation forest
    11    scoring    prioritisation, posture
    12    report     JSON / HTML / PDF (see report.py)
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from . import __version__, baseline, certs, mailproto, ml, rules, scoring, tls
from .features import to_row, vector
from .flows import build_flows
from .models import Finding, SessionResult
from .pcapio import read_packets


@dataclass
class Options:
    trust_store: Optional[str] = None
    use_default_trust: bool = True
    baseline_db: Optional[str] = None
    learn: bool = True
    use_ml: bool = True
    contamination: Optional[float] = None
    criticality: dict = field(default_factory=dict)
    model_path: Optional[str] = None


@dataclass
class Analysis:
    meta: dict
    results: list[SessionResult]
    findings: list[Finding]
    posture: dict
    endpoints: list[dict]
    ml_info: dict
    timings: dict
    packets: list[dict] = field(default_factory=list)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()



MAX_PACKET_ROWS = 20000          # a report is held in memory; a huge capture is summarised

_FLAG_NAMES = ((0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"), (0x01, "FIN"), (0x04, "RST"), (0x20, "URG"))
_TLS_TYPES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "Application Data"}


def _flag_str(flags: int) -> str:
    return ", ".join(name for bit, name in _FLAG_NAMES if flags & bit) or "-"


# Verbs whose argument is, or may contain, a credential. The packet list shows the
# first line of a cleartext payload, so it has to redact at the same standard as
# the transcript: the tool reports that a password crossed the wire, never what it
# was. Matching is on the verb only — the argument is never echoed.
_SECRET_VERBS = re.compile(
    rb"^\s*(PASS|APOP|AUTH|LOGIN|USER)\b"
    rb"|^\s*[A-Za-z0-9._-]+\s+(LOGIN|AUTHENTICATE)\b",   # IMAP tagged commands
    re.IGNORECASE)


def _redact_line(line: bytes) -> bytes:
    """Keep the verb, drop everything after it."""
    m = _SECRET_VERBS.match(line)
    if not m:
        return line
    verb_end = m.end()
    head = line[:verb_end]
    # AUTH PLAIN / AUTH LOGIN: the mechanism name is safe and useful, the rest is not.
    rest = line[verb_end:].lstrip()
    mech = re.match(rb"(PLAIN|LOGIN|CRAM-MD5|DIGEST-MD5|XOAUTH2|EXTERNAL|SCRAM-[A-Z0-9-]+)\b", rest, re.IGNORECASE)
    if mech:
        head += b" " + mech.group(1)
    return head + b" [redacted]"


def _looks_like_base64_secret(line: bytes) -> bool:
    """A bare base64 blob on its own line is a SASL continuation: never show it."""
    t = line.strip()
    return len(t) >= 12 and re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", t) is not None


def _packet_info(p, flags: str, ctx=None, after_tls: bool = False) -> str:
    """A one-line summary in the spirit of a packet-list 'Info' column.

    `ctx` is (reassembled_stream, offset) for this segment. Segments do not
    respect line boundaries — and out-of-order arrival means the payload of the
    frame *before* this one in the capture is often not the text before it in the
    stream — so the line is read out of the reassembled stream at this segment's
    offset, not out of the payload.
    """
    if not p.payload:
        return flags
    b = p.payload
    if after_tls and not (len(b) >= 5 and b[0] in _TLS_TYPES and b[1] == 3):
        # Inside the TLS stream but not at a record boundary: this segment
        # continues a record that began in an earlier one.
        return f"TLS record data, continued ({len(b)} bytes)"
    if b[0] in _TLS_TYPES and b[1] == 3 and len(b) >= 5:
        kind = _TLS_TYPES[b[0]]
        if b[0] == 22 and len(b) >= 6:
            hs = {1: "ClientHello", 2: "ServerHello", 11: "Certificate", 12: "ServerKeyExchange",
                  13: "CertificateRequest", 14: "ServerHelloDone", 16: "ClientKeyExchange",
                  20: "Finished", 4: "NewSessionTicket", 8: "EncryptedExtensions"}.get(b[5])
            if hs:
                return f"TLS {kind}: {hs}"
        return f"TLS {kind} ({len(b)} bytes)"
    # Cleartext protocol: read the line out of the reassembled stream so that a
    # segment starting mid-line is described as such instead of showing a tail.
    prefix = ""
    if ctx is not None:
        stream, off = ctx
        starts_line = off == 0 or stream[off - 1:off] == b"\n"
        if not starts_line:
            nl = stream.find(b"\n", off, off + len(b))
            if nl < 0:
                return f"… continues the previous line ({len(b)} bytes)"
            off, prefix = nl + 1, "… "
        end = stream.find(b"\n", off)
        line = stream[off:end if end >= 0 else off + 90][:90].rstrip(b"\r")
    else:
        line = b.split(b"\r\n", 1)[0][:90]

    if line and all(32 <= c < 127 or c == 9 for c in line):
        if _looks_like_base64_secret(line):
            return prefix + "[redacted SASL token]"
        return prefix + _redact_line(line).decode("ascii", "replace")
    return f"{len(b)} bytes of data"


def _packet_proto(p, session_proto: str, after_tls: bool) -> str:
    """The finest protocol this particular frame actually speaks.

    A bare ACK is TCP whatever the conversation is for. Once the session has
    switched to TLS every later frame is TLS, including the ones that continue a
    record started in an earlier segment and so do not begin with a record
    header — sniffing the first five bytes alone would label those SMTP.
    """
    b = p.payload
    if not b:
        return "TCP"
    if after_tls:
        return "TLS"
    if len(b) >= 5 and b[0] in _TLS_TYPES and b[1] == 3:
        return "TLS"
    return session_proto or "TCP"


def _packet_rows(packets, flows, sessions) -> tuple[list[dict], bool]:
    """One row per captured TCP segment, tagged with the session it belongs to."""
    frame_to_session: dict[int, str] = {}
    frame_meta: dict[int, tuple] = {}          # frame -> (mail protocol, server port)
    tls_here: dict[int, bool] = {}             # frame -> its bytes are inside the TLS stream
    si = 0
    for flow in flows:
        sess = sessions[si] if si < len(sessions) else None
        # sessions were produced from flows in order, skipping the ones that are not mail
        matched = (sess is not None and sess.client == flow.client and sess.server == flow.server
                   and abs(sess.start_ts - flow.start_ts) < 1e-9)
        proto = sess.protocol if matched else ""
        # Byte offset in each direction at which the stream stops being mail
        # protocol and starts being TLS records. None means it never does.
        c_tls = sess.tls_client_offset if matched else None
        s_tls = sess.tls_server_offset if matched else None
        for fn in flow.frame_numbers:
            frame_meta[fn] = (proto, flow.server[1])
        for off, _ln, fn, _ts in flow.client_spans:
            tls_here[fn] = tls_here.get(fn) or (c_tls is not None and off >= c_tls)
        for off, _ln, fn, _ts in flow.server_spans:
            tls_here[fn] = tls_here.get(fn) or (s_tls is not None and off >= s_tls)
        if matched:
            for fn in flow.frame_numbers:
                frame_to_session[fn] = sess.session_id
            si += 1
    # frame -> (reassembled stream for its direction, offset of its bytes in it)
    where: dict[int, tuple] = {}
    for flow in flows:
        for stream, spans in ((flow.client_bytes, flow.client_spans),
                              (flow.server_bytes, flow.server_spans)):
            for off, _length, frame, _ts in spans:
                where.setdefault(frame, (stream, off))

    rows = []
    for p in packets[:MAX_PACKET_ROWS]:
        flags = _flag_str(p.flags)
        mail_proto, server_port = frame_meta.get(p.frame, ("", p.dport))
        rows.append({
            "frame": p.frame, "ts": p.ts,
            "src": p.src, "sport": p.sport, "dst": p.dst, "dport": p.dport,
            "proto": _packet_proto(p, mail_proto, tls_here.get(p.frame, False)),
            "service": mail_proto or "—",
            "port": server_port,
            "flags": flags, "len": len(p.payload), "seq": p.seq,
            "session": frame_to_session.get(p.frame),
            "info": _packet_info(p, flags, where.get(p.frame), tls_here.get(p.frame, False)),
        })
    return rows, len(packets) > MAX_PACKET_ROWS


def analyze(path: str, opts: Optional[Options] = None) -> Analysis:
    opts = opts or Options()
    t0 = time.perf_counter()
    timings: dict[str, float] = {}

    def lap(name: str, since: float) -> float:
        now = time.perf_counter()
        timings[name] = round(now - since, 4)
        return now

    digest = sha256_file(path)   # evidence integrity: hash the input before touching it
    t = time.perf_counter()

    # ---------------- Part 1
    packets, rstats = read_packets(path)
    t = lap("read", t)
    flows = build_flows(packets)
    t = lap("reassembly", t)
    MAIL_PORTS = {25, 465, 587, 2525, 143, 993, 110, 995, 24, 26}
    sessions = []
    unclassified = []
    for flow in flows:
        s = mailproto.parse_session(flow, f"S{len(sessions) + 1:03d}")
        if s is not None:
            sessions.append(s)
        elif flow.server[1] in MAIL_PORTS or flow.client[1] in MAIL_PORTS:
            # A flow on a mail port that we could not parse is not the same as
            # no mail traffic. Dropping it silently let a capture containing
            # visible cleartext SMTP report "no mail session was found".
            unclassified.append({
                "client": f"{flow.client[0]}:{flow.client[1]}",
                "server": f"{flow.server[0]}:{flow.server[1]}",
                "client_bytes": len(flow.client_bytes),
                "server_bytes": len(flow.server_bytes),
                "frames": len(flow.frame_numbers),
                "reason": ("neither side matched a known mail protocol"
                           if flow.client_bytes or flow.server_bytes else "no payload captured"),
            })
    t = lap("protocol", t)

    # ---------------- Part 2
    # An endpoint that answered EHLO elsewhere in this capture is known to speak
    # ESMTP, which turns a HELO-only session from odd into suspicious.
    ehlo_endpoints = {s.endpoint for s in sessions if s.greeting_verb == "EHLO"}

    results: list[SessionResult] = []
    for s in sessions:
        hs = tls.analyze(s.tls_client_bytes, s.tls_server_bytes) if s.tls_used else None
        hostname = (hs.sni if hs and hs.sni else None) or s.server_name
        chain = certs.analyze(hs, hostname, s.start_ts, opts.trust_store, opts.use_default_trust) \
            if hs is not None else None
        results.append(SessionResult(session=s, tls=hs, chain=chain,
                                     findings=rules.evaluate(s, hs, chain,
                                                             baseline_ehlo=s.endpoint in ehlo_endpoints)))
    t = lap("crypto_rules", t)

    # ---------------- Part 3: baseline (leave-one-out within capture + stored history)
    store = baseline.BaselineStore(opts.baseline_db)
    observations = []
    for r in results:
        feats = to_row(vector(r.session, r.tls, r.chain))
        observations.append(baseline.observe(r.session, r.tls, r.chain, r.findings, digest[:16], feats))
    history_cache: dict[str, list] = {}
    for i, (r, o) in enumerate(zip(results, observations)):
        if o.endpoint not in history_cache:
            history_cache[o.endpoint] = store.history(o.endpoint)
        peers = history_cache[o.endpoint] + [p for j, p in enumerate(observations) if j != i and p.endpoint == o.endpoint]
        codes, new = baseline.compare(o, r.session, peers, r.findings)
        r.baseline_deviations = codes
        r.findings.extend(new)
        r.features = vector(r.session, r.tls, r.chain, set(codes))
    t = lap("baseline", t)

    # ---------------- Part 3: ML
    ml_info: dict = {"enabled": opts.use_ml}
    if opts.use_ml and results:
        model = ml.load_model(opts.model_path)
        rows = [to_row(r.features) for r in results]
        for r, risk, expl in zip(results, model.predict(rows), model.explain(rows)):
            r.model_risk = risk
            r.explanation = expl
        anomalies = ml.detect_anomalies(rows, store.feature_history(), opts.contamination)
        for r, flag, reasons, i in zip(results, anomalies.flags, anomalies.reasons, range(len(results))):
            r.anomaly_score = anomalies.scores[i] if anomalies.scores else None
            if flag:
                r.findings.append(Finding(
                    rule_id="SMS-ML-001", title="Statistical outlier session (isolation forest)", severity="medium",
                    category="anomaly", session_id=r.session.session_id, endpoint=r.session.endpoint,
                    evidence=[f"anomaly score {r.anomaly_score}"] + reasons,
                    remediation="Review this session against the endpoint's normal behaviour; outliers are leads, not verdicts.",
                    references=["Isolation Forest (Liu et al., 2008)"], exploitability=0.3, confidence=0.5))
        ml_info.update({"model": type(model.model).__name__, "trained_on": model.trained_on,
                        "holdout_r2": model.holdout_r2, "holdout_mae": model.holdout_mae,
                        "explainer": model.explainer, "anomaly": anomalies.note})
    for r in results:
        r.risk = scoring.blend(scoring.rule_risk(r.findings), r.model_risk,
                               any(f.rule_id == "SMS-ML-001" for f in r.findings))
    t = lap("ml", t)

    # ---------------- Part 3: scoring
    findings = scoring.prioritise(results, opts.criticality)
    cleartext_content = any(r.session.cleartext_message_bytes for r in results)
    unverified_tls = any(r.session.tls_used and r.chain is not None and not r.chain.present for r in results)
    post = scoring.posture(findings, len(results), cleartext_content=cleartext_content,
                           unverified_tls=unverified_tls)
    for r in results:
        ep = r.session.endpoint
        post["endpoints"].setdefault(ep, {"score": 100, "grade": "A", "findings": {}})
    # Re-judge cleanliness after escalation and ML, so an attack session never enters the baseline.
    for r, o in zip(results, observations):
        o.clean = not (any(f.severity in ("critical", "high") for f in r.findings) or r.baseline_deviations)
    learned = store.learn(observations) if (opts.learn and opts.baseline_db) else 0
    endpoints = [baseline.profile_summary(ep, store.history(ep)) for ep in sorted({o.endpoint for o in observations})] \
        if opts.baseline_db else []
    store.close()
    t = lap("scoring", t)
    timings["total"] = round(time.perf_counter() - t0, 4)

    packet_rows, truncated = _packet_rows(packets, flows, [r.session for r in results])

    ts = [r.session.start_ts for r in results] or [0.0]
    meta = {
        "tool": f"SecureMailScope {__version__}",
        "input": os.path.basename(path),
        "input_sha256": digest,
        "input_bytes": os.path.getsize(path),
        "analysed_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "capture_start": dt.datetime.fromtimestamp(min(ts), dt.timezone.utc).isoformat(timespec="seconds"),
        "capture_end": dt.datetime.fromtimestamp(max(r.session.end_ts for r in results) if results else 0,
                                                 dt.timezone.utc).isoformat(timespec="seconds"),
        "read": rstats.to_dict(),
        "flows": len(flows),
        "mail_sessions": len(results),
        "non_mail_flows": len(flows) - len(results),
        "unclassified_mail_flows": unclassified,
        "baseline_db": opts.baseline_db,
        "baseline_learned": learned,
        "trust_store": opts.trust_store or ("certifi (Mozilla)" if opts.use_default_trust else None),
        "mode": "passive, metadata-only (no passwords, tokens or message bodies retained)",
        "packet_rows": len(packet_rows),
        "packet_rows_truncated": truncated,
    }
    return Analysis(meta=meta, results=results, findings=findings, posture=post, endpoints=endpoints,
                    ml_info=ml_info, timings=timings, packets=packet_rows)
