"""Stages 03-04: identify the mail protocol from the banner, run the STARTTLS
state machine, and slice out each direction's TLS bytes.

Never decide the protocol by port. The server banner decides it; ports are
only a hint for implicit-TLS sessions that are encrypted from byte one.

Privacy posture: only verbs, capability names, usernames and byte counts are
kept. Passwords, tokens and message bodies are never stored.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Optional

from .flows import frames_for_span
from .models import AuthEvent, Flow, MailSession

IMPLICIT_TLS_PORT_HINT = {465: "SMTP", 993: "IMAP", 995: "POP3"}
STANDARD_PORTS = {"SMTP": {25, 465, 587}, "IMAP": {143, 993}, "POP3": {110, 995}}
_HOST_RE = re.compile(rb"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,62}\.)+[A-Za-z]{2,63}\.?$")


# --------------------------------------------------------------------------- helpers

class _Reader:
    """Cursor over one direction's reassembled bytes."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def line(self) -> Optional[bytes]:
        if self.pos >= len(self.data) or self.at_tls():
            return None
        nl = self.data.find(b"\n", self.pos)
        if nl < 0:
            return None
        raw = self.data[self.pos:nl]
        self.pos = nl + 1
        return raw.rstrip(b"\r")

    def take(self, n: int) -> bytes:
        # A negative count would slice backwards and rewind the cursor, which turns
        # a malformed length field in the capture into an infinite parse loop.
        if n <= 0:
            return b""
        chunk = self.data[self.pos:self.pos + n]
        self.pos += len(chunk)
        return chunk

    def at_tls(self) -> bool:
        return is_tls_record(self.data[self.pos:self.pos + 3])

    def remaining(self) -> bytes:
        return self.data[self.pos:]


def is_tls_record(b: bytes) -> bool:
    # content type 0x14-0x17, major version 3
    return len(b) >= 2 and 0x14 <= b[0] <= 0x17 and b[1] == 0x03


def _dec(b: bytes) -> str:
    return b.decode("latin-1", "replace")


def _b64(s: bytes) -> Optional[bytes]:
    s = s.strip()
    if not s or s == b"=":
        return b""
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def _looks_mangled(token: str, target: str) -> bool:
    """Is a capability token a same-length rewrite of `target`?

    Stripping middleboxes commonly overwrite 'STARTTLS' with 'XXXXXXXX' (or flip
    a few bytes) so the TCP length is unchanged and no seq rewriting is needed.
    """
    t = token.upper()
    if t == target or len(t) != len(target):
        return False
    if len(set(t)) == 1:
        return True
    diff = sum(a != b for a, b in zip(t, target))
    return diff <= max(1, len(target) // 4) or "XXX" in t


MAX_TRANSCRIPT = 80
REDACTED = "•••••• (secret redacted)"


# Parsing works on the reassembled stream, where the frame a byte came from is no
# longer visible. _CTX holds the two cursors for the session being parsed so every
# transcript entry can record the byte range it consumed; the range is resolved to
# frame numbers once, at the end of parse_session.
_CTX: dict = {"cr": None, "sr": None, "c_at": 0, "s_at": 0}


def _bind_cursors(cr=None, sr=None) -> None:
    _CTX.update({"cr": cr, "sr": sr, "c_at": 0, "s_at": 0})


def _t(sess: MailSession, direction: str, text: str, kind: str = "line", **extra) -> None:
    """Record one redacted protocol line for the replay view. Never pass secrets or bodies here."""
    if len(sess.transcript) >= MAX_TRANSCRIPT:
        return
    ev = {"dir": direction, "kind": kind, "text": text[:220]}
    # Bytes consumed in this direction since the previous entry for it. Entries in
    # one direction therefore tile that direction's stream without overlapping.
    key, cursor = ("c_at", _CTX["cr"]) if direction == "C" else ("s_at", _CTX["sr"])
    if cursor is not None:
        start, end = _CTX[key], cursor.pos
        if end >= start:
            ev["span"] = [start, end]
            _CTX[key] = end
    ev.update(extra)
    sess.transcript.append(ev)


def _t_smtp(sess: MailSession, resp: Optional[tuple[int, list[bytes]]], kind: str = "reply") -> None:
    if resp:
        _t(sess, "S", f"{resp[0]} {_dec(resp[1][0])}", kind)


def _hostname_from(text: bytes) -> Optional[str]:
    for tok in text.split()[:2]:
        tok = tok.strip(b"[]")
        if _HOST_RE.match(tok):
            return _dec(tok).rstrip(".").lower()
    return None


def _sasl_event(mech: str, responses: list[bytes], accepted: Optional[bool]) -> AuthEvent:
    """Decode the client's SASL responses into an AuthEvent (secret discarded)."""
    mech = mech.upper()
    user: Optional[str] = None
    exposed = False
    decoded = [_b64(r) for r in responses]
    decoded = [d for d in decoded if d is not None]
    if mech == "PLAIN" and decoded:
        parts = decoded[0].split(b"\x00")
        if len(parts) >= 3:
            user = _dec(parts[1] or parts[0])
            exposed = bool(parts[2])
    elif mech == "LOGIN":
        if decoded:
            user = _dec(decoded[0])
        exposed = len(decoded) >= 2 and bool(decoded[1])
    elif mech == "CRAM-MD5" and decoded:
        user = _dec(decoded[0].split(b" ")[0])   # response is "user hexdigest": offline-crackable, not reusable
    elif mech in ("XOAUTH2", "OAUTHBEARER") and decoded:
        m = re.search(rb"user=([^\x01,]+)", decoded[0]) or re.search(rb"a=([^,\x01]+)", decoded[0])
        user = _dec(m.group(1)) if m else None
        exposed = b"auth=Bearer" in decoded[0] or b"auth=bearer" in decoded[0]
    elif mech.startswith("SCRAM") and decoded:
        m = re.search(rb"n=([^,]+)", decoded[0])
        user = _dec(m.group(1)) if m else None
    return AuthEvent(mechanism=mech, username=user, secret_exposed=exposed, accepted=accepted)


# --------------------------------------------------------------------------- entry point

# Client-side signatures, used only when the server side gives us nothing. A
# one-sided capture (asymmetric routing, a SPAN port wired to one direction, a
# rotated file) or a capture that began mid-connection has no banner, and
# dropping those flows meant a capture containing 18 KB of visible cleartext
# SMTP reported "no mail session found". Silence is the one answer a tool like
# this must never give.
_SEP = rb"(?=[\s:]|$)"
_CLIENT_SMTP = re.compile(rb"^\s*(EHLO|HELO|MAIL\s+FROM|RCPT\s+TO|STARTTLS|DATA|BDAT|QUIT|RSET|NOOP|VRFY)" + _SEP,
                          re.IGNORECASE | re.MULTILINE)
_CLIENT_IMAP = re.compile(rb"^\s*[A-Za-z0-9._-]{1,32}\s+(CAPABILITY|LOGIN|AUTHENTICATE|STARTTLS|SELECT|"
                          rb"EXAMINE|LIST|LOGOUT|NOOP|ID|FETCH|UID)" + _SEP, re.IGNORECASE | re.MULTILINE)
_CLIENT_POP3 = re.compile(rb"^\s*(USER|PASS|APOP|STLS|CAPA|RETR|LIST|UIDL|STAT|QUIT|DELE|TOP)" + _SEP,
                          re.IGNORECASE | re.MULTILINE)


def identify_from_client(flow: Flow) -> tuple[str, str]:
    """Best-effort protocol from the client's verbs alone. Lower confidence."""
    c = flow.client_bytes[:4096]
    if not c:
        return "UNKNOWN", "unknown"
    # Require two distinct verbs before claiming a protocol: one line of ASCII
    # that happens to start with LIST is not evidence of anything.
    for proto, rx in (("SMTP", _CLIENT_SMTP), ("IMAP", _CLIENT_IMAP), ("POP3", _CLIENT_POP3)):
        hits = {b" ".join(m.group(1).upper().split()) for m in rx.finditer(c)}
        if len(hits) >= 2:
            return proto, "plaintext"
    return "UNKNOWN", "unknown"


def identify(flow: Flow) -> tuple[str, str]:
    """Return (protocol, mode) from the first bytes of each direction."""
    s, c = flow.server_bytes, flow.client_bytes
    if is_tls_record(c[:2]) or is_tls_record(s[:2]):
        return IMPLICIT_TLS_PORT_HINT.get(flow.server[1], "UNKNOWN"), "implicit"
    if re.match(rb"^(220|421|554)[ -]", s):
        return "SMTP", "plaintext"
    if s.startswith((b"* OK", b"* PREAUTH", b"* BYE")):
        return "IMAP", "plaintext"
    if s.startswith((b"+OK", b"-ERR")):
        return "POP3", "plaintext"
    # A response code with no greeting text, which some servers and most test
    # harnesses emit, is still a banner for our purposes.
    if re.match(rb"^(220|250|421|554)\r?\n", s):
        return "SMTP", "plaintext"
    return "UNKNOWN", "unknown"


def _resolve_frames(flow: Flow, sess: MailSession) -> None:
    """Turn each transcript entry's byte span into the frames that carried it."""
    for ev in sess.transcript:
        span = ev.pop("span", None)
        if not span:
            continue
        spans = flow.client_spans if ev["dir"] == "C" else flow.server_spans
        frames = frames_for_span(spans, span[0], span[1])
        if frames:
            ev["frames"] = sorted(frames)


def parse_session(flow: Flow, session_id: str) -> Optional[MailSession]:
    protocol, mode = identify(flow)
    identified_by = "banner"
    if protocol == "UNKNOWN":
        protocol, mode = identify_from_client(flow)
        identified_by = "client-verbs"
    sess = MailSession(
        session_id=session_id, client=flow.client, server=flow.server,
        protocol=protocol, mode=mode, start_ts=flow.start_ts, end_ts=flow.end_ts,
        stream_quality={
            "handshake_seen": flow.handshake_seen,
            "client_role": flow.client_role_reason,
            "retransmissions": flow.client_stats.retransmissions + flow.server_stats.retransmissions,
            "out_of_order": flow.client_stats.out_of_order + flow.server_stats.out_of_order,
            "overlaps_trimmed": flow.client_stats.overlaps_trimmed + flow.server_stats.overlaps_trimmed,
            "overlap_conflicts": flow.client_stats.overlap_conflicts + flow.server_stats.overlap_conflicts,
            "gaps": flow.client_stats.gaps + flow.server_stats.gaps,
        },
    )
    if mode == "implicit":
        sess.tls_client_offset = sess.tls_server_offset = 0
        sess.tls_client_bytes, sess.tls_server_bytes = flow.client_bytes, flow.server_bytes
        if protocol == "UNKNOWN":
            return None  # TLS on a non-mail port: not ours to judge
        sess.notes.append(f"encrypted from first byte; protocol inferred from port {flow.server[1]} (hint only)")
        return sess
    if protocol == "UNKNOWN":
        return None

    sess.identified_by = identified_by
    sess.one_sided = not (flow.client_bytes and flow.server_bytes)
    if identified_by == "client-verbs":
        sess.notes.append(
            "identified from the client's commands: the server side of this conversation is missing or "
            "unrecognised, so negotiation findings (STARTTLS offered, refused, stripped) cannot be evaluated")
    if sess.one_sided:
        sess.notes.append("only one direction of this conversation was captured")

    parser = {"SMTP": _parse_smtp, "IMAP": _parse_imap, "POP3": _parse_pop3}[protocol]
    try:
        parser(flow, sess)
    finally:
        _bind_cursors(None, None)
    _resolve_frames(flow, sess)
    if flow.server[1] not in STANDARD_PORTS[protocol]:
        sess.notes.append(f"{protocol} identified by banner on non-standard port {flow.server[1]}")
    if sess.stream_quality["gaps"]:
        sess.notes.append("capture has missing bytes in this stream; parsing may be incomplete")
    return sess


def _switch_to_tls(sess: MailSession, flow: Flow, cr: _Reader, sr: _Reader, command: str) -> None:
    """The upgrade was accepted. Each direction switches at its own byte offset."""
    sess.starttls_accepted = True
    sess.mode = "starttls"

    def locate(data: bytes, start: int, side: str) -> Optional[int]:
        rest = data[start:]
        if not rest:
            return None
        if is_tls_record(rest[:2]):
            return start
        idx = next((i for i in range(len(rest) - 1) if rest[i] == 0x16 and rest[i + 1] == 0x03), -1)
        cleartext = rest if idx < 0 else rest[:idx]
        verbs = [_dec(l.strip().split(b" ")[0]).upper() for l in cleartext.split(b"\n") if l.strip()]
        _t(sess, "C" if side == "client" else "S",
           f"{' · '.join(verbs[:5]) or 'binary'}  ({len(cleartext)} bytes of cleartext before TLS)", "inject")
        if side == "client":
            sess.injection_indicators.append(
                f"client sent {len(cleartext)} bytes of cleartext after {command} before TLS "
                f"(pipelined commands: {', '.join(verbs[:5]) or 'binary'})")
        else:
            sess.injection_indicators.append(
                f"server sent {len(cleartext)} bytes of cleartext after accepting {command} before TLS "
                f"(response injection: {', '.join(verbs[:5]) or 'binary'})")
        return None if idx < 0 else start + idx

    c_off = locate(flow.client_bytes, cr.pos, "client")
    s_off = locate(flow.server_bytes, sr.pos, "server")
    sess.tls_client_offset, sess.tls_server_offset = c_off, s_off
    if c_off is not None:
        sess.tls_client_bytes = flow.client_bytes[c_off:]
    if s_off is not None:
        sess.tls_server_bytes = flow.server_bytes[s_off:]
    if c_off is not None or s_off is not None:
        _t(sess, "-", f"TLS begins · client at byte {c_off} · server at byte {s_off}", "tls-switch")
    if c_off is None and s_off is None:
        tail = flow.client_bytes[cr.pos:]
        if tail:
            _t(sess, "C", "cleartext continues: no TLS handshake followed", "strip")
            sess.strip_indicators.append(f"{command} accepted but session continued in cleartext (no TLS handshake)")
        else:
            sess.notes.append(f"{command} accepted but capture ends before any TLS bytes")


# --------------------------------------------------------------------------- SMTP (RFC 5321 / 3207 / 4954)

def _smtp_response(sr: _Reader) -> Optional[tuple[int, list[bytes]]]:
    lines: list[bytes] = []
    while True:
        line = sr.line()
        if line is None:
            break
        lines.append(line)
        if len(line) < 4 or line[3:4] != b"-":
            break
    if not lines:
        return None
    try:
        code = int(lines[0][:3])
    except ValueError:
        code = 0
    return code, [l[4:] for l in lines]


def _parse_smtp(flow: Flow, sess: MailSession) -> None:
    cr, sr = _Reader(flow.client_bytes), _Reader(flow.server_bytes)
    _bind_cursors(cr, sr)
    banner = _smtp_response(sr)
    if banner:
        sess.banner = _dec(banner[1][0])
        sess.server_name = _hostname_from(banner[1][0])
        _t_smtp(sess, banner, "banner")
    ehlo_seen = False
    while True:
        cmd = cr.line()
        if cmd is None:
            break
        parts = cmd.split(b" ", 1)
        verb = _dec(parts[0]).upper()
        arg = parts[1] if len(parts) > 1 else b""
        if not verb:
            continue
        sess.cleartext_commands.append(verb)
        if verb == "AUTH":
            a = arg.split(b" ", 1)
            _t(sess, "C", f"AUTH {_dec(a[0]).upper()}" + (f" {REDACTED}" if len(a) > 1 else ""), "auth")
        else:
            _t(sess, "C", _dec(cmd), "starttls" if verb == "STARTTLS" else "cmd")

        if verb == "BDAT":  # chunk bytes precede the reply
            try:
                size = int(arg.split()[0])
            except (ValueError, IndexError):
                size = 0
            if size < 0:
                # RFC 3030 §2: the chunk size is an unsigned integer. A negative one
                # is a malformed client (or a fuzzer); count nothing and keep parsing
                # rather than carrying a negative byte total into the feature vector.
                _t(sess, "C", f"[malformed BDAT chunk size {size}, ignored]", "cmd")
                size = 0
            # Count what was actually on the wire, not what the client announced.
            # The declared size is attacker-controlled; a capture claiming BDAT
            # 999999999 over five real bytes must not inflate the exposure figure
            # that a finding and the feature vector are both built from.
            observed = len(cr.take(size))
            sess.cleartext_message_bytes += observed
            note = "" if observed == size else f" of {size} declared"
            _t(sess, "C", f"[message chunk · {observed} bytes{note}, not stored]", "data")
            _t_smtp(sess, _smtp_response(sr))
            continue

        resp = _smtp_response(sr)
        code = resp[0] if resp else None

        if verb in ("EHLO", "HELO"):
            if sess.greeting_verb is None:
                sess.greeting_verb = verb
            if resp and code == 250:
                ehlo_seen = verb == "EHLO"
                if not sess.server_name:
                    sess.server_name = _hostname_from(resp[1][0])
                caps = [_dec(l).split(" ")[0].upper() for l in resp[1][1:]]
                sess.capabilities = caps
                _t(sess, "S", f"250 {_dec(resp[1][0])}", "caps", caps=caps)
                if ehlo_seen:
                    sess.starttls_offered = "STARTTLS" in caps
                    for cap in caps:
                        if _looks_mangled(cap, "STARTTLS"):
                            sess.strip_indicators.append(f"EHLO capability '{cap}' is a same-length rewrite of STARTTLS")
            else:
                _t_smtp(sess, resp)
        elif verb == "STARTTLS":
            sess.starttls_requested = True
            sess.starttls_response = f"{code} {_dec(resp[1][0])}" if resp else None
            _t_smtp(sess, resp, "starttls" if code == 220 else "strip")
            if code == 220:
                _switch_to_tls(sess, flow, cr, sr, "STARTTLS")
                return
            if resp:
                sess.strip_indicators.append(f"STARTTLS refused with '{sess.starttls_response}'")
        elif verb == "AUTH":
            a = arg.split(b" ", 1)
            mech = _dec(a[0]).upper()
            responses: list[bytes] = [a[1]] if len(a) > 1 else []
            # SASL continuation: 334 challenge -> client line, until a final code
            while resp and resp[0] == 334:
                _t_smtp(sess, resp)
                line = cr.line()
                if line is None:
                    resp = None
                    break
                if line == b"*":
                    break
                responses.append(line)
                _t(sess, "C", REDACTED, "auth")
                resp = _smtp_response(sr)
            _t_smtp(sess, resp)
            accepted = None if not resp else resp[0] == 235
            sess.auth_events.append(_sasl_event(mech, responses, accepted))
        elif verb == "DATA":
            _t_smtp(sess, resp)
            accepted = code == 354
            unaligned = sess.identified_by == "client-verbs" or not flow.server_bytes
            if accepted or unaligned:
                end = flow.client_bytes.find(b"\r\n.\r\n", cr.pos)
                if end < 0:
                    end = flow.client_bytes.find(b"\n.\n", cr.pos)
                    end = len(flow.client_bytes) if end < 0 else end + 3
                else:
                    end = end + 5
                n = end - cr.pos
                if n > 0:
                    sess.cleartext_message_bytes += n
                    suffix = "" if accepted else " (server side not captured; inferred from the client stream)"
                    _t(sess, "C", f"[message body · {n} bytes, not stored{suffix}]", "data")
                cr.pos = end
                if accepted:
                    _t_smtp(sess, _smtp_response(sr))
        else:
            _t_smtp(sess, resp)
            if verb == "QUIT":
                break
    if sess.starttls_offered is None and not ehlo_seen and sess.cleartext_commands:
        sess.notes.append("client used HELO/no EHLO: server capabilities unknown")


# --------------------------------------------------------------------------- IMAP (RFC 3501)

_LITERAL_RE = re.compile(rb"\{(\d+)(\+?)\}$")


def _imap_server_line(sr: _Reader, sess: MailSession) -> Optional[bytes]:
    """One logical server line, skipping any {n} literal payloads (message data)."""
    line = sr.line()
    if line is None:
        return None
    full = line
    while (m := _LITERAL_RE.search(line)):
        n = int(m.group(1))
        sr.take(n)
        sess.cleartext_message_bytes += n
        line = sr.line() or b""
        full += b" " + line
    return full


def _imap_client_command(cr: _Reader, sr: _Reader, sess: MailSession) -> Optional[bytes]:
    line = cr.line()
    if line is None:
        return None
    full = line
    while (m := _LITERAL_RE.search(line)):
        n, nonsync = int(m.group(1)), m.group(2)
        if not nonsync:
            _imap_server_line(sr, sess)  # "+ go ahead"
        lit = cr.take(n)
        if n >= 256:  # APPEND payloads: count them, never keep them
            sess.cleartext_message_bytes += n
            lit = b"<literal>"
        # the marker ends `line`, and `line` is the tail of `full`
        full = full[: len(full) - len(m.group(0))] + b'"' + lit + b'"'
        line = cr.line() or b""
        full += line
    return full


def _imap_caps(text: bytes) -> list[str]:
    m = re.search(rb"CAPABILITY ([^\]]*)", text, re.I)
    return [_dec(t).upper() for t in m.group(1).split()] if m else []


def _imap_args(s: bytes) -> list[str]:
    return [_dec(a or b) for a, b in re.findall(rb'"((?:[^"\\]|\\.)*)"|(\S+)', s)]


def _parse_imap(flow: Flow, sess: MailSession) -> None:
    cr, sr = _Reader(flow.client_bytes), _Reader(flow.server_bytes)
    _bind_cursors(cr, sr)
    greet = _imap_server_line(sr, sess) or b""
    sess.banner = _dec(greet)
    caps = _imap_caps(greet)
    if caps:
        sess.capabilities = caps
    sess.server_name = _hostname_from(greet.split(b"]")[-1].strip()) if greet else None

    def set_caps(c: list[str]) -> None:
        sess.capabilities = c
        sess.starttls_offered = "STARTTLS" in c
        for cap in c:
            if _looks_mangled(cap, "STARTTLS"):
                sess.strip_indicators.append(f"IMAP capability '{cap}' is a same-length rewrite of STARTTLS")

    if caps:
        set_caps(caps)
    if greet:
        _t(sess, "S", _dec(greet), "caps" if caps else "banner", caps=caps)

    while True:
        cmd = _imap_client_command(cr, sr, sess)
        if cmd is None:
            break
        parts = cmd.split(b" ", 2)
        if len(parts) < 2:
            continue
        tag, verb = parts[0], _dec(parts[1]).upper()
        arg = parts[2] if len(parts) > 2 else b""
        sess.cleartext_commands.append(verb)
        sasl: list[bytes] = []
        t_tag = _dec(tag)
        if verb == "LOGIN":
            la = _imap_args(arg)
            _t(sess, "C", f"{t_tag} LOGIN {la[0] if la else ''} {REDACTED}", "auth")
        elif verb == "AUTHENTICATE":
            a = arg.split(b" ", 1)
            _t(sess, "C", f"{t_tag} AUTHENTICATE {_dec(a[0]).upper()}" + (f" {REDACTED}" if len(a) > 1 else ""), "auth")
            if len(a) > 1:
                sasl.append(a[1])  # SASL-IR
        else:
            _t(sess, "C", _dec(cmd), "starttls" if verb == "STARTTLS" else "cmd")
        tagged: Optional[bytes] = None
        untagged_logged = 0
        while True:
            line = _imap_server_line(sr, sess)
            if line is None:
                break
            if line.startswith(b"* "):
                c = _imap_caps(line)
                if c:
                    set_caps(c)
                if untagged_logged < 4:
                    lit = re.search(rb"\{(\d+)\}", line)
                    text = _dec(line.split(b"{")[0]) + f"[message · {lit.group(1).decode()} bytes, not stored])" if lit else _dec(line)
                    _t(sess, "S", text, "caps" if c else ("data" if lit else "reply"), **({"caps": c} if c else {}))
                    untagged_logged += 1
                continue
            if line.startswith(b"+") and verb == "AUTHENTICATE":
                _t(sess, "S", _dec(line), "reply")
                resp = cr.line()
                if resp is None:
                    break
                sasl.append(resp)
                _t(sess, "C", REDACTED, "auth")
                continue
            if line.startswith(tag + b" "):
                tagged = line
                break
        status = tagged.split(b" ")[1].upper() if tagged and len(tagged.split(b" ")) > 1 else b""
        if tagged:
            _t(sess, "S", _dec(tagged), ("starttls" if status == b"OK" else "strip") if verb == "STARTTLS" else "reply")
        c = _imap_caps(tagged or b"")
        if c:
            set_caps(c)

        if verb == "STARTTLS":
            sess.starttls_requested = True
            sess.starttls_response = _dec(tagged) if tagged else None
            if status == b"OK":
                _switch_to_tls(sess, flow, cr, sr, "STARTTLS")
                return
            if tagged:
                sess.strip_indicators.append(f"STARTTLS refused with '{_dec(tagged)}'")
        elif verb == "LOGIN":
            args = _imap_args(arg)
            sess.auth_events.append(AuthEvent("IMAP-LOGIN", args[0] if args else None,
                                              secret_exposed=len(args) >= 2 and bool(args[1]),
                                              accepted=(status == b"OK") if tagged else None))
        elif verb == "AUTHENTICATE":
            mech = _dec(arg.split(b" ", 1)[0]).upper()
            sess.auth_events.append(_sasl_event(mech, sasl, (status == b"OK") if tagged else None))
        elif verb == "LOGOUT":
            break


# --------------------------------------------------------------------------- POP3 (RFC 1939 / 2449 / 2595)

def _pop3_single(sr: _Reader, sess: Optional[MailSession] = None, kind: str = "reply") -> Optional[bytes]:
    line = sr.line()
    if sess is not None and line is not None:
        _t(sess, "S", _dec(line), kind)
    return line


def _pop3_multi(sr: _Reader, sess: MailSession, count_bytes: bool) -> tuple[Optional[bytes], list[bytes]]:
    first = sr.line()
    body: list[bytes] = []
    if first is None or not first.startswith(b"+OK"):
        return first, body
    start = sr.pos
    while True:
        line = sr.line()
        if line is None or line == b".":
            break
        body.append(line)
    if count_bytes:
        sess.cleartext_message_bytes += sr.pos - start
        _t(sess, "S", f"{_dec(first)}  [message · {sr.pos - start} bytes, not stored]", "data")
    else:
        caps = [_dec(l).split(" ")[0].upper() for l in body]
        _t(sess, "S", _dec(first), "caps", caps=caps)
    return first, body


def _parse_pop3(flow: Flow, sess: MailSession) -> None:
    cr, sr = _Reader(flow.client_bytes), _Reader(flow.server_bytes)
    _bind_cursors(cr, sr)
    greet = sr.line() or b""
    sess.banner = _dec(greet)
    sess.server_name = _hostname_from(greet[4:]) if greet.startswith(b"+OK ") else None
    if greet:
        _t(sess, "S", _dec(greet), "banner")
    pending_user: Optional[str] = None
    while True:
        cmd = cr.line()
        if cmd is None:
            break
        parts = cmd.split(b" ", 1)
        verb = _dec(parts[0]).upper()
        arg = parts[1] if len(parts) > 1 else b""
        sess.cleartext_commands.append(verb)
        if verb == "PASS":
            _t(sess, "C", f"PASS {REDACTED}", "auth")
        elif verb == "APOP":
            _t(sess, "C", f"APOP {_dec(arg.split(b' ')[0])} {REDACTED}", "auth")
        elif verb == "AUTH":
            a0 = arg.split(b" ", 1)
            _t(sess, "C", f"AUTH {_dec(a0[0]).upper()}" + (f" {REDACTED}" if len(a0) > 1 else ""), "auth")
        else:
            _t(sess, "C", _dec(cmd), "starttls" if verb == "STLS" else "cmd")
        if verb == "CAPA":
            first, body = _pop3_multi(sr, sess, False)
            caps = [_dec(l).split(" ")[0].upper() for l in body]
            sess.capabilities = caps
            sess.starttls_offered = "STLS" in caps
            for cap in caps:
                if _looks_mangled(cap, "STLS"):
                    sess.strip_indicators.append(f"POP3 capability '{cap}' is a same-length rewrite of STLS")
        elif verb in ("RETR", "TOP"):
            _pop3_multi(sr, sess, True)
        elif verb in ("LIST", "UIDL") and not arg.strip():
            _pop3_multi(sr, sess, False)
        elif verb == "STLS":
            resp = _pop3_single(sr)
            if resp is not None:
                _t(sess, "S", _dec(resp), "starttls" if resp.startswith(b"+OK") else "strip")
            sess.starttls_requested = True
            sess.starttls_response = _dec(resp) if resp else None
            if resp and resp.startswith(b"+OK"):
                _switch_to_tls(sess, flow, cr, sr, "STLS")
                return
            if resp:
                sess.strip_indicators.append(f"STLS refused with '{_dec(resp)}'")
        elif verb == "USER":
            _pop3_single(sr, sess)
            pending_user = _dec(arg.strip())
        elif verb == "PASS":
            resp = _pop3_single(sr, sess)
            sess.auth_events.append(AuthEvent("USER/PASS", pending_user, secret_exposed=bool(arg.strip()),
                                              accepted=resp.startswith(b"+OK") if resp else None))
        elif verb == "APOP":
            resp = _pop3_single(sr, sess)
            user = _dec(arg.split(b" ")[0]) if arg else None
            sess.auth_events.append(AuthEvent("APOP", user, secret_exposed=False,
                                              accepted=resp.startswith(b"+OK") if resp else None))
        elif verb == "AUTH":
            a = arg.split(b" ", 1)
            mech = _dec(a[0]).upper()
            if not mech:  # bare AUTH lists mechanisms
                _pop3_multi(sr, sess, False)
                continue
            responses = [a[1]] if len(a) > 1 else []
            resp = sr.line()
            while resp is not None and resp.startswith(b"+ "):
                _t(sess, "S", _dec(resp), "reply")
                line = cr.line()
                if line is None:
                    resp = None
                    break
                responses.append(line)
                _t(sess, "C", REDACTED, "auth")
                resp = sr.line()
            if resp is not None:
                _t(sess, "S", _dec(resp), "reply")
            sess.auth_events.append(_sasl_event(mech, responses, resp.startswith(b"+OK") if resp else None))
        elif verb == "QUIT":
            _pop3_single(sr, sess)
            break
        else:
            _pop3_single(sr, sess)
    if sess.starttls_offered is None and "CAPA" not in sess.cleartext_commands:
        sess.notes.append("client never sent CAPA: STLS support unknown")
