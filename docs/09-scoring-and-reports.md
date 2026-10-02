# 09 · Scoring and reports (stages 11–12)

Code: [`scoring.py`](../securemailscope/scoring.py), [`report.py`](../securemailscope/report.py),
[`cli.py`](../securemailscope/cli.py), [`server.py`](../securemailscope/server.py)

## Severity is not priority

Severity says how bad a weakness is in the abstract. Priority says which one to fix first **here**.
Each finding gets a priority risk:

```
risk = 100 × severity_weight × exposure × (0.5 + 0.5 × exploitability) × asset_criticality
```

| Factor | Values | Rationale |
|---|---|---|
| severity weight | critical 1.0 · high 0.7 · medium 0.4 · low 0.15 · info 0 | |
| exposure | submission/access 1.0 · non-standard 0.9 · relay 0.85; ×0.8 if both ends are private addresses | client ports carry user passwords and mailboxes; internal-only traffic is less exposed |
| exploitability | set per rule: 1.0 for cleartext (a passive observer can read it) … 0.2 for hygiene | needs active attacker? key compromise? offline work? |
| asset criticality | from `--assets assets.json`, default 1.0 | the analyst knows the payroll relay matters more |

```json
{ "203.0.113.11:587": 1.5, "mx.example.com": 1.2, "default": 1.0 }
```

Findings are sorted by risk (then severity, rule, session) and numbered `priority` 1…n. That's why
"credentials in cleartext on submission" (risk 80) ranks above "stripping on the relay" (65), even
though both are critical.

**Session risk** blends the two views: `0.6 × rule risk + 0.4 × model risk`, plus 10 if the
isolation forest flagged it.

## Posture score

```
score = 100 − Σ penalty over unique (rule, endpoint) pairs
        penalty: critical 30 · high 12 · medium 5 · low 1 · info 0
any critical finding caps the score at 59 (grade F)
grades: A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · F < 60
```

Counting unique `(rule, endpoint)` pairs means one noisy endpoint with 500 identical sessions
can't sink the score 500 times. It's one issue to fix. Every endpoint also gets its own score and
grade.

## Outputs

| Output | For | Notes |
|---|---|---|
| **Terminal** | the analyst | posture, the top-N findings grouped by (rule, endpoint), output paths; `--fail-on high` gives exit code 2 for CI or cron |
| **HTML** | people | one self-contained file: inline CSS/SVG and 20 lines of JS, no network requests. Light by default, dark on `data-theme="dark"`. Posture gauge, severity bar, "act on these first", endpoints table, sessions table (click a row for the transcript summary, TLS, chain and the explanation chart), filterable/searchable findings, method and limits, rule catalogue |
| **JSON** | SIEM / automation | `meta`, `posture`, `findings[]` (full), `sessions[]` (session, TLS, chain, features, risks, explanation), `endpoint_baselines`, `ml`, `timings_seconds` |
| **PDF** | email / archive | via reportlab (`pip install reportlab`): summary, findings table, details |
| **audit.log** | evidence integrity | one JSON line per analysis, appended |

**Numpy scalars aren't JSON-serialisable.** `np.bool_` isn't `bool`, and the encoder rejects it.
`report._json_default` coerces with `.item()`. `test_json_handles_numpy_scalars` guards it.

**Attacker-controlled strings.** Banners, capability tokens, hostnames, usernames and certificate
subjects all come off the wire. Every one is HTML-escaped before it reaches the page.
`test_html_escapes_attacker_controlled_banner` sends `220 <script>alert("x")</script>` and checks
that it renders as text.

## Evidence integrity

- The input file is **SHA-256 hashed before anything else touches it**. The hash appears in the
  report header, the footer, the JSON `meta` and the audit log.
- `audit.log` records, per run: UTC time, tool version, absolute input path, hash, size, output files,
  posture, severity counts and the options used.
- Capture start and end times come from the packets, analysis time from the clock, and both are
  shown. Certificate validity is judged at capture time.
- The report is metadata-only, so it can be shared or archived without re-exposing passwords or mail.

## Web UI and API

```bash
python -m securemailscope serve --port 8000 --trust-store samples/demo-ca.pem
```

The frontend is a single page in `securemailscope/web/` (vanilla JS, no build step) that reads the JSON API:

| View | What it shows |
|---|---|
| `#/` | drag-and-drop upload, "run the built-in demo", recent analyses; the 12 pipeline stages animate during analysis and then show real per-stage timings |
| `#/r/<id>/<section>` | an app shell with a **sidebar**: the report's grade, the sections **Overview** (animated posture ring, counters, severity bar, top four findings), **Wire replay** (every session plays back in order as packets between clients and servers; sealed, cleartext and attacked links are coloured differently, with a live findings feed, play/pause/speed/scrub), **Findings** (filterable, searchable), **Endpoints** (table plus channel and version charts) and **Sessions**, then a quick-jump list of every session with a status dot. Each section fits one screen at 1440×900: long lists scroll inside their card. Below 900 px wide the sidebar becomes a horizontal tab bar |
| `#/r/<id>/s/<sid>` | inside the same shell: **handshake replay** as a client / network path / server sequence diagram, built from the session's redacted `transcript` and the TLS `client_flow` / `server_flow`. Tampering is drawn at the path lane: a stripped offer morphs `STARTTLS` into `XXXXXXXX`, and a swapped certificate morphs "CA cert" into "self-signed". A channel badge moves from cleartext to negotiating to encrypted (or stripped). Each step has a plain-language explanation in the right column; below it, tabs for Findings (each lights up at the step that triggers it), Why this score and Connection |

The replay data is metadata-only too. `MailSession.transcript` keeps commands and replies, but
replaces every password, SASL response and token with `•••••• (secret redacted)` and every message
body with a byte count. `test_transcript_is_redacted_and_ordered` enforces this.

API:

- `GET /api/reports` lists recent analyses; `GET /api/report/<id>` returns one as JSON.
- `POST /api/analyze` takes a multipart `file` and returns the JSON report with its `id` (`?ml=0` to skip ML).
- `POST /api/demo` generates the demo captures once, learns the clean baseline week, then analyses the demo capture.
- `GET /report/<id>` exports the self-contained HTML report; `/report/<id>.json` downloads the JSON.
- `POST /analyze` is the no-JavaScript fallback: an upload form that redirects to the HTML report.

Uploads go to a temp file, are analysed, and are **deleted immediately**. Only the metadata-only
report is kept, in memory. The server binds to `127.0.0.1` by default; the Dockerfile binds
`0.0.0.0` inside the container. Upload size is capped at 256 MB.

## The Certificates section

The dashboard's fifth section answers "what certificates are on this network, and
does each one hold up" — a question the findings list answers only obliquely,
because a certificate defect arrives there once per session rather than once per
certificate.

It deduplicates by SHA-256 leaf fingerprint, so the unit of the table is the
**certificate**, not the session: eleven sessions to one endpoint presenting the
same leaf are one row, seen 11×. That matches what an operator acts on — they
rotate a certificate, not a session.

Each row expands into the verification checklist, one line per check the
analyser actually performed, each marked pass / fail / warning / not-checked:

| Check | Source |
|---|---|
| Validity window | judged at **capture time**, not analysis time |
| Hostname | RFC 6125 — wildcard covers one label, SAN supersedes CN |
| Chain links | does each certificate really sign the one before it |
| Trust path | path validation against the trust store |
| Key strength | type and size |
| Signature algorithm | across the whole chain, excluding self-signed roots |
| Usage constraints | BasicConstraints, EKU serverAuth |
| Certificate Transparency | embedded SCTs — absence means it was never publicly logged |
| Revocation | reported as not checked, with the reason |

Showing the checks that *passed* matters as much as the failures: it is the
difference between a verdict and a measurement, and it is what lets a reviewer
see that "Verified" was earned rather than defaulted to.

Two presentation rules the section follows:

- **The row verdict names the most informative failure, not the first one.**
  Trust-path failure is the commonest outcome and the least diagnostic — a
  private CA trips it — so it is ranked last. A 1024-bit key or an expired
  certificate is what the operator needs to read off the row, with `+N` for the
  remaining failures.
- **Unobservable is its own category**, never folded into pass or fail. A
  TLS 1.3 session contributes to the "not observable" count with the reason
  attached, and no certificate is inferred for it.

## The Capture section

The whole PCAP, one row per TCP segment: frame number, time, endpoints,
protocol, server port, flags, payload length, an Info summary and the session
the frame belongs to. Frame numbers here are the same identity the replay steps
point at, so "this protocol step is these packets" is navigable both ways.

Three columns need explaining, because each encodes a decision:

**PROTO is what the frame's own bytes are, not what the conversation is for.** A
bare ACK is TCP even in an SMTP session. Once a session switches to TLS every
later frame is TLS — including segments that continue a record started earlier
and so carry no record header of their own. Sniffing the first five bytes would
label those as the mail protocol; the label is taken from the session's TLS
offset instead. And a *late retransmission of pre-TLS bytes* is still SMTP,
because the label describes the bytes, not the arrival time.

**PORT is the conversation's server port**, not the port of that one frame, so a
row's port stays the same in both directions and the column can be scanned for
25 / 587 / 465 / 143 / 993 / 110 / 995.

**TIME switches base with the capture.** Seconds since the first frame reads well
for a single capture. A merged corpus spans years, where the same rendering
produces `37032:36:16.9` and tells nobody anything, so a capture spanning more
than a day defaults to wall-clock UTC; the header chip switches either way and
every cell carries the full timestamp as a tooltip.

Info is redacted to the same standard as the transcript: the verb and SASL
mechanism are kept, the argument is dropped, and a bare base64 continuation is
replaced outright. A packet list printing `PASS hunter2` would undo the promise
the rest of the tool makes.

## The "How it scores" section

Rendered from a `scoring` block the analyser emits with every report — severity
weights, penalties, grade bands, exposure factors, the four formulas, the rule
catalogue with a count of what fired in this capture, the model's feature names,
and the list of things deliberately not scored. It is generated from the
constants in `scoring.py` and `rules.py` rather than restated, so the page
cannot drift away from the code: change a penalty and the page changes with it.

That matters beyond tidiness. A posture score is a judgement about somebody's
infrastructure; if the person reading it cannot see the arithmetic that produced
it, they have to take it on trust, and the tool's whole argument is that trust
without measurement is the problem.

## Capture-level floors

Three facts bound a grade rather than being averaged into it, because each one
invalidates the summary a grade is meant to give:

| Floor | Cap | Why |
|---|---|---|
| Any critical finding | F (59) | A passing grade beside a leaked credential reads as "broadly fine" |
| Message content crossed unencrypted | **D (60)** | The tool's central claim; a capture that demonstrates it cannot be a pass |
| Some TLS session had no observable certificate | A (95) | A perfect score would assert verification that never ran |

The middle one was added after an assessment found that **56 of 93 corpus
captures transmitted mail entirely in cleartext and graded A or B** — the worst
relaying 400 KB of readable mail for a score of 90. The detection was never
wrong; `SMS-DATA-001` fired every time. The pricing was: the word "relay"
discounted the same fact three times over, in the rule severity, in the
exposure factor and again in the private-to-private multiplier.

The severity demotion has been removed — `SMS-DATA-001` is **high** wherever it
fires — and the relay discount now applies once, in `exposure_for()`, which is
where contextual weighting belongs. After the change, 54 corpus captures moved
from A to D.

### How floors combine

Floors are evaluated together, not applied one after another, and two rules keep
the report honest about which one decided the grade:

- **Only the strictest floor is binding.** A capture with a critical finding and
  cleartext mail is capped at F by the critical rule; the confidentiality floor
  still applies as a `min()` but did not set the grade, so it is reported as
  *"on its own that would cap the capture at D"* rather than claiming the cap.
  Sequential application printed both as though each had decided the outcome,
  which produced "capping the capture at D" beside a grade of F.
- **A floor above the earned score is not reported at all.** When penalties have
  already taken a capture to 0, nothing was capped, and saying otherwise
  misattributes the grade. `posture.earned_score` carries the pre-floor value so
  the two can always be compared.

`posture.floors` is a list of `{cap, grade, reason, binding}`; `floor_reasons`
renders them as sentences. The binding floor is shown as a red banner above the
grade and named in the posture card; a non-binding one is amber.

## Coverage caveats

A report that silently covers part of its input is the same unearned assertion
the project exists to criticise. Three caveats are now surfaced on the Overview
and in the exported HTML:

- **Read notes** (`meta.read.notes`) — a truncated or corrupt file. Previously
  the analyser recorded that it had read 2.5% of a concatenated capture, and
  then displayed a confident report over the rest.
- **One-sided sessions** — identified from the client's verbs because the server
  side was missing. Credential and content findings still apply; negotiation
  findings cannot, and the banner says so.
- **Unclassified mail-port flows** (`meta.unclassified_mail_flows`) — any flow
  on 25/465/587/143/993/110/995 that could not be parsed, with its byte counts
  and the reason. A flow that vanishes before analysis is indistinguishable from
  one that was never there, which is the worst failure mode a scanner can have.

## Colour in the dashboard

Colour carries four different jobs, and mixing them is how a dashboard becomes
decorative noise. They are kept apart:

| Job | Palette | Where |
|---|---|---|
| **Severity** (state) | status: critical / high / medium / low / info | Chips, finding stripes, severity bar, risk meters |
| **Identity** (category) | categorical hues, fixed order | Protocol: SMTP blue, IMAP orange, POP3 aqua |
| **Posture** (ordinal) | grade band tint | Posture card ground, grade badge, ring |
| **Wayfinding** (chrome) | one hue per section | Sidebar icons, active rail, card headings |

Two rules make that hold:

**Status colours are reserved.** A protocol chip tinted with `--high` would read
as a verdict. The three protocols previously shared one amber pill, so the column
carried no information at all; they now use the first three slots of a
categorical palette whose ordering is the colour-vision-deficiency safety
mechanism, not a cosmetic choice. Validated at *all pairs* in both themes —
worst CVD ΔE 9.2 light / 9.4 dark, worst normal-vision ΔE 24.0 / 20.9 — and
every chip shows its protocol name, so hue is never the only channel.

**Text wears text tokens.** Values, labels and legends stay in ink colours; a
coloured mark beside them carries the identity. Where a tint does sit behind
text, the ink is the dark step of the same hue and clears 4.5:1 against it
(measured: 5.6–7.0 light, 7.3–8.5 dark).

The dark steps are selected for the dark surface, not an automatic inversion of
the light ones — the same eight hues, re-stepped and re-validated.
