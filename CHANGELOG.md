# MAdES Specification — Changelog

All notable changes to the MAdES specification. The reference implementation versions track this independently in `reference/package.json`.

Versioning follows [SemVer](https://semver.org) for the spec:
- **MAJOR** — breaking change to the wire format (existing signed documents may not verify)
- **MINOR** — additive feature (new optional fields / blocks; existing documents still verify)
- **PATCH** — clarification, typo fix, non-normative editorial change

---

## v1.8 — 2026-08-20

**The stability release: the spec becomes dossier-grade and stops moving without cause.**

Five releases in one week was first contact — three implementations went live
against this text at once, and every divergence was repaired here rather than in
one of them. This release ends that phase: §0.2 declares the spec stable —
normative change requires a demonstrated defect, improvements queue under Open
decisions. It also states the algorithm-agility policy — the §c.1
allowlist gains entries in MINOR releases and never loses one; aging algorithms
are marked *not for new signatures* and existing documents are carried by
archive timestamps (§a.13).

### The vectors are now actually published (`vectors/`)

The spec referenced "published v4/v5 vectors" that lived in one vendor's product
tree, where no second implementer could find them — and §e described five v5
category cases that were never built at all. A specification pointing at
evidence its publication does not carry is asserting, not showing. Now in this
repository, read by `reference/test/vectors.test.mjs` on every run:
canonicalisation (13 cases, new), boundary (12 cases, new, both directions),
v4 (4 signed documents), v5 (1 real ceremony), archive layers (5 cases). The
missing category five-pack is named honestly under Open decisions instead of
described as existing.

### One new normative rule (§a.14)

*"Its last block"* means the last block of **either** kind: a boundary check
MUST recognise both `<!-- mades-sig` and `<!-- mades-archive-ts`, even without
processing layers. One implementation read a valid archive layer as appended
bytes within a day of implementing §a.14 — the exact false accusation §a.5
forbids, produced by the anti-tampering section itself. A boundary vector pins
it.

### Structure and neutrality

- **BCP 14 conformance language** (§0.1) — the MUSTs finally say whose MUSTs
  they are.
- **The embedded changelog left the header.** It duplicated this file, had
  drifted (v1.6/v1.7 missing), and was ordered v1.2 → v1.1 → v1.0 → v1.5. In
  its place: a normative **block-version table** — the one thing a verifier
  actually needs from history. v0.4–v1.2 entries are backfilled below.
- **References** section (normative/informative split) and **Annex B**: relation
  to OpenPGP cleartext, C2PA (which can embed in Markdown since 2.4 and answers
  provenance, not commitment), the ETSI AdES family, W3C VC and detached-signing
  tools.
- **§h roll-out** no longer lists shipped work (archive timestamps) as future
  plans, and no longer says "publish v1.2" as an ambition.
- Vendor-extension example is now `com.example.audit` (RFC 2606); the header no
  longer names a product as the reference implementation — it is in this
  repository; Open decisions no longer cites one vendor's internal ticket
  numbers.

Nothing in this release changes any signing input, any canonicalisation or any
verdict on existing documents. Block version stays `5`.

---

## v1.7 — 2026-08-19

**The document boundary accepts a line ending, not only a line feed.**

### What changed (§a.14)

v1.6 said a conforming document ends at its last block "with at most one trailing
line feed". Three independent implementations read that exactly as written, and
rejected `-->\r\n`.

That is defensible from the words and wrong from the format. §a.2 normalises
`CRLF` and a lone `CR` **on purpose**, with its own justification in the spec:

> Rules 1 and 2 are what make a document authored on Windows verify on Linux.
> Without them the failure is silent and has no diagnostic.

A format that goes to that trouble for the content, and then rejects the same
editor at the boundary, holds two opposite positions at once. A user opens a valid
signed document in a Windows editor, saves it without changing a character, and it
stops conforming.

**The word was too narrow, not the rule.** §a.14 now reads *one trailing line
ending* — `LF`, `CRLF` or a lone `CR`, the same three §a.2 already recognises.

### What did not change

- **Two endings is still non-conforming**, in any spelling: `\n\n`, `\r\n\r\n`,
  `\n\r\n`. A blank line is where appended text starts.
- **Trailing whitespace is still non-conforming.** Spaces and tabs are not line
  endings, and the point of the boundary is that it is visible in the bytes.
- Everything else in §a.14: still `invalid` and not a warning, still no change to
  any signing input, still block `version: 5`.

### Why this is MINOR and not PATCH

It reads like a clarification and it is not one. A verifier that rejects `\r\n`
was conforming under v1.6 and is not under v1.7 — behaviour changes, so the
version does. Nothing that verified stops verifying: this only makes more
documents conforming, never fewer.

### Credit

Raised by the **Vecto Sign** implementation on 2026-08-19, the same day v1.6
shipped, as *"the case that hits a real user"*. They had already aligned their
verifier with v1.6 as written, measured the divergence against the reference
implementation, and reported it rather than quietly loosening their own side.
That all three implementations agreed on the wrong answer is exactly why the fix
belongs in the specification.

---

## v1.6 — 2026-08-19

**A signed document now ends where its signature ends.**

### The document boundary (§a.14)

A signature covers the content **preceding** its block. There is no byte range,
no length field and no content digest, so nothing in a block says how long the
document was when it was signed. Text appended after the last block is therefore
outside every signature by construction — every signature still verifies, and a
clause nobody agreed to sits at the bottom of the file.

Until this version nothing in the spec said a reader had to look.

From v1.6: **a conforming document ends at the closing `-->` of its last block**,
with at most one trailing line feed. Anything else is non-conforming, and a
verifier **MUST** report it as `invalid` — not as a warning next to a valid
signature. A warning beside a green result reads as a detail; it is not one, and
leaving the severity to the implementation means the property cannot be held
against a counterparty.

### Why not a signed length or digest

That is the first remedy anyone proposes, and it does not work. Appended bytes
sit *after* the block, so they are not part of the canonicalised content such a
field would describe: the digest still matches, the length still matches, the
clause is still there. A length over the *whole* document is impossible — the
block contains the signature, so it cannot be inside its own digest — and with
sequential signatures the problem simply moves, because block N+1 covers up to
itself and after the last block there is again nothing.

Specifying that field would have shipped a signed value that looks as though it
covers the document and does not. There is a test in the reference suite that
pins this down: `canonicalize()` returns byte-identical output before and after
appending.

### What it costs

**Nothing that is already signed.** No signing input, no canonicalisation and no
field changed. The block version stays `5`; every signature made under v1.5 or
earlier remains valid under v1.6 and is simply read more strictly. The check
needs no keys — whether a document ends at its last block is visible in the bytes.

### eIDAS Article 26

Of the four requirements in Article 26, (d) — any subsequent change to the signed
data is detectable — was the one this format did not meet. The gap was never in
the cryptography or the PKI beneath it; it was that the format placed no limit on
what could follow the signature. Both neighbouring formats already close it, and
neither needed a new field: PAdES covers the entire file, XAdES carries a
`ds:Reference` per data object.

### Reference implementation

- `trailingContent(content)` in `mades-canon.mjs` — the bytes after the last
  block, or `''`.
- `mades-verify.mjs` reports them **first** and as a failure (exit 1), before any
  per-block result.
- Six tests in `reference/test/`, including the two that state the finding rather
  than the fix: the signing input is unchanged by appending, and so is the
  canonicalised content.

### The examples had to move

`examples/01` through `04` carried their "What this example demonstrates" section
**after** the block. Under §a.14 that makes them non-conforming — the first thing
an implementer reads would have been a violation of the rule two sections up. The
explanation now sits before the block and the files end at their closing `-->`.

Examples 05, 06 and 07 already ended at the block and are untouched.

### Credit

Raised by the **Vecto Sign** implementation on 2026-08-19, out of an independent
conformity assessment, measured on both a v1.5 reference run and their own
verifier before being reported. The remedy adopted here is not the one that was
proposed — see above — but the finding was exact, and the proposed alternative
would have shipped a field that gave false comfort.

The README also carried `v1.4` in its header since the v1.5 release; corrected
here. That is the second copy this project keeps proving it should not have.

---

## v1.5 — 2026-08-19

**A signature can name the files that ride along, and a document can be kept
verifiable after its algorithms age.**

### `covers` (§a.12)

An act is often more than one file — a contract with annexes, a report with its
data. Only the text is signed, and until now nothing stopped an annex being
exchanged afterwards without a single value in the block changing. That gap is
not shared by the neighbouring formats: XAdES carries one `ds:Reference` per data
object, and PAdES covers the whole file including anything embedded in it.

```
covers:
  - sha256:9f2c1d40 application/pdf annex-b-pricing.pdf
  - sha256:41ab77e2 image/png floor plan, ground level.png
```

One entry per line: digest, media type, then the name as the remainder — which is
what lets a name carry spaces without a quoting rule, and what keeps the digest
from being pushed out of view by a long name. **The shape follows from the field
syntax** (§a.1 has a list of scalars and a map of scalars; a list of maps is not
expressible), not from preference.

Order is preserved and MUST NOT be sorted: the signer saw a list in an order, and
that order is part of what they agreed to.

A verifier reports an entry it was not given the file for as **asserted but
unverified**, and a mismatching digest as **coverage broken** — never as an
invalid signature. The signature is intact; what it covered is not what was
presented. That is the third place this specification separates *what I cannot
tell* from *this was tampered with*.

The PAdES equivalent is a SHOULD, noted as expected to become a MUST.

### `mades-archive-ts` (§a.13) — and the reserved field is retired

`archive-timestamp` was reserved as a **field** inside a signature block, with the
open question of *whether it covers the block or the whole document*. It is now
its own block and covers the whole document, including every preceding block. A
field in one signature cannot cover the other signatures, and certainly not those
appended after it — which is why both neighbours resolved it the same way
(PAdES' document-time-stamp, CAdES' archive-time-stamp).

**The open question answered itself once the input was written down.** §a.2
already canonicalises everything up to a block, signature blocks included — that
is what makes a counter-signature cover the signatures beneath it. An archive
timestamp takes exactly that input. There is no second canonicalisation rule, and
renewal is an ordinary append rather than an exception to §b.

It asserts nothing about a person: no certificate, no signer, no consent, no
credential. It carries no `commitment` and no `signer`.

Reading is outside-in. A signature beneath a valid layer is **valid as of that
layer**, even where its algorithm would not be chosen today — reporting it as
doubtful discards the only thing the layer establishes. A byte changed beneath a
layer breaks **that layer**, not the signature under it.

### MINOR, with one behavioural note

No existing signed document verifies differently: `covers` is additive, and
`archive-timestamp` was reserved rather than in use.

The exception, and it is a fix rather than a rule change: the reference
implementation silently discarded a line that could not be placed in an
already-opened container — an indented key after a list item, or a list item
after a map key. Both matched their pattern, both failed the container guard, and
both vanished without reaching `unparsed`. A block carrying such a line therefore
received a verdict over content the reader had only partly read. §a.5 already
required `unsupported` there; the implementation now does what the text said.
Blocks affected are malformed ones, and they move from a verdict to no verdict.

Found while drafting §a.12, whose first draft was a nested list of maps — which is
also why `covers` puts one entry on one line.

---

## v1.4 — 2026-08-14

**A document about MAdES can now be signed with MAdES.**

Block location gains two normative rules (§a.1). The opening marker counts only
**at the start of a line**, and never **inside a fenced code block** — CommonMark's
fence rule, so what a verifier skips is exactly what a reader sees rendered as
code.

**MINOR, not MAJOR: no existing signed document verifies differently.** A written
block always begins its own line and never sits inside a fence. Checked rather
than assumed — the real signed document in `examples/` verifies byte-identically
before and after, and the reference suite went from 19 tests to 26 with one
deliberate failure: the test that pinned the old behaviour, written to flip on
exactly this change.

Before these rules, block location was a raw byte scan. It could not tell a
signature from a sentence describing one, so any document *about* the format
produced a second block containing no signature, and a verifier reported over a
sound document that it could not be checked. **A false failure, in a signature
format.** Those cost precisely what false successes cost (§d), and this one hit
the documents most likely to be read by someone deciding whether to trust the
format at all.

Both rules are byte-level and need no Markdown parser. That is the constraint
that shaped them: an implementation that must *understand* a document to find
its signature is one that disagrees with the next implementation about where the
signature was — and disagreement, here, reads to a user as tampering.

**New example: `06-signing-a-document-about-signing.md`**, signed by a real
service with a real certificate and an RFC 3161 timestamp. It quotes the opening
marker in full four times and carries a complete block inside a fence — under
the old byte scan it yielded two blocks, and the verifier reported over a sound
document that it could not be checked. It now yields one, and verifies. The
reference suite asserts both, so the rule is pinned to a real artefact rather
than to a fixture built to pass.

`examples/05-a-real-signed-document.md` still describes the limitation in its
prose, and stays that way. It was signed before the fix; rewriting a signed
document so it says something more flattering is the exact thing this format
exists to prevent. `06` supersedes it editorially — in prose that falls under
its own signature, not through the `revision`/`supersedes` chain of §a.7, which
means something narrower and stronger than what is true between two separate
documents.

---

## v1.3 — 2026-08-14

First publication since v0.3. The specification moved a long way in between and
those drafts were never published, so this entry describes the whole distance
rather than pretending there were releases.

**BREAKING — the signature block is an HTML comment, not a fenced block.**

```
was   ~~~mades-sig … ~~~
is    <!-- mades-sig … -->
```

A fence *renders*; that is its definition. Every reader who opened a signed file
in an ordinary viewer therefore saw kilobytes of base64 where the document
should have been. An HTML comment is hidden by CommonMark renderers, stripped by
GitHub, hidden in Obsidian's reading view and dropped by Pandoc — and fully
present in the source. Invisible in view, present in code.

One normative consequence: the block body must not contain `--`, because an HTML
comment ends at the first one. A block containing it is truncated and the
document reads as *unsigned* rather than invalid — silent and total, so
implementations must check before emitting.

**Block versions 2 through 5.** The block carries its own `version`, and a block
is read under the rules of the version it declares. Existing documents keep
verifying; a reader never applies newer rules to an older block.

- **v4 — parsing is total, and every comment line is signed.** Before this, a
  bare line inside the block was silently appended to the previous field or
  dropped, and a second comment line fell outside the signing input entirely.
  Both were measured on the reference implementation. The consequence was not
  academic: a line reading `# WARNING: this contract has been declared void`
  could be added to a signed block without breaking the signature — and that
  block is exactly what a reader sees in a plain text editor.
- **v5 — `signer-kind`.** Mandatory, closed and binary (`human` | `automated`),
  inside the signed fields, and mirrored by the certificate so a verifier can
  hold the two against each other. Markdown is where humans and machines take
  turns; this is the question MAdES can answer and PAdES never had to ask.

**Cryptography grew up.** Personal signatures are asymmetric, always. HMAC is no
longer a baseline for signatures — it survives as *machine attestation*, which
is a different claim and is named differently. Added: short-lived certificates
with the timestamp as what makes a signature outlive its key, trust anchoring,
container formats, and key distribution.

**New fields.** `appearance`, `lang`, `represents`, `revision`/`supersedes`,
`format`, `key-id`, `certificate-chain`, `timestamp`, `signer-kind`,
`automation`.

**Vendor extensions are namespaced, and the `x-` prefix is gone.**

```
was   x-vecto-void: true
is    build.vecto.void: true
```

A vendor field carries a reverse-DNS namespace the vendor demonstrably controls.
No registry and no institution: the party that controls the domain controls the
namespace. A field whose name carries no recognisable namespace is
`unsupported`. [RFC 6648](https://www.rfc-editor.org/rfc/rfc6648.txt) (BCP 178)
recommends against the `X-` convention and forbids stipulating that such a
prefix means "unstandardised" — unstandardised parameters become de facto
standards anyway, and the deployed world then carries both spellings forever.

**A verifier must show signed fields it does not understand** (§d, Level 4).
With the namespace, and without inventing a meaning. This is the mirror image of
the gap v4 closed: there a signed field could disappear, here it could be
faithfully preserved and never read. Measured on two independent
implementations, both of which preserved unknown fields correctly and showed
none of them.

Both of the last two were raised by the Vecto Sign implementation.

---

## v1.2 — 2026-08-12

**Who signed: a person, or a machine.** Block `version: 5` adds `signer-kind`
(required, closed: `human`/`automated`) with optional `automation`; the category
is anchored in the certificate and a mismatch is `invalid` (§a.11). One
invariant carries it: *`human` can only be established by a human signature* —
an unrecognised value degrades to not-human, never to `human`. Machine
attestations and automated signatures are distinct and must not be presented as
one (§c.2). Pre-v5 blocks report "unspecified (pre-v5)".

## v1.1 — 2026-08-11

**The block says what it signs, and signs what it says.** Block `version: 4`:
parsing is total (comment, blank or well-formed field — no fourth category;
anything else is `unsupported`, §a.1/§a.5), and every comment line and vendor
field is inside the signing input (§a.3). Before this, a warning line could sit
*inside* a signed block without breaking the signature, and a vendor field was
signed but never written back — measured on the reference implementation.

## v1.0 — 2026-08-08

**The signature block becomes invisible, and the signature becomes visible.**
Block `version: 3`: the block moves from a fenced code block to an HTML comment
(hidden by conforming renderers, visible in source), and a signed SVG appearance
— the seal — becomes the visible half (§a.8), deliberately the PDF anatomy.
Also: `lang` (§a.9) and the normative `--` ban (§a.1).

## v0.9 — v0.4 (2026-08-07 and earlier)

Condensed: **v0.9** corrected "B-T is the ceiling" — B-LTA is reachable with
short-lived certificates because archive timestamps rest on the timestamp chain,
not revocation data (§g); nonce comparison made normative (§c.5). **v0.8** trust
is a property of the verifier, not the document (§c.4). **v0.7** exclusion rule
generalised (§a.3). **v0.6** signing input covers the block's own metadata;
`represents`; `revision`/`supersedes`. **v0.4** asymmetric-only personal
signatures; HMAC demoted to machine attestation.

## v0.3 — 2026-04-28

**Added — staged workflow support in `mades-sig-fields`:**

The optional `~~~mades-sig-fields` declaration block now supports `stages:` for workflow orchestration. Each stage groups fields with a `mode` (`serial` | `parallel`) and an optional `depends_on` reference to a prior stage. This makes MAdES expressive enough for complex document-signing workflows (e.g. "first 2 authors sign serially, then 4 reviewers sign in parallel, then 1 final approver"). The format declares the workflow; the orchestration engine that drives signers through it remains a separate concern.

**Backwards-compatible** with v0.2 documents: a `mades-sig-fields` block without `stages:` is treated as a single implicit stage with `mode: parallel`.

Resolves DEC-3 (multi-signer model) and DEC-6 (workflow expressivity).

## v0.2 — 2026-04-28 (internal)

**Added:**
- Vendor-neutral renaming: `~~~vecto-sig` → `~~~mades-sig`, `~~~vecto-sig-fields` → `~~~mades-sig-fields`. Vendor extensions moved to `x-` field-prefix namespace.
- 4-tier algorithm support: `hmac-sha256` (Basic), `ed25519` (Advanced), `ecdsa-p256` (Advanced/Qualified), `rsa-pss-sha256` (Qualified).
- Three-level visual representation model: YAML-comment header (Level 1, MUST), renderer-aware badge (Level 2, SHOULD), inline `~~~mades-visual` companion fence (Level 3, optional).
- eIDAS profile tiers: MAdES-Basic, MAdES-Advanced, MAdES-Qualified.
- Provenance & credits section.

## v0.1 — 2026-04-28 (initial concept)

Initial sketch of the inline-signature concept based on a fenced code block trailing the document content. Single-signer-only; no workflow support; tied to vendor-specific naming. Internal ideation, never published.

---

## Open decisions (tracked in spec)

The current draft has open architectural decisions documented in SPEC.md § g (Open decisions). These will likely drive v0.4+ revisions:

- DEC-7 (eIDAS compliance level + algorithm subset)
- DEC-8 (Key distribution & rotation strategy)
- DEC-9 (Migration path for existing single-format signing mechanisms)
- DEC-10 (GUI validation status display)

Resolutions to these will inform the next minor or major bump.
