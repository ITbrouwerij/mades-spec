> **Status:** Specification · **Version:** 1.4 · **Block `version: 5`** · **Reference implementation:** Vecto OS (ITbrouwerij)
>
> **This is an open specification. It is not the documentation of any one
> product.** MAdES is authored and published by Jan Smets (ITbrouwerij) so that
> anyone can implement it. Vecto Proof is *a* consumer of this specification —
> the first one, and the source of the reference implementation — but it holds
> no privileged position in what follows.
>
> The practical rule for anyone editing this document: it describes the
> **format**, not how a product built on it chooses to work. How a given service
> renders a document to paper, when it stores or timestamps that rendering, how
> it combines MAdES with PAdES, what it charges for a signature — none of that
> belongs here. An implementation detail that leaks into a specification is
> ballast for every other implementer, and a specification carrying one
> vendor's habits has stopped being a standard.
>
> A conforming implementation must be able to succeed knowing nothing about
> Vecto.
>
> MAdES embeds cryptographic signatures directly inside Markdown files, so a
> `.md` file carries its own integrity, authenticity and non-repudiation with no
> companion `.sig` and no container format. Goal: a signed document that
> survives copy-paste, renders normally in any Markdown viewer, and verifies
> offline from the file alone.
>
> **v1.2 changelog (2026-08-12) — who signed: a person, or a machine.** A reader
> can no longer tell whether a document was reasoned about by a human or
> produced in one pass by a model. Markdown is the format in which humans and
> machines alternate, so this is the question MAdES is uniquely placed to
> answer — and it is why MAdES is more than PAdES-for-text.
>
> `version: 5` adds **`signer-kind`** (§a.11): required, closed, `human` or
> `automated`, with an optional open `automation` refinement for *what kind* of
> machine. One invariant carries the whole design:
>
> > **`human` can only be established by a human signature.** An unrecognised
> > value degrades to *not human* — never to `human`.
>
> A self-declared field protects nothing, so the category is **anchored in the
> certificate** and the verifier checks that both agree (§a.11.2); a mismatch is
> `invalid`. Certificates MAY additionally constrain which commitments they can
> carry, which is what lets a deployment issue machine certificates that can fix
> a version but can never express agreement (§a.11.3).
>
> Also clarified: **a machine attestation (§c.2) and an automated signature are
> not the same thing.** Both are `automated`; only one is a signature. §c.2
> carries the table, because an implementer reading it in isolation would
> otherwise conflate them.
>
> Blocks ≤ v4 report the category as **"unspecified (pre-v5)"** — `unsupported`
> is not `invalid`, as always.
>
> **v1.1 (2026-08-10) — the block says what it signs, and signs what it says.**
> Two defects, found in opposite directions, both closed by one principle:
> *parsing is total, and what is signed is written.*
>
> Measured on the reference implementation before the change:
>
> ```
> a second comment line in the block    NOT covered by the signature
> a bare text line in the block         NOT covered
> a vendor field (outside the writer's list)   signed, NOT written back
> ```
>
> The first means `# WARNING: this contract has been declared void` could sit
> **inside** a signature block without breaking the signature — and that block
> is what a reader sees in a plain text editor, where such a line reads as part
> of the signature. The third made any block carrying a vendor extension
> permanently unverifiable: the field went into the digest and never into the
> file.
>
> `version: 4` states both rules normatively (§a.1, §a.3) and adds a verifier
> obligation: a block containing a line the reader cannot parse is
> **`unsupported`**, never `invalid` (§a.5). The distinction is the whole point —
> *we cannot judge this* is not *someone tampered with this*.
>
> **v2 and v3 blocks are read under the rules of THEIR version.** The `version`
> field decides, so existing signatures do not break. Interoperability vectors
> for v4 are published (§e).
>
> **v1.0 (2026-08-07) — the signature block becomes invisible, and the
> signature becomes visible.** Two changes, and they are the same change seen
> from two sides.
>
> A fenced code block cannot be hidden: rendering as a code block is what a
> fence *means*. Every viewer that does not implement MAdES therefore showed
> readers a wall of base64 where a signature should be. **The block moves to an
> HTML comment** (§a.1), which every conforming renderer hides and which remains
> plainly visible in the source. In its place, **a visible SVG appearance** —
> the seal — is embedded as a data-URI image inside the signed content (§a.8).
>
> This is deliberately the PDF anatomy: an appearance you can see, a signature
> you cannot, and validity reported by the verifier rather than claimed by the
> picture. Because the appearance sits inside the signing input, swapping it
> breaks the signature; that is what makes it safe to render at all.
>
> `version: 3`. v2 signatures do not verify under v3 rules and are not expected
> to. Also new: `lang` (§a.9), and a normative ban on `--` inside the block
> (§a.1) — it would close the comment early and silently turn a signed document
> into an unsigned one.
>
> **v0.9** — corrected "B-T is the ceiling": B-LT is unreachable for short-lived
> certificates but **B-LTA is not**, since archive timestamps rest on the
> timestamp chain rather than on revocation data (§g). Nonce comparison made
> normative (§c.5).
> **v0.8** — trust is a property of the verifier, not of the document (§c.4).
> **v0.7** — exclusion rule generalised (§a.3).
> **v0.6** — signing input covers the block's own metadata; `represents`;
> `revision`/`supersedes`.
> **v0.4** — asymmetric-only personal signatures; HMAC demoted to a machine
> attestation.

## 0. Scope &amp; non-goals

**In scope:** the wire-format, canonicalisation, the signing input, the visible
appearance, the multi-signer model, commitment types, the signer category,
representation binding, revision chaining, and the certificate &amp; trust model.

**Out of scope:** binary attachments inside the block, encryption of the signed
payload, and the orchestration engine — the file is the canonical state.

## a. Specification &amp; Format

### a.1 The signature block

A MAdES signature is an **HTML comment** opening with `<!-- mades-sig`, appearing
AFTER the content it covers. The body is the same field syntax as v2.

```markdown
<!-- mades-sig
# ✓ Signed by alice@example.com — approval — human — 2026-08-12
version: 5
algorithm: ed25519
signer: alice@example.com
signer-kind: human
commitment: approval
signed-at: 2026-08-12T11:15:30+02:00
lang: nl
appearance:
  mode: signature
  digest: sha256:6f1c…
certificate-chain:
  - MIIB…
  - MIIC…
timestamp: MIAGCSqGSIb3…
signature: 7a3f…8b2c
-->
```

**Why a comment and not a fence.** A fenced block renders as visible code in
every conforming Markdown renderer — that is its definition. Readers opening a
signed file in an unmodified viewer therefore saw kilobytes of base64 instead of
a document. An HTML comment is hidden by CommonMark renderers (passed through as
an HTML block, displayed by nothing), stripped by GitHub, hidden in Obsidian's
reading view, and dropped by Pandoc on export — while remaining fully visible in
the source. Invisible in view, present in code, which is where a signature
belongs.

> **NORMATIVE (v1.4) — where a block may be found.** An implementation MUST
> recognise the opening marker **only at the start of a line**, and MUST NOT
> recognise it **inside a fenced code block**. A fence opens with three or more
> backticks or tildes, indented by at most three spaces, and closes with at
> least as many of the **same** character and nothing else on the line. This is
> CommonMark's rule, so what a verifier skips is exactly what a reader sees
> rendered as code — and both halves matter. Close a fence on any marker and a
> ` ``` ` inside a `~~~~` region ends it early; ignore the indentation
> allowance and a fence indented by two spaces stays invisible to the scanner
> while still rendering as code. Either way the hole reopens in a corner.
>
> The marker itself is held to the stricter rule: **column zero, no
> indentation.** An indented marker is an indented code block, which renders as
> code too.
>
> Both rules are byte-level and require no Markdown parser. That is deliberate:
> an implementation that must *understand* the document to find the signature is
> an implementation that disagrees with the next one about where the signature
> was, and disagreement here reads as tampering.
>
> **This is a compatibility-preserving clarification, not a format change.** A
> written block always begins its own line and never sits inside a fence, so no
> document that verified under v1.3 verifies differently under v1.4 — verified on
> the reference implementation against a real signed document.
>
> Without these rules, block location is a raw byte scan that cannot tell a
> signature from a sentence describing one. Any document *about* MAdES — a
> tutorial, an issue, this specification — produced a second block with no
> signature in it, and a verifier reported over a sound document that it could
> not be checked. **A specification could not be signed with the thing it
> specifies**, which is a poor advertisement for a signature format and, more
> seriously, a false failure. Those cost exactly what false successes cost (§d).

> **NORMATIVE — the block body MUST NOT contain `--`.** An HTML comment ends at
> the first `--`, so a block containing one is truncated: the closing `-->` is
> never reached, the block does not parse, and the document reads as **unsigned**
> rather than as invalid. Base64 has no hyphen and field names carry single ones,
> so this is satisfied by construction — implementations MUST still check before
> emitting, because the failure is silent and total.

> **NORMATIVE (v4) — parsing is total.** Every line inside the block MUST be one
> of: a comment line (starting with `#`), a blank line, or a well-formed field
> (including its indented list items and sub-keys). **There is no fourth
> category.** A block containing anything else MUST be reported as
> `unsupported` (§a.5).
>
> Before v4, a bare text line was silently appended to the preceding field's
> value or dropped, and a second comment line fell outside the signing input
> entirely. Both were measured on the reference implementation. The consequence
> was not academic: a line reading `# WARNING: this contract has been declared
> void` could be added to a signed block without breaking the signature, and
> that block is exactly what a reader sees in a plain text editor.

**Required fields:** `version` (`5`) · `algorithm` · `signer` · `signer-kind`
(§a.11, v5) · `signed-at` (RFC 3339) · `signature`.

**Optional:** `commitment` (§a.4, default `approval`) · `automation` (§a.11) ·
`lang` (§a.9) · `appearance` (§a.8) · `certificate-chain` (base64 DER,
signer-first) · `timestamp` (§c.5) · `represents` (§a.6) · `revision` +
`supersedes` (§a.7) · `format` (§c.6) · `key-id` (§c.7) · `field` (§b).

**Vendor extensions** carry a namespace the vendor demonstrably controls,
written as a reverse-DNS name: `build.vecto.void`. They are part of the signing
input and MUST be preserved when re-encoding, but MUST NOT be relied on for
validity.

Registration is not required and there is no registry. A DNS name is
self-bearing — the party that controls the domain controls the namespace — and
where there is doubt about a name's meaning, there is an owner to point at. This
is the same device as reverse-DNS package names in Java or bundle identifiers on
Apple platforms, and it needs no institution to work.

**A field whose name carries no recognisable namespace is `unsupported`**
(§a.5), like any other line the reader cannot place. That is what makes the rule
enforceable rather than advisory: an implementation that invents a bare name
does not get silently accommodated.

> **No `x-` prefix, deliberately.** Earlier drafts of this specification marked
> vendor fields with `x-`. RFC 6648 (BCP 178) recommends against precisely that
> — *"SHOULD NOT prefix their parameter names with `X-`"* — and goes further:
> a protocol *"MUST NOT stipulate that a parameter with an `X-` prefix … needs
> to be understood as unstandardized"*. The reasoning is borne out everywhere it
> was ignored: unstandardised parameters become de facto standards anyway, and
> the deployed world is then stuck with both `X-Foo` and `Foo` forever.
> `X-Forwarded-For` is the monument. The namespace carries the same information
> without the trap, and RFC 6648 recommends exactly this alternative —
> *"incorporate the organization's name or primary domain name"*.

### a.2 Canonicalisation of content

Given the content preceding a block, apply **in this order**:

1. **Strip a leading UTF-8 BOM** (U+FEFF), if present.
2. **Normalise line endings** — CRLF and lone CR become LF.
3. **Strip trailing whitespace** (spaces and tabs) from every line.
4. **Exactly one trailing newline.** Empty content stays empty.

Everything else is byte-for-byte untouched: all multi-byte characters, all
leading whitespace, all interior blank lines. **Leading blank lines are
significant** — only *trailing* newlines collapse, and an implementation that
trims both ends produces a different digest.

> Rules 1 and 2 are what make a document authored on Windows verify on Linux.
> Without them the failure is silent and has no diagnostic.

### a.3 The signing input

```
signing input  =  canonical_content  ||  0x0A  ||  canonical_metadata
```

- **`canonical_content`** — everything preceding the block's `<!-- mades-sig`,
  canonicalised per §a.2. **This includes the appearance image** (§a.8).
- **`canonical_metadata`** — the block's own body, rebuilt as:
  1. **every comment line, in document order**, exactly as stored;
  2. every field **not excluded below**, **sorted by key name** (byte-wise
     ascending), one `key: value` per line; lists as `key:` + `  - item` in
     document order; maps as `key:` + `  sub: value` with **sub-keys sorted**;
  3. lines joined with LF, no trailing newline.

> **Point 1 changed in v4.** Up to v3 only the Level-1 comment line (§d) was
> covered, so a *second* comment line could be added to a signed block without
> breaking the signature. Comment lines are the human-readable layer of the
> block; covering one and not the rest protects the sentence nobody would attack
> and leaves the ones an attacker would add.

**Empty lists and maps MUST be omitted entirely.** An emitted `key:` with no
children parses back as absent, so the signing input would differ between
signing and verification — an intermittent, silent failure.

> **NORMATIVE (v4) — what is signed is written.** A serialiser MUST write every
> field that entered the signing input. Filtering the output through a list of
> known field names — while the digest was computed over everything — produces a
> block that can never verify, and the defect only surfaces at the recipient.
> This was measured on the reference implementation for vendor extensions.

#### The exclusion rule

> **A field is excluded from the signing input if and only if it carries the
> signature itself, or evidence that can only be obtained after the signature
> exists.**

| Field | Why it cannot be inside the signature |
|---|---|
| `signature` | it is the output; it cannot be its own input |
| `timestamp` | an RFC 3161 token is computed *over* the signature value |
| `revocation-info` *(reserved, B-LT)* | fetched after signing |
| `archive-timestamp` *(reserved, B-LTA)* | applied over the completed signature, and renewed over time |

Everything else — `certificate-chain`, `signer-kind`, `automation`,
`appearance`, `lang`, `represents`, `revision`, `supersedes`, and all vendor
extensions — **is** covered. Implementations MUST treat this list as complete
for the version they implement and MUST NOT invent additional exclusions.

> **`signer-kind` being inside the signature is what makes it evidence rather
> than a label.** Outside it, anyone could flip `automated` to `human` on a
> finished document without breaking anything. Inside it, changing the category
> invalidates the signature — and the certificate check of §a.11.2 closes the
> remaining gap where a signer declares a category their certificate does not
> support.

> **`certificate-chain` is covered, and that fixes an ordering.** The chain must
> exist before the digest can be computed, so the certificate is issued *before*
> the signer confirms. An implementation that hashes first and fetches the
> certificate afterwards produces a document that looks finished and fails
> verification at the recipient. (Earlier drafts said markdown needs the
> certificate only after signing. That was wrong and is corrected here.)

**Why the comment lines are included:** they are what a reader sees in a plain
text editor. Excluding them would let an attacker rewrite "Signed by Alice —
creation" into "Signed by the CEO — approval", or append a line declaring the
document void, while the signature still verified. Verification uses the
**stored** comment bytes, never a regenerated line.

**Why sorted by key:** any implementation can reproduce it without sharing a
constant. Rendering order (§a.10) is a separate, human-facing concern.

### a.4 Commitment types

| Value | Meaning |
|---|---|
| `creation` | "I produced this and I fix this version." Origin + integrity; does **not** express agreement. |
| `approval` | "I agree to the content." Non-repudiation. **Default.** |
| `receipt` | "I received this." |
| `witness` | "I witnessed this signing." |

Verifiers MUST surface the commitment — a `creation` signature must never be
presented as agreement. Unknown values MUST be reported verbatim as
"unrecognised commitment", never silently treated as `approval`.

> **Commitment and category are orthogonal** (§a.11). The commitment says *what
> was done*; `signer-kind` says *by whom*. `creation` + `automated` is a system
> fixing a version; `creation` + `human` is a person fixing their own. Both are
> legitimate, and conflating them loses exactly the distinction v5 exists for.
> Which combinations a given certificate may produce is a policy question,
> answered by §a.11.3.

### a.5 Verification procedure

1. Locate the block.
2. Canonicalise the content up to (excluding) `<!-- mades-sig` (§a.2).
3. Parse the block **totally** (§a.1). Under v4+, if any line is neither a
   comment, blank, nor a well-formed field, STOP and report the block as
   **`unsupported`** with the number of lines that could not be read. Do not
   attempt verification: a signature checked over a partial understanding of
   what the block says is worse than no answer.
4. Rebuild `canonical_metadata` from the **stored** comment lines and fields,
   applying the exclusion rule (§a.3).
5. Verify the signature over the recomposed signing input.
6. If `appearance` is present, hash the embedded image and compare with
   `appearance.digest` (§a.8).
7. Validate `certificate-chain` against the verifier's trust store, and the
   certificate's validity window against the `timestamp` (or `signed-at` when
   absent, §c.5).
8. **(v5)** Check the signer category against the certificate (§a.11.2) and the
   commitment against any constraint the certificate carries (§a.11.3). Either
   mismatch is **`invalid`** — the block claims something its credential does
   not support.
9. Report commitment, **signer category**, achieved profile (§g), trust-anchor
   outcome (§c.4), revision status (§a.7) and representation-binding status
   (§a.6).

> **`unsupported` is not `invalid`, and implementations MUST NOT collapse the
> two.** `invalid` says the content or the block changed after signing —
> an accusation. `unsupported` says this reader cannot determine what the
> signature covers. A reader that reports the second as the first turns its own
> limitation into someone else's forgery.

> **Reading older blocks.** A v2, v3 or v4 block is verified under the rules of
> ITS version — the `version` field decides, not the reader's own. A pre-v5
> block has no category; verifiers MUST report it as **"signer category
> unspecified (pre-v5)"** and MUST NOT infer `human` from its absence. Most
> pre-v5 signatures were in fact made by people, which is exactly why the
> inference is dangerous: it would be right often enough to be trusted and
> wrong precisely where it matters. Verifiers SHOULD additionally warn when a
> v2/v3 block contains comment lines beyond the first: those fall outside the
> signing input under the rules of that version, they read to a human as part
> of the signature, and the reader is the only party in a position to say so.

### a.6 Representation binding — `represents`

One act may exist in two representations — a Markdown file and a PDF rendered
from it. Two byte-streams, two hashes, two independent signatures, and nothing
in either says they carry the same content: **a conversion error yields two
validly signed documents that say different things.**

```yaml
represents:
  document-id: 018f-…-a31    # stable identifier for the act, shared by both
  format: pades
  digest: sha256:71ab…       # digest of that representation, as signed there
```

Implementations producing both in one ceremony MUST include `represents` in
each, pointing at the other; the PAdES side carries the equivalent as a signed
attribute. Because `represents` is in the signing input, the binding is itself
protected — it is meaningless without §a.3, since a forgeable binding invites
reliance. A verifier seeing only one representation MUST report the binding as
**asserted but unverified**.

### a.7 Revision chaining — `revision` / `supersedes`

```yaml
revision: 3
supersedes: sha256:9f2c…    # digest of the canonical content revision 2 signed
```

`revision` is a monotonically increasing integer from 1; revision 1 omits
`supersedes`. A verifier encountering a signature whose content no longer
matches, but which is referenced by a later revision's `supersedes`, MUST report
it as **superseded (expected)** rather than **invalid**.

> **NORMATIVE — a later block may only supersede an earlier one when it is at
> least as strong.** The later block MUST itself verify, MUST name the earlier
> block, MUST chain to a trusted anchor, and MUST be signed by the same signer.
> Without all four, an attacker modifies content covered by someone else's
> signature, appends an unsigned block declaring `supersedes`, and the reader
> reports "superseded (expected)" instead of "invalid" — the modification is
> then presented as a normal revision. Measured on the reference implementation
> before it was fixed.

**What a revision digest does not prove:** it shows *that* a prior revision
existed and what its digest was, not what it said. A recipient holding only the
current file cannot reconstruct revision 2, only verify a copy if one is
produced. Verifiers SHOULD say so rather than let a chain imply more than it
delivers.

### a.8 The appearance — `appearance`

A signature that nobody can see is a signature nobody trusts. MAdES therefore
defines a **visible seal**, embedded in the content the signature covers.

```yaml
appearance:
  mode: signature | seal | none
  digest: sha256:6f1c…       # of the SVG source bytes
```

**Placement.** The appearance is a standard Markdown image with a `data:` URI,
placed immediately before the block it belongs to:

```markdown
![Digitaal ondertekend — Alice Example — 7 augustus 2026, 11:15 CEST](data:image/svg+xml;base64,PHN2Zy…)
```

It is ordinary content. Every renderer displays it; none needs to understand
MAdES. The alt text MUST carry the same facts as the image, so a screen reader
and a text-only client are not left with "image".

**Why a data-URI image and not a companion fence.** A renderer that does not
understand a `~~~mades-visual` fence shows a *second* code block — the design
gets worse for exactly the audience it was meant to help. An image degrades to
alt text.

**The appearance is inside the signing input, and that is the whole security
argument.** Anyone can paste an SVG that says "Signed by the CEO". Because the
image sits in the canonical content, replacing it breaks the signature. A
verifier MUST NOT present an appearance as authoritative before verifying the
signature, and `appearance.digest` lets it confirm the image on screen is the
image that was signed without parsing SVG.

> **NORMATIVE — a signed document carries its own images.** Every image
> referenced by signed content MUST be embedded (a `data:` URI). A signature
> covers the *reference*, not the bytes behind it, so an external URL leaves the
> visible content changeable by whoever hosts it: the document stays
> cryptographically valid while what a reader sees changes. Signing
> implementations SHOULD embed at sealing time and MUST refuse to seal rather
> than sign a reference they could not resolve. Verifiers SHOULD NOT fetch
> external images — beyond the integrity problem, doing so reports the time and
> place of reading back to whoever wrote the document.

**Modes.**

| Mode | Use |
|---|---|
| `signature` | at a specific place in the text — where a contract puts the signature line. Named person, visible act. |
| `seal` | document-level, at the head or foot. "This document is sealed by X." For version locks and machine attestations. |
| `none` | signed with no visible appearance. PDF supports this too, and it is the right default for machine attestations and for documents where a seal is only noise. |

> **v5 — an automated signature MUST NOT use `mode: signature`.** That mode is
> the contract signature line, and putting a machine on it is the visual form of
> the claim §a.11 exists to prevent. Automated signatures use `seal` or `none`
> (§a.11.4).

**Layout contract (normative).** So that two implementations produce the same
seal rather than two that merely resemble each other:

- `signature`: 560 × 186 px, `viewBox="0 0 560 186"`. Regions: status label and
  check top; written name over a rule, printed name, address, commitment + time
  in the left column (x = 24…330); issuer and fingerprint in the right column
  (x = 378…); a footer strip of 30 px height across the bottom.
- `seal`: 560 × 92 px, single row.
- The **footer strip** is the slot for the party that ran the ceremony, with an
  optional logo of at most 19 × 18 px. It is deliberately separate from the
  issuer column: **the certificate authority vouches for the identity; the
  platform ran the process.** Placing both on one line asserts something untrue,
  and a disputed signature turns on exactly that distinction. An implementation
  that omits the strip is conformant.
- Required content: signer name, address, commitment, signing time **including
  the hour and the UTC offset**, issuer common name, and a short order-independent
  fingerprint of what is being signed. **(v5)** For `signer-kind: automated`,
  the seal MUST additionally carry the category in words (§a.11.4).

**Determinism (normative).** The SVG source bytes are part of the signing input,
so they MUST be reproducible: no generated element ids, no render timestamp, no
measured text, no locale-dependent number formatting. Font *availability* may
differ between systems — that changes how the seal looks, never what the bytes
are, and the signature is unaffected.

**Background.** Implementations SHOULD paint an opaque light card. A fully
transparent appearance was evaluated and rejected on arithmetic: at the 4.5:1
contrast ratio required for readable text, a colour must be `#767676` or darker
on white and `#949494` or lighter on near-black, and those ranges do not
overlap. No single ink survives both grounds, so the small print — issuer, time,
fingerprint — fails somewhere. A light card is also the honest metaphor: a
signature lives on paper, and a PDF page stays white in a dark reader.

**What the appearance MUST NOT contain:** the signature value or the timestamp.
Neither exists when the appearance is built — the same exclusion logic as §a.3.

### a.9 Language — `lang`

A BCP 47 tag stating the language of the **appearance**.

**The appearance cannot be localised per reader.** It is inside the signing
input, so its bytes are fixed at signing: one file, one seal, the same for
everyone. Translating it per viewer would break the signature.

So the split is: **the seal is in the language of the document; the verifier's
own report is in the language of the reader.** This is what PDF readers do — a
French signature appearance with a Dutch validation panel beside it. Signing
implementations SHOULD take the language from the document, falling back to the
signer's preference. Verifiers SHOULD use `lang` to label the appearance, and
MUST NOT redraw it.

### a.10 Rendering order (informative)

Signing uses sorted keys (§a.3); *rendering* MAY use a human-friendly order —
`version, algorithm, signer, signer-kind, automation, commitment, signed-at,
lang, appearance, revision, supersedes, represents, key-id, field, format,
certificate-chain, timestamp, signature`, with vendor extensions last.
Verification never depends on it.

> This is an ordering, **not a filter.** Every field that entered the signing
> input is written, including names this list does not mention (§a.3). An
> implementation that uses this list to decide *what* to emit rather than *in
> what order* produces blocks that cannot verify.

### a.11 The signer category — `signer-kind` / `automation` *(v5)*

Text is now produced by people and by machines in the same file, often in
alternation. A signature that cannot say which one made it leaves the reader's
first question unanswered — and it is a question no other signature format has
had to face, because no other format is the medium in which the two take turns.

> **The invariant: `human` can only be established by a human signature.**
> Everything in this section exists to protect that one sentence. An
> unrecognised or unverifiable category degrades to *not human*, never to
> `human`.

#### a.11.1 The fields

```yaml
signer-kind: human | automated     # REQUIRED from v5. Closed vocabulary.
automation: ai | service | pipeline | …   # OPTIONAL. Open vocabulary.
```

**`signer-kind` is closed and binary** because the reader's question — *did a
person look at this?* — must be answerable by any conforming implementation,
including one written before today's vocabulary existed. A verifier MUST reject
an unrecognised `signer-kind` value as `unsupported` (§a.5) and MUST NOT treat
it as `human`.

**`automation` is open** and refines the machine case. It MUST be reported
verbatim when present, and an implementation that does not recognise the value
reports `automated` plus the raw string. Registered starting values:

| Value | Meaning |
|---|---|
| `ai` | a generative model produced or materially shaped this content |
| `service` | a system acted on behalf of an accountable operator |
| `pipeline` | an automated build or publication step |

`automation` MUST NOT appear with `signer-kind: human`. Where present without
`signer-kind: automated`, the block is `unsupported`.

> Two levels rather than one long list, because the two serve different
> readers. The binary serves everyone, forever, and can never fragment. The
> refinement serves the parties who need to tell an AI-drafted clause from a
> build stamp — a real and growing distinction that should not be frozen today
> by a committee that cannot see next year's categories.

#### a.11.2 Certificate anchoring (normative)

A field a signer fills in about themselves is a courtesy, not evidence. **The
signing certificate MUST assert the signer category, and the verifier MUST
check that the certificate and the block agree. A mismatch is `invalid`.**

The category is asserted as a **certificate policy OID**. Policy OIDs exist for
exactly this purpose, every CA can already issue them, and a verifier can check
one without parsing anything bespoke.

Reference assignments, published under ITbrouwerij's IANA PEN (65498) and
**free for any implementation to use**:

```
1.3.6.1.4.1.65498.2          MAdES
                  .2.1       signer categories
                  .2.1.1     human
                  .2.1.2     automated
```

A deployment MAY instead use policy OIDs of its own, declared in its
certificate policy; verifiers then carry a configured mapping from OID to
category. What is NOT permitted is a certificate that asserts no category at
all being used to sign a v5 block: the verifier MUST report **"category
asserted but not anchored"** and MUST NOT present the block as `human`.

> **Why not a bespoke X.509 extension.** A new extension needs every CA in the
> path to emit it and every verifier to parse it; a policy OID needs neither.
> The cheapest mechanism that actually holds is the one implementations will
> deploy — and one that is not deployed protects nobody.

#### a.11.3 Commitment constraints (normative)

A certificate MAY constrain which commitments (§a.4) it can carry. **A verifier
MUST reject a signature whose commitment exceeds its certificate's
constraint**, reporting `invalid` with the constraint named.

This is what lets a deployment issue machine credentials that can fix a version
but can never express agreement — enforced in the credential rather than in the
application, so it holds even when the application is wrong.

The constraint is expressed in the issuing CA's certificate policy and carried
in the certificate; the **mechanism** is specified here, while **which profile
gets which constraint** is deployment policy.

> **The specification does not forbid automated `approval` or `receipt`
> globally.** An automated receipt confirmation is entirely legitimate — a
> system acknowledging delivery is not pretending to agree to anything. A
> deployment that wants machines never to agree expresses that in its own
> certificate policy, which is where such a rule belongs and where it can be
> audited. A specification that hard-codes one deployment's ethics stops being
> a specification.

#### a.11.4 Presentation (normative)

- A renderer that displays a signature **MUST display the category**.
- An automated signature **MUST NOT be rendered in a form primarily associated
  with human signatures**: no handwritten-style name, no `appearance.mode:
  signature` (§a.8), no wording that reads as endorsement.
- Recommended wording, and what the reference implementation uses: **"prepared
  by"** rather than "signed by" — delivered, not endorsed.
- A pre-v5 block is labelled **"signer category unspecified"**, never "human".

#### a.11.5 Fixing a version is a signature (informative)

The practical consequence, and the reason this section is not academic: the act
of freezing a document — the moment a system says *these are the bytes* — is a
`creation` commitment made by a machine. Expressed as a MAdES signature with
`signer-kind: automated`, it stops being an internal fact of some platform's
database and becomes evidence a third party can check from the file alone. The
human's `approval` then signs over it, including that block, per §b.

That sequence — an automated `creation` beneath a human `approval` — is the
normal shape of a document that a machine prepared and a person stood behind.
It is published as an interoperability vector (§e).

## b. Multi-signer model

### Default: sequential append

Multiple blocks may appear in sequence. Each subsequent block's signing input
includes **all preceding blocks and their appearances** as content, mirroring
legal practice: each signer endorses the state including prior signatures.
Verification walks back-to-front. Tampering with any block invalidates that
block's own signature and every signature after it.

> **This is what makes the automated/human sequence meaningful.** A human
> `approval` over an automated `creation` covers that creation block — so the
> person demonstrably saw, and stood behind, exactly what the machine
> delivered. The two are not independent claims side by side; the second
> endorses the first.

### Optional: pre-declared signature fields

A document MAY declare `<!-- mades-sig-fields … -->` with `stages[]`
(`mode: serial | parallel`, `depends_on`, per-stage `fields` carrying `id`,
`role`, `required`, optional `commitment`). A block references its field via
`field: <field-id>`. The document is fully signed when all `required: true`
fields are filled.

An unfilled field SHOULD carry an appearance in the same layout with the
signature line dashed and the expected name at reduced opacity — a visible "sign
here" rather than an absence. This is what makes a Markdown file a signable
form. The engine that invites signers is out of scope.

### Pure-parallel explicitly NOT supported

All-signatures-over-frozen-bytes would require a container with internal
ordering, breaking the append-only invariant.

## c. Cryptography, keys &amp; certificates

### c.1 Personal signatures are asymmetric, always

A MAdES **signature** MUST use an asymmetric algorithm. Symmetric MACs cannot
express *who*: everyone able to verify can also create, so eIDAS art. 26 (a)
"uniquely linked" and (c) "sole control" can never be met. Normative — a
verifier MUST NOT report a `hmac-sha256` block as a personal signature.

**Algorithms:** `ed25519`, `ecdsa-p256`, `rsa-pss-sha256`, `rsa-sha256`
(RSASSA-PKCS1-v1_5; permitted, `rsa-pss-sha256` preferred for new deployments).
`hmac-sha256` is reserved for machine attestations (§c.2).

> `rsa-sha256` is listed because signing services deliver it in practice. An
> earlier implementation declared `rsa-pss-sha256` while requesting the PKCS#1
> v1.5 OID — the signature was valid and the artifact lied about how to check
> it, so a verifier following the block reported "invalid" on a good signature.
> **The `algorithm` field MUST name the scheme actually used**; implementations
> SHOULD derive it from the OID they request rather than declaring it twice.

> **NORMATIVE — the algorithm name comes from an allowlist.** A verifier MUST
> reject an unrecognised `algorithm` value outright and MUST NOT fall back to a
> default scheme. `algorithm` is chosen by whoever wrote the block, so a
> fallback lets the signer decide how their own signature is checked.

### c.2 Machine attestations — and how they differ from automated signatures

`algorithm: hmac-sha256` produces a **machine attestation** (profile
`MAdES-Machine`): it proves the content passed unchanged through a *system*
holding the key. Renderers MUST present these as "Machine attestation —
&lt;system&gt;" and MUST NOT render them with signature semantics. Such blocks
SHOULD use `appearance.mode: none` or `seal`, never `signature`.

> **NORMATIVE (v5) — a machine attestation and an automated signature are not
> the same thing, and MUST NOT be presented as one.** Both carry
> `signer-kind: automated`; only one of them is a signature.

| | Machine attestation (§c.2) | Automated signature (§a.11) |
|---|---|---|
| Algorithm | `hmac-sha256` | asymmetric (§c.1) |
| Key | shared system secret | own key, certificate-bound |
| What it proves | content passed through this system unchanged | *this* system signed *these* bytes |
| Who can also produce it | anyone holding the shared secret | only the key holder |
| eIDAS position | none — integrity evidence | electronic signature, or a seal with an organisational certificate |
| Profile (§g) | `MAdES-Machine` | `MAdES-Signed` / `-Advanced` / `-Qualified` |

The distinction matters because the second is attributable and the first is
not. A deployment that wants a machine's act to be evidence against that
machine needs the right-hand column.

> **Naming note.** Called `MAdES-Seal` before v0.4, renamed because *seal* has a
> specific eIDAS meaning — an electronic seal (art. 35-36) is made by a **legal
> person**. Signing on behalf of an organisation with an organisational
> certificate is a genuine eIDAS seal and needs no format change.

### c.3 Signer key model — short-lived certificates

1. The signer performs **strong authentication**.
2. A CA issues a **short-lived certificate** binding the verified identity to a
   fresh key pair; lifetime minutes to hours.
3. The block carries the chain, so verification needs no online lookup after the
   certificate has expired.

"Sole control" is realised by the **activation step**, formalised by ETSI TS
119 431-1 and CEN EN 419241. Operationally this is CSC API v2:
`credentials/authorize` binds Signature Activation Data to **this signer** and
**this hash** → `signatures/signHash`. An architecture where the calling
application authorises on the user's behalf produces an organisational seal, not
a personal signature.

> **(v5) Certificates for automated signers.** The same machinery, with a
> different front door: there is no person to authenticate, so issuance is
> authorised by an **accountable operator** whose own identity was verified.
> The certificate asserts the `automated` category (§a.11.2), SHOULD name both
> the automation and its operator in the subject, and SHOULD carry a commitment
> constraint (§a.11.3). Deployments MUST NOT issue automated certificates
> through a path that lets an automation obtain a `human` category — that path
> is the one thing the whole section protects.

**Key usage.** A signing certificate SHOULD assert `nonRepudiation`
(contentCommitment) and SHOULD NOT assert `digitalSignature`: the latter also
covers authentication, blurring "I agreed to this" with "I logged in". **No
extended key usage is required** — document signing has no mandatory EKU, and a
superfluous one only narrows where the certificate is accepted. Its absence is
correct, not an omission.

**Revocation.** A certificate living minutes is not revoked; it expires. Issuers
SHOULD mark such certificates `validity-assured-short-term`, and verifiers MUST
NOT treat absent revocation information as failure for them. The timestamp
(§c.5), not a revocation check, proves the certificate was valid when it signed.

> **Validity windows.** With a short-lived profile, a backdating offset and the
> profile validity are counted from the same instant: an issuer applying a
> 10-minute backdate to a 10-minute certificate produces a window that closes
> where it should have opened, so every certificate is expired at issuance.
> Signing succeeds, the document looks finished, and verification fails at the
> recipient. Issuers SHOULD keep the backdate to a small clock-skew margin.

### c.4 Trust anchoring

**Trust is a property of the verifier, not of the document.** A signature is
cryptographically valid or not; whether the issuing CA is *trusted* is answered
by whichever trust store the verifier consults, and two verifiers may
legitimately answer differently.

**A public trust list is not a precondition for AdES.** eIDAS art. 26 requires
that the signature be uniquely linked to the signatory, capable of identifying
them, created under their sole control, and tamper-evident. None of these
mention any list. Only **QES** requires a qualified certificate from an
EUTL-listed provider.

| | Private CA | Publicly trusted | Qualified (EUTL) |
|---|---|---|---|
| Cryptographic validity | yes | yes | yes |
| Can satisfy art. 26 (AdES) | yes | yes | yes |
| Verifies without installing a root | no | yes | yes |
| Audited attestation of the identity binding | no | yes | yes |
| QES / reversed burden of proof | no | no | yes |

Implementations MUST NOT label a signature "test" or "demo" on the basis of its
issuer. They MUST report the trust-anchor outcome — *chains to a root this
verifier trusts*, or *trust anchor not recognised* — worded so it cannot be read
as forgery (§d).

> **NORMATIVE — establishing that a certificate was issued by another requires
> checking the signature.** Name matching and authority-key-identifier matching
> are hints, not proof: a chain forged with the right issuer names passes both
> while the cryptographic check fails. A verifier MUST verify each certificate
> against its issuer's public key, MUST require the issuer to be a CA, and MUST
> check the issuer's validity window at the relevant moment. Measured on the
> reference implementation: name matching alone accepted a self-made chain and
> reported it as trusted.

**A signature outlives its trust anchor only if the anchor is retained.**
Operators SHOULD archive root and intermediate certificates for the lifetime of
the signatures issued under them, including after the CA stops issuing, and
publish the chain at a stable URL. A retention obligation, not a quality
judgement.

> **A CA rebuild is an event, not a maintenance task.** Verifiers pin anchors;
> replacing a root without announcing it turns every existing signature into
> *trust anchor not recognised* at every relying party simultaneously. Operators
> SHOULD announce a rebuild before it happens, and SHOULD keep the superseded
> root published.

> **Key ceremony (informative, effectively one-shot).** Everything about a CA can
> be improved later except how its root key came into existence. Any conformity
> assessment begins with "demonstrate how this key was generated" and accepts no
> retroactive substitute. At first root generation: generate inside an HSM with
> no plaintext export; review the ceremony script beforehand; enforce m-of-n
> activation with split knowledge; record named witnesses and a contemporaneous
> signed log; keep activation material under tamper-evident custody; **record the
> exact software and firmware versions of the generating device**; retain
> everything for the CA's lifetime plus the retention period.

### c.5 Timestamping

`timestamp` carries a base64 RFC 3161 TimeStampToken over the `signature` value.
**With short-lived certificates a timestamp is REQUIRED** — without it,
`signed-at` is merely a claim and the signature becomes unverifiable once the
certificate expires, typically within minutes. Verifiers MUST accept a signature
whose certificate has since expired when a valid timestamp falls inside the
certificate's validity window.

**Acquisition differs by representation.** PAdES lives in a CMS container and is
normally produced by a toolchain that contacts the TSA itself. **MAdES has
neither.** The implementation must request the token itself and place it in
`timestamp`. An implementation that assumes the signing service supplies it will
silently ship B-B signatures that expire with the certificate.

**Nonce handling (normative).** A request SHOULD carry a nonce, and the response
nonce MUST be compared as an **integer value**, not as raw bytes: DER encodes
INTEGER in minimal signed form, so a nonce whose high bit is set acquires a
leading `0x00` that was not in the request. Byte-wise comparison reports a false
"replay detected" on roughly half of all random nonces — worse than no check,
because it looks like an attack. Both known implementations hit this.

**Verification of the token (normative).** A verifier MUST NOT present `genTime`
as established until it has checked the TSA's own signature. Concretely: the
encapsulated content is a TSTInfo and the signed `contentType` attribute says
so; the signed `messageDigest` equals the digest of that content; the signature
verifies over the signed attributes re-encoded as a `SET OF` (RFC 5652 §5.4);
the certificate is the one the token names (issuer and serial, and where
present `signingCertificateV2`); and that certificate carries
`id-kp-timeStamping` **as its only** extended key usage (RFC 3161 §2.3).

Whether the TSA's chain reaches a trusted anchor is a **separate** answer, on
the same reasoning as §c.4: a genuine token from an unrecognised authority is
not a forged one. Until the check exists, an implementation MUST report the
timestamp as *stated but not verified* rather than omit the distinction — an
absent field reads as "in order".

### c.6 Container formats — `format`

| Value | `signature` contains |
|---|---|
| `raw` (default) | the bare signature bytes, base16 or base64 |
| `jws` | a compact detached JWS over the signing input, chain in `x5c`; can be made JAdES-baseline-compliant (ETSI TS 119 182-1) |
| `cms` | *reserved, unused* |

CSC v2 `signatures/signHash` returns the **raw signature value**, so a MAdES
block carries those bytes directly under `raw`. Where a CMS is required — PAdES
— the container is assembled outside the block by the PDF toolchain.

### c.7 Key distribution &amp; trust material

**Certificate path (the norm):** certificates travel in-block; key distribution
reduces to trust-store management. Fully offline-capable at verify time.

**Raw-key path:** a **`.well-known/mades-keys` HTTPS manifest** in JWK format
(RFC 7517), binding raw-key identity to **domain control** with no central
registry. Responses SHOULD be cached; verifiers SHOULD pin the manifest state
alongside results.

> **(v5) The raw-key path cannot anchor a category** (§a.11.2) — a JWK carries
> no policy OID. A v5 block using `key-id` instead of a certificate chain MUST
> therefore be reported as **"category asserted but not anchored"**, whatever it
> claims. Deployments that need the human/automated distinction to hold use the
> certificate path.

**Retention rule (normative):** manifests MUST retain (or verifiably archive)
expired and revoked keys — any historical signature must stay checkable against
the trust state at its `signed-at`/timestamp moment.

**Reserved: DID resolution.** `key-id` is a URI and `did:` is reserved. An
implementation that cannot resolve them MUST report *"unsupported key-id
scheme"* — never *"invalid signature"*.

## d. Visual representation

- **Level 1 — the comment lines** (MUST at least one): the first line inside the
  block, e.g. `# ✓ Signed by alice@example.com — approval — human — 2026-08-12`.
  **All comment lines are part of the signing input** (§a.3, v4) — editing or
  adding one breaks the signature. They are what a reader sees in a plain text
  editor, and the only human-readable layer in a viewer that strips HTML
  comments without rendering images. **(v5)** The Level-1 line SHOULD name the
  category, since for a text-only reader it is the only place the distinction
  can appear at all.
- **Level 2 — the appearance** (SHOULD): §a.8. Visible in every renderer, signed,
  and never authoritative on its own.
- **Level 3 — verifier report** (SHOULD): a viewer that implements MAdES adds
  what the file cannot carry — the outcome of actually checking. Required
  distinctions: machine attestation versus signature; **human versus automated
  versus unspecified (pre-v5)**; `creation` versus `approval`; **superseded**
  versus **invalid**; **unsupported** versus **invalid**; **timestamp verified**
  versus **timestamp stated**; and **signature valid, trust anchor not
  recognised** versus **valid and anchored in a trusted root**.

  Wording matters. *"Trust anchor not recognised — install the issuer's root to
  complete verification"* is correct; *"untrusted signature"* or *"test
  signature"* is not, and misleads a lay reader into treating a valid signature
  as a forged one. Showing the issuer's name is expected; grading it is not.

  A verifier SHOULD also check that the `signer` field is supported by the
  certificate — compare against the SAN and the CN. `signer` is an assertion in
  the signed metadata, so without this check anyone holding any valid
  certificate can sign a block naming somebody else, and the reader displays
  that name beside a valid verdict. A mismatch does not make the signature
  invalid; it makes the claim untrue, and that is its own answer.

  This report is in the **reader's** language (§a.9).

- **Level 4 — what the reader does not understand** (MUST): a verifier that
  meets a **signed** field it does not implement MUST show it, with its
  namespace, and MUST NOT attach a meaning to it —
  *"build.vecto.void = true (meaning not known to this reader)"*. Not
  interpreted, but not hidden either.

  This is the mirror image of the gap §a.3 closed in v4. There, a signed field
  could **disappear** on re-encoding; here, it can be faithfully preserved and
  **never read**. Both leave a reader believing they have seen what was signed
  when they have not, and the second is the quieter of the two — nothing looks
  wrong.

  It matters because of who puts a field there. A sender adding
  `build.vecto.void: true` puts it *under the signature*: deliberately, at the
  cost of breaking their own signature if they change it, and therefore to be
  read. A verifier that silently drops it has decided on the reader's behalf
  that it did not matter.

  > Measured before it was specified: two independent implementations — the
  > reference implementation and Vecto Sign — both preserved unknown signed
  > fields correctly and both showed none of them. Neither had decided to hide
  > anything; the display side simply never came up. That is what makes this a
  > normative rule rather than advice.

## e. Tooling (reference implementation)

- **`mades-sign`** — `--key`/`--cert-chain` or a CSR flow, `--tsa <url>`,
  `--commitment`, `--signer-kind`, `--automation`, `--format raw|jws`,
  `--appearance signature|seal|none`, `--lang`, `--brand`, `--represents`,
  `--revision`, `--machine`.
- **`mades-verify`** — chain validation against a `--trust-store`, timestamp
  validation, appearance-digest check, raw-key resolution, commitment reporting,
  **category reporting and certificate-consistency checking (§a.11.2)**,
  **commitment-constraint checking (§a.11.3)**, revision-chain evaluation,
  representation-binding report, trust-anchor outcome, profile computation (§g),
  expired-cert-with-valid-timestamp handling.
  Exit: 0 = all valid + complete, 1 = invalid, 2 = valid but incomplete.

**External-signing API (normative).** Production signing happens remotely, so
implementations MUST expose the split: `prepare(content, fields) →
{signingInput, digest}` before the service call, and `finalize(content,
prepared, signature, {timestamp}) → document` after. `finalize` MUST reject any
field that belongs to the signing input — adding one after signing produces a
block that cannot verify. A library offering only "sign this file with this key"
cannot serve a remote-signing deployment, which is the normal case for AdES.

**Persist the signing input, not only its digest.** A digest cannot be reversed
into the bytes it covers, and values fixed at prepare time — `signed-at`, the
certificate chain, the appearance — cannot be reconstructed afterwards. An
implementation that stores only the digest produces genuine signatures nobody
can verify.

**Interoperability fixtures (RECOMMENDED).** Publish canonicalisation test
vectors — input, expected canonical form, expected digest — covering BOM,
CRLF/LF, lone CR, trailing whitespace, missing and multiple trailing newlines,
leading blank lines and leading whitespace, multi-byte characters and empty
content. This is where two implementations silently diverge.

**Published v4 vectors.** `mades-v4-vectors.json` carries four signed documents
with their signing input, digest and signature, plus the key that signed them:
minimal, a vendor field, a counter-signature, and one with a `timestamp`
field to show it falls outside the signing input.

**Published v5 vectors** (`mades-v5-vectors.json`) add the category cases:

1. a `human` block — the ordinary case;
2. an `automated` block with `automation: ai`;
3. **an automated `creation` with a human `approval` signed over it** — the
   sequence a machine-prepared, human-endorsed document actually produces
   (§a.11.5), and the one an implementation is most likely to get wrong;
4. a block whose `signer-kind` disagrees with its certificate, expected result
   **`invalid`** — a negative vector, because a rule nobody tests is a rule
   nobody implements;
5. a v4 block read by a v5 verifier, expected category **"unspecified
   (pre-v5)"**.

Vectors are signed with a throwaway key rather than a production certificate —
what a second implementation needs to check is the **construction of the
signing input**, and that does not depend on who holds the key. Cases 4 and 5
additionally need a certificate, so they ship with a throwaway CA whose root is
included. A generator SHOULD verify each vector through its own verification
path before publishing it: a fixture an implementation cannot itself verify
proves nothing.

## f. Integration in existing flows

| Mechanism | MAdES role | Migration |
|---|---|---|
| Git commit HMAC trailers | Stays separate — commits aren't Markdown | No change |
| Release sign-off chain | Hybrid — release notes get a machine attestation (c.2) | Add verify in the build gate |
| ADR / policy DOCs | Adopt personal signatures | New flow; optional per doc |
| Vault-sync markdown export | Pass-through | Preservation only |
| Version locking / freezing a document | **(v5)** an automated `creation` signature (§a.11.5) | Replaces an internal flag with in-file evidence |

## g. Compliance, conformance &amp; audit trail

Two **orthogonal** axes; neither implies the other, and neither is the
trust-anchor question (§c.4), which is a third, per-verifier dimension. **The
signer category (§a.11) is a fourth**: it says *who* signed, not how well.
An automated signature can reach `MAdES-Advanced`; a human one can sit at
`MAdES-Signed`. Reporting one as a grade of the other is a category error, in
both senses.

**Axis 1 — key custody &amp; activation:**

| Profile | Algorithm | Key custody | eIDAS position |
|---|---|---|---|
| **MAdES-Machine** | hmac-sha256 | shared system secret | none — integrity evidence, not a signature |
| **MAdES-Signed** | asymmetric | platform-held key, or long-lived key without an activation ceremony | electronic signature (SES-class) |
| **MAdES-Advanced** | asymmetric | short-lived certificate issued after strong authentication | AdES — or an advanced electronic **seal** with an organisational certificate |
| **MAdES-Qualified** | asymmetric | qualified certificate on a QSCD from an EUTL-listed QTSP | QES |

> Advanced deliberately does **not** require a publicly trusted CA (§c.4).
>
> **(v5)** For an automated signer, "strong authentication" is read as the
> operator's authorisation of issuance (§c.3): there is no person at the
> keyboard, and the accountable party is the operator whose identity was
> verified.

**Axis 2 — embedded evidence, per the ETSI AdES baseline:**

| Level | Requires | Reachable with short-lived certificates? |
|---|---|---|
| **B-B** | signature only | yes, but see below |
| **B-T** | + a trusted RFC 3161 timestamp | **yes — and it is the minimum** |
| **B-LT** | + chain and revocation data embedded | **no** — no revocation material exists |
| **B-LTA** | + archive timestamps, renewable | **yes** |

**B-T is the minimum whenever short-lived certificates are used**, because
without a timestamp the signature becomes unverifiable once the certificate
expires.

> **B-LT being unreachable does not make B-T the ceiling.** **B-LTA rests on
> archive timestamps, not on revocation data**, so it is reachable with
> short-lived certificates and is the correct target for decade-scale evidence:
> an archive timestamp re-attests the whole signature under current algorithms
> before the old ones weaken. Plan for B-LTA directly and skip B-LT.

**Conformance:** a conformant implementation MUST verify the **Machine, Signed
and Advanced** profiles at **B-B and B-T**, including in-block chain validation
against a configurable trust store, timestamp validation (§c.5), the
appearance-digest check (§a.8), commitment reporting, **the signer category
with its certificate-consistency and commitment-constraint checks (§a.11)**,
the trust-anchor outcome, total parsing with the `unsupported` outcome (§a.1,
§a.5) and the exclusion rule of §a.3. **Qualified** custody and **B-LT / B-LTA**
evidence are OPTIONAL: implementations omitting them MUST report such
signatures as *"valid signature — qualified status not evaluated"*, never as
invalid.

Audit trail: each block records `signer`, `signer-kind`, `commitment`,
`signed-at`, and where present `revision` and `timestamp`; sequential ordering
provides witness-of-prior-state; §§a.2–a.3 make tampering detectable.
Orchestrating engines SHOULD additionally keep an out-of-band evidence record
(identity-verification method, IP, consent).

## h. Roll-out

**Tranche 1:** publish v1.2 · `mades-sign`/`mades-verify` with the comment form,
the three appearance modes, the signer category, and published interoperability
fixtures for v4 and v5 · use internally.
**Tranche 2:** `format: jws` · `.well-known/mades-keys` · a desktop reader with
a proper validation report (§d Level 3) · Python/Rust reference implementations.
**Tranche 3:** pre-declared field UI · publicly trusted CA + qualified TSA · QES
via QTSP · organisational seals · **`archive-timestamp` for B-LTA** · DID key-id
profile · standards-body submission if traction warrants.

## Annex A (informative) — reference deployment

In Vecto Proof, certificate issuance, activation and timestamping sit behind an
in-house **CSC API v2** service. Moving up the trust ladder — private CA →
publicly trusted → qualified — changes how easily third parties verify, not
whether the signatures are advanced electronic signatures. The application's own
work is canonicalisation, appearance generation, hashing, timestamp retrieval,
and embedding; the private key never reaches it.

Proof's use of §a.11: every version lock produces an automated `creation`
signature, and the certificates it issues for automations are constrained to
that commitment — so a machine in that deployment can fix a version and can
never express agreement. That is a *deployment* rule, expressed where §a.11.3
says such rules belong: in the certificate policy, not in this specification.

## Provenance &amp; credits

Proposed by **ITbrouwerij** (&lt;https://itbrouwerij.be&gt;) as part of the Vecto
OS project. v0.5–v1.2 incorporate findings from two independent implementations,
from the first live signatures, and from a security review of the reference
implementation — several normative rules in §a.3, §a.5, §a.7, §c.4 and §c.5
exist because that review found the reference implementation on the wrong side
of them. Vendor extensions via a reverse-DNS namespace (§a.1).

## Open decisions

- **DEC-1 / DEC-7** — conformance: **resolved** (§g).
- **DEC-2 / DEC-8** — key distribution: **resolved** (§c.7).
- **DEC-4 / DEC-9** — migration of Vecto mechanisms: HMAC uses become machine
  attestations (§c.2/f). GUI adoption open.
- **`automation` vocabulary** — three values registered (§a.11.1). Deliberately
  open, so the question is not *which values* but whether a light-weight
  registry becomes necessary once more than one deployment coins terms.
- **Category for the raw-key path** — §c.7 reports it unanchored. A JWK
  extension or a signed manifest attribute could anchor it; not specified,
  because the certificate path covers every deployment that needs the
  distinction today.
- **`archive-timestamp`** — the B-LTA field is reserved but **not yet
  specified**. The higher priority of the two reserved fields, since it is the
  only long-term path on a short-lived-certificate architecture. Open: whether
  it covers the block or the whole document including later blocks, and how
  renewal is represented without breaking the append-only invariant of §b.
- **`revocation-info`** — the B-LT field is reserved, unreachable for short-lived
  certificates, and only worth specifying for deployments issuing long-lived
  ones.
- **Appearance for `mades-sig-fields`** — the unfilled-field appearance is
  described in §b but its layout is not yet pinned to the same normative detail
  as §a.8.
- ~~**Vendor-field collisions**~~ — **resolved** (§a.1, v1.3). A vendor field
  carries a reverse-DNS namespace the vendor demonstrably controls; a name
  without one is `unsupported`. No registry, no institution. Raised by the Vecto
  Sign implementation, which arrived at the same answer independently of
  RFC 6648 and then supplied the piece that was missing: *who* decides whether a
  namespace is legitimate. A DNS name answers that by itself.
- ~~**A document about MAdES cannot be signed with MAdES**~~ — **resolved**
  (§a.1, v1.4). The marker counts only at the start of a line, and never inside
  a fenced code block. Found by writing the specification's own examples: the
  reference verifier reported a phantom block on a document whose signature was
  sound. `examples/05-a-real-signed-document.md` still describes the limitation,
  because it was signed before the fix and rewriting a signed document to make
  it say something more flattering is the exact thing this format exists to
  prevent.
- ~~**Unknown signed fields are invisible**~~ — **resolved** (§d, v1.3). Also
  raised by the Vecto Sign implementation, and confirmed on both sides before it
  was written down: two independent verifiers preserved unknown signed fields
  and showed neither. That is the strongest evidence a normative rule can have,
  because it proves the behaviour does not arise from good intentions.