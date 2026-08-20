# MAdES — Markdown Advanced Electronic Signatures

[![Tests](https://github.com/ITbrouwerij/mades-spec/actions/workflows/test.yml/badge.svg)](https://github.com/ITbrouwerij/mades-spec/actions/workflows/test.yml)

> **Specification v1.8 (frozen until 2027-03-01, §0.2)** · **Block `version: 5`** · **License:** [CC-BY-4.0](LICENSE-SPEC) (spec) / [MIT](LICENSE-CODE) (reference code)
>
> An open specification for signing Markdown. Not the documentation of any one
> product — a conforming implementation must be able to succeed knowing nothing
> about the tools that happen to implement it today.

**A signed `.md` file carries its own proof.** No detached `.sig` companion, no
wrapper format, no database you have to trust. Copy the file, mail it, paste it
in a chat — the signature travels with it, and anyone can check it.

---

## What it looks like

```markdown
# Service Agreement

Acme Corp and Initech agree to the terms below, valid until 2027-12-31.

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

That is the whole format. The signature covers everything above the block, plus
the block's own fields. Verification is strip-and-recompute.

### Why an HTML comment and not a fenced code block

Because a fence *renders*. That is its definition, and it means every reader who
opens a signed file in an ordinary viewer sees kilobytes of base64 where the
document should be. Earlier drafts of this spec used `~~~mades-sig`, and that is
exactly what happened.

An HTML comment is **invisible in view, present in source**: hidden by CommonMark
renderers, stripped by GitHub, hidden in Obsidian's reading view, dropped by
Pandoc on export — and fully there in the file, which is where a signature
belongs.

> **One normative consequence:** the block body must not contain `--`, because an
> HTML comment ends at the first one. A block containing it is truncated, never
> reaches its `-->`, and the document reads as *unsigned* rather than as invalid.
> Base64 has no hyphen and field names carry single ones, so this holds by
> construction — implementations must still check before emitting, because the
> failure is silent and total.

---

## Why this exists

Markdown became a serious document format while nobody was looking. ADRs, RFCs,
governance proposals, policies, contracts-as-code, agent-written records — all
live in `.md`, and none of it can be signed without leaving the format.

Today the options are a detached `.sig` file (lost the first time someone
copy-pastes) or wrapping the content in JWS (which stops being Markdown). MAdES
is the third option: the same trust model as [PAdES](https://en.wikipedia.org/wiki/PAdES)
(PDF), [XAdES](https://en.wikipedia.org/wiki/XAdES) (XML) and JAdES (JSON), for
the format engineers actually write in.

**And one question the others never had to ask.** Markdown is where humans and
machines take turns. A commit message, a generated report, a decision minuted by
an agent — the document does not say which of the two signed it. Since v5, MAdES
does: `signer-kind` is mandatory, closed, and binary (`human` | `automated`), it
sits inside the signed fields, and the certificate carries the same claim so a
verifier can hold the two against each other.

---

## What a signature actually covers

The **signing input** is built, in order, from:

1. the canonicalised content above the block,
2. every comment line inside the block, in document order,
3. the fields, sorted by key name.

`signature` and `timestamp` are excluded — everything else is covered, including
fields a given implementation does not recognise.

Two rules make that trustworthy rather than merely defined:

- **Parsing is total.** Every line inside the block is a comment, a blank, or a
  well-formed field. There is no fourth category; anything else makes the block
  `unsupported`, not `invalid`.
- **What is signed is what is written.** No allowlist at serialisation time. An
  implementation that meets a field it has never heard of still signs it, still
  writes it, and still reports it.

Both exist because of a measured failure. Before they did, a line reading
`# WARNING: this contract has been declared void` could be added inside a signed
block without breaking the signature — and that block is precisely what a reader
sees in a plain text editor.

### And the files that ride along

An act is often more than one file. A contract has annexes; a report has its
data. Those files are not signed — only the text is — and until v1.5 nothing
stopped one being exchanged afterwards without a single value in the block
changing.

`covers` names them, with their digests, inside the block:

```
covers:
  - sha256:9f2c1d40 application/pdf annex-b-pricing.pdf
  - sha256:41ab77e2 image/png floor plan, ground level.png
```

A verifier that was not handed the files says so — *asserted but unverified* —
and one whose digest does not match reports **coverage broken**, never an invalid
signature. The signature is intact; what it covered is not what was presented.
Two different failures, and collapsing them would be its own kind of lie.

---

## What is in the spec

| | |
|---|---|
| **§a** Format | the block, canonicalisation, the signing input, commitment types, verification, representation binding, revision chaining, appearance, language, rendering order, signer category, coverage of accompanying files, archive timestamps |
| **§b** Multi-signer | sequential append by default; pre-declared signature fields for staged workflows; pure-parallel deliberately excluded |
| **§c** Cryptography | asymmetric for personal signatures, short-lived certificates, trust anchoring, timestamping, container formats, key distribution |
| **§d** Visual | how a signed document may present itself without the appearance becoming load-bearing |
| **§e–h** | tooling, integration, compliance and conformance, roll-out |

Read it here: **[SPEC.md](SPEC.md)**.

### Two design choices worth knowing before you read

**Keys live for minutes, not years.** A signer's certificate is minted for the
ceremony and destroyed after it. What makes the signature outlive the key is the
timestamp: it proves the signature existed while the certificate was valid. An
expired certificate on a MAdES signature is normal and is not a finding.

**Pure-parallel signing is not supported, on purpose.** Two signers cannot each
sign the same bytes and have both results merge cleanly, because the second
signature changes what the first covered. The spec says so plainly rather than
leaving implementers to discover it.

**A signature is kept alive by layers, not by bigger keys.** Every algorithm
weakens eventually, and no key size chosen today survives that. An **archive
timestamp** (§a.13, new in v1.5) records that the whole document already stood in
this exact form while the choices beneath it were still sound; a later layer
records the same again before the previous one ages. Reading is outside-in, and a
signature under a valid layer is reported as *valid as of that layer* rather than
as doubtful — discarding that would waste the only thing the layer establishes.

It is its own block, it needs no certificate and no signer, and it takes exactly
the canonicalisation a signature takes. Renewal is an ordinary append.

**A signed document ends where the signature ends** (§a.14, new in v1.6, refined
in v1.7). A signature covers the content *preceding* its block, so anything
appended after the last block is outside every signature by construction — and until v1.6
nothing said a reader had to look. A conforming document therefore ends at its
last block, and a verifier reports anything after it as **invalid**, not as a
note beside a green result.

One trailing line ending is allowed — `LF`, `CRLF` or a lone `CR`, the same three
§a.2 normalises. v1.7 widened that word: v1.6 said "line feed", and a valid
document saved in a Windows editor stopped conforming without a character
changing. Two endings, or trailing whitespace, is still content.

The instinctive remedy — a signed length or digest of the content — was
considered and rejected: appended bytes are not part of the content such a field
describes, so it would have matched anyway. A boundary is a property of the
document, not of a block. Nothing about what gets signed changed, so every
signature made under earlier versions stays valid.

---

## Verifying, in four steps

1. Find the block, parse it totally, read its `version` — the block's own version
   decides which rules apply to it, not the reader's preference.
2. Rebuild the signing input from the file.
3. Check the signature against the certificate in the file, and the chain against
   your trust anchor.
4. Check the timestamp covers the signature value and falls inside the
   certificate's validity window.

If a block declares a version you do not implement, say so. **Do not report it as
modified.** A false red on a verification page costs exactly as much as a false
green — the reader came there for certainty and leaves with the wrong one.

---

## Getting started

- 📜 [**SPEC.md**](SPEC.md) — the specification
- 📚 [**examples/**](examples/) — worked documents, including two signed by a
  real service: [`05`](examples/05-a-real-signed-document.md) with its
  [PDF](examples/05-a-real-signed-document.pdf), and
  [`06`](examples/06-signing-a-document-about-signing.md), which quotes the
  opening marker four times and is signed anyway
- 🛠️ [**reference/**](reference/) — a minimal Node.js implementation
- 📝 [**CHANGELOG.md**](CHANGELOG.md) — what changed per version, and why

---

## Interoperability vectors

`vectors/` carries the published answer files: canonicalisation (§a.2), the
document boundary (§a.14), signed v4 and v5 documents, and archive layers
(§a.13). An implementation compares against these files instead of against its
own reading of the text — three implementations once read one sentence
identically and identically wrongly, which is why a shared answer file exists.
`reference/test/` re-verifies every vector on every run.

## Status

MAdES is **implemented and in use**, not a paper proposal: there is a production
implementation signing real documents with real certificates and timestamps, and
the block format has been through five versions of measured failure.

It is still **not an accepted standard**, and it will not become one by being
declared one. That is the part where outside eyes are worth more than more
internal iterations.

Specific feedback that helps most:

1. **Canonicalisation edge cases** (§a.2) — BOM, CRLF, nested fences, trailing
   whitespace in code blocks. Where does the rule bite?
2. **The signing-input construction** (§a.3) — is sorting by key name the right
   call against a canonical serialisation like JCS?
3. **Trust anchoring and key distribution** (§c.4, §c.7) — is the precedence
   sensible next to what JOSE and OpenID already do?
4. **The signer-category model** (§a.11) — is `human` / `automated` the right
   split, and is binding it to the certificate the right enforcement?
5. **eIDAS profile mapping** (§g) — legal review genuinely wanted.
6. **Archive timestamps** (§a.13, new) — the layer takes the same input a
   signature takes, and renewal is an ordinary append. Is there a case where
   that is not enough, and does the outside-in reading survive a document that
   mixes layers and later signatures?

Issues and pull requests are both welcome; ports to other languages especially.

---

## Provenance & licence

Authored by **Jan Smets** — [ITbrouwerij](https://itbrouwerij.be).

MAdES is intended as a vendor-neutral open standard. Vendor-specific fields
carry a reverse-DNS namespace the vendor demonstrably controls
(`build.vecto.void`) and never sit in the core — no registry, no institution,
and no `x-` prefix ([RFC 6648](https://www.rfc-editor.org/rfc/rfc6648.txt)).

- **Specification text** ([SPEC.md](SPEC.md), [README.md](README.md),
  [CHANGELOG.md](CHANGELOG.md), [examples/](examples/)) —
  [CC-BY-4.0](LICENSE-SPEC). Fork it, implement it, criticise it; please
  attribute.
- **Reference code** ([reference/](reference/)) — [MIT](LICENSE-CODE).
