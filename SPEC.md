# MAdES — Markdown Advanced Electronic Signatures

> **Status:** Draft proposal · **Version:** 0.3 · **Reference implementation:** Vecto OS (ITbrouwerij)
>
> MAdES is a vendor-neutral specification for embedding cryptographic signatures
> directly inside Markdown files via a trailing fenced code block. Goal: enable
> integrity, authenticity, and non-repudiation for `.md` documents without an
> external `.sig` companion file, in a form that survives copy-paste across
> tools and renders as a plain code block in any Markdown viewer.
>
> This document is the working specification. Open questions are tracked as
> linked DECISIONs.


## 0. Scope & non-goals

**In scope:** define the wire-format for inline Markdown signatures, the
canonicalisation rules, the multi-signer model, optional pre-defined signature
fields, and a minimal visual-representation contract for renderers.

**Out of scope (this version):** binary attachments inside the sig-block,
encryption of the signed payload, certificate-based PKI integration (deferred
to "Advanced/Qualified" profile — see DEC-1).


## a. Specification & Format

### Core block

A MAdES signature is a fenced code block with the **info-string `mades-sig`**,
appearing AFTER the content it covers. The block body is YAML.

markdown
~~~mades-sig
version: 1
algorithm: hmac-sha256
signer: alice@example.com
signed-at: 2026-04-28T10:15:30Z
signature: 7a3f...8b2c
~~~


**Required fields** (vendor-neutral):
- `version` — integer, currently `1`
- `algorithm` — one of `hmac-sha256`, `ed25519`, `ecdsa-p256`, `rsa-pss-sha256`
  (see DEC-1 for which subset implementations must support per compliance level)
- `signer` — string identifier of the signing party (typically email or DID)
- `signed-at` — RFC 3339 timestamp
- `signature` — base16 (hex) or base64 encoded signature bytes

**Optional fields:**
- `key-id` — identifier referencing a published key for verification
  (necessary for non-HMAC algorithms; see DEC-2 for key distribution)
- `field` — references a slot from `mades-sig-fields` (see § b, multi-signer)

**Vendor extensions** are permitted via the `x-` prefix; verifiers MUST
preserve them when re-encoding but MUST NOT rely on them for signature
validity. Example:

yaml
x-vecto-tenant-id: 019dd48d-beab-73fe-8c2c-ce931b2489d6
x-vecto-doc-ref: REL-5


### Canonicalisation rule

The signature covers **everything in the document up to (but excluding) its
own opening fence**. Verification:

1. Locate the sig-block to verify.
2. Strip from the opening `~~~mades-sig` line through the closing `~~~`,
   inclusive of any trailing whitespace.
3. Normalise the remaining content: strip trailing whitespace per line, ensure
   single trailing newline, leave all other bytes untouched.
4. Recompute the signature using the algorithm field; compare.

This single rule generalises trivially to multi-signer (see § b).


## b. Multi-signer model

> **Resolves DEC-3 and DEC-6.** Default is sequential append-only. Optional pre-defined
> field declaration enables staged workflows and parallel-feeling signatures.

### Default: sequential append

Multiple `~~~mades-sig` blocks may appear in sequence. Each subsequent block's
signature covers everything before it — **including all preceding sig-blocks**.

markdown
# Contract

Inhoud...

~~~mades-sig
signer: alice@example.com
signed-at: 2026-04-28T10:00:00Z
algorithm: hmac-sha256
signature: SIG_A    # = HMAC over everything above
~~~

~~~mades-sig
signer: bob@example.com
signed-at: 2026-04-28T11:30:00Z
algorithm: hmac-sha256
signature: SIG_B    # = HMAC over everything above (incl. Alice's block)
~~~


This mirrors how legal contracts work: each subsequent signer endorses the
state including prior signatures. Verification is a walk-back: validate the
last block, strip it, validate the next, etc.

**Properties:**
- No container structure required — generalises § a's canonicalisation rule
- Adding a signer is a pure append (no re-encoding needed)
- Each signature individually verifiable
- Order is preserved and meaningful

### Optional: pre-declared signature fields (staged workflows)

For workflow documents (ADRs, releases, policies) that need defined roles and staged orchestration, authors MAY include a **`~~~mades-sig-fields` declaration block** earlier in the document (typically at the top, after the title).

yaml
~~~mades-sig-fields
stages:
  - id: drafting
    mode: serial          # binnen deze stage: één na één tekenen
    fields:
      - id: author
        role: Author
        required: true
      - id: legal-author
        role: Legal-coauthor
        required: true

  - id: review
    mode: parallel        # binnen deze stage: willekeurige volgorde
    depends_on: drafting  # opent pas als drafting compleet
    fields:
      - id: legal-review
        role: Legal
        required: true
      - id: sec-review
        role: Security
        required: true
      - id: tech-review
        role: Technical
        required: true
      - id: compliance-review
        role: Compliance
        required: true

  - id: final-signoff
    mode: serial
    depends_on: review
    fields:
      - id: ceo
        role: CEO
        required: true
~~~


**Semantics:**
- `stages[]`: ordered groups.
- `mode`: `serial` | `parallel` per stage. Default is `parallel`.
- `depends_on`: `<stage-id>`. A stage only opens when all `required: true` fields in the dependency are filled. Default = previous stage in the list.
- Field IDs are globally unique across all stages.
- A document is fully signed when all `required: true` fields in all stages are filled.
- A sig-block references its field via `field: <field-id>` (as in v0.2).

The `mades-sig-fields` declaration is itself part of the canonicalised content
that subsequent signatures cover.

**Backwards compatibility with v0.2:**
If `stages:` is missing in `mades-sig-fields`, the entire flat field-list is treated as one implicit stage with `mode: parallel`. v0.2 documents remain valid in a v0.3-aware tool.

**Workflow engine out-of-scope:**
The format supports staged orchestration, but the engine that invites signers and advances stages is a separate tool (e.g., Vecto's workflow layer or an external MAdES orchestrator). The file itself is the canonical state — an engine reads the stages, counts signatures per field, determines the 'current open stage', and sends notifications. No extra workflow database is needed.

**PDF comparison (informative):**
Document signing tools for PDF (DocuSign, Adobe Sign, etc.) offer exactly this pattern: a doc-template defines signature fields with optional roles, ordering, and gating. MAdES brings that to Markdown. PDF acroform signature widgets ≈ MAdES `mades-sig-fields`. PDF incremental updates ≈ MAdES sequential append.

### Pure-parallel (PDF "finalize") explicitly NOT supported

A model where all signatures cover the same byte-frozen payload (PDF-style)
would require a sig-container structure with internal ordering, breaking the
append-only canonicalisation invariant. For Markdown — a fundamentally living
text format — sequential append captures intent better and keeps the
specification minimal.


## c. Cryptography & Key management

### Algorithms

| Algorithm | eIDAS level | Use case |
|---|---|---|
| `hmac-sha256` | Basic | Internal/automated signing where signer + verifier share a key (release pipelines, CI) |
| `ed25519` | Advanced | User-level signing with public-key cryptography |
| `ecdsa-p256` | Advanced/Qualified | Browser/HSM compatibility |
| `rsa-pss-sha256` | Qualified | PKI integration with X.509 chains |

> **DEC-1 open**: which subset must each implementation support? Proposal:
> all implementations MUST support `hmac-sha256` (zero-dep baseline) and SHOULD
> support `ed25519` (modern, small, fast). PKI-grade algorithms remain optional
> for the Advanced/Qualified profile.

### Key distribution & rotation

> **DEC-2 open**: key distribution model (DID, DNS-based, well-known URI, or
> embedded `key-id` referencing a Vecto/external key registry).

Initial proposal: signatures carry a `key-id` field. Implementations resolve
keys via:

1. A `.well-known/mades-keys` JSON manifest at the signer's domain (HTTPS,
   simple, decentralised).
2. A configured key registry (vendor-specific; e.g. Vecto provides one for
   its tenants).
3. Inline `key-id` URN that fully encodes the key location (e.g. DID URLs).

**Rotation strategy** (proposal): keys carry an `expires-at` and never delete
historical keys — a verifier walking historical signatures must be able to
reach a key valid at the `signed-at` of the signature. Recommended rotation
period: 12-24 months for HMAC, longer for asymmetric.


## d. Visual representation

> **Resolves DEC-5 (partially).** Three levels of visual fidelity, layered.
> Implementations MUST support level 1; level 2 is recommended; level 3 is
> optional.

### Level 1 — YAML comment header (zero-tooling, works in any renderer)

A MAdES sig-block MUST include a human-readable summary as a YAML comment on
the first line inside the block:

yaml
~~~mades-sig
# ✓ Signed by Alice (alice@example.com) — 2026-04-28
version: 1
signer: alice@example.com
signed-at: 2026-04-28T10:00:00Z
algorithm: hmac-sha256
signature: 7a3f...8b2c
~~~


The `#`-prefixed line is a valid YAML comment (preserved in canonicalisation;
ignored by parser; visible in plain-text and any Markdown renderer including
GitHub diff view, terminal `cat`, Notepad). This makes "this document is
signed by X on Y" universally legible without tooling.

### Level 2 — Renderer-aware badge (recommended for Markdown viewers)

A MAdES-aware renderer SHOULD detect `~~~mades-sig` blocks and replace them
with a styled badge (signer name, timestamp, validity status, hover for
signature details). This is the rich-UX path inside dedicated tools.

Renderers that don't support MAdES degrade gracefully to Level 1.

### Level 3 — Inline signature visual (optional, advanced)

For documents that need a "stamp"-like visual that survives even in
non-MAdES-aware renderers, an optional **`mades-visual` companion fence** MAY
appear before each `mades-sig` block, containing inline SVG or Unicode-art:

markdown
~~~mades-visual
┌─────────────────────────────────┐
│ ✓ SIGNED · alice@example.com    │
│ 2026-04-28 · HMAC-SHA256        │
└─────────────────────────────────┘
~~~

~~~mades-sig
# ✓ Signed by Alice — 2026-04-28
...
~~~


Tooling caveat: when the document is updated and re-signed, the visual block
must be regenerated to match. Implementations supporting Level 3 MUST produce
the visual block as part of the sign operation.

### Pre-declared signature fields with visual placeholders

For workflow docs using `~~~mades-sig-fields`, fields MAY declare
`placeholder: true` to instruct MAdES-aware renderers to display an empty
"awaiting signature" placeholder until filled. This is the closest analogue
to PDF's pre-defined signature widgets.


## e. Tooling (reference implementation)

The reference implementation provides two CLI tools, vendor-neutral in name
and behaviour:

- **`mades-sign`** — append a signature block to a Markdown file
  - Reads canonicalised content, computes signature, appends `~~~mades-sig` block
  - Supports all algorithms in § c
  - For workflow docs: validates field declaration + refuses double-signing
    of single-occupancy fields
- **`mades-verify`** — validate signatures in a Markdown file
  - Walks all `~~~mades-sig` blocks back-to-front
  - Reports: signer, timestamp, algorithm, validity per signature
  - Reports completeness against `~~~mades-sig-fields` declaration if present
  - Exit code: 0 = all valid + complete, 1 = invalid, 2 = valid but incomplete

Both tools are zero-dep Node.js scripts (initial reference). Spec is
language-agnostic — implementations in Python, Go, Rust expected.

> **Roll-out Tranche 1:** ship `mades-sign` + `mades-verify` as standalone
> scripts under `scripts/` in the Vecto repo, plus unit tests covering
> canonicalisation edge cases (CRLF vs LF, trailing whitespace, multi-byte
> chars).


## f. Integration in existing flows

> **DEC-4 open**: how do existing Vecto-specific signing mechanisms (commit
> HMAC trailers, release-signoff trailers) migrate to MAdES?

Proposed migration path:

| Mechanism | MAdES role | Migration |
|---|---|---|
| Git commit HMAC trailers | **Stays separate** — commits aren't Markdown | No change |
| Release sign-off chain | **Hybrid** — commit trailers continue for the chain-of-trust; release-notes `.md` ALSO get a MAdES signature as Layer 2 | Add MAdES as additional verification layer in `check-release-sign-off.mjs` |
| ADR / policy DOCs in graph | **Adopt MAdES** for human-author signatures | New flow; optional per doc |
| Vault-sync markdown export | **Pass-through** — sigs travel with the content | No code change beyond preservation |


## g. Compliance & Audit trail

> **DEC-1 open**: what eIDAS compliance level does the spec target?

Proposed three-tier profile system:

- **MAdES-Basic** — `hmac-sha256` only; symmetric key; suitable for
  internal/automated signing (CI, release pipelines). No eIDAS recognition.
- **MAdES-Advanced** — `ed25519` or `ecdsa-p256` with public-key
  distribution; fits eIDAS Advanced Electronic Signature definition (signer
  uniquely identifiable, sole control over signing key, tamper-evident).
- **MAdES-Qualified** — adds X.509 certificate chain + qualified trust
  service provider; meets eIDAS Qualified Electronic Signature requirements.

Each `~~~mades-sig` block declares its profile via the `algorithm` field;
verifiers can compute the highest profile a document achieves.

Audit trail is automatically established by the chain itself: each sig
records `signer` + `signed-at`, sequential ordering provides
witness-of-prior-state, and the canonicalisation rule makes any tampering
detectable.


## h. Roll-out & adoption strategy

**Tranche 1 (initial):**
1. Publish this spec as a public draft (proposed via ITbrouwerij / Vecto OS,
   vendor-neutral content)
2. Ship `mades-sign` + `mades-verify` reference scripts (Node.js)
3. Use internally in Vecto for release-notes signing as Layer 2
4. Solicit feedback from the open Markdown community

**Tranche 2:**
5. Add `ed25519` support (zero-dep via Node's built-in `crypto.sign`)
6. Reference implementations in Python + Rust
7. Renderer integration: Vecto GUI badge (Level 2), Obsidian plugin

**Tranche 3:**
8. Pre-declared field UI in Vecto (Level 3 with placeholders)
9. Submit to relevant standards bodies (W3C? IETF I-D?) if traction warrants
10. Qualified profile with certificate-chain support


## Provenance & credits

The MAdES specification was originally proposed by **ITbrouwerij**
(<https://itbrouwerij.be>) as part of the Vecto OS project
(<https://github.com/ITbrouwerij/vecto-os>). The reference implementation
ships in the Vecto OS repository under `scripts/mades-sign.mjs` and
`scripts/mades-verify.mjs`.

The specification itself is intended as a vendor-neutral open standard.
Vendor-specific extensions are accommodated via the `x-` field-prefix
namespace (see § a). The reference implementation's `x-vecto-*` fields are
illustrative; other implementations are free to define their own
`x-vendor-*` extensions.


## Open decisions

- **DEC-1** — eIDAS compliance level (proposal in § g)
- **DEC-2** — Key distribution & rotation strategy (proposal in § c)
- **DEC-4** — Migration of existing Vecto-sig mechanisms (proposal in § f)
- **DEC-5** — GUI validation status display — **partially resolved in § d (3-level visual model); GUI-specific UX still open**
