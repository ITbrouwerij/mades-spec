# MAdES Specification — Changelog

All notable changes to the MAdES specification. The reference implementation versions track this independently in `reference/package.json`.

Versioning follows [SemVer](https://semver.org) for the spec:
- **MAJOR** — breaking change to the wire format (existing signed documents may not verify)
- **MINOR** — additive feature (new optional fields / blocks; existing documents still verify)
- **PATCH** — clarification, typo fix, non-normative editorial change

---

## v0.3 — 2026-04-28 (current draft)

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
