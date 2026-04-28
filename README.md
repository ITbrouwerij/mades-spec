# MAdES — Markdown Advanced Electronic Signatures

> **Status:** Draft proposal · **Version:** 0.3 · **License:** [CC-BY-4.0](LICENSE-SPEC) (spec) / [MIT](LICENSE-CODE) (reference code)
>
> **Seeking peer review.** This is an early-stage proposal — not an accepted standard. Specific technical feedback (canonicalisation edge cases, algorithm choices, key-distribution model) is more valuable than a general "is this useful?" discussion.

## What is MAdES?

MAdES is a vendor-neutral specification for embedding cryptographic signatures **directly inside Markdown files** via a trailing fenced code block. The signature travels with the document — no separate `.sig` companion file, no orphan-file synchronisation problems, and the document still renders as plain Markdown in any viewer.

Think of MAdES as the Markdown analogue of [PAdES](https://en.wikipedia.org/wiki/PAdES) (PDF), [XAdES](https://en.wikipedia.org/wiki/XAdES) (XML), and [JAdES](https://www.etsi.org/deliver/etsi_ts/119100_119199/119182/01.01.01_60/ts_119182v010101p.pdf) (JSON Web Signatures). It targets the same eIDAS-style trust model, but for the format engineers actually write specs, ADRs, contracts and policies in.

## The 30-second example

```markdown
# Service Agreement

This agreement between Acme Corp and Initech is valid until 2027-12-31.

~~~mades-sig
# ✓ Signed by alice@acme.example — 2026-04-28
version: 1
algorithm: hmac-sha256
signer: alice@acme.example
signed-at: 2026-04-28T10:15:30Z
signature: 7a3f...8b2c
~~~
```

That's it. The signature covers everything before its own opening fence. Verification is a strip-and-recompute. Multiple signers can append; the format supports both sequential signing and staged workflows (serial → parallel → final-signoff patterns).

## Why this is interesting (or maybe useful)

- **Markdown is becoming a serious document format.** ADRs, RFCs, DAO governance, contracts-as-code, GitHub-rendered policies — all live in `.md`. They have **no native signing**. Today the best you can do is a detached `.sig` file (lost in copy-paste) or wrap the content in JWS (loses Markdown rendering).
- **Single-file portability.** Copy the file. Forward in email. Drop in a chat. The signature stays attached.
- **Renders as a code block in any Markdown viewer.** No special tooling required just to read the document. MAdES-aware renderers can show a richer badge; non-aware renderers show a YAML block with a human-readable header line.
- **Bridges to existing standards.** The format intentionally mirrors PAdES/XAdES design patterns (incremental updates, signature widgets, profile tiers for eIDAS Basic/Advanced/Qualified) — so existing crypto + legal frameworks apply.
- **Open standard intent.** Vendor-neutral field names. Vendor extensions live in an `x-` namespace. Anyone can implement.

## Quick links

- 📜 [**Full specification (SPEC.md)**](SPEC.md)
- 📚 [**Worked examples**](examples/)
- 🛠️ [**Reference implementation (Node.js)**](reference/)
- 📜 [**Changelog**](CHANGELOG.md)

## Status

**This is a draft proposal seeking peer review.** No part of MAdES is implemented in production-grade tooling yet. The reference scripts in [`reference/`](reference/) are functional but minimal — they're a proof of "this works", not a hardened production library.

Specific feedback I'm looking for:

1. **Canonicalisation rule** (SPEC.md § a) — does the trim+normalise rule break in any edge case I haven't thought of? UTF-8 BOM, CRLF vs LF, fenced-code-blocks containing `~~~` themselves, etc.
2. **Algorithm matrix** (SPEC.md § c) — is the `hmac-sha256` baseline + optional `ed25519`/`ecdsa-p256`/`rsa-pss-sha256` ladder the right ramp? Did I miss something obvious?
3. **Key distribution** (SPEC.md § c) — `.well-known/mades-keys` + DID URLs + vendor registries. Is the precedence sensible? Is there a better pattern from JOSE / OpenID land?
4. **Workflow expressivity** (SPEC.md § b) — does the `mades-sig-fields` stages syntax cover real document-signing-workflow patterns (DocuSign / Adobe Sign equivalents)?
5. **eIDAS profile mapping** (SPEC.md § g) — am I oversimplifying the legal tiers? Real-world legal review wanted.

## Provenance

Originally proposed by Jan Smets - ITbrouwerij ([itbrouwerij.be](https://itbrouwerij.be)).

Reference implementation lives in this repo. The MAdES specification itself is intended as a vendor-neutral open standard — vendor extensions go in the `x-` field-prefix namespace.

## License

- **Specification text** ([`SPEC.md`](SPEC.md), [`README.md`](README.md), [`CHANGELOG.md`](CHANGELOG.md), [`examples/`](examples/)): [Creative Commons Attribution 4.0 International (CC-BY-4.0)](LICENSE-SPEC). Promote, fork, implement, criticise — please attribute.
- **Reference code** ([`reference/`](reference/)): [MIT](LICENSE-CODE).

## Contributing / feedback

- **Issues** → for spec discussion, edge-cases, algorithm questions, naming bikesheds
- **Pull requests** → especially for examples, reference-implementation hardening, language ports (Python / Rust / Go welcome)
- **Forum threads** → cross-posts on [CommonMark Talk](https://talk.commonmark.org), Hacker News, etc. linked from this repo's [Discussions](../../discussions)
