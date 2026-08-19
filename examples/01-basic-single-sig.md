# Example 1: Basic single signature

The simplest MAdES document: one agreement, one human signer.

The content is followed by a single `<!-- mades-sig -->` block. The signature
covers everything from the start of the document up to the opening `<!--`, plus
the block's own comment lines and fields. To verify: rebuild the signing input
(§a.3), check it against the certificate in the block, and check the certificate
chain against your trust anchor.

---

## Sample agreement

Acme Corp engages Initech to deliver project Cornerstone by 2027-03-31.

Total compensation: €50,000, paid in three milestones (40% / 40% / 20%).

Either party may terminate with 30 days written notice.

---

## What this example demonstrates

- **The block is an HTML comment, not a fence.** Open this file in any Markdown
  viewer: the agreement renders and the signature does not. Open it in an editor
  and the signature is right there. Invisible in view, present in source.
- **`signer-kind: human`** — mandatory since v5. This document says a person
  signed it, and the certificate says the same; a verifier holds the two against
  each other (§a.11).
- **`commitment: approval`** — *"I agree to the content"*, as opposed to
  `creation` (*"I produced this and I fix this version"*). The commitment is
  signed, so it cannot be reinterpreted afterwards.
- **The certificate travels with the document.** No key server to reach, no
  lookup that can fail in five years. The chain is in the file; only the trust
  anchor has to come from somewhere else.
- **The timestamp is what makes it last.** These certificates live for minutes
  (§c.3). The timestamp proves the signature existed while the certificate was
  valid, so an expired certificate is normal and is not a finding.

> ⚠️ The base64 values above are illustrative and truncated. This is a
> documentation example, not a verifiable document — see
> [`reference/`](../reference/) to produce a real one.

---

<!-- mades-sig
# ✓ Signed by jane.doe@acme.example — approval — human — 2026-08-14
version: 5
algorithm: ecdsa-p256
signer: jane.doe@acme.example
signer-kind: human
commitment: approval
signed-at: 2026-08-14T14:30:00+02:00
lang: en
certificate-chain:
  - MIIBkTCCATegAwIBAgIUY2hlY2sgdGhpcyBpcyBhbiBleGFtcGxl…
  - MIIB3jCCAYSgAwIBAgIUZXhhbXBsZSBpc3N1aW5nIGF1dGhvcml0…
timestamp: MIAGCSqGSIb3DQEHAqCAMIACAQMxDzANBglghkgBZQMEAgEFAD…
signature: MEUCIQDf4Xk2mQ8vRr1pLbYcT7wZ9nKjHgFsEaVuOxNdPqWiCg…
-->
