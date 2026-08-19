# Example 2: Sequential multi-signature

Two parties sign the same document in turn. **Each signature covers everything
before its own block — including the previous signature.** That mirrors how
paper contracts work: the second signer endorses the document *and* the fact
that the first signer already endorsed it.

It is also why pure-parallel signing does not exist in MAdES (§b): the moment
Alice signs, the bytes Bob would have signed no longer exist.

---

## Mutual non-disclosure agreement

This NDA between Acme Corp and Initech protects information exchanged during
evaluation of project Cornerstone. It is in effect from the date of the second
signature below until 2028-08-14.

Confidential information includes source code, customer lists, pricing,
roadmaps, and technical architecture documents.

Either party may share information with employees, contractors or legal advisors
strictly bound by equivalent confidentiality terms.

---

## What this example demonstrates

- **Append, never merge.** Bob's block sits after Alice's, and Bob's signing
  input contains Alice's block verbatim. Remove Alice's signature and Bob's
  breaks too — which is exactly the property you want from a counter-signature.
- **Different commitments on the same document.** Alice signed `creation`
  (*"I produced this and I fix this version"*); Bob signed `approval` (*"I agree
  to the content"*). Both are signed fields, so neither can be re-read later as
  the other.
- **Order is evidence.** The `signed-at` values are within the document, under
  each signature. A reordering of the blocks would break both.
- **Verification is per-block.** A verifier reports each signature separately.
  One block failing does not make the others invalid — it makes *that* claim
  untrue, which is its own answer (§a.5).

> ⚠️ Base64 values are illustrative and truncated.

---

<!-- mades-sig
# ✓ Signed by alice@acme.example — creation — human — 2026-08-14
version: 5
algorithm: ed25519
signer: alice@acme.example
signer-kind: human
commitment: creation
signed-at: 2026-08-14T09:00:00+02:00
lang: en
certificate-chain:
  - MIIBkTCCATegAwIBAgIUYWxpY2UgYXQgYWNtZSBleGFtcGxlIGNl…
  - MIIB3jCCAYSgAwIBAgIUZXhhbXBsZSBpc3N1aW5nIGF1dGhvcml0…
timestamp: MIAGCSqGSIb3DQEHAqCAMIACAQMxDzANBglghkgBZQMEAgEFAD…
signature: 3QK8mFvXe2rTgYbNc7wPqLd9ZhJsAiUoEx1vRtBnMk4CfHyWpS…
-->

<!-- mades-sig
# ✓ Signed by bob@initech.example — approval — human — 2026-08-14
version: 5
algorithm: ed25519
signer: bob@initech.example
signer-kind: human
commitment: approval
signed-at: 2026-08-14T16:45:00+02:00
lang: en
certificate-chain:
  - MIIBkTCCATegAwIBAgIUYm9iIGF0IGluaXRlY2ggZXhhbXBsZSBj…
  - MIIB3jCCAYSgAwIBAgIUZXhhbXBsZSBpc3N1aW5nIGF1dGhvcml0…
timestamp: MIAGCSqGSIb3DQEHAqCAMIACAQMxDzANBglghkgBZQMEAgEFAD…
signature: 7wLpQnZ4dK1sXmEbVc9tRfGh2YjAiPoUx5vNtCkMr8DfHyWqTe…
-->
