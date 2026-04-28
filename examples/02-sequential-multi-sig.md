# Example 2: Sequential multi-signature

Two parties sign the same document in sequence. Each signature covers everything before its own opening fence — including the prior signature block. This mirrors how legal contracts work: each subsequent signer endorses the document state including all prior endorsements.

This example also upgrades to `ed25519` (MAdES-Advanced profile), which uses public-key cryptography. The `key-id` field tells verifiers where to fetch the public key.

---

## Mutual non-disclosure agreement

This NDA between Acme Corp and Initech protects information exchanged during evaluation of project Cornerstone (initial discussion 2026-04-15). The agreement is in effect from the date of the second signature below until 2028-04-28.

Confidential information includes: source code, customer lists, pricing, roadmaps, and technical architecture documents.

Either party may share information with employees, contractors, or legal advisors strictly bound by equivalent confidentiality terms.

---

~~~mades-sig
# ✓ Signed by alice@acme.example — 2026-04-28T09:00:00Z (Ed25519, MAdES-Advanced)
version: 1
algorithm: ed25519
signer: alice@acme.example
signed-at: 2026-04-28T09:00:00Z
key-id: https://acme.example/.well-known/mades-keys#alice-2026
signature: aGVsbG93b3JsZHRoaXNpc25vdGFyZWFsc2lnbmF0dXJlanVzdGFwbGFjZWhvbGRlcg==
~~~

~~~mades-sig
# ✓ Signed by bob@initech.example — 2026-04-28T11:45:00Z (Ed25519, MAdES-Advanced)
version: 1
algorithm: ed25519
signer: bob@initech.example
signed-at: 2026-04-28T11:45:00Z
key-id: did:web:initech.example#bob-master
signature: dGhpc2lzbm90YXJlYWxzaWduYXR1cmVlaXRoZXJqdXN0YW5leGFtcGxlcGxhY2Vob2xkZXI=
~~~

---

## What this example demonstrates

- **Sequential signing**: Alice signs first; Bob signs second. Bob's signature covers everything above his block — including Alice's full sig-block. This means: tampering with Alice's signature after-the-fact would invalidate Bob's signature.
- **Walk-back verification**: to verify, start with the *last* sig-block. Strip it, normalise, compute, compare. Then strip the next one, compute, compare. Each signature is individually valid only against the document state that existed when *it* was added.
- **Public-key cryptography (ed25519)**: no shared secret. Each signer holds their own private key; verifiers fetch the corresponding public key via `key-id`.
- **Two key-id resolution patterns**:
  - Alice uses an HTTPS URL pointing to a `.well-known/mades-keys` JSON manifest with a key fragment.
  - Bob uses a [DID URL](https://www.w3.org/TR/did-core/) (`did:web`) with a key fragment. Verifiers that support DID resolution can use this directly.
- **Order matters**: the order of `~~~mades-sig` blocks is the order of signing. Reordering is detectable (would break signatures).
