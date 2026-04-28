# Example 1: Basic single signature

The simplest possible MAdES use: one document, one signer.

The content below is followed by a single `~~~mades-sig` block. The signature covers everything from the start of this document up to (but excluding) the opening `~~~mades-sig` fence. To verify: strip the sig-block, normalise trailing whitespace, recompute HMAC-SHA256 with the shared key, compare with the `signature` field.

---

## Sample agreement

Acme Corp engages Initech to deliver project Cornerstone by 2027-03-31.

Total compensation: €50,000, paid in three milestones (40% / 40% / 20%).

Either party may terminate with 30 days written notice.

---

~~~mades-sig
# ✓ Signed by jane.doe@acme.example — 2026-04-28T14:30:00Z (HMAC-SHA256, MAdES-Basic)
version: 1
algorithm: hmac-sha256
signer: jane.doe@acme.example
signed-at: 2026-04-28T14:30:00Z
signature: 9f4e2b8c1d7a5f6e3b9c8d2a1f4e7b6c5d8a9f2e1b4c7d6a8f5e2b9c1d4a7f6e
~~~

---

## What this example demonstrates

- **Required fields only**: `version`, `algorithm`, `signer`, `signed-at`, `signature`. No vendor extensions, no field references, no key-id.
- **Level 1 visual representation**: the `# ✓ Signed by ...` comment line is YAML (a comment, parser-ignored, content-hash-included). Anyone reading the raw `.md` immediately sees who signed and when, even without MAdES-aware tooling.
- **HMAC baseline**: works with a pre-shared symmetric key. No public-key infrastructure needed. Good for internal/automated signing (CI, release pipelines). Doesn't qualify under eIDAS — for that, see Example 2's `ed25519` upgrade.

> ⚠️ **Note**: the `signature` field above is illustrative, not a real HMAC. Don't try to verify against any specific key — this is a documentation example.
