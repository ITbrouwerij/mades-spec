# Example 4: A machine signed this, and a field you do not recognise

Two things that are new in block version 5 and specification v1.3, in one
document — because in practice they arrive together.

Markdown is where humans and machines take turns. A release note written by a
pipeline, a report generated nightly, a decision minuted by an agent: the
document has always been able to say *who* signed, and since v5 it says *what*
signed. And an automated signer is exactly the kind that carries vendor-specific
context a reader may not know.

---

## Release attestation — cornerstone-api v2.4.0

Build `#4821` produced from commit `9f4e2b8` on 2026-08-14.

All 1 284 tests passed. SBOM attached to the release. No known CVEs in the
dependency tree at build time.

---

## What this example demonstrates

### `signer-kind: automated` — the question PAdES never had to ask

`human` and `automated` is a closed, binary distinction and it is **inside the
signed fields**, so it cannot be edited without breaking the signature. The
certificate carries the same category, and a verifier holds the two against each
other (§a.11). A pipeline cannot quietly present itself as a person.

`automation: ci-pipeline` refines the machine side. That vocabulary is
deliberately open — the useful terms will be discovered, not designed.

> Note the Level-1 comment line names the category too. For a reader in a plain
> text editor, that line is the only place the distinction can appear at all.

### `build.acme.*` — a vendor field you are not expected to understand

Two fields here belong to Acme and to nobody else. A conforming verifier that
has never heard of Acme must do three things with them (§a.1, §d):

1. **Sign them.** They were in the signing input; that is not optional.
2. **Preserve them** when re-encoding. Dropping a signed field breaks the
   signature and, worse, hides that it existed.
3. **Show them**, with the namespace and without inventing a meaning —
   *"build.acme.pipeline-run = 4821 (meaning not known to this reader)"*.

That third one is new in v1.3, and it exists because two independent
implementations got it wrong in the same direction: both preserved unknown
signed fields faithfully and both showed none of them. A field that falls under
the signature and that the reader never sees is the mirror image of a field that
disappears.

### Why the namespace, and why not `x-`

`build.acme.*` is reverse-DNS: Acme controls `acme.example`, so it controls the
namespace, and no registry has to exist for that to be true. Where two
implementations would otherwise both invent `build-id` with different meanings,
they now cannot collide.

Earlier drafts used an `x-` prefix. [RFC 6648](https://www.rfc-editor.org/rfc/rfc6648.txt)
(BCP 178) recommends against exactly that, and forbids a protocol from
stipulating that such a prefix means "unstandardised" — because unstandardised
parameters become de facto standards anyway, and then the deployed world carries
both spellings forever. The namespace says the same thing without the trap.

> ⚠️ Base64 values are illustrative and truncated.

---

<!-- mades-sig
# ✓ Signed by ci@acme.example — creation — automated — 2026-08-14
version: 5
algorithm: ecdsa-p256
signer: ci@acme.example
signer-kind: automated
automation: ci-pipeline
commitment: creation
signed-at: 2026-08-14T03:12:44Z
lang: en
build.acme.pipeline-run: 4821
build.acme.source-commit: 9f4e2b8
certificate-chain:
  - MIIBkTCCATegAwIBAgIUY2kgYXQgYWNtZSBleGFtcGxlIGJ1aWxk…
  - MIIB3jCCAYSgAwIBAgIUZXhhbXBsZSBpc3N1aW5nIGF1dGhvcml0…
timestamp: MIAGCSqGSIb3DQEHAqCAMIACAQMxDzANBglghkgBZQMEAgEFAD…
signature: MEQCIBqZ7XnRw2LmKdVeC5oPtYfHg8sJa1UxNbEiOrPvWkCmAg…
-->
