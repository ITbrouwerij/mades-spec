# Example 3: Staged workflow with pre-declared signature fields

A document-signing workflow with three stages: drafting (serial, two authors), review (parallel, three reviewers, two required), and final signoff (serial, one approver). The `~~~mades-sig-fields` declaration block at the top declares the workflow shape; `~~~mades-sig` blocks fill in the fields as signers complete their parts.

This is the MAdES analogue of a DocuSign / Adobe Sign template: declarative signature slots with role-based ordering and gating between stages.

---

~~~mades-sig-fields
stages:
  - id: drafting
    mode: serial
    fields:
      - id: lead-author
        role: Lead Author
        required: true
      - id: co-author
        role: Co-author
        required: true

  - id: review
    mode: parallel
    depends_on: drafting
    fields:
      - id: legal-review
        role: Legal Reviewer
        required: true
      - id: security-review
        role: Security Reviewer
        required: true
      - id: technical-review
        role: Technical Reviewer
        required: false

  - id: signoff
    mode: serial
    depends_on: review
    fields:
      - id: ceo-approval
        role: CEO Approval
        required: true
~~~

# ADR-024: Adopting MAdES for internal document signing

## Context

Acme Corp signs roughly 200 internal policy and contract documents per quarter. Today this happens via DocuSign, costing approximately €12,000/year and creating a vendor dependency for legally binding artifacts.

This ADR proposes adopting MAdES (Markdown Advanced Electronic Signatures) for internal documents that don't require formal qualified electronic signatures under eIDAS. External-facing legal documents requiring qualified signatures will continue using a qualified-signature provider (currently TBD — see DEC-1).

## Decision

We will:

1. Implement MAdES-Advanced (ed25519) for all internal policies, ADRs, RFCs, and security reviews.
2. Publish per-employee `mades-keys` manifests at `https://keys.acme.example/<email>.json`.
3. Build a thin internal tool (`acme-sign`) wrapping the MAdES reference implementation, with our key-management integrated.
4. Continue using DocuSign for external contracts requiring qualified eIDAS signatures (estimated <20% of current volume).

## Consequences

Reduced cost (~€10,000/year saved). Internal artifacts become self-contained (`.md` file = signed document, no portal dependency). Minor onboarding cost for staff (5-minute training, internal tool handles everything). External legal exposure unchanged — qualified signatures stay with the certified provider.

---

~~~mades-sig
# ✓ Signed by alice@acme.example — 2026-04-28T09:00:00Z [field: lead-author]
version: 1
algorithm: ed25519
signer: alice@acme.example
signed-at: 2026-04-28T09:00:00Z
field: lead-author
key-id: https://keys.acme.example/alice@acme.example.json#current
signature: bGVhZGF1dGhvcnNpZ25hdHVyZXBsYWNlaG9sZGVydmFsdWVoZXJl
~~~

~~~mades-sig
# ✓ Signed by carol@acme.example — 2026-04-28T11:30:00Z [field: co-author]
version: 1
algorithm: ed25519
signer: carol@acme.example
signed-at: 2026-04-28T11:30:00Z
field: co-author
key-id: https://keys.acme.example/carol@acme.example.json#current
signature: Y29hdXRob3JzaWduYXR1cmVwbGFjZWhvbGRlcnZhbHVlaGVyZQ==
~~~

~~~mades-sig
# ✓ Signed by david@acme.example — 2026-04-29T08:15:00Z [field: legal-review]
version: 1
algorithm: ed25519
signer: david@acme.example
signed-at: 2026-04-29T08:15:00Z
field: legal-review
key-id: https://keys.acme.example/david@acme.example.json#current
signature: bGVnYWxyZXZpZXdzaWduYXR1cmVwbGFjZWhvbGRlcnZhbHVlaGVyZQ==
~~~

~~~mades-sig
# ✓ Signed by eva@acme.example — 2026-04-29T10:42:00Z [field: security-review]
version: 1
algorithm: ed25519
signer: eva@acme.example
signed-at: 2026-04-29T10:42:00Z
field: security-review
key-id: https://keys.acme.example/eva@acme.example.json#current
signature: c2VjdXJpdHlyZXZpZXdzaWduYXR1cmVwbGFjZWhvbGRlcnZhbHVlaGVyZQ==
~~~

---

## Document status

This document is **partially signed**: the `drafting` and `review` stages have completed (all required fields filled). The `signoff` stage is now open and awaiting `ceo-approval`. Once that signature is appended, the document is considered fully signed under its declared workflow.

Note that the `technical-review` field in the `review` stage was declared `required: false`, so its absence does not block stage progression.

## What this example demonstrates

- **Three-stage workflow**: drafting → review → signoff. Each stage opens only when the prior stage's required fields are complete.
- **Mode mixing**: `drafting` is `serial` (Alice signs before Carol), `review` is `parallel` (David and Eva sign in any order).
- **Required vs optional fields**: `technical-review` is optional; the document can progress to `signoff` without it.
- **Field-id binding**: each `~~~mades-sig` block references its declared field via `field: <id>`. Signers cannot fill fields that aren't declared, and (per MAdES rules) cannot double-fill a single-occupancy field.
- **Self-describing workflow status**: the document itself is the canonical state. A workflow engine reading this file can determine "stage `signoff` is now open, awaiting signer for field `ceo-approval`" — no external workflow database needed. The file is the truth.
- **Workflow engine is a separate concern**: MAdES declares the shape of the workflow; an orchestration engine (sending invitations, reminders, dashboard) reads the declaration and drives signers through it. Out of scope for the spec itself.
