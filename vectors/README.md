# Interoperability vectors

The answer files of the specification (§e). An implementation compares its
results with these files, not with its own reading of the text: three
implementations once read one sentence identically and identically wrongly.

Every file has the envelope of
[`mades-vectors-1.schema.json`](mades-vectors-1.schema.json): `$schema`, `spec`,
`note`, `cases`, and where it applies `specVersion`, `blockVersion` and
`signingInputEncoding`. The schema is loose about what a case holds, because
that differs per rule. This page describes it.

## Conventions

- **A document is a JSON string**, and its bytes are the UTF-8 encoding of that
  string. Line endings are escaped, so no checkout can rewrite them.
- **A signing input** is encoded as the file's `signingInputEncoding` says:
  `base64` of the UTF-8 bytes, or `utf8`, the text itself. That holds wherever
  the field sits in a case.
- **A digest** is `sha256:` followed by lowercase hex, over UTF-8 bytes, unless
  its name says base64 (`digestSha256Base64`, `signedDigestB64`).
- **An expectation that is absent is not pinned by that case.** It does not mean
  empty or false.

## The files

| file | rules | a case holds |
|---|---|---|
| `canonicalisation-vectors.json` | §a.2 | `input`, the `canonical` form, its `digest` |
| `boundary-vectors.json` | §a.14 | `document`, whether it is `conforming` |
| `block-vectors.json` | §a.1, §a.3, §a.5, §a.12, §a.13 | `document`, the expected reading of every block |
| `certificate-policy-vectors.json` | §a.11.2, §a.11.3 | `certificate`, what it asserts |
| `mades-v4-vectors.json` | §a.3, block version 4 | a signed document, its signing input, digest and signature, and the throwaway key |
| `mades-v5-vectors.json` | §a.3, §a.8, block version 5 | one real ceremony: document, signing input, signed digest, chain, timestamp token |
| `mades-lta-vectors.json` | §a.13 | `document`, the signature count and a verdict per layer |
| `mades-examples-vectors.json` | §a.1, §a.3, §a.8, §a.14 | the signed documents in `examples/`, the verdict of each signature, variants |

### `block-vectors.json`

`expect.blocks` lists every block in the document, in document order.
Signatures and archive layers are one sequence (§a.13). An empty list means the
document holds no block.

For each block:

- **`kind`** — `sig` for `<!-- mades-sig`, `archive-ts` for
  `<!-- mades-archive-ts`.
- **`unparsedLines`** — how many lines are neither a comment, a blank nor a
  well-formed field that can be placed (§a.1). From block version 4, any at all
  makes the block `unsupported` (§a.5). Such a block has no further
  expectations: a reader does not go on to read it.
- **`fields`** — the parsed fields. Every value is a string. A list is an array
  of strings in document order, a map an object of strings.
- **`comments`** — the comment lines, verbatim, in document order.
- **`signingInput`** (§a.3), **`canonicalContent`** (§a.2 applied to everything
  before the block's opening marker, which is the input of an archive layer,
  §a.13) and **`coversEntries`** (each `covers` entry split into `digest`,
  `mediaType` and `name`, §a.12) appear only where the case is about them.

### `certificate-policy-vectors.json`

`certificate` is the signing certificate, base64 of its DER. `mapping` gives
the OIDs the expectations assume, which are the reference assignments of
§a.11.2 and §a.11.3. A deployment with OIDs of its own gets other answers from
the same certificate.

- **`policyOids`** — the OIDs in certificatePolicies, in the order they appear.
- **`category`** — `human`, `automated`, or `null` when the certificate asserts
  none (§a.11.2: asserted but not anchored).
- **`permittedCommitments`** — the permitted set, or `null` when the
  certificate is unconstrained. Never an empty list.
- **`checks`** — one per commitment tried against the certificate. `commitment`
  is the block's field, `null` when the block has none; `effective` is the
  commitment compared (§a.11.3 rule 4); `constraint` is `unconstrained`,
  `permitted` or `exceeded`. `exceeded` makes the signature `invalid` (§a.5
  step 9).

### `mades-examples-vectors.json`

`document` is the file named in `file`, byte for byte. `expect` is about the
last block:

- **`blockKinds`** — the kinds of all blocks found.
- **`signerKind`** — the block's `signer-kind`.
- **`signingInputDigest`** — the digest of the signing input rebuilt from the
  document.
- **`signature`** — `valid` or `invalid`: the signature value checked with the
  algorithm the block names, over that signing input, under the public key of
  the first certificate in `certificate-chain`. Trust in the chain (§c.4) and
  the timestamp (§c.5) are not part of it.
- **`conforming`** — whether the document ends at its last block (§a.14).

`variants` each apply one edit to `document` and say what holds afterwards:

- **`replace`** — at UTF-8 byte offset `at`, the bytes of `from` are replaced by
  the bytes of `to`. `from` is what stands there; if it is not, the vector is
  broken.
- **`append`** — text added at the end.

## What has no vector

Obligations on a writer — refusing a block body that contains `--` (§a.1),
omitting empty lists and maps (§a.3), reading back what was written — are
tested in `reference/test/` and not here. A vector file states inputs and
answers, and a writer's refusal has no answer to state.
