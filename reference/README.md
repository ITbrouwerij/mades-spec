# MAdES command line

The implementation of MAdES is
[`@itbrouwerij/mades-verify`](https://www.npmjs.com/package/@itbrouwerij/mades-verify),
published on npm under MIT. It is what the vectors in [`../vectors/`](../vectors/)
are run against, and what signs documents in production.

This directory holds two command lines around it, and the tests. Node 20+.

```
mades-verify.mjs   verify a document using nothing but the document
mades-sign.mjs     append a signature, signing with a local key
test/              every file in ../vectors/ through the package, and the command lines
```

```sh
npm install        # from the repository root; no token, no registry setup
npm test
```

**Until v1.10.1 this directory was an implementation of its own** — a block
parser, a canonicaliser, a reader of certificate policies — beside the one that
signs real documents. Two readings of one format drift apart, and nothing in
either says when. Every judgement now comes from the package; what stays here
is the command line.

## Verify

```sh
node mades-verify.mjs ../examples/05-a-real-signed-document.md
node mades-verify.mjs doc.md --anchor issuer-root.pem   # check the chain
node mades-verify.mjs doc.md --key signer-public.pem    # raw-key path (§c.7)
```

The same invocation and the same report as before v1.11, with three
differences, all the package's:

- **The timestamp is verified**, not only stated: the token, what it covers, and
  whether its time falls inside the certificate's validity (§c.5).
- **Archive layers are verified** against their tokens (§a.13), and a broken
  layer is a failure.
- **The appearance is checked** against its digest (§a.8).

`--anchor` trusts the root it is given for both signing and timestamping.

**It never claims more than it checked.** A block it cannot parse, an algorithm
it does not implement, a document with no key available — each ends in *"no
verdict"* and a non-zero exit, never in a green tick. Exit codes: `0` when at
least one signature verifies and nothing failed, `1` otherwise, `2` for a usage
error.

## Sign

```sh
node mades-sign.mjs keygen > signer.key
node mades-sign.mjs sign doc.md --key signer.key \
     --signer alice@example.com --kind human --commitment approval
```

Other options: `--at`, `--lang`, `--automation`, `--key-id`.

The package builds the signing input and writes the block, through the
`prepare` / `finalize` pair §e requires of every implementation. The key signs
the prepared input with `node:crypto`; that is the one step the package leaves
to its caller, because it holds no keys.

`--kind` has **no default**. Defaulting it to `human` would give away the whole
of §a.11 in one line: every caller who forgets the flag would produce a document
claiming a person signed it.

Two things differ from the writer before v1.11, both the package's:

- **The content above the block is written in its canonical form** (§a.2): a
  byte-order mark, CRLF line endings and trailing whitespace are gone from the
  signed file. What a verifier rebuilds is then what is on disk.
- **The comment line does not name the category**:
  `# ✓ Signed by alice@example.com — approval — 2026-08-14`. §d says it SHOULD
  (v5); the former writer did.

The signer reads its own output back before reporting success.

## What this is not

**It signs with a raw key, not a certificate.** Issuing short-lived certificates
(§c.3) needs a certificate authority, an identity check and a confirmation
channel the signer controls — a service, not a script. Documents signed here
carry `key-id` rather than `certificate-chain`, and verify with `--key`; no
issuer vouches for the name on them, which is the honest answer for a key
nobody vouched for.

§e describes more options than these two command lines have — `--cert-chain`,
`--tsa`, `--format`, `--appearance` among them. They are not here.
