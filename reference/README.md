# MAdES reference implementation (Node.js)

A working sign + verify cycle for block version 5. Zero dependencies — Node
built-ins only. Node 20+.

```
mades-canon.mjs    block location, parsing, canonicalisation, signing input
mades-verify.mjs   verify a document using nothing but the document
mades-sign.mjs     append a signature, signing with a local key
test/              19 tests, including one against a real signed document
```

## Verify

```sh
node mades-verify.mjs ../examples/05-a-real-signed-document.md
```

That file is signed by a real service, with a real certificate and an RFC 3161
timestamp. It is the acceptance test for everything here: an implementation
checked only against its own output proves that its encoder and its decoder
agree with each other, which is not the property a recipient needs.

```sh
node mades-verify.mjs doc.md --anchor issuer-root.pem   # check the chain
node mades-verify.mjs doc.md --key signer-public.pem    # raw-key path (§c.7)
```

**It never claims more than it checked.** A block it cannot parse, an algorithm
it does not implement, a document with no key available — each ends in *"no
verdict"* and a non-zero exit, never in a green tick. A false failure on a
verification page costs exactly what a false success costs, and both were
produced during this specification's development.

## Sign

```sh
node mades-sign.mjs keygen > signer.key
node mades-sign.mjs sign doc.md --key signer.key \
     --signer alice@example.com --kind human --commitment approval
```

`--kind` has **no default**. Defaulting it to `human` would give away the whole
of §a.11 in one line: every caller who forgets the flag would produce a document
claiming a person signed it, and forgetting is the most common way this goes
wrong.

The signer reads its own output back before reporting success. A signer that
does not is a signer that ships broken documents and hears about it from a
recipient.

## What this is not

**It signs with a raw key, not a certificate.** Issuing short-lived certificates
(§c.3) needs a certificate authority, an identity check and a confirmation
channel the signer controls — a service, not a script. Documents signed here
carry `key-id` rather than `certificate-chain`, and a verifier reports their
trust anchor as unrecognised, which is the honest answer for a key nobody
vouched for.

The half that *does* belong here is the half every implementation must agree on
byte-for-byte: how the signing input is built, how blocks are parsed, and what a
verifier is allowed to claim.

**Timestamps are read, not verified.** The field is reported with its size; its
contents are not parsed. Verifying RFC 3161 properly is a library, and pretending
otherwise would be the same mistake as the false green above.

## Known limitation

Block location is a byte scan for the opening marker, so **a document that
quotes it — a tutorial, an issue, this specification — produces a phantom
block**. The verifier reports *"may be prose describing one"* rather than
claiming the document is modified, but the underlying gap is real: a
specification cannot presently be signed with the thing it specifies.

The proposed fix is in SPEC.md under open decisions: recognise the marker only
at the start of a line, and skip fenced code regions. There is a test pinning
today's behaviour, and it flips when the fix lands.

## Tests

```sh
npm test
```

19 tests. The first suite verifies the real signed document, checks that a single
changed character breaks it, and asserts the file still has LF endings — that
last one is a `.gitattributes` test in disguise, and the reason CI runs on
Windows. Without `-text` on that file, git rewrites it on checkout there and the
signature fails for everyone who cloned the repository.
