/**
 * Tests for the MAdES reference implementation.
 *
 * The centrepiece is the first suite: a document signed by a real service with
 * a real certificate, verified from the file and nothing else. Everything after
 * it is a property this implementation must not lose.
 *
 * A reference implementation checked only against its own output proves that
 * the encoder and the decoder agree with each other. That is not the property
 * anyone needs, and it is exactly how both of the implementations that produced
 * this specification managed to be confidently wrong.
 */
import { strict as assert } from 'node:assert';
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as signRaw, verify as verifyRaw, X509Certificate, createVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import {
  normalize, findBlocks, parseBlockBody, signingInputForBlock, serializeBlock, rulesFor,
} from '../mades-canon.mjs';

const REAL = new URL('../../examples/05-a-real-signed-document.md', import.meta.url);

// ---------------------------------------------------------------------------

describe('a real signed document', () => {
  const document = readFileSync(REAL, 'utf8');

  it('contains exactly one signature block', () => {
    assert.equal(findBlocks(document).length, 1);
  });

  it('VERIFIES from the file alone', () => {
    // The whole claim of the format, in four lines. No database, no key server,
    // no knowledge of how the document was produced.
    const d = signingInputForBlock(document, 0);
    const leaf = new X509Certificate(Buffer.from(d.fields['certificate-chain'][0], 'base64'));
    const v = createVerify('sha256');
    v.update(d.signingInput, 'utf8');
    assert.ok(v.verify(leaf.publicKey, Buffer.from(d.signature, 'base64')));
  });

  it('breaks when a single character changes', () => {
    // Without this, the test above is satisfied by a verifier that always
    // returns true.
    const tampered = (document[0] === 'x' ? 'y' : 'x') + document.slice(1);
    const d = signingInputForBlock(tampered, 0);
    const leaf = new X509Certificate(Buffer.from(d.fields['certificate-chain'][0], 'base64'));
    const v = createVerify('sha256');
    v.update(d.signingInput, 'utf8');
    assert.equal(v.verify(leaf.publicKey, Buffer.from(d.signature, 'base64')), false);
  });

  it('survives checkout with its bytes intact', () => {
    // This is a `.gitattributes` test wearing a crypto disguise, and it is the
    // reason the CI matrix includes Windows. Without `-text` on this file, git
    // rewrites its line endings on checkout there, and the signature above
    // fails for every reader who cloned the repository — silently, and blamed
    // on the format rather than on the checkout.
    assert.ok(!document.includes('\r'), 'the file must be stored and checked out with LF endings');
  });

  it('is block version 5 and names its signer category', () => {
    const { fields } = signingInputForBlock(document, 0);
    assert.equal(rulesFor(fields), 5);
    assert.ok(['human', 'automated'].includes(fields['signer-kind']));
  });

  it('carries the seal INSIDE what was signed', () => {
    // The appearance is created during the ceremony and falls within the
    // signing input. Rebuilding the input from the pre-signing content misses
    // it — 9 KB, in the case this document came from — and concludes that a
    // sound signature is broken.
    const { signingInput } = signingInputForBlock(document, 0);
    assert.ok(signingInput.includes('data:image/'), 'the embedded seal belongs in the signing input');
  });
});

// ---------------------------------------------------------------------------

describe('canonicalisation (§a.2)', () => {
  it('strips a BOM, normalises CRLF and lone CR', () => {
    assert.equal(normalize('﻿a\r\nb\rc'), 'a\nb\nc\n');
  });

  it('strips trailing whitespace per line but never inside one', () => {
    assert.equal(normalize('a  b   \nc\t\n'), 'a  b\nc\n');
  });

  it('collapses trailing newlines to exactly one', () => {
    assert.equal(normalize('a\n\n\n'), 'a\n');
    assert.equal(normalize(''), '');
  });
});

// ---------------------------------------------------------------------------

describe('parsing is total (§a.5)', () => {
  it('reads flat fields, nested maps and lists', () => {
    const { fields } = parseBlockBody([
      'version: 5',
      'appearance:',
      '  mode: signature',
      '  digest: sha256:abc',
      'certificate-chain:',
      '  - MIIB',
      '  - MIIC',
    ].join('\n'));
    assert.equal(fields.version, '5');
    assert.deepEqual(fields.appearance, { mode: 'signature', digest: 'sha256:abc' });
    assert.deepEqual(fields['certificate-chain'], ['MIIB', 'MIIC']);
  });

  it('keeps a line it cannot read instead of discarding it', () => {
    // The gap v4 closed. A bare line used to be appended to the previous field
    // or dropped, which meant a line reading "# WARNING: this contract has been
    // declared void" could sit inside a signed block without breaking anything.
    const { unparsed } = parseBlockBody('version: 5\nthis is not a field');
    assert.deepEqual(unparsed, ['this is not a field']);
  });

  it('covers EVERY comment line from v4 onward', () => {
    const body = '# first\n# second\nversion: 5\nsigner: a@b.example';
    const doc = `content\n\n<!-- mades-sig\n${body}\n-->\n`;
    const { signingInput } = signingInputForBlock(doc, 0);
    assert.ok(signingInput.includes('# first'));
    assert.ok(signingInput.includes('# second'), 'a second comment line must be signed too');
  });

  it('reads a v3 block under v3 rules, so old signatures keep verifying', () => {
    const body = '# first\n# second\nversion: 3\nsigner: a@b.example';
    const doc = `content\n\n<!-- mades-sig\n${body}\n-->\n`;
    const { signingInput, rules } = signingInputForBlock(doc, 0);
    assert.equal(rules, 3);
    assert.ok(!signingInput.includes('# second'), 'v3 covered only the first comment line');
  });
});

// ---------------------------------------------------------------------------

describe('vendor fields (§a.1)', () => {
  it('accepts a reverse-DNS namespace as a field name', () => {
    // The pattern used to be [A-Za-z0-9_-]+, which rejected the very names the
    // specification requires. Every vendor field parsed as `unsupported`.
    const { fields, unparsed } = parseBlockBody('version: 5\nbuild.vecto.void: true');
    assert.equal(fields['build.vecto.void'], 'true');
    assert.deepEqual(unparsed, []);
  });

  it('signs an unknown vendor field like any other', () => {
    const doc = 'content\n\n<!-- mades-sig\n# c\nversion: 5\nbuild.acme.run: 4821\n-->\n';
    const { signingInput } = signingInputForBlock(doc, 0);
    assert.ok(signingInput.includes('build.acme.run: 4821'));
  });
});

// ---------------------------------------------------------------------------

describe('serialisation', () => {
  it('refuses a body containing `--`, which would truncate the comment', () => {
    // An HTML comment ends at the first `--`. A block containing one never
    // reaches its `-->`, so the document reads as UNSIGNED rather than invalid:
    // silent and total.
    assert.throws(() => serializeBlock({ version: 5, note: 'a -- b' }), /truncate/);
  });

  it('omits an empty list rather than writing a bare key', () => {
    // A bare `key:` parses back as absent, which breaks the round-trip.
    assert.ok(!serializeBlock({ version: 5, 'certificate-chain': [] }).includes('certificate-chain'));
  });
});

// ---------------------------------------------------------------------------

describe('sign → verify round trip', () => {
  it('produces a signature the verifier accepts', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const publicKey = createPublicKey(privateKey);
    const fields = {
      version: 5, algorithm: 'ed25519', signer: 'alice@example.com',
      'signer-kind': 'human', commitment: 'approval', 'signed-at': '2026-08-14T10:00:00Z',
    };
    const comment = '# ✓ Signed by alice@example.com — approval — human — 2026-08-14';

    const draft = 'content\n\n' + serializeBlock({ ...fields, signature: 'x' }, [comment]) + '\n';
    const { signingInput } = signingInputForBlock(draft, 0);
    fields.signature = signRaw(null, Buffer.from(signingInput, 'utf8'), privateKey).toString('base64');

    const doc = 'content\n\n' + serializeBlock(fields, [comment]) + '\n';
    const back = signingInputForBlock(doc, 0);

    assert.equal(back.signingInput, signingInput, 'the written block must rebuild to what was signed');
    assert.ok(verifyRaw(null, Buffer.from(back.signingInput, 'utf8'), publicKey, Buffer.from(back.signature, 'base64')));
  });
});

// ---------------------------------------------------------------------------

describe('the known limitation', () => {
  it('mistakes prose that quotes the opening marker for a block', () => {
    // Documented rather than hidden. A document *about* MAdES — a tutorial, an
    // issue, this specification — produces a phantom block, and a verifier that
    // reports "modified" over it tells a reader the opposite of the truth.
    //
    // When the fix lands (marker only at line start, fenced regions skipped)
    // this test flips to asserting zero blocks.
    const doc = 'A block opens with <!-- mades-sig and closes with -->.\n';
    assert.equal(findBlocks(doc).length, 1, 'today it finds one; see SPEC.md open decisions');
    assert.equal(signingInputForBlock(doc, 0).signature, null, 'and it carries no signature');
  });
});
