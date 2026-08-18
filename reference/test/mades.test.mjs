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
  normalize, findBlocks, parseBlockBody, signingInputForBlock, serializeBlock, rulesFor, canonicalize,
} from '../mades-canon.mjs';

const REAL = new URL('../../examples/05-a-real-signed-document.md', import.meta.url);
const ABOUT = new URL('../../examples/06-signing-a-document-about-signing.md', import.meta.url);
const WORKED = new URL('../../examples/07-a-worked-example.md', import.meta.url);

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

describe('a signed document that describes signing', () => {
  // The v1.4 rules, proven on a real artefact rather than on a fixture built to
  // pass. This document quotes the opening marker in full four times and
  // contains a complete block inside a fence. Under the pre-v1.4 byte scan it
  // yielded two blocks, and a verifier reported over a sound document that it
  // could not be checked.
  const document = readFileSync(ABOUT, 'utf8');

  it('quotes the opening marker in full, repeatedly', () => {
    // If this ever drops to zero the test below proves nothing: a document that
    // does not mention the marker cannot demonstrate the rule.
    const quotes = (document.match(/<!-- mades-sig/g) ?? []).length;
    assert.ok(quotes >= 3, `expected the marker quoted several times, found ${quotes}`);
  });

  it('contains exactly ONE block regardless', () => {
    assert.equal(findBlocks(document).length, 1);
  });

  it('VERIFIES from the file alone', () => {
    const d = signingInputForBlock(document, 0);
    const leaf = new X509Certificate(Buffer.from(d.fields['certificate-chain'][0], 'base64'));
    const v = createVerify('sha256');
    v.update(d.signingInput, 'utf8');
    assert.ok(v.verify(leaf.publicKey, Buffer.from(d.signature, 'base64')));
  });

  it('survives checkout with its bytes intact', () => {
    assert.ok(!document.includes('\r'), 'the file must be stored and checked out with LF endings');
  });
});

// ---------------------------------------------------------------------------

describe('the worked example that supersedes 05', () => {
  // `05` still says a document about MAdES cannot be signed with MAdES. It was
  // signed before v1.4 and is deliberately left alone — a signed document is not
  // rewritten to say something more flattering. This one replaces it, and writes
  // the marker in full to show why it can.
  const document = readFileSync(WORKED, 'utf8');

  it('quotes the opening marker in ordinary prose', () => {
    assert.ok((document.match(/<!-- mades-sig/g) ?? []).length >= 2);
  });

  it('contains exactly ONE block, and verifies', () => {
    assert.equal(findBlocks(document).length, 1);
    const d = signingInputForBlock(document, 0);
    const leaf = new X509Certificate(Buffer.from(d.fields['certificate-chain'][0], 'base64'));
    const v = createVerify('sha256');
    v.update(d.signingInput, 'utf8');
    assert.ok(v.verify(leaf.publicKey, Buffer.from(d.signature, 'base64')));
  });

  it('survives checkout with its bytes intact', () => {
    assert.ok(!document.includes(String.fromCharCode(13)), 'the file must be stored and checked out with LF endings');
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

describe('locating blocks (§a.1)', () => {
  // Two rules, and both exist so that a document ABOUT MAdES can be signed with
  // MAdES. Until v1.4 this was a raw byte scan, and every tutorial, issue and
  // draft of this specification produced a phantom block — which a verifier
  // then reported over, telling the reader the opposite of the truth.

  it('ignores the marker inside a sentence', () => {
    const doc = 'A block opens with <!-- mades-sig and closes with -->.\n';
    assert.equal(findBlocks(doc).length, 0);
  });

  it('ignores a whole block inside a fenced example', () => {
    // The case that motivated the rule: this specification quotes complete
    // blocks, and they are not signatures on it.
    const doc = [
      '# How to read a block', '',
      '```', '<!-- mades-sig', 'version: 5', 'signer: alice@example.com', '-->', '```', '',
    ].join('\n');
    assert.equal(findBlocks(doc).length, 0);
  });

  it('ignores an indented marker, which Markdown renders as code', () => {
    assert.equal(findBlocks('text\n\n    <!-- mades-sig\n    version: 5\n    -->\n').length, 0);
  });

  it('finds the real block in a document that also demonstrates one', () => {
    // Both rules at once, which is the shape of every honest document about
    // this format.
    const doc = [
      'Written like this:', '',
      '```md', '<!-- mades-sig', 'version: 5', '-->', '```', '',
      'and inline as <!-- mades-sig too.', '',
      '<!-- mades-sig', 'version: 5', 'signer: alice@example.com', 'signature: AAAA', '-->', '',
    ].join('\n');
    const blocks = findBlocks(doc);
    assert.equal(blocks.length, 1);
    assert.equal(signingInputForBlock(doc, 0).fields.signer, 'alice@example.com');
  });

  it('recognises a fence indented up to three spaces, as CommonMark does', () => {
    // The corner where the hole reopens. An indented fence still renders as
    // code; a scanner that misses it, and a marker at column 0 inside it, and
    // the phantom block is back.
    const doc = ['text', '', '  ```', '<!-- mades-sig', 'version: 5', '-->', '  ```', ''].join('\n');
    assert.equal(findBlocks(doc).length, 0);
  });

  it('closes a fence only with the same character, and at least as many', () => {
    // CommonMark's rule. Getting it wrong reopens the hole: a ``` inside a
    // ~~~~ region would end the region early and expose the example inside it.
    const doc = ['~~~~', '```', '<!-- mades-sig', 'version: 5', '-->', '```', '~~~~', ''].join('\n');
    assert.equal(findBlocks(doc).length, 0);
  });

  it('does not read a block\'s own contents as fences', () => {
    const doc = ['<!-- mades-sig', 'version: 5', 'signature: AAAA', '-->', '', 'after', ''].join('\n');
    assert.equal(findBlocks(doc).length, 1);
    assert.equal(findBlocks(doc)[0].start, 0, 'a block at the very start of the file counts');
  });

  it('still refuses to treat an unterminated marker as a block', () => {
    // The safe direction, unchanged: unsigned content must never read as signed.
    assert.equal(findBlocks('text\n\n<!-- mades-sig\nversion: 5\n').length, 0);
  });

  it('SIGNS AND VERIFIES A DOCUMENT THAT DESCRIBES THE FORMAT', () => {
    // The acceptance test for v1.4, and the reason it exists. Before these
    // rules, this document could not be signed with the thing it specifies.
    const { privateKey } = generateKeyPairSync('ed25519');
    const publicKey = createPublicKey(privateKey);
    const prose = [
      '# The MAdES block', '',
      'A block opens with <!-- mades-sig at the start of a line:', '',
      '```', '<!-- mades-sig', 'version: 5', 'signer: bob@example.com', '-->', '```', '',
    ].join('\n');
    const fields = {
      version: 5, algorithm: 'ed25519', signer: 'alice@example.com',
      'signer-kind': 'human', commitment: 'approval', 'signed-at': '2026-08-14T10:00:00Z',
    };

    const draft = prose + '\n' + serializeBlock({ ...fields, signature: 'x' }) + '\n';
    const { signingInput } = signingInputForBlock(draft, 0);
    fields.signature = signRaw(null, Buffer.from(signingInput, 'utf8'), privateKey).toString('base64');

    const doc = prose + '\n' + serializeBlock(fields) + '\n';
    const back = signingInputForBlock(doc, 0);
    assert.equal(findBlocks(doc).length, 1, 'the quoted example must not count as a signature');
    assert.ok(verifyRaw(null, Buffer.from(back.signingInput, 'utf8'), publicKey, Buffer.from(back.signature, 'base64')));
  });
});

// ---------------------------------------------------------------------------

describe('§a.12 covers — the files that ride along', () => {
  // The shape follows from the field syntax, which has exactly two containers:
  // a list of scalars and a map of scalars. A list of maps is not expressible,
  // so an entry is one line and the name is the remainder of it.
  const doc = [
    'Agreement, with annexes.',
    '',
    '<!-- mades-sig',
    'version: 5',
    'algorithm: ed25519',
    'signer: alice@example.com',
    'signed-at: 2026-08-19T09:00:00Z',
    'covers:',
    '  - sha256:9f2c1d40 application/pdf annex-b-pricing.pdf',
    '  - sha256:41ab77e2 image/png floor plan, ground level.png',
    'signature: 00',
    '-->',
    '',
  ].join('\n');

  it('parses as a list of entries, in the order written', () => {
    const { fields } = parseBlockBody(findBlocks(doc)[0].body);
    assert.deepEqual(fields.covers, [
      'sha256:9f2c1d40 application/pdf annex-b-pricing.pdf',
      'sha256:41ab77e2 image/png floor plan, ground level.png',
    ]);
  });

  it('lets a name carry spaces, because it is the remainder of the line', () => {
    const { fields } = parseBlockBody(findBlocks(doc)[0].body);
    const [, , , name] = /^(\S+)[ ](\S+)[ ](.+)$/.exec(fields.covers[1]);
    assert.equal(name, 'floor plan, ground level.png');
  });

  it('is inside the signing input, so a changed digest is a changed signature', () => {
    // The whole point of the field. Were it outside, an annex could be swapped
    // and no value in the block would move (§a.3).
    const before = signingInputForBlock(doc, 0).signingInput;
    const after = signingInputForBlock(doc.replace("9f2c1d40", "9f2c1d41"), 0).signingInput;
    assert.notEqual(before, after);
  });

  it('survives a round trip through serializeBlock', () => {
    const { fields, comments } = parseBlockBody(findBlocks(doc)[0].body);
    const round = serializeBlock(fields, comments);
    assert.deepEqual(parseBlockBody(findBlocks(round)[0].body).fields.covers, fields.covers);
  });

  it('is a field this reader knows, so it does not make the block unsupported', () => {
    // §a.3 calls its list of covered fields complete, and §a.1 makes a bare name
    // this reader cannot place `unsupported`. Forgetting to register `covers`
    // would therefore turn every document carrying one into an unreadable block.
    const source = readFileSync(new URL('../mades-verify.mjs', import.meta.url), 'utf8');
    assert.match(source, /'covers',/);
  });
});

// ---------------------------------------------------------------------------

describe('§a.13 archive timestamps', () => {
  const doc = [
    'The agreement.',
    '',
    '<!-- mades-sig',
    'version: 5',
    'algorithm: ed25519',
    'signer: alice@example.com',
    'signature: aa',
    '-->',
    '',
    '<!-- mades-archive-ts',
    '# ⧗ Archive timestamp — 2026-08-19T09:12:04Z — covers everything above',
    'version: 5',
    'timestamp: MIAGCSqGSIb3',
    '-->',
    '',
  ].join('\n');

  it('is found as its own kind, not as a signature', () => {
    const blocks = findBlocks(doc);
    assert.deepEqual(blocks.map((b) => b.kind), ['sig', 'archive-ts']);
  });

  it('shares one index space with signatures', () => {
    // Separate numbering and the two kinds would stop seeing each other: a
    // signature appended later must cover the layer, and the layer must cover
    // every signature above it.
    assert.equal(findBlocks(doc).length, 2);
  });

  it('takes the SAME canonicalisation a signature takes — no second rule', () => {
    // §a.13: the document from its start up to this block own opening marker.
    // If this ever diverges from canonicalize(), the section is wrong.
    const upToLayer = canonicalize(doc, 1);
    assert.ok(upToLayer.includes('The agreement.'));
    assert.ok(upToLayer.includes('<!-- mades-sig'), 'the layer covers the signature above it');
    assert.ok(!upToLayer.includes('mades-archive-ts'), 'and not itself');
  });

  it('does not disturb the signature beneath it', () => {
    // The load-bearing property of the whole section. Placing a layer must not
    // change what any earlier signature signed, or every renewal would break
    // every signature it was meant to preserve.
    const zonder = ['The agreement.', '', '<!-- mades-sig', 'version: 5',
      'algorithm: ed25519', 'signer: alice@example.com', 'signature: aa', '-->', ''].join('\n');
    assert.equal(signingInputForBlock(doc, 0).signingInput, signingInputForBlock(zonder, 0).signingInput);
  });

  it('a second layer covers the first', () => {
    const twee = doc + ['<!-- mades-archive-ts', 'version: 5', 'timestamp: MIAB',
      '-->', ''].join('\n');
    const blocks = findBlocks(twee);
    assert.deepEqual(blocks.map((b) => b.kind), ['sig', 'archive-ts', 'archive-ts']);
    assert.ok(canonicalize(twee, 2).includes('MIAGCSqGSIb3'), 'the outer layer covers the inner one');
  });

  it('the marker is not a prefix of the signature marker', () => {
    // Deliberate: an archive timestamp read as a signature would be reported as
    // a signature with no signature value.
    assert.ok(!'<!-- mades-archive-ts'.startsWith('<!-- mades-sig'));
  });
});

// ---------------------------------------------------------------------------

describe('§a.5 a line that cannot be placed is reported, never dropped', () => {
  // FOUND WHILE DRAFTING §a.12. The first draft of `covers` was a list of maps,
  // and the parser accepted the first line and made the rest disappear — not
  // into `unparsed`, simply gone. A block like that received a verdict over
  // content the reader had not fully read, which is the exact outcome §a.5's
  // totality rule exists to prevent.
  const block = (body) => findBlocks(['x', '', '<!-- mades-sig', body, '-->', ''].join('\n'))[0];

  it('an indented key after a list item does not vanish', () => {
    const { fields, unparsed } = parseBlockBody(block([
      'covers:',
      '  - name: annex.pdf',
      '    media-type: application/pdf',
      '    digest: sha256:9f2c',
    ].join('\n')).body);
    assert.deepEqual(fields.covers, ['name: annex.pdf']);
    assert.equal(unparsed.length, 2, 'both orphaned lines are reported');
    assert.match(unparsed[0], /media-type/);
  });

  it('a list item after a map key does not vanish either', () => {
    const { unparsed } = parseBlockBody(block([
      'appearance:',
      '  mode: signature',
      '  - stray',
    ].join('\n')).body);
    assert.equal(unparsed.length, 1);
    assert.match(unparsed[0], /stray/);
  });

  it('and a well-formed map or list is untouched', () => {
    const { fields, unparsed } = parseBlockBody(block([
      'appearance:',
      '  mode: signature',
      'certificate-chain:',
      '  - MIIB',
      '  - MIIC',
    ].join('\n')).body);
    assert.deepEqual(fields.appearance, { mode: 'signature' });
    assert.deepEqual(fields['certificate-chain'], ['MIIB', 'MIIC']);
    assert.equal(unparsed.length, 0);
  });
});

