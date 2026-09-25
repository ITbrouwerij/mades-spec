/**
 * Tests for the MAdES reference implementation.
 *
 * WHAT MOVED OUT (v1.10.1). The cases about the format and the verdict — where
 * a block is, how it parses, what it signs, the three real signed documents in
 * examples/ — are published vectors now, in vectors/, and vectors.test.mjs runs
 * this implementation over them. Here they could be read by one implementation
 * only, which is the one thing a test of a specification must not depend on.
 *
 * What remains is what a vector file cannot carry: the writer (serialisation
 * and round trips with a fresh key), the reference's own source, properties of
 * the files in this repository, and cases whose rule another vector file
 * already pins.
 *
 * A reference implementation checked only against its own output proves that
 * the encoder and the decoder agree with each other. That is not the property
 * anyone needs, and it is exactly how both of the implementations that produced
 * this specification managed to be confidently wrong.
 */
import { strict as assert } from 'node:assert';
import { createPublicKey, generateKeyPairSync, sign as signRaw, verify as verifyRaw } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import {
  normalize, findBlocks, parseBlockBody, signingInputForBlock, serializeBlock,
  trailingContent,
} from '../mades-canon.mjs';

const REAL = new URL('../../examples/05-a-real-signed-document.md', import.meta.url);
const ABOUT = new URL('../../examples/06-signing-a-document-about-signing.md', import.meta.url);
const WORKED = new URL('../../examples/07-a-worked-example.md', import.meta.url);

// ---------------------------------------------------------------------------

describe('the signed examples, as files in this repository', () => {
  // Whether they verify is in vectors/mades-examples-vectors.json. What stays
  // here is about the FILES: the bytes a checkout gives you, and that each still
  // demonstrates what it was written to demonstrate.

  it('05 survives checkout with its bytes intact', () => {
    // This is a `.gitattributes` test wearing a crypto disguise, and it is the
    // reason the CI matrix includes Windows. Without `-text` on this file, git
    // rewrites its line endings on checkout there, and the signature fails for
    // every reader who cloned the repository — silently, and blamed on the
    // format rather than on the checkout.
    assert.ok(!readFileSync(REAL, 'utf8').includes('\r'), 'the file must be stored and checked out with LF endings');
  });

  it('06 quotes the opening marker in full, repeatedly', () => {
    // If this ever drops to zero, its vector proves nothing: a document that
    // does not mention the marker cannot demonstrate the rule.
    const quotes = (readFileSync(ABOUT, 'utf8').match(/<!-- mades-sig/g) ?? []).length;
    assert.ok(quotes >= 3, `expected the marker quoted several times, found ${quotes}`);
  });

  it('06 survives checkout with its bytes intact', () => {
    assert.ok(!readFileSync(ABOUT, 'utf8').includes('\r'), 'the file must be stored and checked out with LF endings');
  });

  it('07 quotes the opening marker in ordinary prose', () => {
    // `05` still says a document about MAdES cannot be signed with MAdES. It was
    // signed before v1.4 and is deliberately left alone — a signed document is
    // not rewritten to say something more flattering. This one replaces it, and
    // writes the marker in full to show why it can.
    assert.ok((readFileSync(WORKED, 'utf8').match(/<!-- mades-sig/g) ?? []).length >= 2);
  });

  it('07 survives checkout with its bytes intact', () => {
    assert.ok(!readFileSync(WORKED, 'utf8').includes(String.fromCharCode(13)), 'the file must be stored and checked out with LF endings');
  });
});

// ---------------------------------------------------------------------------

describe('canonicalisation (§a.2)', () => {
  it('collapses trailing newlines to exactly one', () => {
    // Both inputs have a counterpart in canonicalisation-vectors.json.
    assert.equal(normalize('a\n\n\n'), 'a\n');
    assert.equal(normalize(''), '');
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

  it('SIGNS AND VERIFIES A DOCUMENT THAT DESCRIBES THE FORMAT', () => {
    // The acceptance test for v1.4 (§a.1), and the reason it exists. Before
    // those rules, this document could not be signed with the thing it
    // specifies. Where the block is found is in block-vectors.json; what stays
    // here is the writer's half.
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
  // How `covers` parses, splits and signs is in block-vectors.json. What stays
  // here is the writer, and the reader's list of known fields.
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
  // Kind, index space and input of a layer are in block-vectors.json.
  it('the marker is not a prefix of the signature marker', () => {
    // Deliberate: an archive timestamp read as a signature would be reported as
    // a signature with no signature value.
    assert.ok(!'<!-- mades-archive-ts'.startsWith('<!-- mades-sig'));
  });
});

// ---------------------------------------------------------------------------

describe('the document boundary (§a.14)', () => {
  // Each rule here is pinned in boundary-vectors.json on a small document; these
  // run it on a real signed one. The worked example itself — conforming as
  // published, and an appended clause that leaves the signature valid and the
  // document invalid — is in mades-examples-vectors.json.
  const worked = readFileSync(WORKED, 'utf8');

  it('one trailing line ending is allowed and is not content', () => {
    // Text editors add one. It carries nothing and reporting it would train
    // readers to ignore this check.
    const bare = worked.replace(/\n*$/, '');
    assert.equal(trailingContent(bare + '\n'), '');
    assert.equal(trailingContent(bare), '');
  });

  it('CRLF and a lone CR count as that one ending too (v1.7)', () => {
    // THE CASE THAT HITS A REAL USER. v1.6 accepted only `\n`, so a valid signed
    // document opened and saved in a Windows editor stopped conforming without a
    // character changing. §a.2 normalises exactly these three spellings so that a
    // document authored on Windows verifies on Linux; the boundary now says the
    // same thing instead of the opposite.
    const bare = worked.replace(/\n*$/, '');
    assert.equal(trailingContent(bare + '\r\n'), '');
    assert.equal(trailingContent(bare + '\r'), '');
  });

  it('but TWO endings is still content, in any spelling', () => {
    // The rule loosened by one word, not by one degree. Two endings means a blank
    // line was added, and a blank line is where appended text starts.
    const bare = worked.replace(/\n*$/, '');
    assert.notEqual(trailingContent(bare + '\n\n'), '');
    assert.notEqual(trailingContent(bare + '\r\n\r\n'), '');
    assert.notEqual(trailingContent(bare + '\n\r\n'), '');
  });

  it('and trailing whitespace is not a line ending', () => {
    const bare = worked.replace(/\n*$/, '');
    assert.notEqual(trailingContent(bare + '\n  '), '');
    assert.notEqual(trailingContent(bare + ' '), '');
  });
});
