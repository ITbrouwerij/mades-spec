/**
 * The published vectors, run through the implementation — every release, not once.
 *
 * WHY THIS FILE EXISTS. The specification referenced "published vectors" for two
 * versions while the repository contained none. A specification that points at
 * evidence its own publication does not carry is asserting, not showing. From
 * v1.8 the vectors live here, and this suite is what keeps them honest: a vector
 * no implementation passes proves nothing (§e).
 *
 * WHICH IMPLEMENTATION (v1.11). Until v1.11 this suite ran a reference
 * implementation that lived in this repository, beside the implementation that
 * signs real documents: two readings of one format, free to drift. MAdES has
 * one implementation now, `@itbrouwerij/mades-verify` from npm, and this suite
 * runs every vector file through it at the version package.json allows.
 *
 * WHAT IS CHECKED. Every expectation a file states. That includes what the
 * former reference could not check and left to "a full implementation": the
 * per-layer verdicts of the archive vectors, against their RFC 3161 tokens.
 * The certificate-policy vectors are read by certpolicy.test.mjs.
 */
import { strict as assert } from 'node:assert';
import { createHash, createPublicKey, X509Certificate } from 'node:crypto';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import {
  canonicalize,
  documentBoundary,
  findBlocks,
  normalize,
  ontleedVatl,
  parseBlockBody,
  parseCoversEntry,
  signingInputForBlock,
  verifyArchiveLayers,
  verifySignature,
  vermeldingenVanPem,
} from '@itbrouwerij/mades-verify';
import { nodePoort } from '@itbrouwerij/mades-verify/node';

const vec = (name) =>
  JSON.parse(readFileSync(new URL(`../../vectors/${name}`, import.meta.url), 'utf8'));

const sha256hex = (text) => `sha256:${createHash('sha256').update(text, 'utf8').digest('hex')}`;
const sha256b64 = (text) => createHash('sha256').update(text, 'utf8').digest('base64');

/**
 * The signing input of one case, decoded according to what the FILE declares.
 *
 * Reading `signingInput` without consulting `signingInputEncoding` works for
 * whichever file the reader happened to open first and fails on the other.
 */
const decodeSigningInput = (file, testCase) => {
  const encoding = file.signingInputEncoding;
  assert.ok(encoding, 'the file does not declare signingInputEncoding');
  return encoding === 'base64'
    ? Buffer.from(testCase.signingInput, 'base64').toString('utf8')
    : testCase.signingInput;
};

// ---------------------------------------------------------------------------

describe('canonicalisation vectors (§a.2)', () => {
  const { cases } = vec('canonicalisation-vectors.json');

  it('carries the divergence-prone cases', () => {
    assert.ok(cases.length >= 12, `only ${cases.length} cases`);
  });

  for (const c of cases) {
    it(c.name, () => {
      const canonical = normalize(c.input);
      assert.equal(canonical, c.canonical);
      assert.equal(sha256hex(canonical), c.digest);
    });
  }
});

describe('boundary vectors (§a.14)', () => {
  const { cases } = vec('boundary-vectors.json');

  it('carries conforming AND non-conforming cases', () => {
    // A file with only the good half would prove the check lets things
    // through, not that it checks.
    assert.ok(cases.some((c) => c.conforming) && cases.some((c) => !c.conforming));
  });

  for (const c of cases) {
    it(`${c.conforming ? 'conforming' : 'non-conforming'}: ${c.name}`, () => {
      assert.equal(documentBoundary(c.document).ok, c.conforming);
    });
  }
});

// ---------------------------------------------------------------------------

describe('block vectors (§a.1, §a.3, §a.5, §a.12, §a.13)', () => {
  // Each case expects the reading of EVERY block in its document;
  // `signingInput`, `canonicalContent` and `coversEntries` appear only where the
  // case is about them.
  const file = vec('block-vectors.json');

  for (const c of file.cases) {
    it(`${c.section} ${c.name}`, () => {
      const blocks = findBlocks(c.document);
      assert.deepEqual(blocks.map((b) => b.kind), c.expect.blocks.map((b) => b.kind), 'blocks found');

      for (const [i, e] of c.expect.blocks.entries()) {
        const { fields, comments, unparsed } = parseBlockBody(blocks[i].body);
        // A count and not the lines: §a.5 reports how many lines could not be
        // read, and what a reader echoes back of them is its own affair.
        assert.equal(unparsed.length, e.unparsedLines, `block ${i}: unparsed lines`);
        if (e.unparsedLines > 0) continue; // `unsupported` — nothing further to read (§a.5)
        assert.deepEqual(fields, e.fields, `block ${i}: fields`);
        assert.deepEqual(comments, e.comments, `block ${i}: comment lines`);
        if ('signingInput' in e) {
          assert.equal(signingInputForBlock(c.document, i).signingInput, decodeSigningInput(file, e), `block ${i}: signing input`);
        }
        if ('canonicalContent' in e) {
          assert.equal(canonicalize(c.document, i), e.canonicalContent, `block ${i}: canonical content`);
        }
        if ('coversEntries' in e) {
          assert.deepEqual(fields.covers.map(parseCoversEntry), e.coversEntries, `block ${i}: covers entries`);
        }
      }
    });
  }
});

// ---------------------------------------------------------------------------

describe('v4 vectors — signing-input reconstruction and signatures', () => {
  const v4 = vec('mades-v4-vectors.json');
  const key = createPublicKey(v4.key.publicKeyPem);

  for (const c of v4.cases) {
    it(c.name, async () => {
      const blocks = findBlocks(c.document);
      assert.ok(blocks.length >= 1, 'no block found');
      const recorded = decodeSigningInput(v4, c);
      // The LAST block is the one the vector records; earlier ones are what a
      // counter-signature case counters.
      const derived = signingInputForBlock(c.document, blocks.length - 1);
      assert.deepEqual(derived.unparsed, [], 'the block must parse totally');
      assert.equal(derived.signingInput, recorded, 'signing input drifted');
      assert.equal(sha256b64(recorded), c.digestSha256Base64, 'the recorded digest is not the digest of the recorded input');
      // The raw-key path (§c.7): the key travels in the file, not in the block.
      assert.ok(
        await verifySignature(nodePoort, recorded, Buffer.from(c.signature, 'base64'), { publiekeSleutel: key }, 'ed25519'),
        'the recorded signature does not verify over the reconstructed input'
      );
    });
  }
});

describe('v5 vector — a real ceremony, reconstructed from the file alone', () => {
  const v5 = vec('mades-v5-vectors.json');

  for (const c of v5.cases) {
    it(c.name, () => {
      const blocks = findBlocks(c.document);
      const derived = signingInputForBlock(c.document, blocks.length - 1);
      assert.deepEqual(derived.unparsed, [], 'the block must parse totally');
      const recorded = decodeSigningInput(v5, c);
      assert.equal(derived.signingInput, recorded, 'signing input drifted');
      assert.equal(sha256b64(recorded), c.signedDigestB64, 'the digest the service signed is not the digest of this input');
      // Trust in the chain is the verifier's question (§c.4), not this vector's.
      const leaf = new X509Certificate(Buffer.from(c.certificateChain[0], 'base64'));
      assert.ok(leaf.subject.length > 0);
    });
  }
});

describe('archive-layer vectors (§a.13)', () => {
  const lta = vec('mades-lta-vectors.json');
  let anchors;
  const tsaAnchors = async () => {
    anchors ??= (await ontleedVatl(
      nodePoort,
      await vermeldingenVanPem(nodePoort, lta.trustRootPem, { dienstsoorten: ['tijdstempel'] })
    )).ankers;
    return anchors;
  };

  for (const c of lta.cases) {
    it(c.name, async () => {
      const blocks = findBlocks(c.document);
      // One index space — a layer covers every block above it.
      assert.equal(blocks.filter((b) => b.kind === 'sig').length, c.expect.signatures, 'signature count');
      assert.equal(blocks.filter((b) => b.kind === 'archive-ts').length, c.expect.layers.length, 'layer count');
      assert.ok(documentBoundary(c.document).ok, 'a layered document still ends at its last block');
      // The per-layer verdicts, outside-in, against the tokens themselves.
      const layers = await verifyArchiveLayers(nodePoort, c.document, { ankers: await tsaAnchors() });
      assert.deepEqual(
        layers.map((l) => ({ verdict: l.verdict, covers: l.covers })),
        c.expect.layers,
        'layer verdicts'
      );
    });
  }
});

describe('example vectors — the signed documents in examples/, from the file alone', () => {
  const file = vec('mades-examples-vectors.json');

  /** A variant is the case's document with one edit: bytes replaced at an offset, or text appended. */
  const variantOf = (document, v) => {
    let bytes = Buffer.from(document, 'utf8');
    if (v.replace) {
      const from = Buffer.from(v.replace.from, 'utf8');
      assert.ok(bytes.subarray(v.replace.at, v.replace.at + from.length).equals(from), 'replace.from is not what stands there');
      bytes = Buffer.concat([
        bytes.subarray(0, v.replace.at),
        Buffer.from(v.replace.to, 'utf8'),
        bytes.subarray(v.replace.at + from.length),
      ]);
    }
    if (v.append !== undefined) bytes = Buffer.concat([bytes, Buffer.from(v.append, 'utf8')]);
    return bytes.toString('utf8');
  };

  const check = async (document, expect) => {
    const blocks = findBlocks(document);
    if (expect.blockKinds) assert.deepEqual(blocks.map((b) => b.kind), expect.blockKinds, 'blocks found');
    const d = signingInputForBlock(document, blocks.length - 1);
    assert.deepEqual(d.unparsed, [], 'the block must parse totally');
    assert.equal(d.fields.version, String(file.blockVersion), 'block version');
    if (expect.signerKind) assert.equal(d.fields['signer-kind'], expect.signerKind, 'signer-kind');
    if (expect.signingInputDigest) assert.equal(sha256hex(d.signingInput), expect.signingInputDigest, 'signing input digest');
    if (expect.signature) {
      // The cryptographic check alone: trust and timestamp are not part of it.
      const leaf = await nodePoort.certificaat(Buffer.from(d.fields['certificate-chain'][0], 'base64'));
      const valid = await verifySignature(nodePoort, d.signingInput, Buffer.from(d.signature, 'base64'), leaf, d.fields.algorithm);
      assert.equal(valid ? 'valid' : 'invalid', expect.signature, 'signature');
    }
    if ('conforming' in expect) assert.equal(documentBoundary(document).ok, expect.conforming, 'document boundary (§a.14)');
  };

  for (const c of file.cases) {
    describe(c.name, () => {
      it('is the published example, byte for byte', () => {
        // Also what catches a checkout that rewrote the example's line endings:
        // the vector is JSON-escaped and cannot be rewritten that way.
        assert.equal(c.document, readFileSync(new URL(`../../${c.file}`, import.meta.url), 'utf8'));
      });
      it('reads as the vector says', () => check(c.document, c.expect));
      for (const v of c.variants ?? []) {
        it(`variant: ${v.name}`, () => check(variantOf(c.document, v), v.expect));
      }
    });
  }
});

// ---------------------------------------------------------------------------

describe('the vector files describe themselves (§e)', () => {
  const ALL = [
    'canonicalisation-vectors.json',
    'boundary-vectors.json',
    'block-vectors.json',
    'certificate-policy-vectors.json',
    'mades-v4-vectors.json',
    'mades-v5-vectors.json',
    'mades-lta-vectors.json',
    'mades-examples-vectors.json',
  ];

  it('every file in vectors/ is read by a suite', () => {
    // A vector file nobody reads proves nothing, and adding one without a suite
    // is the easiest way to publish one. certificate-policy-vectors.json is read
    // by certpolicy.test.mjs; the others above.
    const published = readdirSync(new URL('../../vectors/', import.meta.url))
      .filter((n) => n.endsWith('.json') && !n.endsWith('.schema.json'))
      .sort();
    assert.deepEqual(published, [...ALL].sort());
  });

  it('the schema they declare is itself valid JSON', () => {
    // It was not, from v1.8.1 until v1.10.1: a regular-expression escape made it
    // unparseable, and the check below only asked whether the file existed.
    const schema = JSON.parse(
      readFileSync(new URL('../../vectors/mades-vectors-1.schema.json', import.meta.url), 'utf8')
    );
    assert.ok(new RegExp(schema.properties.specVersion.pattern).test('1.10.1'));
  });

  for (const name of ALL) {
    describe(name, () => {
      const file = vec(name);

      it('declares a schema that exists in this repository', () => {
        // A file that points at a schema which does not resolve is worse than
        // one that points at none: it looks described.
        const tail = file.$schema.split('/').slice(-2).join('/');
        assert.ok(
          existsSync(new URL(`../../${tail}`, import.meta.url)),
          `${file.$schema} does not resolve to a file here`
        );
      });

      it('declares how its signing input is encoded, if it carries one', () => {
        // Anywhere in a case, not only at its top level: block-vectors.json
        // carries one per block.
        if (!JSON.stringify(file.cases).includes('"signingInput"')) return;
        assert.ok(
          ['base64', 'utf8'].includes(file.signingInputEncoding),
          'a consumer would have to guess, and two files answer differently'
        );
      });
    });
  }
});
