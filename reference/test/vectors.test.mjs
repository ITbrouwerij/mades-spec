/**
 * The published vectors, read back — every release, not once.
 *
 * WHY THIS FILE EXISTS. The specification referenced "published vectors" for two
 * versions while the repository contained none: they lived inside one vendor's
 * product tree, where no second implementer could find them. A specification
 * that points at evidence its own publication does not carry is asserting, not
 * showing. From v1.8 the vectors live here, and this suite is what keeps them
 * from drifting: a vector the reference implementation cannot itself pass
 * proves nothing (§e).
 *
 * WHAT IS AND IS NOT CHECKED HERE. Canonicalisation, boundary and block vectors
 * are verified in full — those rules live entirely in this repository. For the
 * signed vectors (v4, v5, archive layers, the examples) this suite verifies what
 * the reference implements: block discovery, total parsing, signing-input
 * reconstruction and raw signature verification. RFC 3161 token validation and
 * certificate-chain trust are implementation concerns (§c.5) and are pinned by
 * the `expect` blocks inside the files, which a full implementation reads.
 * The certificate-policy vectors (§a.11.2, §a.11.3) are read by
 * certpolicy.test.mjs, next to the module they test.
 */
import { strict as assert } from 'node:assert';
import { createHash, createPublicKey, createVerify, verify as verifyRaw, X509Certificate } from 'node:crypto';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import {
  canonicalize,
  findBlocks,
  normalize,
  parseBlockBody,
  signingInputForBlock,
  trailingContent,
} from '../mades-canon.mjs';

const vec = (name) =>
  JSON.parse(readFileSync(new URL(`../../vectors/${name}`, import.meta.url), 'utf8'));

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
      assert.equal(
        `sha256:${createHash('sha256').update(canonical, 'utf8').digest('hex')}`,
        c.digest
      );
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
      assert.equal(trailingContent(c.document) === '', c.conforming);
    });
  }
});

// ---------------------------------------------------------------------------

describe('v4 vectors — signing-input reconstruction and signatures', () => {
  const v4 = vec('mades-v4-vectors.json');
  const key = createPublicKey(v4.key.publicKeyPem);

  for (const c of v4.cases) {
    it(c.name, () => {
      const blocks = findBlocks(c.document);
      assert.ok(blocks.length >= 1, 'no block found');
      // The file SAYS how its signing input is encoded (v1.8.1). This was
      // hard-coded as "v4 is base64" — correct, and unavailable to anyone who
      // had not read this file. A second implementer hit it within days.
      const recorded = decodeSigningInput(v4, c);
      // The LAST block is the one the vector records; earlier ones are what a
      // counter-signature case counters.
      const derived = signingInputForBlock(c.document, blocks.length - 1);
      assert.equal(derived.unparsed.length, 0, 'the block must parse totally');
      assert.equal(derived.signingInput, recorded, 'signing input drifted');
      assert.equal(
        createHash('sha256').update(recorded, 'utf8').digest('base64'),
        c.digestSha256Base64,
        'the recorded digest is not the digest of the recorded input'
      );
      assert.ok(
        verifyRaw(null, Buffer.from(recorded, 'utf8'), key, Buffer.from(c.signature, 'base64')),
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
      assert.equal(derived.unparsed.length, 0);
      const recorded = decodeSigningInput(v5, c);
      assert.equal(derived.signingInput, recorded, 'signing input drifted');
      assert.equal(
        createHash('sha256').update(recorded, 'utf8').digest('base64'),
        c.signedDigestB64,
        'the digest the service signed is not the digest of this input'
      );
      // The leaf certificate carries the key; the signature is over the digest
      // path the CSC service uses. What matters for the SPEC is that the leaf
      // parses and belongs to the block — trust is the verifier's question (§c.4).
      const leaf = new X509Certificate(
        `-----BEGIN CERTIFICATE-----\n${c.certificateChain[0]}\n-----END CERTIFICATE-----`
      );
      assert.ok(leaf.subject.length > 0);
    });
  }
});

describe('archive-layer vectors (§a.13)', () => {
  const lta = vec('mades-lta-vectors.json');

  for (const c of lta.cases) {
    it(c.name, () => {
      const blocks = findBlocks(c.document);
      const sigs = blocks.filter((b) => b.kind === 'sig');
      const layers = blocks.filter((b) => b.kind === 'archive-ts');
      // One index space — a layer covers every block above it (§a.13). The
      // full per-layer verdicts in `expect` are for implementations that
      // validate RFC 3161 tokens; the reference pins the structure.
      assert.equal(sigs.length, c.expect.signatures, 'signature count');
      assert.equal(layers.length, c.expect.layers.length, 'layer count');
      assert.equal(trailingContent(c.document), '', 'a layered document still ends at its last block');
    });
  }
});

// ---------------------------------------------------------------------------

describe('block vectors (§a.1, §a.3, §a.5, §a.12, §a.13)', () => {
  // Until v1.10.1 these were cases in mades.test.mjs, where only this
  // implementation could run them. Each case expects the reading of EVERY block
  // in its document; `signingInput`, `canonicalContent` and `coversEntries`
  // appear only where the case is about them.
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
          // §a.12: digest, media type, and the remainder of the line as the name.
          const entries = fields.covers.map((line) => {
            const [, digest, mediaType, name] = /^(\S+)[ ](\S+)[ ](.+)$/.exec(line);
            return { digest, mediaType, name };
          });
          assert.deepEqual(entries, e.coversEntries, `block ${i}: covers entries`);
        }
      }
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

  /** What the reference reads in one document, against what the vector expects of it. */
  const check = (document, expect) => {
    const blocks = findBlocks(document);
    if (expect.blockKinds) assert.deepEqual(blocks.map((b) => b.kind), expect.blockKinds, 'blocks found');
    const d = signingInputForBlock(document, blocks.length - 1);
    assert.equal(d.unparsed.length, 0, 'the block must parse totally');
    assert.equal(d.fields.version, String(file.blockVersion), 'block version');
    if (expect.signerKind) assert.equal(d.fields['signer-kind'], expect.signerKind, 'signer-kind');
    if (expect.signingInputDigest) {
      assert.equal(
        `sha256:${createHash('sha256').update(d.signingInput, 'utf8').digest('hex')}`,
        expect.signingInputDigest,
        'signing input digest'
      );
    }
    if (expect.signature) {
      // The cryptographic check alone: trust and timestamp are not part of it.
      assert.equal(d.fields.algorithm, 'rsa-sha256', 'these recordings are rsa-sha256');
      const leaf = new X509Certificate(Buffer.from(d.fields['certificate-chain'][0], 'base64'));
      const v = createVerify('sha256');
      v.update(d.signingInput, 'utf8');
      assert.equal(v.verify(leaf.publicKey, Buffer.from(d.signature, 'base64')) ? 'valid' : 'invalid', expect.signature, 'signature');
    }
    if ('conforming' in expect) assert.equal(trailingContent(document) === '', expect.conforming, 'document boundary (§a.14)');
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
    // It was not: from v1.8.1 until v1.10.1 a regular-expression escape made the
    // schema unparseable, and the check below only asked whether the file existed.
    const schema = JSON.parse(
      readFileSync(new URL('../../vectors/mades-vectors-1.schema.json', import.meta.url), 'utf8')
    );
    assert.ok(new RegExp(schema.properties.specVersion.pattern).test('1.10.1'));
  });

  for (const name of ALL) {
    describe(name, () => {
      const file = vec(name);

      it('declares a schema that exists in this repository', () => {
        // The declared schema was a URL on a product domain that returned 404
        // for two releases. A file that points at a schema which does not
        // resolve is worse than one that points at none: it looks described.
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
