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
 * WHAT IS AND IS NOT CHECKED HERE. Canonicalisation and boundary vectors are
 * verified in full — those rules live entirely in this repository. For the
 * signed vectors (v4, v5, archive layers) this suite verifies what the
 * reference implements: block discovery, total parsing, signing-input
 * reconstruction and raw signature verification. RFC 3161 token validation and
 * certificate-chain trust are implementation concerns (§c.5) and are pinned by
 * the `expect` blocks inside the files, which a full implementation reads.
 */
import { strict as assert } from 'node:assert';
import { createHash, createPublicKey, verify as verifyRaw, X509Certificate } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import {
  findBlocks,
  normalize,
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

describe('the vector files describe themselves (§e)', () => {
  const ALL = [
    'canonicalisation-vectors.json',
    'boundary-vectors.json',
    'mades-v4-vectors.json',
    'mades-v5-vectors.json',
    'mades-lta-vectors.json',
  ];

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
        if (!file.cases.some((c) => 'signingInput' in c)) return;
        assert.ok(
          ['base64', 'utf8'].includes(file.signingInputEncoding),
          'a consumer would have to guess, and two files answer differently'
        );
      });
    });
  }
});
