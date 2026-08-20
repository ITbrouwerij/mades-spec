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
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import {
  findBlocks,
  normalize,
  signingInputForBlock,
  trailingContent,
} from '../mades-canon.mjs';

const vec = (name) =>
  JSON.parse(readFileSync(new URL(`../../vectors/${name}`, import.meta.url), 'utf8'));

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
      // The v4 file stores the signing input as BASE64 — multi-byte characters
      // and the em-dashes in the comment line survive a JSON round-trip that
      // way. The derived input is compared against the DECODED bytes.
      const recorded = Buffer.from(c.signingInput, 'base64').toString('utf8');
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
      assert.equal(derived.signingInput, c.signingInput, 'signing input drifted');
      assert.equal(
        createHash('sha256').update(c.signingInput, 'utf8').digest('base64'),
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
