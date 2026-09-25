/**
 * §a.11.2 / §a.11.3 — what a certificate asserts about its own signer.
 *
 * The cases are published vectors: `vectors/certificate-policy-vectors.json`.
 * Until v1.10.1 the certificates were recorded here, where no second
 * implementation could run them.
 *
 * They are REAL certificates, as DER. Two of the three properties pinned cannot
 * be shown with a hand-built object: they are about how ordinary, unremarkable
 * certificates behave, and the whole risk of §a.11.3 is what happens to
 * certificates that were never issued with it in mind.
 *
 * Both were produced with OpenSSL and are self-signed test material with
 * throwaway keys. Nothing here trusts them; only their extensions are read.
 */
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import {
  CATEGORY_POLICY_OIDS,
  COMMITMENT_POLICY_OIDS,
  categoryOf,
  commitmentPermitted,
  permittedCommitmentsOf,
  policyOidsOf,
} from '../mades-certpolicy.mjs';

const file = JSON.parse(
  readFileSync(new URL('../../vectors/certificate-policy-vectors.json', import.meta.url), 'utf8')
);

// ---------------------------------------------------------------------------

describe('certificate-policy vectors (§a.11.2, §a.11.3)', () => {
  it('the mapping the vectors assume is the reference assignment', () => {
    assert.deepEqual(file.mapping.category, CATEGORY_POLICY_OIDS);
    assert.deepEqual(file.mapping.commitment, COMMITMENT_POLICY_OIDS);
  });

  for (const c of file.cases) {
    it(c.name, () => {
      // The module reads the DER and nothing else, so the bytes are handed over
      // as they are — including the case that is not a certificate at all.
      const cert = { raw: Buffer.from(c.certificate, 'base64') };

      assert.deepEqual(policyOidsOf(cert), c.expect.policyOids, 'policy OIDs, in order');
      // `null` is its own answer: "asserts no category" is a shortcoming of the
      // issuance, not a finding about the signer.
      assert.equal(categoryOf(cert), c.expect.category, 'category');
      // `null` and not `[]`, so that "unconstrained" cannot be lost to a
      // truthiness check downstream.
      const permitted = permittedCommitmentsOf(cert);
      assert.deepEqual(permitted, c.expect.permittedCommitments, 'permitted commitments');

      for (const check of c.expect.checks ?? []) {
        // The EFFECTIVE commitment: an absent field is `approval` (§a.4), and a
        // certificate constrained to `creation` does not escape by omitting it.
        const effective = check.commitment ?? 'approval';
        assert.equal(effective, check.effective, `effective commitment of ${check.commitment}`);
        const constraint = permitted === null
          ? 'unconstrained'
          : commitmentPermitted(effective, permitted) ? 'permitted' : 'exceeded';
        assert.equal(constraint, check.constraint, `constraint on ${effective}`);
      }
    });
  }
});
