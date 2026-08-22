/**
 * §a.11.2 / §a.11.3 — what a certificate asserts about its own signer.
 *
 * These run against REAL certificates, recorded below as DER. Two of the three
 * properties this suite pins cannot be shown with a hand-built object: they are
 * about how ordinary, unremarkable certificates behave, and the whole risk of
 * §a.11.3 is what happens to certificates that were never issued with it in
 * mind.
 *
 * Both were produced with OpenSSL and are self-signed test material with
 * throwaway keys. Nothing here trusts them; only their extensions are read.
 */
import { strict as assert } from 'node:assert';
import { X509Certificate } from 'node:crypto';
import { describe, it } from 'node:test';

import {
  categoryOf,
  commitmentPermitted,
  permittedCommitmentsOf,
  policyOidsOf,
} from '../mades-certpolicy.mjs';

/**
 * A version-locking machine credential:
 *   1.3.6.1.4.1.65498.1.1.1   an assurance level — NOT a constraint
 *   1.3.6.1.4.1.65498.2.1.2   category: automated
 *   1.3.6.1.4.1.65498.2.2.1   commitment constraint: creation
 */
const CONSTRAINED = cert(`
MIIBmDCCAT2gAwIBAgIUTFvidqZ1CDAtO6rNARgiFDdL25IwCgYIKoZIzj0EAwIwIDEeMBwGA1UE
AwwVVmVyc2lvbiBMb2NrZXIgKHRlc3QpMB4XDTI2MDgyMjEzMDU1OFoXDTM2MDgxOTEzMDU1OFow
IDEeMBwGA1UEAwwVVmVyc2lvbiBMb2NrZXIgKHRlc3QpMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEjRINsniqAKOxLceLGIOo8mKMM9JiVWyyEbchjKxNtuOY4tYfwmEqnMuZSEHyZfHINMNuu4jy
hfckt1yI3Fg6VKNVMFMwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBsAwNgYDVR0gBC8wLTANBgsr
BgEEAYP/WgEBATANBgsrBgEEAYP/WgIBAjANBgsrBgEEAYP/WgICATAKBggqhkjOPQQDAgNJADBG
AiEAgIJDzaOJ2NamY9S7Rdc79P73iRs0mui9VQauAx6+GjYCIQDxDv354ErcHqpurqtuVxh8GUf5
gwhxzUAXbXXoiXHzKA==`);

/**
 * An ordinary signing certificate, of the shape the world is full of:
 *   2.23.140.1.2.1            CA/Browser Forum domain-validated
 *   1.3.6.1.4.1.65498.1.1.1   an assurance level
 * It carries policies, and none of them is a category or a constraint.
 */
const UNCONSTRAINED = cert(`
MIIBhTCCASugAwIBAgIUSFJSe4ph3KMpnLHEdgaxSacfMPswCgYIKoZIzj0EAwIwITEfMB0GA1UE
AwwWT3JkaW5hcnkgU2lnbmVyICh0ZXN0KTAeFw0yNjA4MjIxMzA1NThaFw0zNjA4MTkxMzA1NTha
MCExHzAdBgNVBAMMFk9yZGluYXJ5IFNpZ25lciAodGVzdCkwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAAQJtAUlQ1mQz4ps86mivfTNqFTPKzKTK4P0OgP4uOnzd1pevsT7mPqyBA689CB++2jH6z1R
Iy/UTMCbX6p8YS/lo0EwPzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIGwDAiBgNVHSAEGzAZMAgG
BmeBDAECATANBgsrBgEEAYP/WgEBATAKBggqhkjOPQQDAgNIADBFAiBIEl+HX4V10XTgGHjMN1vE
RbxglxnxRWiahfsFWDMuLgIhAIcpkfz9f0pAABZB5nGSVf8YWZDJBzUCUE1iMULUwIVV`);

function cert(base64) {
  return new X509Certificate(Buffer.from(base64.replace(/\s+/g, ''), 'base64'));
}

// ---------------------------------------------------------------------------

describe('reading certificatePolicies (§a.11.2, §a.11.3)', () => {
  it('reads every policy OID, in order, out of a real certificate', () => {
    assert.deepEqual(policyOidsOf(CONSTRAINED), [
      '1.3.6.1.4.1.65498.1.1.1',
      '1.3.6.1.4.1.65498.2.1.2',
      '1.3.6.1.4.1.65498.2.2.1',
    ]);
    assert.deepEqual(policyOidsOf(UNCONSTRAINED), [
      '2.23.140.1.2.1',
      '1.3.6.1.4.1.65498.1.1.1',
    ]);
  });

  it('anchors the category, and says nothing when the certificate says nothing', () => {
    assert.equal(categoryOf(CONSTRAINED), 'automated');
    // Not `human`, and not `automated` either. "Asserts no category" is its own
    // answer — the difference between a shortcoming of the issuance and a
    // finding about the signer.
    assert.equal(categoryOf(UNCONSTRAINED), null);
  });
});

describe('commitment constraints (§a.11.3)', () => {
  it('permits exactly the constrained set and nothing else', () => {
    const permitted = permittedCommitmentsOf(CONSTRAINED);
    assert.deepEqual(permitted, ['creation']);
    assert.equal(commitmentPermitted('creation', permitted), true);
    assert.equal(commitmentPermitted('approval', permitted), false);
    assert.equal(commitmentPermitted('receipt', permitted), false);
    // An unrecognised value (§a.4) cannot be a member of a constrained set.
    assert.equal(commitmentPermitted('frobnicate', permitted), false);
  });

  it('AN OID IT DOES NOT RECOGNISE IS NOT A CONSTRAINT', () => {
    // The rule the whole section stands or falls on. This certificate carries
    // two policy OIDs and neither is a commitment. Read as "constrained to the
    // empty set", it would reject every signature made under every certificate
    // ever issued — every one of them carries policy OIDs for other reasons.
    //
    // `null` and not `[]`, so that the difference is in the type and cannot be
    // lost to a truthiness check downstream.
    const permitted = permittedCommitmentsOf(UNCONSTRAINED);
    assert.equal(permitted, null);
    for (const c of ['creation', 'approval', 'receipt', 'witness', 'frobnicate']) {
      assert.equal(commitmentPermitted(c, permitted), true);
    }
  });

  it('compares the EFFECTIVE commitment — an absent field is approval', () => {
    // The trap this exists to close: a machine constrained to `creation` does
    // not escape by omitting `commitment`. §a.4 makes the default `approval`,
    // so omitting the field is claiming agreement, and a constrained credential
    // must reject it. The caller resolves the default; this pins the arithmetic
    // that makes the caller's choice matter.
    const permitted = permittedCommitmentsOf(CONSTRAINED);
    const effective = undefined ?? 'approval';
    assert.equal(commitmentPermitted(effective, permitted), false);
  });

  it('a certificate it cannot parse constrains nothing', () => {
    // The safe direction. A reader that cannot read the bytes must not turn its
    // own limitation into someone else's rejected signature (§a.5).
    const broken = { raw: Buffer.from([0x30, 0x80, 0x01]) };
    assert.deepEqual(policyOidsOf(broken), []);
    assert.equal(permittedCommitmentsOf(broken), null);
    assert.equal(categoryOf(broken), null);
  });
});
