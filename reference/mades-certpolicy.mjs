/**
 * What a certificate itself asserts: the signer category (§a.11.2) and the
 * commitment constraint (§a.11.3).
 *
 * Both are certificate policy OIDs, and that is the whole design. A policy OID
 * needs no new X.509 extension, no CA in the path to emit anything bespoke, and
 * no verifier to parse anything it does not already have in front of it. The
 * cheapest mechanism that actually holds is the one implementations deploy, and
 * one that is not deployed protects nobody.
 *
 * WHY THIS IS ITS OWN MODULE. §a.11.2 and §a.11.3 read the same bytes for
 * different questions. Two readers of certificatePolicies in one implementation
 * is two chances to disagree about what a certificate says — and disagreement
 * there is not a display bug, it is one verifier calling `human` what another
 * calls a machine.
 *
 * Node's X509Certificate does not expose certificatePolicies, so the DER is
 * walked here. It is a small, bounded walk: TBSCertificate → [3] extensions →
 * the one with OID 2.5.29.32 → SEQUENCE OF PolicyInformation → each one's
 * first element.
 */

/**
 * Reference assignments under ITbrouwerij's IANA PEN (65498), published by the
 * specification and free for any implementation to use.
 *
 * A deployment MAY use arcs of its own and hand a verifier a different mapping;
 * these two tables are simply this reader's mapping.
 */
export const CATEGORY_POLICY_OIDS = Object.freeze({
  '1.3.6.1.4.1.65498.2.1.1': 'human',
  '1.3.6.1.4.1.65498.2.1.2': 'automated',
});

export const COMMITMENT_POLICY_OIDS = Object.freeze({
  '1.3.6.1.4.1.65498.2.2.1': 'creation',
  '1.3.6.1.4.1.65498.2.2.2': 'approval',
  '1.3.6.1.4.1.65498.2.2.3': 'receipt',
  '1.3.6.1.4.1.65498.2.2.4': 'witness',
});

/**
 * The signer category a certificate asserts: `'human'`, `'automated'`,
 * `'conflict'`, or `null` for "asserts none".
 *
 * `null` is deliberately its own answer and not `automated`. "This certificate
 * says nothing about the category" is a different fact from "this certificate
 * says it is a machine": the first is a shortcoming of the issuance, the second
 * is a finding, and a reader must be able to tell them apart (§a.11.2).
 *
 * Two categories in one certificate is not "pick one" — it is a certificate
 * asserting two incompatible things, which is precisely when not to guess.
 */
export function categoryOf(cert, mapping = CATEGORY_POLICY_OIDS) {
  const found = new Set(policyOidsOf(cert).map((o) => mapping[o]).filter(Boolean));
  if (found.size === 0) return null;
  if (found.size > 1) return 'conflict';
  return [...found][0];
}

/**
 * The commitments a certificate permits, or `null` for "unconstrained" (§a.11.3).
 *
 * THE EMPTY LIST IS NEVER THE ANSWER, and this is the rule that must not be got
 * wrong. Certificates carry policy OIDs for all sorts of reasons — assurance
 * levels, CA policy, national schemes. An implementation that read "this
 * certificate has policies, none of which I map to a commitment" as
 * "constrained to nothing" would reject every signature made under every
 * certificate ever issued. Only OIDs present in the mapping are constraints;
 * the rest are invisible to this section. Hence `null`, not `[]`.
 */
export function permittedCommitmentsOf(cert, mapping = COMMITMENT_POLICY_OIDS) {
  const found = policyOidsOf(cert).map((o) => mapping[o]).filter(Boolean);
  return found.length ? [...new Set(found)] : null;
}

/**
 * Is this commitment within the certificate's constraint?
 *
 * The caller passes the EFFECTIVE commitment: `approval` when the block carries
 * no `commitment` field (§a.4), never "none". A certificate constrained to
 * `creation` does not get a free pass by omitting the field — omitting it is
 * claiming agreement.
 */
export function commitmentPermitted(commitment, permitted) {
  if (permitted === null) return true;
  return permitted.includes(commitment);
}

/**
 * The certificate policy OIDs of a certificate, in the order they appear.
 *
 * A certificate that cannot be read yields an empty list, and therefore
 * "asserts nothing". That is the safe direction on both questions: no category
 * is established, so never `human`; and no constraint is found, so a signature
 * is not rejected because this reader could not parse the bytes.
 */
export function policyOidsOf(cert) {
  const EXTENSIONS_TAG = 0xa3; // [3] extensions, in a TBSCertificate
  const CERTIFICATE_POLICIES = '2.5.29.32'; // id-ce-certificatePolicies, RFC 5280 §4.2.1.4
  try {
    const tbs = children(tlv(cert.raw).value)[0];
    const extensions = children(tbs.value).find((f) => f.tag === EXTENSIONS_TAG);
    if (!extensions) return [];
    for (const ext of children(tlv(extensions.value).value)) {
      const parts = children(ext.value);
      if (oid(parts[0].value) !== CERTIFICATE_POLICIES) continue;
      // extnValue is an OCTET STRING wrapping SEQUENCE OF PolicyInformation;
      // each PolicyInformation begins with its own OID. The last element is
      // taken because `critical` is optional and may or may not be present.
      const inner = tlv(parts[parts.length - 1].value);
      return children(inner.value).map((pi) => oid(children(pi.value)[0].value));
    }
    return [];
  } catch {
    return [];
  }
}

// --- a bounded DER reader ---------------------------------------------------

/** Read one TLV at `offset`. */
function tlv(buf, offset = 0) {
  if (offset >= buf.length) throw new Error('truncated DER: no tag');
  const tag = buf[offset];
  let cursor = offset + 1;
  if (cursor >= buf.length) throw new Error('truncated DER: no length');
  let length = buf[cursor++];
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0) throw new Error('indefinite length is not valid DER');
    if (count > 4) throw new Error('DER length field too large');
    length = 0;
    for (let i = 0; i < count; i++) {
      if (cursor >= buf.length) throw new Error('truncated DER');
      // `* 256`, not `<< 8`. JavaScript bitshifts are 32-bit and SIGNED: a
      // length of 0xFFFFFFFA becomes -6, so `cursor + length` points BACKWARDS
      // and the loop below never terminates. Measured, in a sibling
      // implementation, as a twelve-byte input that hung a whole service.
      length = length * 256 + buf[cursor++];
    }
  }
  const end = cursor + length;
  if (!Number.isSafeInteger(end) || end < cursor || end > buf.length) {
    throw new Error('invalid DER length');
  }
  return { tag, value: buf.subarray(cursor, end), end };
}

/** Read a sequence of TLVs laid end to end. */
function children(buf) {
  const out = [];
  let offset = 0;
  while (offset < buf.length) {
    const node = tlv(buf, offset);
    // Progress is mandatory, and not because `tlv` guarantees it. A loop that
    // can stall belongs to the loop to know, not to an assumption about what
    // its callee returns.
    if (node.end <= offset) throw new Error('DER element makes no progress');
    out.push(node);
    offset = node.end;
  }
  return out;
}

/** Decode an OID value into dotted form. */
function oid(value) {
  const parts = [Math.floor(value[0] / 40), value[0] % 40];
  let acc = 0;
  for (const byte of value.subarray(1)) {
    // Same reason as the length above: `<< 7` overflows and can land exactly on
    // the value of a DIFFERENT OID. For a function that decides which policy
    // this is, a collision is a misidentification, not a rounding error.
    acc = acc * 128 + (byte & 0x7f);
    if (!Number.isSafeInteger(acc)) throw new Error('OID arc too large');
    if (!(byte & 0x80)) {
      parts.push(acc);
      acc = 0;
    }
  }
  return parts.join('.');
}
