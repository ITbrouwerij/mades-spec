#!/usr/bin/env node
/**
 * MAdES verifier — checks a signed document using nothing but the document.
 *
 *   node mades-verify.mjs <file.md>
 *   node mades-verify.mjs <file.md> --anchor root.pem
 *
 * Zero dependencies. Node built-ins only.
 *
 * **The whole point is that this needs no context.** No database, no key
 * server, no memory of how the document was produced. If it cannot be checked
 * from the file alone, it is not a MAdES signature.
 *
 * That sounds obvious and is the thing implementations get wrong. A verifier
 * that rebuilds the document from its own stored pieces proves that the encoder
 * and the decoder agree with each other — which is not the property a recipient
 * needs. Ours did exactly that, and reported `signature does NOT verify` over a
 * signature that was perfectly sound.
 */
import { createVerify, createPublicKey, verify as verifyRaw, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { findBlocks, parseBlockBody, signingInputForBlock } from './mades-canon.mjs';

const KNOWN_FIELDS = new Set([
  'version', 'algorithm', 'signer', 'signer-kind', 'automation', 'commitment',
  'signed-at', 'lang', 'appearance', 'revision', 'supersedes', 'represents',
  'covers', 'key-id', 'field', 'format', 'certificate-chain', 'timestamp',
  'signature',
]);

/** Node's verifier names, keyed by the `algorithm` field (§c.1). */
const ALGORITHMS = {
  'ed25519': null, // Ed25519 signs the message directly; no separate digest
  'ecdsa-p256': 'sha256',
  'rsa-sha256': 'sha256',
  'rsa-pss-sha256': 'sha256',
};

const C = process.stdout.isTTY
  ? { dim: '\x1b[2m', bold: '\x1b[1m', green: '\x1b[32m', red: '\x1b[31m', yellow: '\x1b[33m', reset: '\x1b[0m' }
  : { dim: '', bold: '', green: '', red: '', yellow: '', reset: '' };

const ok = (m) => console.log(`  ${C.green}ok${C.reset}    ${m}`);
const bad = (m) => { failures++; console.log(`  ${C.red}FAIL${C.reset}  ${m}`); };
const note = (m) => console.log(`  ${C.yellow}?${C.reset}     ${m}`);
const info = (k, v) => console.log(`        ${C.dim}${String(k).padEnd(14)}${C.reset}${v}`);

let failures = 0;
let verified = 0;   // blocks whose signature was actually checked
let withheld = 0;   // blocks on which no verdict could be offered

// ---------------------------------------------------------------------------

const file = process.argv[2];
if (!file) {
  console.error('usage: mades-verify.mjs <file.md> [--anchor root.pem]');
  process.exit(2);
}
const anchorArg = process.argv.indexOf('--anchor');
const anchorPem = anchorArg !== -1 ? readFileSync(process.argv[anchorArg + 1], 'utf8') : null;
// The raw-key path (§c.7): a document signed without a certificate names its
// key with `key-id`, and the reader has to hold that key already.
const keyArg = process.argv.indexOf('--key');
const publicKeyPem = keyArg !== -1 ? readFileSync(process.argv[keyArg + 1], 'utf8') : null;

const document = readFileSync(file, 'utf8');
const blocks = findBlocks(document);

console.log(`${C.bold}${file}${C.reset} ${C.dim}— ${Buffer.byteLength(document)} bytes, ${blocks.length} block(s)${C.reset}\n`);

if (blocks.length === 0) {
  console.log('  no signature block — this document is unsigned.');
  process.exit(1);
}

for (let i = 0; i < blocks.length; i++) {
  verifyBlock(i);
  if (i < blocks.length - 1) console.log('');
}

console.log('');
if (failures) {
  console.log(`${C.red}${C.bold}${failures} problem(s).${C.reset}`);
  process.exit(1);
}
// NEVER report success over blocks that were not checked.
//
// The first version of this printed "All signatures verify" after withholding
// a verdict on every block — a false green, in a verifier, for a signature
// specification. It is the most expensive bug this file could carry, and it
// took one run against a real document to produce it.
if (verified === 0) {
  console.log(`${C.yellow}${C.bold}No verdict.${C.reset} ${withheld} block(s) could not be checked; nothing here says the document is sound.`);
  process.exit(1);
}
const rest = withheld ? ` ${withheld} block(s) withheld.` : '';
console.log(`${C.green}${C.bold}${verified} signature(s) verify.${C.reset}${rest}`);

// ---------------------------------------------------------------------------

/**
 * §a.13 — an archive layer.
 *
 * WHAT IT ESTABLISHES, and the wording is the whole job: everything above this
 * block already stood in exactly this form at the moment in the token. That is
 * why a signature beneath a valid layer stays readable after its algorithm has
 * aged — the layer is what carries it.
 *
 * The input is the SAME canonicalisation a signature uses (§a.2, §a.3): the
 * document from its start up to this block's own opening marker. No separate
 * rule, because there was never a second question — an archive timestamp asks
 * “what stood here” exactly like a signature does, and answers it with an
 * authority's clock instead of a signer's key.
 *
 * Nothing in this block is covered by its own token, which is unavoidable: the
 * token cannot cover the bytes that carry it, the same reason `signature` and
 * `timestamp` are excluded in §a.3. So the comment line is a restatement for a
 * human and the token's own `genTime` is what counts.
 */
function reportArchiveLayer(index) {
  const { fields, unparsed } = parseBlockBody(findBlocks(document)[index].body);
  console.log(`${C.bold}archive layer${C.reset}`);

  if (unparsed.length) {
    withheld++;
    note(`unsupported — ${unparsed.length} line(s) could not be parsed`);
    return;
  }

  info('covers', 'everything above this block, including every earlier layer');
  info('version', fields.version ?? '(absent)');

  if (!fields.timestamp) {
    // A layer with no token is not a weak layer, it is not a layer.
    bad('no `timestamp` — this block establishes nothing (§a.13)');
    return;
  }
  const bytes = Buffer.from(fields.timestamp, 'base64').length;
  info('timestamp', `present (${bytes} bytes, RFC 3161)`);
  // Same stance as §c.5 above: parsing RFC 3161 is out of scope for a reference
  // implementation, and pretending otherwise would be the more expensive lie.
  info('', C.dim + 'stated, not verified here — see SPEC.md §a.13' + C.reset);
}

function verifyBlock(index) {
  const block = findBlocks(document)[index];

  // §a.13 — an archive timestamp is not a signature and is not reported as one.
  if (block.kind === 'archive-ts') return reportArchiveLayer(index);

  const d = signingInputForBlock(document, index);
  console.log(`${C.bold}signature ${index + 1}${C.reset}`);

  // §a.5 — a block we cannot fully read is `unsupported`, never `invalid`.
  // "We do not know" and "this was tampered with" are different answers, and
  // reporting the second when you mean the first is its own kind of lie.
  if (d.unparsed.length) {
    withheld++;
    note(`unsupported — ${d.unparsed.length} line(s) could not be parsed`);
    for (const l of d.unparsed.slice(0, 3)) info('', JSON.stringify(l));
    info('meaning', 'no verdict is offered on this block');
    return;
  }
  if (!d.signature) {
    withheld++;
    // Most often this is not a signature at all but prose that quotes the
    // opening marker. See the limitation noted in mades-canon.mjs.
    note('no signature value in this block — it may be prose describing one');
    return;
  }

  info('signer', d.fields.signer ?? '(absent)');
  info('signed-at', d.fields['signed-at'] ?? '(absent)');
  info('commitment', d.fields.commitment ?? '(absent)');

  // §a.11 — who signed, and what signed.
  const kind = d.fields['signer-kind'];
  if (d.rules >= 5 && !kind) bad('signer-kind is required from block version 5');
  else if (kind) info('signer-kind', kind + (d.fields.automation ? ` (${d.fields.automation})` : ''));
  else info('signer-kind', C.dim + 'unspecified (pre-v5 block)' + C.reset);

  // --- the signature itself ------------------------------------------------

  // Two ways to reach a public key: the certificate chain inside the document,
  // or a key the reader already holds (§c.7, the `key-id` path).
  const chain = toList(d.fields['certificate-chain']);
  let leaf = null;
  let publicKey = null;

  if (chain.length) {
    try {
      leaf = new X509Certificate(Buffer.from(chain[0], 'base64'));
      publicKey = leaf.publicKey;
    } catch (err) {
      bad(`the first certificate could not be read: ${err.message}`);
      return;
    }
  } else if (publicKeyPem) {
    publicKey = createPublicKey(publicKeyPem);
    info('key', `supplied by the reader${d.fields['key-id'] ? ` for ${d.fields['key-id']}` : ''}`);
  } else {
    withheld++;
    note('no certificate in the document and no key supplied — no verdict offered');
    info('how', 'pass --key <public.pem> for a document signed on the raw-key path (§c.7)');
    return;
  }

  const algorithm = d.fields.algorithm;
  if (!(algorithm in ALGORITHMS)) {
    note(`unsupported algorithm \`${algorithm}\` — no verdict offered`);
    return;
  }

  const signature = Buffer.from(d.signature, 'base64');
  const input = Buffer.from(d.signingInput, 'utf8');
  const digest = ALGORITHMS[algorithm];

  // Ed25519 signs the message itself; everything else signs a digest of it.
  const check = (bytes, sig) => digest === null
    ? verifyRaw(null, bytes, publicKey, sig)
    : (() => { const v = createVerify(digest); v.update(bytes); return v.verify(publicKey, sig); })();

  const valid = check(input, signature);

  if (valid) { verified++; ok(`${C.bold}SIGNATURE VERIFIES${C.reset} against ${leaf ? 'the certificate in the file' : 'the supplied key'}`); }
  else { bad('signature does NOT verify'); return; }

  // The other half. A verifier that always returns true passes the check above.
  const tampered = (document[0] === 'x' ? 'y' : 'x') + document.slice(1);
  const t = signingInputForBlock(tampered, index);
  const tv = check(Buffer.from(t.signingInput, 'utf8'), Buffer.from(t.signature, 'base64'));
  if (tv) bad('a modified document still verifies — the check above proves nothing');
  else ok('a single changed character breaks it');

  // --- who vouches for the name --------------------------------------------

  if (!leaf) {
    // The raw-key path. The signature is sound and nobody vouched for the name
    // attached to it — which is a different statement from "invalid", and the
    // reader is entitled to the difference.
    note('raw-key path — no certificate, so no issuer vouches for this name');
  } else {
    info('subject', leaf.subject.replace(/\n/g, ', '));
    info('issuer', leaf.issuer.replace(/\n/g, ', '));

    // §a.11 — the field and the certificate must agree. Without this, anyone
    // holding any valid certificate can sign a block naming somebody else, and
    // the reader sees that name beside a valid verdict.
    if (d.fields.signer && !certNames(leaf).includes(String(d.fields.signer).toLowerCase())) {
      bad(`the \`signer\` field (${d.fields.signer}) is not supported by the certificate`);
      info('meaning', 'the signature is valid; the claim about who made it is not');
    } else if (d.fields.signer) {
      ok('the `signer` field is supported by the certificate');
    }

    info('cert validity', `${leaf.validFrom} … ${leaf.validTo}`);
    if (new Date(leaf.validTo) < new Date()) {
      info('', C.dim + 'expired — normal for MAdES, the timestamp carries it (§c.3)' + C.reset);
    }
  }

  if (leaf && anchorPem) {
    // Wording matters here. "Trust anchor not recognised" is correct;
    // "untrusted signature" misleads a reader into treating a valid signature
    // as a forged one (§d).
    const anchored = chain.some((c) => {
      try { return new X509Certificate(Buffer.from(c, 'base64')).verify(new X509Certificate(anchorPem).publicKey); }
      catch { return false; }
    });
    if (anchored) ok('the chain is anchored in the supplied root');
    else note('trust anchor not recognised — supply the issuer\'s root to complete verification');
  } else {
    note('no trust anchor supplied — pass --anchor <root.pem> to check the chain');
  }

  // --- the timestamp -------------------------------------------------------

  if (d.fields.timestamp) {
    // Parsing RFC 3161 is out of scope for a reference implementation; what
    // matters here is that the field is present and that its absence is not
    // silently equivalent to its presence.
    info('timestamp', `present (${Buffer.from(d.fields.timestamp, 'base64').length} bytes, RFC 3161)`);
    info('', C.dim + 'stated, not verified here — see SPEC.md §c.5' + C.reset);
  } else {
    note('no timestamp — this signature cannot outlive its certificate');
  }

  // --- §a.12 the files that ride along -----------------------------------

  if (d.fields.covers) {
    const entries = toList(d.fields.covers);
    info('covers', `${entries.length} accompanying file(s)`);
    let readable = true;
    for (const line of entries) {
      // §a.12: digest, media type, then the name — which is the remainder, so a
      // name may contain spaces and the two before it may not.
      const m = /^(\S+)[ ](\S+)[ ](.+)$/.exec(String(line));
      if (!m) {
        bad(`a \`covers\` entry is not «digest media-type name»: ${line}`);
        readable = false;
        continue;
      }
      const [, digest, mediaType, name] = m;
      info('', `${name} ${C.dim}— ${mediaType} — ${digest}${C.reset}`);
    }
    if (readable) {
      // The files themselves were not handed to this reader, so the honest
      // verdict is §a.6's: the claim is signed, and unchecked. Reporting it as
      // satisfied would be the failure the field exists to prevent.
      note('the accompanying files were not supplied — coverage is asserted but unverified (§a.12)');
    }
  }

  // --- §d level 4: what this reader does not understand --------------------

  const unknown = Object.keys(d.fields).filter((k) => !KNOWN_FIELDS.has(k));
  if (unknown.length) {
    console.log(`  ${C.bold}signed fields this reader does not implement${C.reset}`);
    for (const k of unknown) {
      const namespaced = k.includes('.');
      info(k, `${render(d.fields[k])} ${C.dim}(meaning not known to this reader)${C.reset}`);
      if (!namespaced) {
        bad(`\`${k}\` carries no vendor namespace — unsupported (§a.1)`);
      }
    }
  }
}

// ---------------------------------------------------------------------------

function toList(v) {
  if (!v) return [];
  return Array.isArray(v) ? v : [v];
}

function certNames(cert) {
  const out = [];
  const cn = /CN=([^,\n]+)/.exec(cert.subject);
  if (cn) out.push(cn[1].trim().toLowerCase());
  for (const m of (cert.subjectAltName ?? '').matchAll(/email:([^,\s]+)/gi)) {
    out.push(m[1].toLowerCase());
  }
  return out;
}

function render(v) {
  if (Array.isArray(v)) return `[${v.length} item(s)]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).join(', ')}}`;
  return String(v);
}
