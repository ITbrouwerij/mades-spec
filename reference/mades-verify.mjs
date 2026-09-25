#!/usr/bin/env node
/**
 * MAdES verifier — a command line around @itbrouwerij/mades-verify.
 *
 *   node mades-verify.mjs <file.md>
 *   node mades-verify.mjs <file.md> --anchor root.pem
 *   node mades-verify.mjs <file.md> --key public.pem
 *
 * EVERY JUDGEMENT HERE IS THE PACKAGE'S. Until v1.11 this file carried its own
 * block parser, canonicaliser and certificate reader, next to the implementation
 * that signs real documents — two readings of one format, free to drift apart.
 * MAdES has one implementation now, and the specification's vectors are what
 * it is held to (vectors/, run by reference/test/ on every release). What stays
 * here is the command line: arguments in, the report printed, an exit code.
 *
 * **The whole point is still that this needs no context.** No database, no key
 * server, no memory of how the document was produced. If it cannot be checked
 * from the file alone, it is not a MAdES signature.
 */
import { createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';

import {
  commitmentPermitted,
  findBlocks,
  signingInputForBlock,
  verifyDocument,
  verifySignature,
  vermeldingenVanPem,
} from '@itbrouwerij/mades-verify';
import { nodePoort } from '@itbrouwerij/mades-verify/node';

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
if (!file || file.startsWith('--')) {
  console.error('usage: mades-verify.mjs <file.md> [--anchor root.pem] [--key public.pem]');
  process.exit(2);
}
const anchorArg = process.argv.indexOf('--anchor');
const anchorPem = anchorArg !== -1 ? readFileSync(process.argv[anchorArg + 1], 'utf8') : null;
// The raw-key path (§c.7): a document signed without a certificate names its
// key with `key-id`, and the reader has to hold that key already.
const keyArg = process.argv.indexOf('--key');
const publicKey = keyArg !== -1 ? createPublicKey(readFileSync(process.argv[keyArg + 1], 'utf8')) : null;

const document = readFileSync(file, 'utf8');
const blocks = findBlocks(document);

console.log(`${C.bold}${file}${C.reset} ${C.dim}— ${Buffer.byteLength(document)} bytes, ${blocks.length} block(s)${C.reset}\n`);

if (blocks.length === 0) {
  console.log('  no signature block — this document is unsigned.');
  process.exit(1);
}

// A supplied root is trusted for both services it can have: signing and
// timestamping. That is what `--anchor` meant before, when there was one kind.
const vatl = anchorPem ? await vermeldingenVanPem(nodePoort, anchorPem) : [];
const report = await verifyDocument(nodePoort, document, { vatl });

// THE DOCUMENT BOUNDARY, BEFORE ANY SIGNATURE (§a.14). Reported first and as a
// failure: a warning next to "1 signature verifies" is read as a detail.
if (!report.boundary.ok) {
  bad(`${report.boundary.bytes} byte(s) after the last block — outside every signature (§a.14)`);
  for (const r of report.boundary.lines) info('', `${C.red}${r.slice(0, 72)}${C.reset}`);
  if (report.boundary.lineCount > report.boundary.lines.length) {
    info('', `${C.dim}… ${report.boundary.lineCount - report.boundary.lines.length} more line(s)${C.reset}`);
  }
  console.log('');
}

for (let i = 0; i < blocks.length; i++) {
  if (blocks[i].kind === 'archive-ts') reportLayer(i);
  else await reportSignature(i);
  if (i < blocks.length - 1) console.log('');
}

console.log('');
if (failures) {
  console.log(`${C.red}${C.bold}${failures} problem(s).${C.reset}`);
  process.exit(1);
}
// NEVER report success over blocks that were not checked.
if (verified === 0) {
  console.log(`${C.yellow}${C.bold}No verdict.${C.reset} ${withheld} block(s) could not be checked; nothing here says the document is sound.`);
  process.exit(1);
}
const rest = withheld ? ` ${withheld} block(s) withheld.` : '';
console.log(`${C.green}${C.bold}${verified} signature(s) verify.${C.reset}${rest}`);

// ---------------------------------------------------------------------------

/**
 * §a.13 — an archive layer, as the package judged it.
 *
 * The verdict is printed and the package's `reason` is not: for layers it is
 * written in Dutch, and this command line reports in English.
 */
function reportLayer(index) {
  const layer = report.layers.find((l) => l.index === index);
  console.log(`${C.bold}archive layer${C.reset}`);
  if (!layer || layer.verdict === 'unsupported') {
    withheld++;
    note('unsupported — this layer could not be read, and the layers beneath it stand on their own (§a.13)');
    return;
  }
  info('covers', `${layer.covers} block(s) above it, and everything they cover`);
  if (layer.verdict === 'broken') {
    bad('the layer is broken — something beneath it changed, or its token does not hold (§a.13)');
    return;
  }
  ok(`intact — everything above stood in this form at ${layer.at}`);
  if (layer.authority) info('authority', layer.authority);
  trustLine(layer.trust, 'the timestamping authority');
}

/** One signature block, as the package judged it. */
async function reportSignature(index) {
  const s = report.signatures.find((r) => r.index === index);
  console.log(`${C.bold}signature ${index + 1}${C.reset}`);

  // §a.5 — `unsupported` is never `invalid`. "We do not know" and "this was
  // tampered with" are different answers.
  if (s.verdict === 'unsupported' && !(s.reasonCode === 'no-certificate' && publicKey)) {
    withheld++;
    switch (s.reasonCode) {
      case 'unparsed-lines':
        note(`unsupported — ${s.unparsedLines} line(s) could not be parsed`);
        info('meaning', 'no verdict is offered on this block');
        return;
      case 'no-signature-value':
        note('no signature value in this block — it may be prose describing one');
        return;
      case 'no-certificate':
        note('no certificate in the document and no key supplied — no verdict offered');
        info('how', 'pass --key <public.pem> for a document signed on the raw-key path (§c.7)');
        return;
      case 'unknown-algorithm':
        note(`unsupported algorithm \`${s.algorithm}\` — no verdict offered`);
        return;
      default:
        note(`unsupported — ${s.reason ?? s.reasonCode}`);
        return;
    }
  }

  info('signer', s.signer ?? '(absent)');
  info('signed-at', s.signedAt ?? '(absent)');
  info('commitment', s.commitment ?? '(absent)');
  // The category as the package resolved it against the certificate; on the
  // raw-key path there is no certificate, and the block's own field is shown.
  const category = s.category;
  const declared = signingInputForBlock(document, index).fields;
  const kind = category?.kind ?? category?.claimed ?? declared['signer-kind'];
  const automation = category?.automation ?? declared.automation;
  if (kind) info('signer-kind', kind + (automation ? ` (${automation})` : ''));
  else info('signer-kind', C.dim + 'unspecified (pre-v5 block)' + C.reset);

  // --- the signature itself ------------------------------------------------

  if (s.reasonCode === 'no-certificate') return rawKeyPath(index, s);

  if (s.reasonCode === 'changed-after-signing') {
    bad('signature does NOT verify');
    return;
  }
  verified++;
  ok(`${C.bold}SIGNATURE VERIFIES${C.reset} against the certificate in the file`);
  await tamperCheck(index, (r) => r.reasonCode === 'changed-after-signing');

  // --- who vouches for the name --------------------------------------------

  if (s.subject) info('subject', s.subject);
  if (s.issuer) info('issuer', s.issuer);

  if (s.signerBinding === 'mismatch') {
    bad(`the \`signer\` field (${s.signer}) is not supported by the certificate`);
    info('meaning', 'the signature is valid; the claim about who made it is not');
  } else if (s.signerBinding === 'matches') {
    ok('the `signer` field is supported by the certificate');
  }

  // §a.11.2 — the category must be anchored in the certificate.
  if (category?.state === 'anchored') {
    ok(`the signer category (${category.kind}) is anchored in the certificate`);
  } else if (category?.state === 'unanchored') {
    note(`the block says ${category.claimed}; the certificate asserts no category — asserted but not anchored (§a.11.2)`);
  } else if (category?.state === 'mismatch') {
    bad(`the block says ${category.claimed}, the certificate says ${category.certificate} (§a.11.2)`);
  }

  // §a.11.3 — what the credential may commit to. The EFFECTIVE commitment:
  // `approval` when the field is absent (§a.4).
  if (s.permittedCommitments) {
    const commitment = s.commitment ?? 'approval';
    info('constrained to', s.permittedCommitments.join(', '));
    if (commitmentPermitted(commitment, s.permittedCommitments)) {
      ok(`the commitment (${commitment}) is within the certificate's constraint`);
    } else {
      bad(`the certificate permits ${s.permittedCommitments.join(', ')}; the block commits ${commitment} (§a.11.3)`);
    }
  }

  if (s.validFrom && s.validTo) {
    info('cert validity', `${s.validFrom} … ${s.validTo}`);
    if (new Date(s.validTo) < new Date()) {
      info('', C.dim + 'expired — normal for MAdES, the timestamp carries it (§c.3)' + C.reset);
    }
  }

  if (anchorPem) {
    if (s.trust === 'trusted') ok('the chain is anchored in the supplied root');
    else note('trust anchor not recognised — supply the issuer\'s root to complete verification');
  } else {
    note('no trust anchor supplied — pass --anchor <root.pem> to check the chain');
  }

  if (s.appearance?.declared) {
    if (s.appearance.matches) ok('the appearance matches its digest (§a.8)');
    else note('the appearance does not match its digest (§a.8)');
  }

  timestampLines(s.timestamp);
  coversLines(s.covers);
  unreadLines(s.unread);
}

/**
 * The raw-key path (§c.7). The package builds the signing input and checks the
 * signature; the reader supplies the key, which is the only thing a document
 * signed without a certificate cannot carry.
 */
async function rawKeyPath(index, s) {
  const d = signingInputForBlock(document, index);
  const valid = await verifySignature(
    nodePoort, d.signingInput, Buffer.from(d.signature, 'base64'), { publiekeSleutel: publicKey }, s.algorithm
  );
  const keyId = d.fields['key-id'];
  if (!valid) {
    bad('signature does NOT verify against the supplied key');
    return;
  }
  verified++;
  ok(`${C.bold}SIGNATURE VERIFIES${C.reset} against the supplied key`);
  info('key', `supplied by the reader${keyId ? ` for ${keyId}` : ''}`);
  await tamperCheck(index, null);
  // The signature is sound and nobody vouched for the name attached to it —
  // a different statement from "invalid".
  note('raw-key path — no certificate, so no issuer vouches for this name');
  // A token is checked against the certificate it was issued over, and here
  // there is none.
  if (d.fields.timestamp) note('timestamp present, not verified on the raw-key path (§c.5)');
  else note('no timestamp — this signature cannot outlive its key');
  coversLines(s.covers);
  unreadLines((s.unread ?? []).filter((u) => u.name !== 'key-id'));
}

/**
 * The other half: a verifier that always says yes passes every check above.
 * One changed character must break the signature.
 */
async function tamperCheck(index, broke) {
  const tampered = (document[0] === 'x' ? 'y' : 'x') + document.slice(1);
  let still = false;
  try {
    if (broke) {
      const r = (await verifyDocument(nodePoort, tampered)).signatures.find((x) => x.index === index);
      still = r !== undefined && !broke(r);
    } else {
      const t = signingInputForBlock(tampered, index);
      still = await verifySignature(
        nodePoort, t.signingInput, Buffer.from(t.signature, 'base64'), { publiekeSleutel: publicKey }, t.fields.algorithm
      );
    }
  } catch {
    // The change removed the block itself: nothing verifies any more.
  }
  if (still) bad('a modified document still verifies — the check above proves nothing');
  else ok('a single changed character breaks it');
}

function trustLine(trust, who) {
  if (trust === 'trusted') ok(`${who} is anchored in the supplied root`);
  else if (anchorPem) note(`trust anchor not recognised for ${who}`);
}

/** §c.5 — the package verifies RFC 3161 tokens; the reference used to only state them. */
function timestampLines(t) {
  if (!t?.present) {
    note('no timestamp — this signature cannot outlive its certificate');
    return;
  }
  if (t.verified) {
    ok(`timestamp verified — ${t.genTime}${t.tsa ? `, ${t.tsa}` : ''}`);
    if (t.coversSignature === false) bad('the timestamp does not cover this signature (§c.5)');
    if (t.insideCertificateWindow === false) bad('the timestamp falls outside the certificate\'s validity (§c.5)');
    trustLine(t.trust, 'the timestamping authority');
  } else {
    note(`timestamp present, not verified${t.problem ? ` — ${t.problem}` : ''} (§c.5)`);
  }
}

/** §a.12 — the files that ride along. */
function coversLines(covers) {
  if (!covers?.length) return;
  info('covers', `${covers.length} accompanying file(s)`);
  for (const c of covers) info('', `${c.name} ${C.dim}— ${c.mediaType} — ${c.digest}${C.reset}`);
  if (covers.some((c) => c.state === 'broken')) bad('coverage broken — a file does not match its digest (§a.12)');
  if (covers.some((c) => c.state === 'asserted-unverified')) {
    note('the accompanying files were not supplied — coverage is asserted but unverified (§a.12)');
  }
}

/** §d level 4 — signed fields this reader does not implement: shown, not interpreted. */
function unreadLines(unread) {
  if (!unread?.length) return;
  console.log(`  ${C.bold}signed fields this reader does not implement${C.reset}`);
  for (const u of unread) {
    info(u.name, `${render(u.value)} ${C.dim}(meaning not known to this reader)${C.reset}`);
  }
}

function render(v) {
  if (Array.isArray(v)) return `[${v.length} item(s)]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).join(', ')}}`;
  return String(v);
}
