#!/usr/bin/env node
/**
 * MAdES signer — appends a signature block to a Markdown document.
 *
 *   node mades-sign.mjs keygen > signer.key
 *   node mades-sign.mjs sign doc.md --key signer.key \
 *        --signer alice@example.com --kind human --commitment approval
 *
 * Zero dependencies. Node built-ins only.
 *
 * **This signs with a raw key, not a certificate.** Issuing short-lived
 * certificates (§c.3) needs a CA, an identity check and a confirmation channel
 * — a service, not a script, and none of it belongs in a reference
 * implementation. What this demonstrates is the half that every implementation
 * must agree on byte-for-byte: how the signing input is built and how the block
 * is written.
 *
 * A document signed this way carries `key-id` instead of `certificate-chain`
 * (§c.7). It verifies, and it reports its trust anchor as unrecognised, which
 * is the honest answer for a key nobody vouched for.
 */
import { generateKeyPairSync, createPrivateKey, sign as signRaw, createSign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

import { findBlocks, canonicalize, serializeBlock, signingInputForBlock } from './mades-canon.mjs';

const BLOCK_VERSION = 5;

const command = process.argv[2];
if (command === 'keygen') keygen();
else if (command === 'sign') sign();
else {
  console.error('usage:\n  mades-sign.mjs keygen > signer.key\n  mades-sign.mjs sign <file.md> --key <key.pem> --signer <email> [options]');
  process.exit(2);
}

// ---------------------------------------------------------------------------

function keygen() {
  const { privateKey } = generateKeyPairSync('ed25519');
  process.stdout.write(privateKey.export({ type: 'pkcs8', format: 'pem' }));
}

function sign() {
  const file = process.argv[3];
  if (!file) die('which file?');

  const key = createPrivateKey(readFileSync(flag('--key') ?? die('--key <file> is required'), 'utf8'));
  const signer = flag('--signer') ?? die('--signer <email> is required');

  // NO DEFAULT FOR `signer-kind`, and that is the point (§a.11).
  //
  // Defaulting to `human` would give the whole rule away in one line: every
  // caller who forgets the flag produces a document claiming a person signed
  // it. Forgetting is the most common way this goes wrong, so forgetting has
  // to be loud.
  const kind = flag('--kind');
  if (!kind) die('--kind <human|automated> is required from block version 5');
  if (!['human', 'automated'].includes(kind)) die('--kind must be `human` or `automated`');

  const document = readFileSync(file, 'utf8');
  const blockIndex = findBlocks(document).length; // append after any existing blocks

  const fields = {
    version: BLOCK_VERSION,
    algorithm: algorithmFor(key),
    signer,
    'signer-kind': kind,
    commitment: flag('--commitment') ?? 'approval',
    'signed-at': flag('--at') ?? new Date().toISOString(),
  };
  if (flag('--automation')) fields.automation = flag('--automation');
  if (flag('--lang')) fields.lang = flag('--lang');
  if (flag('--key-id')) fields['key-id'] = flag('--key-id');

  const comment = `# ✓ Signed by ${signer} — ${fields.commitment} — ${kind} — ${fields['signed-at'].slice(0, 10)}`;

  // Build the signing input exactly as a verifier will rebuild it: content up
  // to where this block will sit, then the comment lines, then the fields
  // sorted by key. Producing it any other way is how a signer and a verifier
  // come to disagree about a document neither of them changed.
  const draft = document.replace(/\n*$/, '\n\n') + serializeBlock({ ...fields, signature: 'x' }, [comment]) + '\n';
  const { signingInput } = signingInputForBlock(draft, blockIndex);

  fields.signature = produce(key, signingInput);

  const out = document.replace(/\n*$/, '\n\n') + serializeBlock(fields, [comment]) + '\n';
  writeFileSync(file, out);

  // Verify what we just wrote, from the file, before claiming success. A signer
  // that does not read back its own output is a signer that ships broken
  // documents and finds out from a recipient.
  const check = signingInputForBlock(readFileSync(file, 'utf8'), blockIndex);
  if (check.signingInput !== signingInput) {
    die('the block that was written does not rebuild to what was signed — refusing to claim success');
  }

  console.error(`signed ${file} — block ${blockIndex + 1}, ${fields.algorithm}, ${kind}`);
}

// ---------------------------------------------------------------------------

function algorithmFor(key) {
  const t = key.asymmetricKeyType;
  if (t === 'ed25519') return 'ed25519';
  if (t === 'ec') return 'ecdsa-p256';
  if (t === 'rsa') return 'rsa-sha256';
  return die(`unsupported key type: ${t}`);
}

function produce(key, input) {
  if (key.asymmetricKeyType === 'ed25519') {
    return signRaw(null, Buffer.from(input, 'utf8'), key).toString('base64');
  }
  const s = createSign('sha256');
  s.update(input);
  return s.sign(key).toString('base64');
}

function flag(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

function die(message) {
  console.error(`mades-sign: ${message}`);
  process.exit(1);
}
