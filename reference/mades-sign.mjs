#!/usr/bin/env node
/**
 * MAdES signer — appends a signature block to a Markdown document.
 *
 *   node mades-sign.mjs keygen > signer.key
 *   node mades-sign.mjs sign doc.md --key signer.key \
 *        --signer alice@example.com --kind human --commitment approval
 *
 * A COMMAND LINE AROUND @itbrouwerij/mades-verify, like its sibling. The
 * package decides the signing input and writes the block, through the pair §e
 * requires of every implementation: `prepare` before the signature, `finalize`
 * after. What stays here is the one thing the package deliberately does not do:
 * hold a private key. The key signs the prepared input, with node:crypto.
 *
 * **This signs with a raw key, not a certificate.** Issuing short-lived
 * certificates (§c.3) needs a CA, an identity check and a confirmation channel
 * — a service, not a script. A document signed here carries `key-id` if you
 * give one, and no `certificate-chain` (§c.7). It verifies with `--key`, and no
 * issuer vouches for the name on it, which is the honest answer for a key
 * nobody vouched for.
 */
import { createPrivateKey, createSign, generateKeyPairSync, sign as signRaw } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

import { finalize, findBlocks, prepare, signingInputForBlock } from '@itbrouwerij/mades-verify';
import { nodePoort } from '@itbrouwerij/mades-verify/node';

const command = process.argv[2];
if (command === 'keygen') keygen();
else if (command === 'sign') await sign();
else {
  console.error('usage:\n  mades-sign.mjs keygen > signer.key\n  mades-sign.mjs sign <file.md> --key <key.pem> --signer <email> --kind <human|automated> [options]');
  process.exit(2);
}

// ---------------------------------------------------------------------------

function keygen() {
  const { privateKey } = generateKeyPairSync('ed25519');
  process.stdout.write(privateKey.export({ type: 'pkcs8', format: 'pem' }));
}

async function sign() {
  const file = process.argv[3];
  if (!file) die('which file?');

  const key = createPrivateKey(readFileSync(flag('--key') ?? die('--key <file> is required'), 'utf8'));
  const signer = flag('--signer') ?? die('--signer <email> is required');

  // NO DEFAULT FOR `signer-kind`, and that is the point (§a.11). Defaulting to
  // `human` would give the whole rule away in one line: every caller who
  // forgets the flag produces a document claiming a person signed it. The
  // package refuses a missing kind too; failing here says which flag.
  const kind = flag('--kind');
  if (!kind) die('--kind <human|automated> is required from block version 5');
  if (!['human', 'automated'].includes(kind)) die('--kind must be `human` or `automated`');

  const document = readFileSync(file, 'utf8');
  const blockIndex = findBlocks(document).length; // append after any existing blocks

  const fields = {
    algorithm: algorithmFor(key),
    signer,
    'signer-kind': kind,
    commitment: flag('--commitment') ?? 'approval',
  };
  if (flag('--at')) fields['signed-at'] = flag('--at');
  if (flag('--automation')) fields.automation = flag('--automation');
  if (flag('--lang')) fields.lang = flag('--lang');
  if (flag('--key-id')) fields['key-id'] = flag('--key-id');

  let prepared;
  try {
    prepared = await prepare(nodePoort, document, fields);
  } catch (err) {
    die(err.message);
  }

  // `finalize` writes the content above the block in its canonical form (§a.2):
  // what a verifier rebuilds is then byte for byte what is on disk.
  const out = finalize(document, prepared, produce(key, prepared.signingInput));
  writeFileSync(file, out);

  // Read back what was written before claiming success. A signer that does not
  // is a signer that ships broken documents and hears about it from a recipient.
  const check = signingInputForBlock(readFileSync(file, 'utf8'), blockIndex);
  if (check.signingInput !== prepared.signingInput) {
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
  s.update(input, 'utf8');
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
