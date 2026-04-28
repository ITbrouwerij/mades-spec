#!/usr/bin/env node
/**
 * mades-sign — append a MAdES signature block to a Markdown file.
 *
 * Usage:
 *   mades-sign --input doc.md --signer alice@example.com --secret <hex> [options]
 *
 * Required:
 *   --input <file>          Markdown file to sign (read + write in place unless --output given)
 *   --signer <id>           Signer identifier (typically email or DID)
 *   --secret <hex|file>     HMAC secret as hex string OR path to file containing it
 *
 * Optional:
 *   --algorithm <alg>       Signature algorithm. Default: hmac-sha256
 *                           (v0.3 reference impl: only hmac-sha256 supported)
 *   --field <id>            Reference a field from a mades-sig-fields declaration
 *   --output <file>         Write to a different file instead of overwriting input
 *   --help                  Show this message
 *
 * Exit codes:
 *   0 = signed successfully
 *   1 = error (validation, IO, crypto)
 *   2 = field-validation error (e.g., field already signed in single-occupancy stage)
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { canonicalise, parseDocument, ALGORITHMS, buildHeaderComment } from './mades-canon.mjs';

function usage() {
  console.error(`mades-sign — append a MAdES signature to a Markdown file.

Usage:
  mades-sign --input doc.md --signer alice@example.com --secret <hex|file> [options]

Required:
  --input <file>       Markdown file to sign
  --signer <id>        Signer identifier (email, DID, etc.)
  --secret <hex|file>  HMAC secret as hex string OR path to file containing it

Optional:
  --algorithm <alg>    Signature algorithm (default: hmac-sha256)
  --field <id>         Reference a field declared in a mades-sig-fields block
  --output <file>      Write to different file (default: overwrite --input)
  --help               Show this message

Exit codes: 0=ok, 1=error, 2=field validation error
`);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') { args.help = true; continue; }
    if (a.startsWith('--')) {
      args[a.slice(2)] = argv[++i];
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help || !args.input || !args.signer || !args.secret) {
    usage();
    process.exit(args.help ? 0 : 1);
  }

  const algorithm = args.algorithm || 'hmac-sha256';
  if (!ALGORITHMS[algorithm]) {
    console.error(`Error: algorithm '${algorithm}' not supported by reference impl.`);
    console.error(`Supported: ${Object.keys(ALGORITHMS).join(', ')}`);
    process.exit(1);
  }

  // Resolve secret: literal hex string OR file path
  let secret = args.secret;
  if (existsSync(secret)) {
    secret = readFileSync(secret, 'utf8').trim();
  }
  if (!/^[0-9a-fA-F]+$/.test(secret)) {
    console.error('Error: --secret must be hex (or a file containing hex)');
    process.exit(1);
  }

  if (!existsSync(args.input)) {
    console.error(`Error: input file not found: ${args.input}`);
    process.exit(1);
  }

  const original = readFileSync(args.input, 'utf8');
  const parsed = parseDocument(original);

  // ── Field validation against mades-sig-fields if present ──────────────
  // (Reference impl: best-effort. We look for a mades-sig-fields block in
  // the prefix and check if the requested field is declared + still
  // single-occupancy. Full stage-dependency-graph validation is left for
  // a richer implementation.)
  if (args.field) {
    const fieldsPattern = /~~~mades-sig-fields\n([\s\S]*?)\n~~~/;
    const m = original.match(fieldsPattern);
    if (m) {
      const declaration = m[1];
      // Naive: check field id appears in declaration
      const fieldRegex = new RegExp(`\\bid:\\s*${args.field}\\b`);
      if (!fieldRegex.test(declaration)) {
        console.error(`Error: field '${args.field}' not declared in mades-sig-fields block`);
        process.exit(2);
      }
      // Naive: check no existing sig-block already references this field
      for (const blk of parsed.blocks) {
        if (blk.parsed.field === args.field) {
          console.error(`Error: field '${args.field}' already signed in this document`);
          process.exit(2);
        }
      }
    }
  }

  const signedAt = new Date().toISOString();
  const algo = ALGORITHMS[algorithm];

  // ── Build a "fake" sig-block-less document to compute the signature over ──
  // The signature covers everything before the new block's opening fence.
  // We append the new block at the end, so the signed content is the
  // canonicalised current document.
  const canonical = canonicalise(original);
  const signature = await algo.sign(canonical, { secret });

  // ── Compose the new sig-block ─────────────────────────────────────────
  const headerComment = buildHeaderComment({
    signer: args.signer,
    signedAt,
    algorithm,
    field: args.field,
  });

  const yamlLines = [
    headerComment,
    `version: 1`,
    `algorithm: ${algorithm}`,
    `signer: ${args.signer}`,
    `signed-at: ${signedAt}`,
  ];
  if (args.field) yamlLines.push(`field: ${args.field}`);
  yamlLines.push(`signature: ${signature}`);

  const newBlock = `~~~mades-sig\n${yamlLines.join('\n')}\n~~~\n`;

  // ── Write result ──────────────────────────────────────────────────────
  // Append new block (with one blank line separator if needed)
  const sep = canonical.endsWith('\n') ? '\n' : '\n\n';
  const output = canonical + sep + newBlock;

  const outPath = args.output || args.input;
  writeFileSync(outPath, output, 'utf8');

  console.log(`Signed: ${outPath}`);
  console.log(`  algorithm: ${algorithm}`);
  console.log(`  signer:    ${args.signer}`);
  console.log(`  signed-at: ${signedAt}`);
  if (args.field) console.log(`  field:     ${args.field}`);
  console.log(`  signature: ${signature.slice(0, 16)}... (${signature.length} chars)`);
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exit(1);
});
