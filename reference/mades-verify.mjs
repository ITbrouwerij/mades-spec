#!/usr/bin/env node
/**
 * mades-verify — validate MAdES signatures in a Markdown file.
 *
 * Walks all `~~~mades-sig` blocks back-to-front. For each: reconstructs the
 * canonical content as it existed when that block was added, recomputes the
 * signature, compares with the stored value.
 *
 * Usage:
 *   mades-verify --input doc.md --secret <hex|file>
 *   mades-verify --input doc.md --keys-manifest keys.json
 *
 * Required:
 *   --input <file>          Markdown file to verify
 *
 * One of:
 *   --secret <hex|file>     Shared HMAC secret (for hmac-sha256 algorithm)
 *   --keys-manifest <file>  JSON file mapping key-id → key material
 *                           (v0.4+ — for non-HMAC algorithms)
 *
 * Optional:
 *   --json                  Output machine-readable JSON instead of human text
 *   --strict                Exit non-zero if any signature invalid OR any
 *                           required field unsigned
 *   --help                  Show this message
 *
 * Exit codes:
 *   0 = all signatures valid + (if --strict) all required fields filled
 *   1 = at least one signature invalid
 *   2 = (with --strict) signatures valid but required fields unsigned
 *   3 = error (IO, parse)
 */

import { readFileSync, existsSync } from 'node:fs';
import { parseDocument, ALGORITHMS } from './mades-canon.mjs';

function usage() {
  console.error(`mades-verify — validate MAdES signatures in a Markdown file.

Usage:
  mades-verify --input doc.md --secret <hex|file>
  mades-verify --input doc.md --keys-manifest keys.json

Optional:
  --json     Output machine-readable JSON
  --strict   Exit non-zero if required fields unsigned

Exit codes: 0=ok, 1=invalid signature, 2=incomplete (--strict only), 3=error
`);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') { args.help = true; continue; }
    if (a === '--json') { args.json = true; continue; }
    if (a === '--strict') { args.strict = true; continue; }
    if (a.startsWith('--')) {
      args[a.slice(2)] = argv[++i];
    }
  }
  return args;
}

function loadSecret(secretArg) {
  if (existsSync(secretArg)) {
    return readFileSync(secretArg, 'utf8').trim();
  }
  return secretArg.trim();
}

function parseFieldDeclaration(text) {
  // Best-effort: extract field IDs + required flag from a mades-sig-fields block
  const m = text.match(/~~~mades-sig-fields\n([\s\S]*?)\n~~~/);
  if (!m) return null;
  const declaration = m[1];
  const fields = [];
  // Naive line-walk; supports both flat list and stages structure
  const lines = declaration.split('\n');
  let currentField = null;
  for (const line of lines) {
    const idMatch = line.match(/^\s*-?\s*id:\s*(\S+)/);
    if (idMatch) {
      if (currentField) fields.push(currentField);
      currentField = { id: idMatch[1], required: false };
      continue;
    }
    const reqMatch = line.match(/^\s*required:\s*(true|false)/);
    if (reqMatch && currentField) {
      currentField.required = reqMatch[1] === 'true';
    }
  }
  if (currentField) fields.push(currentField);
  return fields;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help || !args.input) {
    usage();
    process.exit(args.help ? 0 : 3);
  }

  if (!existsSync(args.input)) {
    console.error(`Error: input file not found: ${args.input}`);
    process.exit(3);
  }

  const original = readFileSync(args.input, 'utf8');
  const parsed = parseDocument(original);

  if (parsed.blocks.length === 0) {
    const out = { ok: false, reason: 'no signatures found', blocks: [] };
    console.log(args.json ? JSON.stringify(out, null, 2) : 'No signatures found.');
    process.exit(1);
  }

  const results = [];
  let allValid = true;

  for (const blk of parsed.blocks) {
    const algo = ALGORITHMS[blk.parsed.algorithm];
    if (!algo) {
      results.push({
        signer: blk.parsed.signer,
        algorithm: blk.parsed.algorithm,
        valid: false,
        error: `algorithm '${blk.parsed.algorithm}' not supported by reference impl`,
      });
      allValid = false;
      continue;
    }

    if (blk.parsed.algorithm === 'hmac-sha256') {
      if (!args.secret) {
        results.push({
          signer: blk.parsed.signer,
          algorithm: 'hmac-sha256',
          valid: false,
          error: '--secret required for hmac-sha256 verification',
        });
        allValid = false;
        continue;
      }
      const secret = loadSecret(args.secret);
      const valid = await algo.verify(blk.priorContent, blk.parsed.signature, { secret });
      results.push({
        signer: blk.parsed.signer,
        algorithm: 'hmac-sha256',
        signedAt: blk.parsed['signed-at'],
        field: blk.parsed.field || null,
        valid,
      });
      if (!valid) allValid = false;
    } else {
      // Non-HMAC: not yet implemented in reference (v0.4+)
      results.push({
        signer: blk.parsed.signer,
        algorithm: blk.parsed.algorithm,
        valid: null,
        error: 'reference impl supports only hmac-sha256 in v0.3',
      });
    }
  }

  // Field-completeness check
  const declaredFields = parseFieldDeclaration(original);
  let unsignedRequired = [];
  if (declaredFields) {
    const signedFieldIds = new Set(
      parsed.blocks.map((b) => b.parsed.field).filter(Boolean),
    );
    unsignedRequired = declaredFields
      .filter((f) => f.required && !signedFieldIds.has(f.id))
      .map((f) => f.id);
  }

  // Exit code
  let exitCode = 0;
  if (!allValid) exitCode = 1;
  else if (args.strict && unsignedRequired.length > 0) exitCode = 2;

  // Output
  if (args.json) {
    console.log(JSON.stringify({
      ok: exitCode === 0,
      signatureCount: parsed.blocks.length,
      results,
      declaredFields: declaredFields || null,
      unsignedRequiredFields: unsignedRequired,
    }, null, 2));
  } else {
    console.log(`Verified ${parsed.blocks.length} signature(s) in ${args.input}:`);
    for (const r of results) {
      const icon = r.valid === true ? '✓' : r.valid === false ? '✗' : '?';
      const fieldPart = r.field ? ` [field: ${r.field}]` : '';
      const errPart = r.error ? ` (${r.error})` : '';
      console.log(`  ${icon} ${r.signer} — ${r.algorithm}${fieldPart}${errPart}`);
    }
    if (declaredFields) {
      console.log(`\nField-completeness: ${unsignedRequired.length === 0 ? 'COMPLETE' : 'INCOMPLETE'}`);
      if (unsignedRequired.length > 0) {
        console.log(`  Unsigned required fields: ${unsignedRequired.join(', ')}`);
      }
    }
  }

  process.exit(exitCode);
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exit(3);
});
