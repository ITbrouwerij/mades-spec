/**
 * Canonicalisation + sign/verify round-trip tests.
 *
 * Run with: node --test reference/test/canonicalisation.test.mjs
 * (or: npm test from the repo root)
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  canonicalise,
  parseDocument,
  parseSimpleYaml,
  buildHeaderComment,
  ALGORITHMS,
} from '../mades-canon.mjs';

// Resolve script paths once (cross-platform — fileURLToPath handles Windows leading slash)
const __filename = fileURLToPath(import.meta.url);
const REFERENCE_DIR = dirname(dirname(__filename));
const SIGN = join(REFERENCE_DIR, 'mades-sign.mjs');
const VERIFY = join(REFERENCE_DIR, 'mades-verify.mjs');

const TEST_SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

// ─── canonicalise ────────────────────────────────────────────────────────────

test('canonicalise: CRLF normalisation', () => {
  const input = 'line one\r\nline two\r\n';
  const out = canonicalise(input);
  assert.equal(out, 'line one\nline two\n');
});

test('canonicalise: trailing whitespace per line stripped', () => {
  const input = 'hello   \nworld\t\t\n';
  const out = canonicalise(input);
  assert.equal(out, 'hello\nworld\n');
});

test('canonicalise: inner whitespace preserved', () => {
  const input = 'hello   world\n';
  const out = canonicalise(input);
  assert.equal(out, 'hello   world\n');
});

test('canonicalise: multiple trailing newlines collapsed to one', () => {
  const input = 'content\n\n\n\n';
  const out = canonicalise(input);
  assert.equal(out, 'content\n');
});

test('canonicalise: ensures exactly one trailing newline (none → one)', () => {
  const input = 'no trailing newline';
  const out = canonicalise(input);
  assert.equal(out, 'no trailing newline\n');
});

test('canonicalise: idempotent', () => {
  const input = 'line 1\r\nline 2 \t\nline 3\n\n\n';
  const once = canonicalise(input);
  const twice = canonicalise(once);
  assert.equal(once, twice);
});

test('canonicalise: unicode preserved untouched', () => {
  const input = 'héllo wörld 🌍\n';
  const out = canonicalise(input);
  assert.equal(out, 'héllo wörld 🌍\n');
});

// ─── parseSimpleYaml ─────────────────────────────────────────────────────────

test('parseSimpleYaml: flat key-value pairs', () => {
  const out = parseSimpleYaml('version: 1\nsigner: alice@example.com\n');
  assert.deepEqual(out, { version: '1', signer: 'alice@example.com' });
});

test('parseSimpleYaml: comment lines ignored', () => {
  const out = parseSimpleYaml('# this is a comment\nkey: value\n# another\nfoo: bar\n');
  assert.deepEqual(out, { key: 'value', foo: 'bar' });
});

test('parseSimpleYaml: quoted values stripped', () => {
  const out = parseSimpleYaml('key: "quoted value"\nother: \'single\'\n');
  assert.deepEqual(out, { key: 'quoted value', other: 'single' });
});

// ─── parseDocument ───────────────────────────────────────────────────────────

test('parseDocument: zero sig-blocks', () => {
  const doc = '# Title\n\nJust content.\n';
  const out = parseDocument(doc);
  assert.equal(out.blocks.length, 0);
});

test('parseDocument: one sig-block, prior content correct', () => {
  const doc = '# Title\n\nContent.\n\n~~~mades-sig\nversion: 1\nsigner: a@b.c\nsignature: abc\n~~~\n';
  const out = parseDocument(doc);
  assert.equal(out.blocks.length, 1);
  assert.equal(out.blocks[0].parsed.signer, 'a@b.c');
  // Prior content should NOT include the sig-block opening fence
  assert.ok(!out.blocks[0].priorContent.includes('mades-sig'));
  assert.ok(out.blocks[0].priorContent.includes('# Title'));
});

test('parseDocument: two sig-blocks, second covers the first', () => {
  const doc = [
    '# Title',
    '',
    '~~~mades-sig',
    'version: 1',
    'signer: alice',
    'signature: SIG_A',
    '~~~',
    '',
    '~~~mades-sig',
    'version: 1',
    'signer: bob',
    'signature: SIG_B',
    '~~~',
    '',
  ].join('\n');
  const out = parseDocument(doc);
  assert.equal(out.blocks.length, 2);
  // Bob's prior content INCLUDES Alice's full sig-block
  assert.ok(out.blocks[1].priorContent.includes('SIG_A'));
  assert.ok(out.blocks[1].priorContent.includes('signer: alice'));
  // Alice's prior content does NOT include any sig-block (she signed first)
  assert.ok(!out.blocks[0].priorContent.includes('mades-sig'));
});

test('parseDocument: unterminated sig-block throws', () => {
  const doc = '# Title\n\n~~~mades-sig\nversion: 1\nsigner: a@b.c\n';
  assert.throws(() => parseDocument(doc), /Unterminated mades-sig block/);
});

// ─── buildHeaderComment ──────────────────────────────────────────────────────

test('buildHeaderComment: HMAC produces MAdES-Basic profile label', () => {
  const out = buildHeaderComment({
    signer: 'alice@example.com',
    signedAt: '2026-04-28T10:00:00Z',
    algorithm: 'hmac-sha256',
  });
  assert.match(out, /^# /);
  assert.match(out, /alice@example\.com/);
  assert.match(out, /MAdES-Basic/);
  assert.match(out, /2026-04-28/);
});

test('buildHeaderComment: includes field reference if provided', () => {
  const out = buildHeaderComment({
    signer: 'a',
    signedAt: '2026-01-01T00:00:00Z',
    algorithm: 'hmac-sha256',
    field: 'reviewer',
  });
  assert.match(out, /\[field: reviewer\]/);
});

// ─── ALGORITHMS.hmac-sha256 ──────────────────────────────────────────────────

test('hmac-sha256: sign then verify round-trip', async () => {
  const algo = ALGORITHMS['hmac-sha256'];
  const content = 'hello world\n';
  const sig = await algo.sign(content, { secret: TEST_SECRET });
  assert.equal(typeof sig, 'string');
  assert.match(sig, /^[0-9a-f]{64}$/); // SHA-256 hex
  const valid = await algo.verify(content, sig, { secret: TEST_SECRET });
  assert.equal(valid, true);
});

test('hmac-sha256: verify rejects tampered content', async () => {
  const algo = ALGORITHMS['hmac-sha256'];
  const sig = await algo.sign('original\n', { secret: TEST_SECRET });
  const valid = await algo.verify('tampered\n', sig, { secret: TEST_SECRET });
  assert.equal(valid, false);
});

test('hmac-sha256: verify rejects wrong secret', async () => {
  const algo = ALGORITHMS['hmac-sha256'];
  const sig = await algo.sign('content\n', { secret: TEST_SECRET });
  const wrongSecret = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
  const valid = await algo.verify('content\n', sig, { secret: wrongSecret });
  assert.equal(valid, false);
});

// ─── End-to-end: sign + verify CLI scripts ───────────────────────────────────

test('CLI round-trip: sign then verify a fresh document', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'mades-test-'));
  const docPath = join(tmp, 'doc.md');
  writeFileSync(docPath, '# Test Document\n\nThis is a test.\n', 'utf8');

  // Sign
  const signResult = spawnSync('node', [
    SIGN,
    '--input', docPath,
    '--signer', 'tester@example.com',
    '--secret', TEST_SECRET,
  ], { encoding: 'utf8' });
  assert.equal(signResult.status, 0, `sign failed: ${signResult.stderr}`);

  // Verify
  const verifyResult = spawnSync('node', [
    VERIFY,
    '--input', docPath,
    '--secret', TEST_SECRET,
    '--json',
  ], { encoding: 'utf8' });
  assert.equal(verifyResult.status, 0, `verify failed: ${verifyResult.stderr}`);

  const out = JSON.parse(verifyResult.stdout);
  assert.equal(out.ok, true);
  assert.equal(out.signatureCount, 1);
  assert.equal(out.results[0].valid, true);
  assert.equal(out.results[0].signer, 'tester@example.com');

  rmSync(tmp, { recursive: true, force: true });
});

test('CLI round-trip: sequential multi-sig — both signatures verify', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'mades-test-'));
  const docPath = join(tmp, 'doc.md');
  writeFileSync(docPath, '# Multi-sig test\n\nContent.\n', 'utf8');

  // Sign by Alice
  let r = spawnSync('node', [SIGN, '--input', docPath, '--signer', 'alice@example.com', '--secret', TEST_SECRET], { encoding: 'utf8' });
  assert.equal(r.status, 0);

  // Sign by Bob (covers Alice's signature too)
  r = spawnSync('node', [SIGN, '--input', docPath, '--signer', 'bob@example.com', '--secret', TEST_SECRET], { encoding: 'utf8' });
  assert.equal(r.status, 0);

  // Verify
  r = spawnSync('node', [VERIFY, '--input', docPath, '--secret', TEST_SECRET, '--json'], { encoding: 'utf8' });
  assert.equal(r.status, 0);
  const out = JSON.parse(r.stdout);
  assert.equal(out.signatureCount, 2);
  assert.equal(out.results[0].signer, 'alice@example.com');
  assert.equal(out.results[1].signer, 'bob@example.com');
  assert.equal(out.results.every((x) => x.valid === true), true);

  rmSync(tmp, { recursive: true, force: true });
});

test('CLI: tampering with content invalidates earlier signature', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'mades-test-'));
  const docPath = join(tmp, 'doc.md');
  writeFileSync(docPath, '# Original\n\nThis content matters.\n', 'utf8');

  // Sign
  let r = spawnSync('node', [SIGN, '--input', docPath, '--signer', 'a@b.c', '--secret', TEST_SECRET], { encoding: 'utf8' });
  assert.equal(r.status, 0);

  // Tamper: change body content
  const tampered = readFileSync(docPath, 'utf8').replace('This content matters.', 'This content has been tampered with.');
  writeFileSync(docPath, tampered, 'utf8');

  // Verify — must fail
  r = spawnSync('node', [VERIFY, '--input', docPath, '--secret', TEST_SECRET, '--json'], { encoding: 'utf8' });
  assert.equal(r.status, 1, 'verify should reject tampered content');
  const out = JSON.parse(r.stdout);
  assert.equal(out.ok, false);
  assert.equal(out.results[0].valid, false);

  rmSync(tmp, { recursive: true, force: true });
});
