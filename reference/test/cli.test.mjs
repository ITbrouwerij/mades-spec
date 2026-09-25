/**
 * The two command lines, run as a user runs them.
 *
 * Since v1.11 both are thin: every judgement is `@itbrouwerij/mades-verify`'s.
 * What can still go wrong is the part that is theirs — arguments, the exit
 * code, and whether the report says what the package decided. A command line
 * that prints "verify" over a verdict it misread is the false green this
 * repository exists to prevent, so the exit codes are what these tests hold.
 */
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { createPublicKey } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, describe, it } from 'node:test';

const VERIFY = fileURLToPath(new URL('../mades-verify.mjs', import.meta.url));
const SIGN = fileURLToPath(new URL('../mades-sign.mjs', import.meta.url));
const example = (name) => fileURLToPath(new URL(`../../examples/${name}`, import.meta.url));

const run = (script, ...args) => {
  const r = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
};

const dir = mkdtempSync(join(tmpdir(), 'mades-cli-'));
after(() => rmSync(dir, { recursive: true, force: true }));

// ---------------------------------------------------------------------------

describe('mades-verify', () => {
  for (const name of [
    '05-a-real-signed-document.md',
    '06-signing-a-document-about-signing.md',
    '07-a-worked-example.md',
  ]) {
    it(`verifies examples/${name} from the file alone`, () => {
      const { code, out } = run(VERIFY, example(name));
      assert.equal(code, 0, out);
      assert.match(out, /SIGNATURE VERIFIES/);
      assert.match(out, /a single changed character breaks it/);
      assert.match(out, /1 signature\(s\) verify\./);
    });
  }

  it('fails a document with one character changed', () => {
    const file = join(dir, 'tampered.md');
    writeFileSync(file, 'x' + readFileSync(example('05-a-real-signed-document.md'), 'utf8').slice(1));
    const { code, out } = run(VERIFY, file);
    assert.equal(code, 1, out);
    assert.match(out, /signature does NOT verify/);
  });

  it('fails a document with a clause after its last block, before any signature (§a.14)', () => {
    const file = join(dir, 'appended.md');
    writeFileSync(file, readFileSync(example('07-a-worked-example.md'), 'utf8') + '\n## Additional clause\n');
    const { code, out } = run(VERIFY, file);
    assert.equal(code, 1, out);
    assert.ok(out.indexOf('outside every signature') < out.indexOf('signature 1'), 'the boundary is reported first');
  });

  it('says an unsigned document is unsigned', () => {
    const file = join(dir, 'unsigned.md');
    writeFileSync(file, '# Nothing signed here\n');
    const { code, out } = run(VERIFY, file);
    assert.equal(code, 1);
    assert.match(out, /this document is unsigned/);
  });

  it('exits 2 without a file', () => {
    assert.equal(run(VERIFY).code, 2);
  });
});

describe('mades-sign, and back through mades-verify', () => {
  const key = join(dir, 'signer.key');
  const pub = join(dir, 'signer.pub');
  const doc = join(dir, 'doc.md');

  it('keygen writes a key', () => {
    const { code, out } = run(SIGN, 'keygen');
    assert.equal(code, 0);
    writeFileSync(key, out);
    writeFileSync(pub, createPublicKey(out).export({ type: 'spki', format: 'pem' }));
  });

  it('refuses to sign without --kind: forgetting must not produce `human` (§a.11)', () => {
    writeFileSync(doc, '# Agreement\n\nThe parties agree.\n');
    const { code, err } = run(SIGN, 'sign', doc, '--key', key, '--signer', 'alice@example.com');
    assert.equal(code, 1);
    assert.match(err, /--kind/);
    assert.equal(readFileSync(doc, 'utf8'), '# Agreement\n\nThe parties agree.\n', 'nothing was written');
  });

  it('signs, and the result verifies with the key the reader holds (§c.7)', () => {
    const signed = run(SIGN, 'sign', doc, '--key', key, '--signer', 'alice@example.com', '--kind', 'human', '--key-id', 'alice-1');
    assert.equal(signed.code, 0, signed.err);
    const { code, out } = run(VERIFY, doc, '--key', pub);
    assert.equal(code, 0, out);
    assert.match(out, /SIGNATURE VERIFIES.*against the supplied key/);
    assert.match(out, /signer-kind\s+human/);
    assert.match(out, /no issuer vouches for this name/);
  });

  it('withholds a verdict when the reader holds no key', () => {
    const { code, out } = run(VERIFY, doc);
    assert.equal(code, 1);
    assert.match(out, /No verdict\./);
  });

  it('counter-signs: a second block covers the first', () => {
    const signed = run(SIGN, 'sign', doc, '--key', key, '--signer', 'bob@example.com', '--kind', 'automated', '--automation', 'pipeline', '--commitment', 'creation');
    assert.equal(signed.code, 0, signed.err);
    const { code, out } = run(VERIFY, doc, '--key', pub);
    assert.equal(code, 0, out);
    assert.match(out, /2 signature\(s\) verify\./);
  });
});
