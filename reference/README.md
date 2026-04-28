# MAdES reference implementation (Node.js)

Reference scripts that demonstrate a working MAdES sign + verify cycle. Zero dependencies (Node.js built-ins only). Targets Node 18+.

## Status

- ✅ **`hmac-sha256`** — fully implemented (sign + verify, CLI + library)
- ⏳ **`ed25519`** — TODO v0.4 (using `node:crypto` `sign()` / `verify()` with PKCS#8 keys)
- ⏳ **`ecdsa-p256`** — TODO v0.4
- ⏳ **`rsa-pss-sha256`** — TODO v0.4
- ⏳ **Key-id resolution** — TODO v0.4 (`.well-known/mades-keys`, DID URLs)

## Files

| File | Purpose |
|---|---|
| `mades-canon.mjs` | Canonicalisation + sig-block parsing + algorithm registry. Pure functions, zero deps. Importable as a library. |
| `mades-sign.mjs` | CLI to append a signature to a Markdown file |
| `mades-verify.mjs` | CLI to verify all signatures in a Markdown file |
| `test/canonicalisation.test.mjs` | Tests using `node --test`. Covers canonicalisation edge cases + sign/verify round-trips. |

## Quickstart

```bash
# Generate a 256-bit secret (or use any hex string of equivalent entropy)
SECRET=$(openssl rand -hex 32)
echo "# My Document" > doc.md
echo "Some content here." >> doc.md

# Sign
node reference/mades-sign.mjs \
  --input doc.md \
  --signer alice@example.com \
  --secret $SECRET

# Inspect — the file now has a ~~~mades-sig block appended
cat doc.md

# Verify
node reference/mades-verify.mjs \
  --input doc.md \
  --secret $SECRET
# → ✓ alice@example.com — hmac-sha256
```

## Library use (programmatic)

```javascript
import { canonicalise, parseDocument, ALGORITHMS } from './reference/mades-canon.mjs';
import { readFileSync } from 'node:fs';

const doc = readFileSync('doc.md', 'utf8');
const parsed = parseDocument(doc);

for (const block of parsed.blocks) {
  const algo = ALGORITHMS[block.parsed.algorithm];
  const valid = await algo.verify(
    block.priorContent,
    block.parsed.signature,
    { secret: 'your-hex-secret-here' }
  );
  console.log(`${block.parsed.signer}: ${valid ? 'OK' : 'INVALID'}`);
}
```

## Running tests

```bash
node --test reference/test/
```

## Acknowledged limitations

This is **reference code**, not a production-hardened library. Known shortcuts:

- `parseSimpleYaml` is a flat-key-value parser, not a real YAML parser. It handles sig-block bodies fine but won't parse general YAML (e.g. nested maps, multi-line strings). For production use: `import yaml from 'js-yaml'` (or equivalent) and replace `parseSimpleYaml`.
- `mades-sign` field-validation is best-effort (regex checks against the declaration block). Full stage-dependency-graph evaluation is left to a workflow-engine implementation.
- No key-rotation, no expired-key handling, no certificate-chain validation.
- HMAC only — no public-key crypto in v0.3.
- The reference impl is not formally security-audited.

For production: use this as a starting point, replace the YAML parser, add the algorithms you need, build your own key-management.

## License

MIT — see [`../LICENSE-CODE`](../LICENSE-CODE).
