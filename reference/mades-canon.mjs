/**
 * MAdES canonicalisation + sig-block parsing.
 *
 * Pure functions, zero dependencies, used by sign + verify.
 *
 * Per SPEC.md § a:
 *   1. Locate the sig-block to verify.
 *   2. Strip from the opening `~~~mades-sig` line through the closing `~~~`,
 *      inclusive of any trailing whitespace.
 *   3. Normalise the remaining content: strip trailing whitespace per line,
 *      ensure single trailing newline, leave all other bytes untouched.
 *   4. Recompute the signature using the algorithm field; compare.
 */

const SIG_OPEN = '~~~mades-sig';
const SIG_CLOSE = '~~~';

/**
 * Normalise a chunk of markdown for hashing: strip trailing whitespace per
 * line, normalise CRLF → LF, ensure exactly one trailing newline.
 *
 * Deliberately conservative: leaves all bytes inside lines untouched
 * (no Unicode normalisation, no whitespace collapsing inside paragraphs).
 *
 * @param {string} text
 * @returns {string}
 */
export function canonicalise(text) {
  // CRLF → LF (universal text-file convention)
  let out = text.replace(/\r\n/g, '\n');
  // Strip trailing whitespace on every line
  out = out.split('\n').map((line) => line.replace(/[ \t]+$/, '')).join('\n');
  // Single trailing newline (no leading)
  out = out.replace(/\n+$/, '') + '\n';
  return out;
}

/**
 * Parse a complete markdown document into a sequence of sig-blocks plus the
 * content runs between/around them. Used by both sign (to find where to
 * append) and verify (to walk back-to-front).
 *
 * Returns:
 *   {
 *     prefix: string,           // content before any sig-block
 *     blocks: Array<{
 *       startLine: number,      // 0-based line index of opening fence
 *       endLine: number,        // 0-based line index of closing fence (inclusive)
 *       yamlBody: string,       // raw YAML lines between the fences
 *       parsed: object,         // minimal YAML parse (key: value)
 *       priorContent: string,   // canonicalised content before this block (= what was signed)
 *     }>,
 *     trailingContent: string,  // content after last sig-block (usually empty)
 *   }
 *
 * @param {string} text
 */
export function parseDocument(text) {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  const blocks = [];

  let i = 0;
  while (i < lines.length) {
    if (lines[i].trim() === SIG_OPEN) {
      const startLine = i;
      // Find closing fence
      let j = i + 1;
      while (j < lines.length && lines[j].trim() !== SIG_CLOSE) j++;
      if (j >= lines.length) {
        throw new Error(`Unterminated mades-sig block starting at line ${startLine + 1}`);
      }
      const yamlBody = lines.slice(startLine + 1, j).join('\n');
      const parsed = parseSimpleYaml(yamlBody);
      blocks.push({ startLine, endLine: j, yamlBody, parsed, priorContent: '' });
      i = j + 1;
    } else {
      i++;
    }
  }

  // Compute prior content per block (= canonicalised text from start through
  // the line BEFORE the opening fence, with everything from opening fence
  // onwards stripped).
  for (let b = 0; b < blocks.length; b++) {
    const upTo = blocks[b].startLine; // exclusive
    const priorRaw = lines.slice(0, upTo).join('\n');
    blocks[b].priorContent = canonicalise(priorRaw);
  }

  const prefix = blocks.length > 0
    ? canonicalise(lines.slice(0, blocks[0].startLine).join('\n'))
    : canonicalise(text);

  const lastEnd = blocks.length > 0 ? blocks[blocks.length - 1].endLine + 1 : lines.length;
  const trailingContent = lines.slice(lastEnd).join('\n');

  return { prefix, blocks, trailingContent };
}

/**
 * Minimal YAML parser sufficient for sig-block fields.
 *
 * Supports:
 *   - `key: value` flat pairs
 *   - String values (with or without quotes)
 *   - Comment lines starting with `#` (ignored)
 *
 * Does NOT support: nested maps, arrays, multi-line strings, anchors, tags.
 * Sig-blocks are intentionally simple — if a real YAML parser is needed,
 * swap this out (the parsed map shape stays the same).
 *
 * @param {string} yamlText
 * @returns {Record<string, string>}
 */
export function parseSimpleYaml(yamlText) {
  const result = {};
  for (const rawLine of yamlText.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;
    const key = line.slice(0, colonIdx).trim();
    let value = line.slice(colonIdx + 1).trim();
    // Strip wrapping quotes
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    result[key] = value;
  }
  return result;
}

/**
 * Produce a human-readable comment line for the YAML-comment header (Level 1
 * visual representation per SPEC.md § d).
 *
 * @param {{ signer: string; signedAt: string; algorithm: string; field?: string }} info
 * @returns {string}
 */
export function buildHeaderComment({ signer, signedAt, algorithm, field }) {
  const date = signedAt.split('T')[0];
  const profile = algorithm === 'hmac-sha256'
    ? 'MAdES-Basic'
    : algorithm.startsWith('ed25519') || algorithm.startsWith('ecdsa')
      ? 'MAdES-Advanced'
      : 'MAdES-Qualified';
  const fieldPart = field ? ` [field: ${field}]` : '';
  return `# ✓ Signed by ${signer} — ${date} (${algorithm}, ${profile})${fieldPart}`;
}

/**
 * Algorithm registry. Each entry knows how to produce + verify a signature.
 *
 * v0.3 reference implementation supports HMAC-SHA256 (MAdES-Basic baseline).
 * Ed25519 / ECDSA-P256 / RSA-PSS are recognised in the spec but require
 * either WebCrypto subtle or explicit key material — left as TODO for v0.4.
 */
export const ALGORITHMS = {
  'hmac-sha256': {
    profile: 'MAdES-Basic',
    /**
     * @param {string} canonicalContent
     * @param {{ secret: string }} key
     * @returns {Promise<string>} hex signature
     */
    async sign(canonicalContent, key) {
      const { createHmac } = await import('node:crypto');
      return createHmac('sha256', key.secret).update(canonicalContent, 'utf8').digest('hex');
    },
    /**
     * @param {string} canonicalContent
     * @param {string} signatureHex
     * @param {{ secret: string }} key
     * @returns {Promise<boolean>}
     */
    async verify(canonicalContent, signatureHex, key) {
      const expected = await this.sign(canonicalContent, key);
      return constantTimeEqual(expected, signatureHex);
    },
  },
};

/**
 * Constant-time string comparison (prevents timing attacks on signature
 * verification). Both inputs must be hex-encoded.
 */
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}
