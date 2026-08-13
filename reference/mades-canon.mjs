/**
 * MAdES core — block location, parsing, canonicalisation, signing input.
 *
 * Zero dependencies. Node built-ins only.
 *
 * This is the piece every implementation has to get byte-identical, so it is
 * written to be read rather than to be clever. Everything below follows
 * SPEC.md §a.1–§a.3; where a rule looks arbitrary, the comment says which
 * failure it came from.
 *
 * Verified against `examples/05-a-real-signed-document.md` — a document signed
 * by a real service with a real certificate. A reference implementation checked
 * only against its own output proves that the encoder and the decoder agree
 * with each other, which is not the property anyone needs.
 */

const BLOCK_OPEN = '<!-- mades-sig';
const BLOCK_CLOSE = '-->';

/** Excluded from the signing input. Everything else is covered (§a.3). */
const UNSIGNED_FIELDS = new Set(['signature', 'timestamp']);

/**
 * Field names.
 *
 * Dots are allowed because vendor fields carry a reverse-DNS namespace
 * (§a.1) — `build.vecto.void`. An earlier pattern of `[A-Za-z0-9_-]+` rejected
 * exactly the names the specification requires, which made every vendor field
 * `unsupported` rather than understood.
 */
const KEY = '[A-Za-z0-9_.-]+';

// ---------------------------------------------------------------------------
// §a.2 Canonicalisation
// ---------------------------------------------------------------------------

/**
 * Normalise content for hashing.
 *
 * Deliberately conservative: nothing inside a line is touched. No Unicode
 * normalisation, no whitespace collapsing. Two systems must agree on bytes, and
 * every additional transformation is another place they can disagree.
 */
export function normalize(text) {
  let s = text;
  if (s.charCodeAt(0) === 0xfeff) s = s.slice(1); // strip BOM
  s = s.replace(/\r\n?/g, '\n'); // CRLF and lone CR become LF
  s = s.split('\n').map((l) => l.replace(/[ \t]+$/, '')).join('\n'); // trailing ws
  s = s.replace(/\n+$/, ''); // collapse trailing newlines
  return s.length === 0 ? '' : s + '\n'; // exactly one, unless empty
}

// ---------------------------------------------------------------------------
// §a.1 Locating blocks
// ---------------------------------------------------------------------------

/**
 * Every signature block in the document, in order.
 *
 * > **Known limitation.** This scans for the opening marker as raw bytes and
 * > cannot tell a signature from a sentence describing one. A document that
 * > quotes the marker — a tutorial, an issue, this specification — produces a
 * > phantom block with no signature, and a verifier then reports a valid
 * > document as broken. See the open decision in SPEC.md; the proposed fix is
 * > to recognise the marker only at the start of a line and to skip fenced
 * > code regions.
 *
 * An unterminated block is not a block. That is the safe direction: unsigned
 * content must never read as signed.
 */
export function findBlocks(content) {
  const blocks = [];
  let from = 0;
  for (;;) {
    const start = content.indexOf(BLOCK_OPEN, from);
    if (start === -1) break;
    const end = content.indexOf(BLOCK_CLOSE, start);
    if (end === -1) break;
    blocks.push({
      start,
      end: end + BLOCK_CLOSE.length,
      body: content.slice(start + BLOCK_OPEN.length, end),
    });
    from = end + BLOCK_CLOSE.length;
  }
  return blocks;
}

// ---------------------------------------------------------------------------
// §a.5 Parsing is total
// ---------------------------------------------------------------------------

/**
 * Parse a block body into fields, comment lines, and whatever could not be read.
 *
 * **Every line is one of three things**: a comment, a blank, or a well-formed
 * field. There is no fourth category. Anything else lands in `unparsed`, and a
 * block with unparsed lines is `unsupported` — not invalid, and never silently
 * accepted.
 *
 * Before this rule existed, a bare line was appended to the previous field's
 * value or dropped. The consequence was not academic: a line reading
 * `# WARNING: this contract has been declared void` could be placed inside a
 * signed block without breaking the signature, and that block is exactly what a
 * reader sees in a plain text editor.
 */
export function parseBlockBody(body) {
  const fields = {};
  const comments = [];
  const unparsed = [];
  let pendingKey = null;
  let container = null; // 'list' | 'map'

  for (const raw of body.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (line.trim() === '') continue;
    if (line.trimStart().startsWith('#')) {
      comments.push(line);
      continue;
    }

    // Indented: a list item or a sub-key belonging to the previous key.
    if (/^[ \t]/.test(line) && pendingKey) {
      const item = /^[ \t]+-[ \t]+(.*)$/.exec(line);
      if (item) {
        if (container === null) { container = 'list'; fields[pendingKey] = []; }
        if (container === 'list') fields[pendingKey].push(item[1].trim());
        continue;
      }
      const sub = new RegExp(`^[ \\t]+(${KEY}):[ \\t]*(.*)$`).exec(line);
      if (sub) {
        if (container === null) { container = 'map'; fields[pendingKey] = {}; }
        if (container === 'map') fields[pendingKey][sub[1]] = sub[2].trim();
      } else {
        unparsed.push(line); // indented, but neither — do not discard it
      }
      continue;
    }

    const kv = new RegExp(`^(${KEY}):[ \\t]*(.*)$`).exec(line);
    if (!kv) { unparsed.push(line); continue; }
    const [, key, value] = kv;
    pendingKey = value === '' ? key : null;
    container = null;
    if (value !== '') fields[key] = value.trim();
  }

  return { fields, comments, unparsed };
}

// ---------------------------------------------------------------------------
// §a.3 The signing input
// ---------------------------------------------------------------------------

/** Which rules a block is read under. The block's own version decides. */
export function rulesFor(fields) {
  const declared = Number(fields.version);
  if (declared >= 5) return 5;
  return declared >= 4 ? 4 : 3;
}

/**
 * Render one field.
 *
 * Nested maps emit their sub-keys sorted, so rendering and signing agree. An
 * empty list or map is omitted entirely: a bare `key:` would parse back as
 * absent and break the round-trip.
 */
function renderField(lines, key, value) {
  if (value === undefined || value === null) return;
  if (Array.isArray(value)) {
    if (value.length === 0) return;
    lines.push(`${key}:`);
    for (const item of value) lines.push(`  - ${item}`);
  } else if (typeof value === 'object') {
    const subKeys = Object.keys(value).filter((k) => value[k] != null).sort();
    if (subKeys.length === 0) return;
    lines.push(`${key}:`);
    for (const k of subKeys) lines.push(`  ${k}: ${value[k]}`);
  } else {
    lines.push(`${key}: ${value}`);
  }
}

/**
 * The metadata half of the signing input: comment lines, then fields sorted by
 * key name.
 *
 * v3 covered only the FIRST comment line. A second line therefore appeared in
 * the block but not in what was signed — see the warning in `parseBlockBody`.
 * v4 covers them all. v3 blocks keep being read under v3 rules, because
 * anything else would break every signature that already exists.
 */
function canonicalMetadata(fields, comments, rules) {
  const lines = [];
  lines.push(...(rules >= 4 ? comments : comments.slice(0, 1)));
  for (const key of Object.keys(fields).filter((k) => !UNSIGNED_FIELDS.has(k)).sort()) {
    renderField(lines, key, fields[key]);
  }
  return lines.join('\n');
}

/** Content up to the given block, canonicalised. */
export function canonicalize(content, blockIndex) {
  const blocks = findBlocks(content);
  const idx = blockIndex === undefined ? blocks.length : blockIndex;
  if (idx < 0 || idx > blocks.length) {
    throw new RangeError(`block index ${idx} out of range (0..${blocks.length})`);
  }
  const upTo = idx === blocks.length ? content.length : blocks[idx].start;
  return normalize(content.slice(0, upTo));
}

/**
 * Rebuild what a given block signed, from the document alone.
 *
 * This is the function a recipient runs. It takes the file and nothing else —
 * no database, no memory of how the document was produced.
 */
export function signingInputForBlock(content, blockIndex) {
  const blocks = findBlocks(content);
  const block = blocks[blockIndex];
  if (!block) throw new RangeError(`no block at index ${blockIndex}`);

  const { fields, comments, unparsed } = parseBlockBody(block.body);
  const rules = rulesFor(fields);

  return {
    signingInput: canonicalize(content, blockIndex) + '\n' + canonicalMetadata(fields, comments, rules),
    fields,
    comments,
    unparsed,
    rules,
    signature: typeof fields.signature === 'string' ? fields.signature : null,
  };
}

/** Serialise a block for writing into a document. */
export function serializeBlock(fields, comments = []) {
  const lines = [...comments];
  const order = [
    'version', 'algorithm', 'signer', 'signer-kind', 'automation', 'commitment',
    'signed-at', 'lang', 'appearance', 'revision', 'supersedes', 'represents',
    'key-id', 'field', 'format', 'certificate-chain', 'timestamp', 'signature',
  ];
  const seen = new Set(order);
  // Ordering, not a filter: every field is written, known or not (§a.10).
  for (const key of order) if (key in fields) renderField(lines, key, fields[key]);
  for (const key of Object.keys(fields).sort()) {
    if (!seen.has(key)) renderField(lines, key, fields[key]);
  }
  const body = lines.join('\n');
  if (body.includes('--')) {
    // An HTML comment ends at the first `--`. A block containing one is
    // truncated, never reaches its `-->`, and the document reads as UNSIGNED
    // rather than invalid. Silent and total, so it is checked before emitting.
    throw new Error('block body contains `--`, which would truncate the comment (§a.1)');
  }
  return `${BLOCK_OPEN}\n${body}\n${BLOCK_CLOSE}`;
}

export { BLOCK_OPEN, BLOCK_CLOSE, UNSIGNED_FIELDS };
