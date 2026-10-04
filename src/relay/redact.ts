// Exact-match redaction of secrets this process knows about.
//
// Relay API keys are 64 lowercase hex characters with no prefix, so there is no
// safe generic pattern for them: a 64-hex rule would also hide SHA-256 hashes and
// message ids people need. Only values this process has actually held are
// redacted, wherever they appear, including when split by invisible characters
// or re-cased.
//
// Two lists:
// - held: keys and webhook secrets loaded from the credential store or minted by
//   the relay. Never dropped, so no amount of later input can push them out.
// - refused: key-shaped values a caller passed as a tool argument and was refused.
//   Only 64-hex values are accepted, and the list is capped (oldest dropped
//   first). A caller cannot use it to hide arbitrary text such as a DID from
//   later results, or to add very long patterns.
//
// Both lists only take values made of key characters, so a pattern can never
// match JSON punctuation. Structured values are redacted string by string.

// Invisible characters a secret can be split with and still be read as the secret.
const GAP = '[\\u00AD\\u180E\\u200B-\\u200F\\u2060-\\u2064\\uFEFF]*';
const SECRET_RE = /^[A-Za-z0-9+/=_-]{16,512}$/;
const KEY_SHAPE_RE = /^[0-9a-f]{64}$/i;
const MAX_REFUSED = 64;

export const REDACTED = '[redacted-key]';

const held = new Map<string, RegExp>();
const refused = new Map<string, RegExp>();

const escapeRe = (ch: string) => ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const pattern = (secret: string) => new RegExp(Array.from(secret, escapeRe).join(GAP), 'gi');

/** Remember a key or webhook secret this process holds. Never forgotten. */
export function registerSecret(value: unknown): void {
  if (typeof value !== 'string') return;
  const secret = value.trim();
  if (!SECRET_RE.test(secret)) return;
  const k = secret.toLowerCase();
  if (held.has(k)) return;
  held.set(k, pattern(secret));
  refused.delete(k);
}

/** Remember a key-shaped value that a caller passed and was refused. */
export function registerRefusedValue(value: unknown): void {
  if (typeof value !== 'string') return;
  const secret = value.trim();
  if (!KEY_SHAPE_RE.test(secret)) return;
  const k = secret.toLowerCase();
  if (held.has(k) || refused.has(k)) return;
  if (refused.size >= MAX_REFUSED) {
    const first = refused.keys().next().value;
    if (first !== undefined) refused.delete(first);
  }
  refused.set(k, pattern(secret));
}

/** Replace every known secret in `text`. */
export function redact(text: string): string {
  let out = text;
  for (const list of [held, refused]) {
    for (const re of list.values()) {
      re.lastIndex = 0;
      out = out.replace(re, REDACTED);
    }
  }
  return out;
}

function walk(value: unknown, depth: number): unknown {
  if (typeof value === 'string') return redact(value);
  if (value === null || typeof value !== 'object') return value;
  if (depth > 64) return '[nested too deep]';
  if (Array.isArray(value)) return value.map((v) => walk(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[redact(k)] = walk(v, depth + 1);
  return out;
}

/** Redact every string in a JSON-shaped value (used on every outgoing MCP message). */
export function redactDeep<T>(value: T): T {
  if (held.size === 0 && refused.size === 0) return value;
  return walk(value, 0) as T;
}

/** For tests only. */
export function knownSecretCount(): number {
  return held.size + refused.size;
}
