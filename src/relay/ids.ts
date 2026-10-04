// Shape checks for every caller-supplied value that ends up in a relay URL path
// or names another agent. A value that fails is refused before any request is
// built; values that pass are still percent-encoded when placed in a path.

// did:voidly:<base58 of the first 16 bytes of the Ed25519 public key>
export const DID_RE = /^did:voidly:[1-9A-HJ-NP-Za-km-z]{16,32}$/;
// Relay object ids (messages, channels, tasks, capabilities, attestations,
// invites, broadcasts, webhooks) are UUIDs or short prefixed tokens.
export const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
// Memory namespaces and key names. No slash, backslash, percent sign, space or
// control character, and never a dot-only or '..'-containing name.
const SEGMENT_RE = /^[A-Za-z0-9_.:@+=-]+$/;

export class InputRefused extends Error {
  readonly word: string;
  constructor(word: string, message: string) {
    super(message);
    this.word = word;
  }
}

export function requireDid(value: unknown, field: string): string {
  if (typeof value !== 'string' || !DID_RE.test(value)) {
    throw new InputRefused('invalid_did', `${field} must be a DID of the form did:voidly:<base58>. Nothing was sent.`);
  }
  return value;
}

export function requireId(value: unknown, field: string): string {
  if (typeof value !== 'string' || !ID_RE.test(value)) {
    throw new InputRefused('invalid_id', `${field} must be 1-64 characters of A-Z, a-z, 0-9, '_' or '-'. Nothing was sent.`);
  }
  return value;
}

export function requireSegment(value: unknown, field: string, max: number): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > max ||
    !SEGMENT_RE.test(value) ||
    value.includes('..') ||
    /^\.+$/.test(value)
  ) {
    throw new InputRefused(
      'invalid_name',
      `${field} must be 1-${max} characters of A-Z, a-z, 0-9 and _ . : @ + = -, without '..'. Nothing was sent.`,
    );
  }
  return value;
}

/** Percent-encode a checked value for use as one path segment. */
export function seg(value: string): string {
  return encodeURIComponent(value);
}
