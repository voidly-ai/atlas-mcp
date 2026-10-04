// Relay credential store.
//
//   <root>/                      0700  (VOIDLY_MCP_RELAY_HOME, default ~/.voidly/mcp-relay)
//   <root>/identities/           0700
//   <root>/identities/<id>.json  0600  one file per identity: DID, API key, public keys,
//                                      webhook secrets
//   <root>/active                0600  the DID the MCP tools act as
//
// The MCP tools read the key from here; it is never a tool argument and never
// part of a tool result. First writes use O_CREAT|O_EXCL (which also refuses a
// planted symlink), later writes go to a 0600 temp file that is fsynced and
// renamed over the old one, and reads use O_NOFOLLOW and refuse files that other
// users can read or that another user owns.
//
// Limit, stated: 0600 files keep other OS users out. They do not keep out a
// program running as the same user with its own shell or file access, such as an
// agent with a terminal tool.

import {
  chmodSync,
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readSync,
  renameSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { DID_RE } from './ids.js';
import { registerSecret } from './redact.js';

export const CREDENTIALS_FORMAT = 'voidly-mcp-relay-credentials/1';
export const API_KEY_RE = /^[0-9a-f]{64}$/;
const MAX_FILE_BYTES = 256 * 1024;
const posix = process.platform !== 'win32';

export interface RelayCredentials {
  format: typeof CREDENTIALS_FORMAT;
  did: string;
  api_key: string;
  /** How the relay holds this identity's secret keys. */
  identity_mode: 'relay-held-keys';
  name: string | null;
  signing_public_key: string | null;
  encryption_public_key: string | null;
  status: 'active' | 'deactivated';
  created_at: string;
  updated_at: string;
  api_key_version: number;
  /** Webhook id -> signing secret, kept here so the model never sees it. */
  webhook_secrets: Record<string, string>;
}

export class KeystoreError extends Error {
  readonly word: string;
  constructor(word: string, message: string) {
    super(message);
    this.word = word;
  }
}

export function relayHome(env: NodeJS.ProcessEnv = process.env): string {
  const override = env.VOIDLY_MCP_RELAY_HOME;
  return override && override.trim() ? override.trim() : join(homedir(), '.voidly', 'mcp-relay');
}

function identitiesDir(root: string): string {
  return join(root, 'identities');
}

export function didSuffix(did: string): string {
  if (!DID_RE.test(did)) throw new KeystoreError('invalid_did', 'Not a relay DID.');
  return did.slice('did:voidly:'.length);
}

export function credentialPath(root: string, did: string): string {
  return join(identitiesDir(root), `${didSuffix(did)}.json`);
}

function currentUid(): number | null {
  return posix && typeof process.getuid === 'function' ? process.getuid() : null;
}

/** A directory we will keep secrets in: real directory, ours, not group/other accessible. */
function assertPrivateDir(path: string): void {
  const st = lstatSync(path);
  if (st.isSymbolicLink() || !st.isDirectory()) {
    throw new KeystoreError('key_directory_unsafe', `${path} is not a plain directory.`);
  }
  const uid = currentUid();
  if (uid !== null && st.uid !== uid) {
    throw new KeystoreError('key_directory_unsafe', `${path} is owned by another user.`);
  }
  if (posix && (st.mode & 0o077) !== 0) {
    throw new KeystoreError('key_directory_unsafe', `${path} is accessible to other users; run chmod 700 on it.`);
  }
}

function ensurePrivateDir(path: string): void {
  try {
    mkdirSync(path, { mode: 0o700 });
    if (posix) chmodSync(path, 0o700);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
  }
  assertPrivateDir(path);
}

/** Create (or check) the root and identities directories. */
export function prepareStore(root: string): void {
  mkdirSync(join(root, '..'), { recursive: true });
  ensurePrivateDir(root);
  ensurePrivateDir(identitiesDir(root));
}

/** True when the store has never been created. */
function storeMissing(root: string): boolean {
  try {
    lstatSync(root);
    return false;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return true;
    throw error;
  }
}

function writeAll(fd: number, text: string): void {
  const buf = Buffer.from(text, 'utf8');
  let off = 0;
  while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
}

/** New 0600 file; refuses to replace anything, including a symlink. */
function writeExclusive(path: string, text: string): void {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    if (posix) fchmodSync(fd, 0o600);
    writeAll(fd, text);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Atomic replace: 0600 temp file in the same directory, fsync, rename. */
function replaceAtomic(dir: string, path: string, text: string): void {
  const temp = join(dir, `.tmp-${randomBytes(8).toString('hex')}`);
  writeExclusive(temp, text);
  try {
    renameSync(temp, path);
  } catch (error) {
    try {
      unlinkSync(temp);
    } catch {
      /* best effort */
    }
    throw error;
  }
}

/** Read a small private file without following symlinks. */
function readPrivateFile(path: string): string {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') throw new KeystoreError('no_identity', `${path} does not exist.`);
    if (code === 'ELOOP') throw new KeystoreError('key_file_unsafe', `${path} is a symlink; refusing to follow it.`);
    throw error;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new KeystoreError('key_file_unsafe', `${path} is not a regular file.`);
    const uid = currentUid();
    if (uid !== null && st.uid !== uid) throw new KeystoreError('key_file_unsafe', `${path} is owned by another user.`);
    if (posix && (st.mode & 0o077) !== 0) {
      throw new KeystoreError('key_file_unsafe', `${path} is readable by other users; run chmod 600 on it.`);
    }
    if (st.size > MAX_FILE_BYTES) throw new KeystoreError('key_file_unsafe', `${path} is too large.`);
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < st.size) {
      const n = readSync(fd, buf, off, st.size - off, off);
      if (n === 0) break;
      off += n;
    }
    return buf.subarray(0, off).toString('utf8');
  } finally {
    closeSync(fd);
  }
}

function parseCredentials(text: string, path: string): RelayCredentials {
  let data: any;
  try {
    data = JSON.parse(text);
  } catch {
    throw new KeystoreError('key_file_invalid', `${path} is not valid JSON.`);
  }
  if (
    !data ||
    data.format !== CREDENTIALS_FORMAT ||
    typeof data.did !== 'string' ||
    !DID_RE.test(data.did) ||
    typeof data.api_key !== 'string' ||
    !API_KEY_RE.test(data.api_key)
  ) {
    throw new KeystoreError('key_file_invalid', `${path} does not hold relay credentials.`);
  }
  registerSecret(data.api_key);
  const secrets: Record<string, string> = {};
  if (data.webhook_secrets && typeof data.webhook_secrets === 'object') {
    for (const [id, secret] of Object.entries(data.webhook_secrets)) {
      if (typeof secret === 'string') {
        registerSecret(secret);
        secrets[id] = secret;
      }
    }
  }
  return {
    format: CREDENTIALS_FORMAT,
    did: data.did,
    api_key: data.api_key,
    identity_mode: 'relay-held-keys',
    name: typeof data.name === 'string' ? data.name : null,
    signing_public_key: typeof data.signing_public_key === 'string' ? data.signing_public_key : null,
    encryption_public_key: typeof data.encryption_public_key === 'string' ? data.encryption_public_key : null,
    status: data.status === 'deactivated' ? 'deactivated' : 'active',
    created_at: typeof data.created_at === 'string' ? data.created_at : '',
    updated_at: typeof data.updated_at === 'string' ? data.updated_at : '',
    api_key_version: Number.isSafeInteger(data.api_key_version) ? data.api_key_version : 0,
    webhook_secrets: secrets,
  };
}

function serialise(creds: RelayCredentials): string {
  return JSON.stringify(creds, null, 2) + '\n';
}

/** Read one identity's credentials by DID. */
export function readCredentials(root: string, did: string): { creds: RelayCredentials; path: string } {
  assertPrivateDir(root);
  assertPrivateDir(identitiesDir(root));
  const path = credentialPath(root, did);
  const creds = parseCredentials(readPrivateFile(path), path);
  if (creds.did !== did) throw new KeystoreError('key_file_invalid', `${path} holds a different DID.`);
  return { creds, path };
}

/** Read credentials from an explicit file path (owner-supplied). */
export function readCredentialsFile(path: string): RelayCredentials {
  return parseCredentials(readPrivateFile(path), path);
}

/** The DID in <root>/active, or null. */
export function readActiveDid(root: string): string | null {
  if (storeMissing(root)) return null;
  assertPrivateDir(root);
  let text: string;
  try {
    text = readPrivateFile(join(root, 'active'));
  } catch (error) {
    if (error instanceof KeystoreError && error.word === 'no_identity') return null;
    throw error;
  }
  const did = text.trim();
  if (did === '') return null;
  if (!DID_RE.test(did)) throw new KeystoreError('key_file_invalid', `${join(root, 'active')} does not hold a DID.`);
  return did;
}

export function writeActiveDid(root: string, did: string | null): void {
  prepareStore(root);
  if (did !== null && !DID_RE.test(did)) throw new KeystoreError('invalid_did', 'Not a relay DID.');
  replaceAtomic(root, join(root, 'active'), did === null ? '\n' : `${did}\n`);
}

/**
 * Which identity the MCP tools act as: VOIDLY_MCP_RELAY_DID if the owner set it,
 * otherwise <root>/active. The model has no way to choose.
 */
export function selectedDid(root: string, env: NodeJS.ProcessEnv = process.env): string | null {
  const pinned = env.VOIDLY_MCP_RELAY_DID?.trim();
  if (pinned) {
    if (!DID_RE.test(pinned)) throw new KeystoreError('invalid_did', 'VOIDLY_MCP_RELAY_DID is not a relay DID.');
    return pinned;
  }
  return readActiveDid(root);
}

/** Every stored identity (never the keys). */
export function listIdentities(root: string): Array<{ did: string; name: string | null; status: string; path: string; created_at: string }> {
  if (storeMissing(root)) return [];
  assertPrivateDir(root);
  const dir = identitiesDir(root);
  try {
    assertPrivateDir(dir);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
  const out: Array<{ did: string; name: string | null; status: string; path: string; created_at: string }> = [];
  for (const entry of readdirSync(dir)) {
    if (!/^[1-9A-HJ-NP-Za-km-z]{16,32}\.json$/.test(entry)) continue;
    const did = `did:voidly:${entry.slice(0, -5)}`;
    try {
      const { creds, path } = readCredentials(root, did);
      out.push({ did, name: creds.name, status: creds.status, path, created_at: creds.created_at });
    } catch (error) {
      out.push({ did, name: null, status: `unreadable (${(error as KeystoreError).word ?? 'error'})`, path: join(dir, entry), created_at: '' });
    }
  }
  return out;
}

/** Replace an existing identity file atomically. */
export function saveCredentials(root: string, creds: RelayCredentials): string {
  if (!API_KEY_RE.test(creds.api_key)) throw new KeystoreError('key_invalid', 'Refusing to save a malformed API key.');
  prepareStore(root);
  const path = credentialPath(root, creds.did);
  registerSecret(creds.api_key);
  replaceAtomic(identitiesDir(root), path, serialise({ ...creds, updated_at: new Date().toISOString() }));
  return path;
}

/** Last-resort save beside the identity file; never overwrites. */
export function saveCredentialsBeside(root: string, creds: RelayCredentials): string {
  const path = `${credentialPath(root, creds.did)}.new-${randomBytes(4).toString('hex')}`;
  writeExclusive(path, serialise(creds));
  return path;
}

/** First save of an identity. Refuses if a file for this DID already exists. */
export function saveNewCredentials(root: string, creds: RelayCredentials): string {
  if (!API_KEY_RE.test(creds.api_key)) throw new KeystoreError('key_invalid', 'Refusing to save a malformed API key.');
  prepareStore(root);
  const path = credentialPath(root, creds.did);
  registerSecret(creds.api_key);
  try {
    writeExclusive(path, serialise(creds));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
      throw new KeystoreError('identity_exists', `${path} already exists; nothing was overwritten.`);
    }
    throw error;
  }
  return path;
}

// ── Registration staging ─────────────────────────────────────────────────
// Registration mints a key that is shown once. So the file it goes into is
// created BEFORE the relay call: if the store cannot be written, nothing is
// registered. After the call the staged file is filled and linked to its final
// name (link(2) refuses an existing target, symlinks included). If that last
// step fails the key stays in the staged file, which is reported, never deleted.

export interface Staged {
  path: string;
}

export function stageNewIdentity(root: string): Staged {
  prepareStore(root);
  const path = join(identitiesDir(root), `.pending-${randomBytes(8).toString('hex')}.json`);
  writeExclusive(path, '{}\n');
  return { path };
}

export function discardStaged(staged: Staged): void {
  try {
    unlinkSync(staged.path);
  } catch {
    /* best effort */
  }
}

export function commitStaged(root: string, staged: Staged, creds: RelayCredentials): { path: string; moved: boolean } {
  registerSecret(creds.api_key);
  const fd = openSync(staged.path, constants.O_WRONLY | constants.O_TRUNC | (constants.O_NOFOLLOW ?? 0));
  try {
    if (posix) fchmodSync(fd, 0o600);
    writeAll(fd, serialise(creds));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  const target = credentialPath(root, creds.did);
  try {
    linkSync(staged.path, target);
  } catch {
    return { path: staged.path, moved: false };
  }
  try {
    unlinkSync(staged.path);
  } catch {
    /* the final name already holds the credentials */
  }
  return { path: target, moved: true };
}

/** Write an export to a new 0600 file (owner CLI). */
export function writeExport(path: string, text: string): void {
  writeExclusive(path, text);
}
