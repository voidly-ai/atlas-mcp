// Owner command line for relay credentials: `voidly-mcp relay <command>`.
//
// These are the owner's actions: bringing an existing key into the store,
// replacing (rotating) the key, exporting the credentials, switching the
// selected identity and deactivating an identity. None of them is an MCP tool,
// and the MCP server never imports this file.
//
// The key is never read from argv or the environment (both leak into shell
// history and process listings). import-legacy reads it from standard input.
// Commands print DIDs and file paths, not keys; `export` is the one command
// that writes the credentials out, and it does so on purpose.

import { createInterface } from 'node:readline';
import {
  API_KEY_RE,
  CREDENTIALS_FORMAT,
  KeystoreError,
  listIdentities,
  prepareStore,
  readActiveDid,
  readCredentials,
  relayHome,
  saveCredentials,
  saveCredentialsBeside,
  saveNewCredentials,
  selectedDid,
  writeActiveDid,
  writeExport,
  type RelayCredentials,
} from './relay/keystore.js';
import { relayCall, RelayError } from './relay/client.js';
import { DID_RE } from './relay/ids.js';
import { redact, registerSecret } from './relay/redact.js';
import { cleanString } from './relay/untrusted.js';

const USAGE = `Usage: voidly-mcp relay <command> [options]

Owner commands for the relay credentials used by the MCP server. None of these
are MCP tools.

  list                          Stored identities (DID, name, status, file). No keys.
  use <did> | use --none        Select the identity the MCP tools act as.
  import-legacy [--name <n>]    Store an existing API key. The key is read from
                                standard input (typed without echo, or piped).
  rotate [--did <did>]          Replace the API key on the relay and in the file.
  export [--did <did>] [--out <file>]
                                Write the credentials (including the key) to a new
                                0600 file, or to standard output without --out.
  deactivate [--did <did>] [--yes]
                                Deactivate the identity on the relay. Irreversible.

Environment:
  VOIDLY_MCP_RELAY_HOME   credential directory (default ~/.voidly/mcp-relay)
  VOIDLY_MCP_RELAY_DID    pin the identity the MCP tools act as
`;

function out(text: string): void {
  process.stdout.write(redact(text) + '\n');
}

function err(text: string): void {
  process.stderr.write(redact(text) + '\n');
}

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  if (i === -1) return undefined;
  const v = args[i + 1];
  if (v === undefined || v.startsWith('--')) throw new Error(`${name} needs a value.`);
  return v;
}

function targetDid(args: string[], root: string): string {
  const given = flag(args, '--did');
  if (given !== undefined) {
    if (!DID_RE.test(given)) throw new Error('--did is not a relay DID.');
    return given;
  }
  const did = selectedDid(root);
  if (!did) throw new Error('No identity is selected. Pass --did, or run `voidly-mcp relay use <did>`.');
  return did;
}

/** Read one secret line: hidden when stdin is a terminal, otherwise the piped input. */
async function readSecret(prompt: string): Promise<string> {
  const stdin = process.stdin;
  if (stdin.isTTY && typeof stdin.setRawMode === 'function') {
    process.stderr.write(prompt);
    return await new Promise<string>((resolve, reject) => {
      let value = '';
      stdin.setRawMode(true);
      stdin.resume();
      stdin.setEncoding('utf8');
      const onData = (chunk: string) => {
        for (const ch of chunk) {
          if (ch === '\r' || ch === '\n') {
            cleanup();
            process.stderr.write('\n');
            resolve(value);
            return;
          }
          if (ch === '\u0003') {
            cleanup();
            reject(new Error('Cancelled.'));
            return;
          }
          if (ch === '\u007f' || ch === '\b') value = value.slice(0, -1);
          else value += ch;
        }
      };
      const cleanup = () => {
        stdin.off('data', onData);
        stdin.setRawMode(false);
        stdin.pause();
      };
      stdin.on('data', onData);
    });
  }
  const chunks: Buffer[] = [];
  for await (const chunk of stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}

async function confirm(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    return await new Promise<string>((resolve) => rl.question(question, resolve));
  } finally {
    rl.close();
  }
}

function describeError(error: unknown): string {
  if (error instanceof RelayError || error instanceof KeystoreError) return `${error.word}: ${error.message}`;
  if (error instanceof Error) return error.message;
  return 'failed';
}

// ── Commands ────────────────────────────────────────────────────────────

function cmdList(root: string): number {
  const ids = listIdentities(root);
  let active: string | null = null;
  try {
    active = readActiveDid(root);
  } catch {
    active = null;
  }
  if (ids.length === 0) {
    out(`No relay identities in ${root}.`);
    return 0;
  }
  for (const id of ids) {
    const name = id.name ? cleanString(id.name).replace(/\s+/g, ' ').slice(0, 64) : '(no name)';
    out(`${id.did === active ? '*' : ' '} ${id.did}  ${id.status}  ${JSON.stringify(name)}  ${id.path}`);
  }
  out('* = selected for the MCP tools. Keys are not shown.');
  return 0;
}

function cmdUse(args: string[], root: string): number {
  if (args[0] === '--none') {
    writeActiveDid(root, null);
    out('No identity is selected now. The MCP tools will ask for one to be set up.');
    return 0;
  }
  const did = args[0];
  if (!did || !DID_RE.test(did)) throw new Error('Give a relay DID, or --none.');
  const { creds } = readCredentials(root, did);
  if (creds.status !== 'active') throw new Error(`${did} is ${creds.status}; select an active identity.`);
  writeActiveDid(root, did);
  out(`Selected ${did}.`);
  return 0;
}

async function cmdImportLegacy(args: string[], root: string): Promise<number> {
  const label = flag(args, '--name');
  prepareStore(root);
  const raw = (await readSecret('Relay API key (input hidden): ')).trim();
  registerSecret(raw);
  if (!API_KEY_RE.test(raw)) throw new Error('That is not a relay API key (64 lowercase hex characters). Nothing was stored.');
  const { data } = await relayCall('Profile lookup', '/v1/agent/profile', { apiKey: raw });
  const did = typeof data?.did === 'string' && DID_RE.test(data.did) ? data.did : null;
  if (!did) throw new Error('The relay did not return a DID for this key. Nothing was stored.');
  const now = new Date().toISOString();
  const creds: RelayCredentials = {
    format: CREDENTIALS_FORMAT,
    did,
    api_key: raw,
    identity_mode: 'relay-held-keys',
    name: label ?? (typeof data?.name === 'string' ? data.name : null),
    signing_public_key: null,
    encryption_public_key: null,
    status: data?.status === 'active' || data?.status === undefined ? 'active' : 'deactivated',
    created_at: now,
    updated_at: now,
    api_key_version: 0,
    webhook_secrets: {},
  };
  const path = saveNewCredentials(root, creds);
  out(`Stored ${did} in ${path} (mode 0600).`);
  if (!readActiveDid(root)) {
    writeActiveDid(root, did);
    out('It is now the identity the MCP tools act as.');
  }
  out(
    'If this key was ever pasted into a chat, passed as a tool argument or kept in an MCP config file, a model or a log has seen it. ' +
      `Replace it now: voidly-mcp relay rotate --did ${did}`,
  );
  return 0;
}

async function cmdRotate(args: string[], root: string): Promise<number> {
  const did = targetDid(args, root);
  const { creds } = readCredentials(root, did);
  if (creds.status !== 'active') throw new Error(`${did} is ${creds.status}.`);
  // Prove the file can be rewritten before the relay replaces the key.
  saveCredentials(root, creds);

  const { data } = await relayCall('Rotation', '/v1/agent/rotate-api-key', { method: 'POST', apiKey: creds.api_key, body: {} });
  const newKey = typeof data?.api_key === 'string' ? data.api_key : '';
  registerSecret(newKey);
  if (!API_KEY_RE.test(newKey) || data?.did !== did) {
    throw new Error('The relay answered with an unexpected shape. The old key may already be revoked; run `voidly-mcp relay list` and contact the relay operator.');
  }
  const version = Number.isSafeInteger(data?.api_key_version) ? data.api_key_version : creds.api_key_version + 1;
  const updated: RelayCredentials = { ...creds, api_key: newKey, api_key_version: version };
  let path: string;
  try {
    path = saveCredentials(root, updated);
  } catch {
    try {
      path = saveCredentialsBeside(root, updated);
      err(`The credentials file could not be replaced; the new key was written to ${path}. Move it over the old file (keep mode 0600).`);
    } catch {
      // Last resort: the relay has already revoked the old key and keeps only a
      // hash of the new one, so losing it here would lock the owner out.
      process.stderr.write(
        'The new key could not be saved anywhere. It is printed once below so it is not lost; store it and do not paste it into a chat.\n' +
          `${newKey}\n`,
      );
      return 1;
    }
  }
  out(`Rotated the API key of ${did}. Key version ${version}. The previous key stopped working on the relay.`);
  out(`Credentials file: ${path}`);
  const hooks = Array.isArray(data?.disabled?.webhooks) ? data.disabled.webhooks : [];
  const push = Number(data?.disabled?.push_subscriptions) || 0;
  if (hooks.length || push) {
    out(`Switched off by the relay: ${hooks.length} webhook(s), ${push} push subscription(s). Re-register the ones you recognise.`);
    for (const h of hooks) out(`  webhook ${cleanString(String(h?.id ?? ''))}  ${cleanString(String(h?.webhook_url ?? ''))}`);
  }
  if (typeof data?.limits === 'string') out(`Relay notes: ${cleanString(data.limits)}`);
  return 0;
}

async function cmdExport(args: string[], root: string): Promise<number> {
  const did = targetDid(args, root);
  const { creds } = readCredentials(root, did);
  const text = JSON.stringify(creds, null, 2) + '\n';
  const outPath = flag(args, '--out');
  if (outPath) {
    writeExport(outPath, text);
    out(`Wrote the credentials of ${did} to ${outPath} (mode 0600). The file contains the API key.`);
    return 0;
  }
  // Deliberate: this command exists to hand the owner the key. Written raw,
  // not through the redactor.
  process.stdout.write(text);
  return 0;
}

async function cmdDeactivate(args: string[], root: string): Promise<number> {
  const did = targetDid(args, root);
  const { creds } = readCredentials(root, did);
  if (!args.includes('--yes')) {
    if (!process.stdin.isTTY) throw new Error('Pass --yes to deactivate without a terminal prompt.');
    const typed = (await confirm(`Deactivating ${did} is permanent. Type the DID to confirm: `)).trim();
    if (typed !== did) {
      out('Not confirmed. Nothing was changed.');
      return 1;
    }
  }
  await relayCall('Deactivation', '/v1/agent/deactivate', { method: 'DELETE', apiKey: creds.api_key });
  saveCredentials(root, { ...creds, status: 'deactivated' });
  let active: string | null = null;
  try {
    active = readActiveDid(root);
  } catch {
    active = null;
  }
  if (active === did) writeActiveDid(root, null);
  out(`Deactivated ${did} on the relay. The local file is kept and marked deactivated.`);
  return 0;
}

export async function main(argv: string[]): Promise<number> {
  const [command, ...args] = argv;
  const root = relayHome();
  try {
    switch (command) {
      case 'list':
        return cmdList(root);
      case 'use':
        return cmdUse(args, root);
      case 'import-legacy':
        return await cmdImportLegacy(args, root);
      case 'rotate':
        return await cmdRotate(args, root);
      case 'export':
        return await cmdExport(args, root);
      case 'deactivate':
        return await cmdDeactivate(args, root);
      case undefined:
      case 'help':
      case '--help':
      case '-h':
        out(USAGE);
        return command === undefined ? 1 : 0;
      default:
        err(`Unknown command: ${cleanString(command).slice(0, 40)}\n\n${USAGE}`);
        return 1;
    }
  } catch (error) {
    err(`voidly-mcp relay ${command}: ${describeError(error)}`);
    return 1;
  }
}
