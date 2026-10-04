// HTTP client for the relay. The API key is read from the credential store for
// each call and sent only in the X-Agent-Key header. Error text coming back from
// the relay is cleaned, capped and passed through the redactor before it can
// reach a tool result.

import { KeystoreError, readCredentials, relayHome, selectedDid, type RelayCredentials } from './keystore.js';
import { redact } from './redact.js';
import { cleanString } from './untrusted.js';

const DEFAULT_BASE = 'https://api.voidly.ai';
const TIMEOUT_MS = 30_000;

export class RelayError extends Error {
  readonly word: string;
  readonly status: number | null;
  constructor(word: string, message: string, status: number | null = null) {
    super(message);
    this.word = word;
    this.status = status;
  }
}

/**
 * Relay base URL. VOIDLY_MCP_RELAY_API_BASE exists for local tests and accepts
 * only a loopback http origin, so a config mistake cannot send the key to
 * another host.
 */
export function relayBase(env: NodeJS.ProcessEnv = process.env): string {
  const override = env.VOIDLY_MCP_RELAY_API_BASE?.trim();
  if (!override) return DEFAULT_BASE;
  let url: URL;
  try {
    url = new URL(override);
  } catch {
    throw new RelayError('relay_base_refused', 'VOIDLY_MCP_RELAY_API_BASE is not a URL.');
  }
  const loopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '[::1]';
  if (url.protocol !== 'http:' || !loopback || url.pathname !== '/' || url.search || url.username || url.password) {
    throw new RelayError(
      'relay_base_refused',
      'VOIDLY_MCP_RELAY_API_BASE only accepts a loopback http origin (for tests). Unset it to use the public relay.',
    );
  }
  return url.origin;
}

export const OWNER_CLI_HINT = 'npx @voidly/mcp-server relay';

/** Load the identity the tools act as. Never returns the key to a caller outside this module tree. */
export function loadIdentity(env: NodeJS.ProcessEnv = process.env): { creds: RelayCredentials; path: string } {
  const root = relayHome(env);
  let did: string | null;
  try {
    did = selectedDid(root, env);
  } catch (error) {
    if (error instanceof KeystoreError) throw new RelayError(error.word, `Relay credential store: ${error.message}`);
    throw error;
  }
  if (!did) {
    throw new RelayError(
      'no_identity',
      `No relay identity is set up on this machine. Call agent_register to create one, or ask the human owner to run \`${OWNER_CLI_HINT} import-legacy\` for an existing identity.`,
    );
  }
  let loaded: { creds: RelayCredentials; path: string };
  try {
    loaded = readCredentials(root, did);
  } catch (error) {
    if (error instanceof KeystoreError) {
      throw new RelayError(error.word, `Relay credential store: ${error.message} Ask the human owner to run \`${OWNER_CLI_HINT} list\`.`);
    }
    throw error;
  }
  if (loaded.creds.status !== 'active') {
    throw new RelayError('identity_deactivated', 'The selected relay identity was deactivated. Ask the human owner to select or register another one.');
  }
  return loaded;
}

function cleanDetail(value: unknown): string {
  const raw = typeof value === 'string' ? value : value === undefined ? '' : JSON.stringify(value);
  return redact(cleanString(raw ?? '').replace(/\s+/g, ' ').trim()).slice(0, 200);
}

export interface RelayRequest {
  method?: string;
  query?: Record<string, string | number | boolean | undefined | null>;
  body?: unknown;
  /** Send X-Agent-Key from the credential store. */
  auth?: boolean;
  /** Use this key instead of the store (owner CLI only). */
  apiKey?: string;
  /** Statuses that are returned instead of thrown. */
  allow?: number[];
}

export interface RelayResponse {
  status: number;
  data: any;
}

export async function relayCall(label: string, path: string, req: RelayRequest = {}, env: NodeJS.ProcessEnv = process.env): Promise<RelayResponse> {
  const base = relayBase(env);
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (req.apiKey) headers['X-Agent-Key'] = req.apiKey;
  else if (req.auth) headers['X-Agent-Key'] = loadIdentity(env).creds.api_key;
  let body: string | undefined;
  if (req.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(req.body);
  }
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(req.query ?? {})) {
    if (v !== undefined && v !== null && v !== '') params.set(k, String(v));
  }
  const qs = params.toString();
  const url = `${base}${path}${qs ? `?${qs}` : ''}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(url, { method: req.method ?? 'GET', headers, body, signal: controller.signal, redirect: 'error' });
  } catch (error: any) {
    if (error?.name === 'AbortError') throw new RelayError('relay_timeout', `${label}: the relay did not answer within 30 seconds.`);
    throw new RelayError('relay_unreachable', `${label}: could not reach the relay.`);
  } finally {
    clearTimeout(timer);
  }

  const text = await response.text().catch(() => '');
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (response.ok || req.allow?.includes(response.status)) return { status: response.status, data };

  const word = data && typeof data.error === 'string' && /^[a-z_]{3,48}$/.test(data.error) ? data.error : `http_${response.status}`;
  const detail = data && typeof data === 'object'
    ? cleanDetail(data.recovery ?? data.error ?? data.message ?? '')
    : cleanDetail(text);
  throw new RelayError(word, `${label} failed (${response.status})${detail ? `. Relay said: ${detail}` : '.'}`, response.status);
}
