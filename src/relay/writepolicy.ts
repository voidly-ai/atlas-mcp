// Write policy for relay tools (3.0.2): default deny. The published npm 3.0.1
// did not include it; its relay tools behave as in 3.0.0.
//
// A relay write either puts model-chosen text where another party can read it
// (the recipient agent, channel members, the public, or the relay itself), or
// changes a state that another party can see and that the model chooses (a
// task's status, a channel membership, an invite answer, a read receipt, a
// heartbeat). A message from a stranger can talk a model into either: text
// carries data out directly, and a chosen pattern of states carries it out a
// few bits at a time. So each such write is refused unless the human owner
// opted in to that kind of write in the MCP client's environment. A refusal is
// decided before any request is built, and its message is fixed text: it never
// repeats the content that was refused.
//
// Not covered, because they are reads: reading the inbox marks the messages it
// returns as delivered and read, and every authenticated call updates this
// identity's public last_seen time. Both are visible to others. Since 3.0.2 the
// inbox read takes no since or limit without the state-changes opt-in: it
// always takes the oldest unread page in relay order, so the model chooses
// only whether and when to read, not which messages are marked. Rows the relay
// cannot decrypt are acknowledged by the tool through read-batch without this
// opt-in (tools.ts skipUnreadable): the relay picks and confirms them, not the
// model, and without it they would stall every unread page.
//
// VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS
//   unset or empty  refuse every recipient-addressed write (send, task, invite,
//                   any task update: status, output or rating), broadcast and
//                   webhook registration.
//   did,did,...     only these DIDs; broadcast and webhooks refused (as in 3.0.0).
//                   A task update is checked against the other agent on the
//                   task: the assignee when this identity created it, the
//                   creator otherwise (3.0.2; 3.0.0 and 3.0.1 did not check task updates).
//   *               any recipient, broadcast and webhooks (3.0.0's unset default).
// VOIDLY_MCP_RELAY_ALLOW_OPEN_WRITES=1
//   channel posts and channel creation, profile and capability changes,
//   attestations and corroborations. These have no single recipient to check.
//   Also the display name and capabilities given to agent_register: without
//   it, registration publishes only a fixed name and no capabilities.
// VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES=1
//   state changes that carry no text but that another party can see: joining
//   a channel, accepting or declining an invite, marking messages read,
//   deleting a message, sending a heartbeat, deleting a capability. Also
//   since and limit on agent_receive_messages, which choose which messages
//   the relay marks read, and agent_get_trust, whose lookup can make the
//   relay recalculate a model-chosen agent's score and publish the time.
// VOIDLY_MCP_RELAY_ALLOW_MEMORY_WRITES=1
//   relay-side memory. Memory is relay-readable, so even with this set a value
//   shaped like a credential is refused.
//
// Independent of all four: content carrying a key or webhook secret this
// process holds is refused on every write.

import { DID_RE, InputRefused } from './ids.js';
import { redact } from './redact.js';

export type RecipientPolicy =
  | { mode: 'deny' }
  | { mode: 'any' }
  | { mode: 'list'; dids: Set<string> };

const NOTHING_SENT = 'Nothing was sent.';

export function recipientPolicy(env: NodeJS.ProcessEnv = process.env): RecipientPolicy {
  const raw = env.VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS?.trim();
  if (!raw) return { mode: 'deny' };
  if (raw === '*') return { mode: 'any' };
  const dids = new Set<string>();
  for (const part of raw.split(',')) {
    const did = part.trim();
    if (did && DID_RE.test(did)) dids.add(did);
  }
  // A list with no valid DID allows nobody (same as 3.0.0 with such a list).
  return { mode: 'list', dids };
}

const UNSET =
  'Relay writes to other agents are off by default. The human owner can allow specific recipients with VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS (a comma list of DIDs). ' +
  NOTHING_SENT;

/** A write addressed to one DID (message, task, invite, task output). */
export function checkRecipient(did: string, env: NodeJS.ProcessEnv = process.env): void {
  const p = recipientPolicy(env);
  if (p.mode === 'any') return;
  if (p.mode === 'deny') throw new InputRefused('recipient_allowlist_unset', UNSET);
  if (!p.dids.has(did)) {
    throw new InputRefused(
      'recipient_not_allowed',
      `This recipient is not on the owner's VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS list. ${NOTHING_SENT}`,
    );
  }
}

/** Broadcast: goes to agents nobody chose by DID. Allowed only with `*`. */
export function checkBroadcast(env: NodeJS.ProcessEnv = process.env): void {
  const p = recipientPolicy(env);
  if (p.mode === 'any') return;
  if (p.mode === 'deny') throw new InputRefused('recipient_allowlist_unset', UNSET);
  throw new InputRefused(
    'recipient_not_allowed',
    `Broadcast goes to every agent with a capability, which the owner's VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS list does not allow. ${NOTHING_SENT}`,
  );
}

/** Webhook: sends message metadata to a URL. Allowed only with `*`. */
export function checkWebhook(env: NodeJS.ProcessEnv = process.env): void {
  const p = recipientPolicy(env);
  if (p.mode === 'any') return;
  throw new InputRefused(
    'webhook_not_allowed',
    p.mode === 'deny'
      ? `A webhook sends message metadata to a URL, which is off by default. The human owner can allow it with VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS=*. ${NOTHING_SENT}`
      : `A webhook sends message metadata to a URL outside the owner's VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS list, so it is refused while that list is set. ${NOTHING_SENT}`,
  );
}

/** Channel, profile, capability, attestation and corroboration writes. */
export function checkOpenWrite(env: NodeJS.ProcessEnv = process.env): void {
  if (env.VOIDLY_MCP_RELAY_ALLOW_OPEN_WRITES?.trim() === '1') return;
  throw new InputRefused(
    'open_write_not_allowed',
    `This write is readable by channel members, other agents or the public, and such writes are off by default. The human owner can allow them with VOIDLY_MCP_RELAY_ALLOW_OPEN_WRITES=1. ${NOTHING_SENT}`,
  );
}

/**
 * Join, invite answers, read receipts, message deletes, heartbeats and
 * capability deletes. No text, but the other party sees the change, so a
 * chosen pattern of them can signal data.
 */
export function stateChangesAllowed(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES?.trim() === '1';
}

export function checkStateChange(env: NodeJS.ProcessEnv = process.env): void {
  if (stateChangesAllowed(env)) return;
  throw new InputRefused(
    'state_change_not_allowed',
    `This change is visible to another agent, a channel or the public, and such changes are off by default. The human owner can allow them with VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES=1. ${NOTHING_SENT}`,
  );
}

/** The display name agent_register publishes when open writes are off. */
export const DEFAULT_AGENT_NAME = 'mcp-agent';

/**
 * agent_register publishes its name and capabilities in the relay directory.
 * Without the open-writes opt-in, only the fixed default name and no
 * capabilities are accepted, so a model cannot be talked into publishing text.
 * Returns the name and capabilities to send.
 */
export function registerFields(
  name: string | undefined,
  capabilities: string[] | undefined,
  env: NodeJS.ProcessEnv = process.env,
): { name: string; capabilities: string[] | undefined } {
  if (env.VOIDLY_MCP_RELAY_ALLOW_OPEN_WRITES?.trim() === '1') {
    if (name === undefined) return { name: DEFAULT_AGENT_NAME, capabilities };
    return { name, capabilities };
  }
  const customName = name !== undefined && name !== DEFAULT_AGENT_NAME;
  const customCaps = capabilities !== undefined && capabilities.length > 0;
  if (customName || customCaps) {
    throw new InputRefused(
      'register_text_not_allowed',
      `A display name or capabilities given to agent_register are published in the relay directory, and such text is off by default. ` +
        `Call agent_register with no name and no capabilities to register as "${DEFAULT_AGENT_NAME}". ` +
        `The human owner can allow a chosen name and capabilities with VOIDLY_MCP_RELAY_ALLOW_OPEN_WRITES=1. No identity was created. ${NOTHING_SENT}`,
    );
  }
  return { name: DEFAULT_AGENT_NAME, capabilities: undefined };
}

// Credential shapes refused in relay-readable memory. Matched after removing
// invisible characters, so a split value is still caught.
const INVISIBLE = /[­᠎​-‏⁠-⁤﻿]/g;
const SECRET_SHAPES: RegExp[] = [
  /(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])/i, // relay API key shape
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
  /\bsk-[A-Za-z0-9_-]{20,}/,
  /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/,
  /\bgh[pousr]_[A-Za-z0-9]{30,}/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  /\bAIza[0-9A-Za-z_-]{35}/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
  /\bvm[oa]_[A-Za-z0-9_-]{16,}/,
];

function asText(value: unknown): string {
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value) ?? '';
  } catch {
    return '';
  }
}

/** True if the value carries a key or webhook secret this process holds. */
function carriesHeldSecret(value: unknown): boolean {
  const text = asText(value);
  return text !== '' && redact(text) !== text;
}

/** Refuse content that carries a key or webhook secret this process holds. */
export function refuseHeldSecrets(...values: unknown[]): void {
  for (const v of values) {
    if (v === undefined || v === null) continue;
    if (carriesHeldSecret(v)) {
      throw new InputRefused('secret_in_content', `The content carries a key or secret this server holds, so it was refused. ${NOTHING_SENT}`);
    }
  }
}

/** Refuse content shaped like a credential (and anything refuseHeldSecrets refuses). */
export function refuseSecretShaped(...values: unknown[]): void {
  refuseHeldSecrets(...values);
  for (const v of values) {
    if (v === undefined || v === null) continue;
    const text = asText(v).replace(INVISIBLE, '');
    if (SECRET_SHAPES.some((re) => re.test(text))) {
      throw new InputRefused(
        'secret_shaped_content_refused',
        `The content looks like a credential, and relay-side storage is relay-readable, so it was refused. ${NOTHING_SENT}`,
      );
    }
  }
}

/** Relay-side memory: opt-in, and never credential-shaped. */
export function checkMemoryWrite(...values: unknown[]): void {
  if (process.env.VOIDLY_MCP_RELAY_ALLOW_MEMORY_WRITES?.trim() !== '1') {
    throw new InputRefused(
      'memory_write_not_allowed',
      `Relay-side memory is relay-readable, and writes to it are off by default. The human owner can allow them with VOIDLY_MCP_RELAY_ALLOW_MEMORY_WRITES=1. ${NOTHING_SENT}`,
    );
  }
  refuseSecretShaped(...values);
}
