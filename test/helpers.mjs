// Test helpers: a local mock relay that records every request, and an MCP
// client that runs the built server over stdio. Synthetic values only.

import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const DIST = join(ROOT, 'dist', 'index.js');

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function fakeDid() {
  let s = '';
  const bytes = randomBytes(22);
  for (const b of bytes) s += B58[b % B58.length];
  return `did:voidly:${s}`;
}
/** A synthetic relay key: 64 lowercase hex, with a recognisable prefix. */
export function fakeKey() {
  return 'deadbeef' + randomBytes(28).toString('hex');
}
export function fakeSecret() {
  return 'cafebabe' + randomBytes(28).toString('hex');
}

/** Every representation of a key that must never appear in output. */
export function leakForms(key) {
  return [key, key.toUpperCase(), key.slice(0, 32), key.slice(32)];
}

export function assertNoLeak(assert, text, keys, where) {
  for (const key of keys) {
    for (const form of leakForms(key)) {
      assert.ok(!text.includes(form), `${where} contains key material (${form.slice(0, 12)}...)`);
    }
    // Also the zero-width-joined form.
    const zw = Array.from(key).join('\u200b');
    assert.ok(!text.includes(zw), `${where} contains a zero-width split key`);
  }
}

const now = '2026-09-24 10:00:00';

/** Mock relay. `state.key` is the only API key it accepts. */
export async function startMockRelay() {
  const state = {
    did: fakeDid(),
    other: fakeDid(),
    key: fakeKey(),
    webhookSecret: fakeSecret(),
    requests: [],
    /** When set, every JSON string in a response gets this appended. */
    poison: null,
    /** When set, every response is this status + body. */
    forceError: null,
    /** Optional per-test override: (req) => {status, body} | undefined, or a promise of one. */
    override: null,
    inbound: 'hello from another agent',
    registered: false,
    /**
     * Optional stateful inbox (null keeps the fixed one-message receive). Rows:
     * { id, from, content, created_at, urgent, decryptable, sender_missing,
     *   malformed, read_at, delivered }. Receive, raw receive, message get and
     * the mark-read routes then follow the worker's handlers (agentRelay.ts at
     * 7901d9cb5): unread filter, priority-then-oldest order, LIMIT, and
     * /receive drops rows it cannot decrypt without marking them. A `malformed`
     * row (non-base64 ciphertext or a nonce that is not 24 bytes, which
     * /send/encrypted accepts) is dropped by /receive the same way, but the
     * worker's get-by-id does not catch the decode error, so it answers 500.
     */
    inbox: null,
    /** Called after each /v1/agent/receive on the stateful inbox. */
    afterReceive: null,
    /** When set, /receive/raw returns up to 100 rows whatever limit was asked. */
    rawIgnoresLimit: false,
  };

  function inboxSelect(query, unreadDefault) {
    const since = (query.since || '1970-01-01 00:00:00').replace('T', ' ').replace('Z', '').replace(/\.\d+$/, '');
    const rawLimit = query.limit;
    let limit = 50;
    if (rawLimit !== undefined) {
      limit = Number(rawLimit);
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) return null;
    }
    const unread = query.unread === undefined ? unreadDefault : unreadDefault ? query.unread !== 'false' : query.unread === 'true';
    const rows = state.inbox
      .map((r, seq) => ({ r, seq }))
      .filter(({ r }) => r.created_at >= since && (!unread || !r.read_at))
      .sort((a, b) => (a.r.urgent ? 0 : 1) - (b.r.urgent ? 0 : 1) || (a.r.created_at < b.r.created_at ? -1 : a.r.created_at > b.r.created_at ? 1 : a.seq - b.seq))
      .slice(0, limit)
      .map(({ r }) => r);
    return { rows, limit };
  }

  function inboxRoutes(method, path, body, query) {
    const R = (status, b) => ({ status, body: b });
    let m;
    if (method === 'GET' && path === '/v1/agent/receive') {
      const sel = inboxSelect(query, false);
      if (!sel) return R(400, { error: 'Invalid limit parameter.' });
      const messages = [];
      for (const r of sel.rows) {
        if (!r.decryptable || r.sender_missing || r.malformed) continue;
        r.delivered = 1;
        r.read_at = r.read_at ?? now;
        messages.push({ id: r.id, from: r.from, to: state.did, content: r.content, message_type: 'text', thread_id: null, signature_valid: true, timestamp: r.created_at });
      }
      const out = R(200, { messages, count: messages.length, has_more: sel.rows.length === sel.limit });
      state.afterReceive?.();
      return out;
    }
    if (method === 'GET' && path === '/v1/agent/receive/raw') {
      const sel = inboxSelect(state.rawIgnoresLimit ? { ...query, limit: '100' } : query, true);
      if (!sel) return R(400, { error: 'Invalid limit parameter.' });
      for (const r of sel.rows) r.delivered = 1;
      return R(200, {
        messages: sel.rows.map((r) => ({ id: r.id, from: r.from, to: state.did, ciphertext: `CIPHERTEXT-${r.id}`, nonce: 'bm9uY2U=', signature: 'c2ln', timestamp: r.created_at })),
        count: sel.rows.length,
        has_more: sel.rows.length === sel.limit,
        mode: 'client_side_decryption',
      });
    }
    if (method === 'POST' && path === '/v1/agent/messages/read-batch') {
      const ids = Array.isArray(body?.message_ids) ? body.message_ids : [];
      let updated = 0;
      for (const r of state.inbox) if (ids.includes(r.id) && !r.read_at) { r.read_at = now; updated++; }
      return R(200, { read: true, updated, total_requested: ids.length });
    }
    if (method === 'POST' && (m = path.match(/^\/v1\/agent\/messages\/([^/]+)\/read$/))) {
      const r = state.inbox.find((x) => x.id === m[1]);
      if (!r) return R(404, { error: 'Message not found.' });
      if (r.read_at) return R(200, { already_read: true, read_at: r.read_at });
      r.read_at = now;
      return R(200, { read: true, message_id: r.id, read_at: now });
    }
    if (method === 'GET' && (m = path.match(/^\/v1\/agent\/messages\/([^/]+)$/)) && m[1] !== 'unread-count') {
      const r = state.inbox.find((x) => x.id === m[1]);
      if (!r || r.sender_missing) return R(404, { error: 'Message not found' });
      if (r.malformed) return R(500, { error: 'Internal server error' });
      if (r.decryptable) return R(200, { id: r.id, from: r.from, to: state.did, content: r.content, timestamp: r.created_at, delivered: r.delivered });
      return R(200, { id: r.id, from: r.from, to: state.did, timestamp: r.created_at, delivered: r.delivered, encrypted: true });
    }
    return undefined;
  }

  function routes(method, path, body, authed) {
    const DID = state.did;
    const OTHER = state.other;
    const need = () => (authed ? null : { status: 401, body: { error: 'Invalid or missing X-Agent-Key' } });
    const R = (status, b) => ({ status, body: b });
    let m;
    if (method === 'POST' && path === '/v1/agent/register') {
      if (!body?.name) return R(400, { error: 'A display name is required.' });
      state.registered = true;
      return R(201, { did: DID, api_key: state.key, signing_public_key: 'c2lnbmluZw==', encryption_public_key: 'ZW5jcnlwdA==', name: body.name, client_side: false });
    }
    if (method === 'POST' && path === '/v1/agent/rotate-api-key') {
      const n = need(); if (n) return n;
      const newKey = fakeKey();
      state.previousKey = state.key;
      state.key = newKey;
      return R(200, { did: DID, api_key: newKey, api_key_version: 1, rotated_at: now, previous_key: 'revoked', disabled: { webhooks: [{ id: 'w1', webhook_url: 'https://example.com/hook' }], push_subscriptions: 0 }, limits: 'Re-register webhooks you recognise.' });
    }
    if (method === 'DELETE' && path === '/v1/agent/deactivate') { const n = need(); if (n) return n; return R(200, { did: DID, status: 'inactive' }); }
    if (method === 'GET' && path === '/v1/agent/profile') { const n = need(); if (n) return n; return R(200, { did: DID, name: 'me', status: 'active', message_count: 1, capabilities: ['research'], created_at: now, last_seen: now }); }
    if (method === 'PATCH' && path === '/v1/agent/profile') { const n = need(); if (n) return n; return R(200, { ok: true }); }
    if (method === 'GET' && path === '/v1/agent/discover') return R(200, { agents: [{ did: OTHER, name: 'other agent', capabilities: ['c'], last_seen: now, message_count: 2, encryption_public_key: 'a2V5' }], count: 1 });
    if (method === 'GET' && (m = path.match(/^\/v1\/agent\/identity\/([^/]+)$/))) return R(200, { did: decodeURIComponent(m[1]), name: 'other agent', status: 'active', signing_public_key: 'c2ln', encryption_public_key: 'ZW5j', capabilities: [], created_at: now, last_seen: now, message_count: 1 });
    if (method === 'GET' && (m = path.match(/^\/v1\/agent\/username\/([^/]+)$/))) {
      const u = decodeURIComponent(m[1]);
      if (u === 'missing_user') return R(404, { error: 'Username not found' });
      return R(200, { username: u, did: OTHER, display_name: state.inbound, signing_public_key: 'c2ln', encryption_public_key: 'ZW5j', capabilities: ['c'], claimed_at: now });
    }
    if (method === 'GET' && (m = path.match(/^\/v1\/sentinel\/current_risk\/([A-Z]{2})$/))) {
      return R(200, {
        country: m[1], country_name: `Country ${m[1]}`, issued_at: now, model_version: 'mock',
        forecast_summary: { max_risk: 0.1, max_risk_day: 3, key_drivers: ['election'] },
        honest_forecast: { probability: 0.1, risk_band: 'low', recommended_threshold: 0.5 },
        trust: {
          probability: 0.1, interval_90: [0, 0.4], conformal_coverage: 0.9, model_version: 'mock-v1',
          top_features: [{ name: 'block_rate', contribution: 0.05, direction: 'up' }],
          similar_incident: { readable_id: `${m[1]}-2025-0001`, severity: 'high', url: 'https://example.com/i' },
          evidence_permalinks: [{ source: 'ooni', signal_type: 'blocking', observed_at: now, permalink: 'https://example.com/e' }],
        },
      });
    }
    if (method === 'GET' && path === '/v1/sentinel/global_heatmap') {
      return R(200, { eval_date: '2026-09-24', n: 1, honest_caveat: 'mock caveat', countries: [{ country: 'IR', country_name: 'Iran', max_risk: 0.2, max_risk_day: 2, above_threshold: false, threshold: 0.5 }] });
    }
    if (method === 'GET' && path === '/v1/sentinel/accuracy') {
      return R(200, {
        degraded: true, degradation_reason: 'mock degraded', published_warning: 'mock warning', notes: 'mock notes',
        prod_rolling: { n_evaluated: 40, precision: 0.1, recall: 0.2, accuracy: 0.5, brier_score: 0.3, calibration_mae: 0.2, confusion: { true_positive: 1, false_positive: 2, true_negative: 3, false_negative: 4 } },
        training_holdout: { roc_auc: 0.9, f1: 0.8, precision: 0.8, recall: 0.8, samples: 100, positive_rate: 0.1, split_loco: { f1_median: 0.5, n_countries_evaluated: 10 } },
      });
    }
    if (method === 'GET' && path === '/v1/sentinel/manifest.json') {
      return R(200, { stage: 'mock', license: { data: 'CC-BY-4.0', code: 'Apache-2.0' }, description: 'mock manifest', endpoints: [{ method: 'GET', path: '/v1/sentinel/accuracy', summary: 's' }], mcp_tools: [{ name: 'sentinel_accuracy' }], reliability_commitment: 'mock' });
    }
    if (method === 'GET' && path === '/v1/sentinel/calibration/history') {
      return R(200, { n: 1, history: [{ date: '2026-09-24', q90: 0.25, empirical_coverage: 0.9, n_holdout: 100, drift_alert: false, drift_delta: 0.01 }] });
    }
    if (method === 'POST' && path === '/v1/agent/verify') return R(200, { valid: true, sender_did: OTHER, verified_at: now });
    if (method === 'GET' && path === '/v1/agent/stats') return R(200, { relay: { version: '1', encryption: 'x', signing: 'y', identity: 'z' }, stats: { total_agents: 3, active_agents_24h: 1, total_messages: 9, capabilities: ['c'] } });
    if (method === 'POST' && path === '/v1/agent/send') { const n = need(); if (n) return n; return R(201, { id: 'm1', from: DID, to: body?.to, timestamp: now, expires_at: now, encrypted: true }); }
    if (method === 'GET' && path === '/v1/agent/receive') { const n = need(); if (n) return n; return R(200, { messages: [{ id: 'm1', from: OTHER, to: DID, content: state.inbound, timestamp: now, thread_id: null, signature_valid: true, message_type: 'text' }], count: 1, has_more: false }); }
    if (method === 'DELETE' && /^\/v1\/agent\/messages\/[^/]+$/.test(path)) { const n = need(); if (n) return n; return R(200, { ok: true }); }
    if (method === 'POST' && path === '/v1/agent/messages/read-batch') { const n = need(); if (n) return n; return R(200, { updated: 1, total_requested: 1 }); }
    if (method === 'POST' && /^\/v1\/agent\/messages\/[^/]+\/read$/.test(path)) { const n = need(); if (n) return n; return R(200, { read_at: now }); }
    if (method === 'GET' && path === '/v1/agent/messages/unread-count') { const n = need(); if (n) return n; return R(200, { unread_count: 1, by_sender: [{ from: OTHER, count: 1 }] }); }
    if (method === 'POST' && path === '/v1/agent/webhooks') { const n = need(); if (n) return n; return R(201, { id: 'w1', webhook_url: body?.webhook_url, secret: state.webhookSecret, events: ['message'] }); }
    if (method === 'GET' && path === '/v1/agent/webhooks') { const n = need(); if (n) return n; return R(200, { webhooks: [{ id: 'w1', webhook_url: 'https://example.com/hook', events: ['message'], enabled: true, failure_count: 0 }] }); }
    if (method === 'POST' && path === '/v1/agent/channels') { const n = need(); if (n) return n; return R(201, { id: 'c1', name: body?.name, type: 'public', topic: null }); }
    if (method === 'GET' && path === '/v1/agent/channels') return R(200, { channels: [{ id: 'c1', name: 'chan', topic: 't', member_count: 1, message_count: 1, description: 'd', last_activity: now }] });
    if (method === 'POST' && /^\/v1\/agent\/channels\/[^/]+\/join$/.test(path)) { const n = need(); if (n) return n; return R(200, { role: 'member' }); }
    if (method === 'POST' && /^\/v1\/agent\/channels\/[^/]+\/messages$/.test(path)) { const n = need(); if (n) return n; return R(201, { id: 'p1', timestamp: now }); }
    if (method === 'GET' && /^\/v1\/agent\/channels\/[^/]+\/messages$/.test(path)) { const n = need(); if (n) return n; return R(200, { messages: [{ id: 'p1', sender: OTHER, sender_name: 'poster', content: state.inbound, timestamp: now }], count: 1 }); }
    if (method === 'POST' && /^\/v1\/agent\/channels\/[^/]+\/invite$/.test(path)) { const n = need(); if (n) return n; return R(201, { id: 'i1', expires_at: now }); }
    if (method === 'GET' && path === '/v1/agent/invites') { const n = need(); if (n) return n; return R(200, { invites: [{ id: 'i1', channel_id: 'c1', channel_name: 'chan', inviter: OTHER, inviter_name: 'x', message: state.inbound }], count: 1 }); }
    if (method === 'POST' && /^\/v1\/agent\/invites\/[^/]+\/respond$/.test(path)) { const n = need(); if (n) return n; return R(200, { channel_id: 'c1', role: 'member' }); }
    if (method === 'POST' && path === '/v1/agent/capabilities') { const n = need(); if (n) return n; return R(201, { id: 'cap1', name: body?.name, did: DID }); }
    if (method === 'GET' && path === '/v1/agent/capabilities/search') return R(200, { results: [{ id: 'cap1', name: 'n', description: 'd', agent: { did: OTHER, name: 'a' }, invocations: 0, avg_rating: 0 }], count: 1 });
    if (method === 'GET' && path === '/v1/agent/capabilities') { const n = need(); if (n) return n; return R(200, { capabilities: [{ id: 'cap1', name: 'n', version: '1.0.0', description: 'd', invocations: 0, avg_rating: 0 }], count: 1 }); }
    if (method === 'DELETE' && /^\/v1\/agent\/capabilities\/[^/]+$/.test(path)) { const n = need(); if (n) return n; return R(200, {}); }
    if (method === 'POST' && path === '/v1/agent/tasks/broadcast') { const n = need(); if (n) return n; return R(201, { broadcast_id: 'b1', capability: 'c', priority: 'normal', agents_matched: 1, tasks: [{ task_id: 't2', agent_did: OTHER }] }); }
    if (method === 'GET' && path === '/v1/agent/tasks/broadcasts') { const n = need(); if (n) return n; return R(200, { broadcasts: [{ id: 'b1', capability: 'c', status: 'active', tasks_completed: 0, tasks_created: 1 }] }); }
    if (method === 'GET' && /^\/v1\/agent\/tasks\/broadcasts\/[^/]+$/.test(path)) { const n = need(); if (n) return n; return R(200, { broadcast: { id: 'b1', capability: 'c', status: 'active', tasks_completed: 0, tasks_created: 1, tasks_failed: 0 }, tasks: [{ agent: OTHER, agent_name: 'a', status: 'pending' }] }); }
    if (method === 'POST' && path === '/v1/agent/tasks') { const n = need(); if (n) return n; return R(201, { id: 't1', to: body?.to, priority: 'normal', status: 'pending' }); }
    if (method === 'GET' && path === '/v1/agent/tasks') { const n = need(); if (n) return n; return R(200, { tasks: [{ id: 't1', status: 'pending', priority: 'normal', from_did: DID, to_did: OTHER, capability: 'c' }], role: 'assignee', count: 1 }); }
    if (method === 'GET' && /^\/v1\/agent\/tasks\/[^/]+$/.test(path)) { const n = need(); if (n) return n; return R(200, { id: 't1', from: OTHER, to: DID, capability: 'c', status: 'pending', priority: 'normal', input: state.inbound, created_at: now }); }
    if (method === 'PATCH' && /^\/v1\/agent\/tasks\/[^/]+$/.test(path)) { const n = need(); if (n) return n; return R(200, { status: body?.status ?? 'pending' }); }
    if (method === 'POST' && path === '/v1/agent/attestations') { const n = need(); if (n) return n; return R(201, { id: 'a1', claim_type: body?.claim_type, confidence: 1, consensus_score: 0.5 }); }
    if (method === 'GET' && path === '/v1/agent/attestations/consensus') return R(200, { consensus: [{ claim_type: 'domain-blocked', domain: 'x.com', country: 'IR', total_attestations: 1, avg_consensus: 0.5, total_corroborations: 0 }] });
    if (method === 'GET' && path === '/v1/agent/attestations') return R(200, { attestations: [{ id: 'a1', claim_type: 'domain-blocked', domain: 'x.com', country: 'IR', agent: OTHER, consensus_score: 0.5, corroboration_count: 0, timestamp: now }], count: 1 });
    if (method === 'POST' && /^\/v1\/agent\/attestations\/[^/]+\/corroborate$/.test(path)) { const n = need(); if (n) return n; return R(200, { new_consensus_score: 0.6, corroboration_count: 1, refutation_count: 0 }); }
    if (method === 'GET' && /^\/v1\/agent\/attestations\/[^/]+$/.test(path)) return R(200, { id: 'a1', agent: OTHER, agent_name: 'a', claim_type: 'domain-blocked', claim_data: { note: state.inbound }, country: 'IR', domain: 'x.com', confidence: 1, consensus_score: 0.5, corroboration_count: 1, refutation_count: 0, corroborations: [{ agent: OTHER, vote: 'corroborate', comment: 'c' }] });
    if (method === 'GET' && path === '/v1/agent/trust/leaderboard') return R(200, { leaderboard: [{ rank: 1, agent: OTHER, name: 'a', trust_score: 0.5, trust_level: 'low', tasks_completed: 0, attestations_made: 0 }] });
    if (method === 'GET' && /^\/v1\/agent\/trust\/[^/]+$/.test(path)) return R(200, { agent: OTHER, name: 'a', trust_score: 0.5, trust_level: 'low', components: { task_completion_rate: 1, task_quality_avg: 1, attestation_accuracy: 1, message_reliability: 1 }, activity: { tasks_completed: 0, tasks_failed: 0, attestations_made: 0, messages_sent: 0 }, member_since: now });
    if (method === 'GET' && path === '/v1/agent/analytics') { const n = need(); if (n) return n; return R(200, { agent: DID, name: 'me', period: '7d', member_since: now, messaging: { sent: 1, received: 1, read: 1, read_rate: 1, channel_posts: 0, channels_joined: 0 }, tasks: { created: 0, received: 0, completed: 0, completion_rate: 0 }, attestations: { made: 0, corroborations_received: 0 }, reputation: { trust_score: 0.5, trust_level: 'low' } }); }
    if ((m = path.match(/^\/v1\/agent\/memory\/([^/]+)\/(.+)$/))) {
      const n = need(); if (n) return n;
      if (method === 'PUT') return R(200, { namespace: decodeURIComponent(m[1]), key: decodeURIComponent(m[2]), size_bytes: 5 });
      if (method === 'GET') return R(200, { namespace: decodeURIComponent(m[1]), key: decodeURIComponent(m[2]), value: state.inbound, value_type: 'string', size_bytes: 5, updated_at: now });
      if (method === 'DELETE') return R(200, {});
    }
    if (method === 'GET' && (m = path.match(/^\/v1\/agent\/memory\/([^/]+)$/))) { const n = need(); if (n) return n; return R(200, { namespace: decodeURIComponent(m[1]), keys: [{ key: 'k', value_type: 'string', size_bytes: 1, updated_at: now }], total_keys: 1, total_bytes: 1 }); }
    if (method === 'GET' && path === '/v1/agent/memory') { const n = need(); if (n) return n; return R(200, { quota: { used_bytes: 1, quota_bytes: 100 }, namespaces: [{ namespace: 'n', key_count: 1, total_bytes: 1, last_updated: now }] }); }
    if (method === 'POST' && path === '/v1/agent/export') { const n = need(); if (n) return n; return R(200, { export_id: 'e1', identity: { did: DID, name: 'me' }, exported_at: now, stats: { messages: 1 } }); }
    if (method === 'GET' && path === '/v1/relay/info') return R(200, { relay: { name: 'r', protocol: 'p', encryption: 'e', identity_format: 'i', features: ['f'] }, stats: { agents: 1, messages: 1 }, federation: { accepts_peers: true, sync_protocol: 's' } });
    if (method === 'GET' && path === '/v1/relay/peers') return R(200, { peers: [{ relay_name: 'p', relay_url: 'https://p.example', status: 'active', agents_synced: 0, messages_routed: 0 }], total: 1 });
    if (method === 'POST' && path === '/v1/agent/ping') { const n = need(); if (n) return n; return R(200, { did: DID, name: 'me', status: 'active', uptime: { days: 1, hours: 2 }, message_count: 1, server_time: now }); }
    if (method === 'GET' && /^\/v1\/agent\/ping\/[^/]+$/.test(path)) return R(200, { did: OTHER, name: 'a', online_status: 'online', last_seen: now, minutes_since_seen: 1, uptime_days: 1, message_count: 1 });
    if (method === 'POST' && path === '/v1/agent/keys/pin') { const n = need(); if (n) return n; return R(200, { status: 'pinned' }); }
    if (method === 'GET' && path === '/v1/agent/keys/pins') { const n = need(); if (n) return n; return R(200, { pins: [{ pinned_did: OTHER, pinned_name: 'a', status: 'ok', first_seen: now, last_verified: now }], total: 1 }); }
    if (method === 'GET' && /^\/v1\/agent\/keys\/verify\/[^/]+$/.test(path)) { const n = need(); if (n) return n; return R(200, { verified: true, first_seen: now }); }
    return R(404, { error: 'not_found' });
  }

  const poisonValue = (v, extra) => {
    if (typeof v === 'string') return `${v} ${extra}`;
    if (Array.isArray(v)) return v.map((x) => poisonValue(x, extra));
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, poisonValue(x, extra)]));
    return v;
  };

  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      let body = null;
      try { body = raw ? JSON.parse(raw) : null; } catch { body = null; }
      const url = new URL(req.url, 'http://127.0.0.1');
      const record = { method: req.method, rawUrl: req.url, path: url.pathname, query: Object.fromEntries(url.searchParams), headers: req.headers, raw, body };
      state.requests.push(record);
      const authed = req.headers['x-agent-key'] === state.key;
      let out = await state.override?.(record);
      if (!out && state.forceError) out = state.forceError;
      if (!out && state.inbox && authed) out = inboxRoutes(req.method, url.pathname, body, Object.fromEntries(url.searchParams));
      if (!out) out = routes(req.method, url.pathname, body, authed);
      let payload = out.body;
      if (state.poison && out.status < 400) payload = poisonValue(payload, state.poison);
      res.writeHead(out.status, { 'Content-Type': 'application/json' });
      res.end(typeof payload === 'string' ? payload : JSON.stringify(payload));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    state,
    base: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

export function tempHome() {
  const dir = mkdtempSync(join(tmpdir(), 'voidly-mcp-test-'));
  return { dir, relayHome: join(dir, 'relay'), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/** Start the built server over stdio. Returns the client and captured stderr. */
export async function startServer(env) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [DIST],
    env: { PATH: process.env.PATH ?? '', ...env },
    stderr: 'pipe',
  });
  const logs = { text: '' };
  transport.stderr?.on('data', (c) => { logs.text += c.toString('utf8'); });
  const client = new Client({ name: 'test', version: '0.0.0' });
  await client.connect(transport);
  return {
    client,
    logs,
    call: (name, args = {}) => client.callTool({ name, arguments: args }),
    close: () => client.close(),
  };
}

export function resultText(result) {
  return JSON.stringify(result);
}

/** Run the owner CLI. */
export function runCli(args, env, input) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [DIST, 'relay', ...args], { env: { PATH: process.env.PATH ?? '', ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
    if (input !== undefined) child.stdin.end(input);
    else child.stdin.end();
  });
}
