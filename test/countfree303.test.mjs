// 3.0.3: Voidly's own usage numbers are internal operator metrics (owner order
// 2026-10-27). The relay and the public API stopped returning them; these tools
// must not print or promise them either, even if an older relay still sends
// them. Each mock below answers with the pre-2026-10-28 shape, every count set
// to a sentinel, and the tool output must not carry the sentinel or the key.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { startMockRelay, startServer, tempHome, resultText, fakeDid } from './helpers.mjs';

const N = 987654;
const COUNT_KEYS = [
  'total_agents', 'active_agents_24h', 'total_messages', 'agents_synced', 'messages_routed',
  'member_count', 'message_count', 'last_activity', 'invocations', 'tasks_completed',
  'attestations_made', 'messages_sent', 'minutes_since_seen', 'uptime_days', 'last_seen',
];

async function server(extraEnv = {}) {
  const relay = await startMockRelay();
  const home = tempHome();
  const srv = await startServer({ HOME: home.dir, VOIDLY_MCP_RELAY_HOME: home.relayHome, VOIDLY_MCP_RELAY_API_BASE: relay.base, ...extraEnv });
  return { relay, srv, async done() { await srv.close(); await relay.close(); home.cleanup(); } };
}

const did = fakeDid();
const legacy = {
  '/v1/agent/stats': { relay: { version: '2', encryption: 'x25519', signing: 'ed25519', identity: 'did' }, degraded: false, unavailable: [],
    stats: { total_agents: N, active_agents_24h: N, total_messages: N, capabilities: ['cap'] } },
  '/v1/relay/info': { relay: { name: 'r', agents: N }, federation: { accepts_peers: true, messages_routed: N }, degraded: false, stats: { agents: N, messages: N } },
  '/v1/relay/peers': { peers: [{ id: 'p1', relay_url: 'https://peer.example', relay_name: 'peer', status: 'active', agents_synced: N, messages_routed: N }], total: N, active: N, stale: N },
  '/v1/agent/trust/leaderboard': { leaderboard: [{ rank: 1, agent: did, name: 'a', trust_score: 0.5, trust_level: 'low', tasks_completed: N, attestations_made: N, member_since: '2026-01-01T00:00:00Z' }], total: N },
  '/v1/agent/channels': { channels: [{ id: 'c1', name: 'n', topic: 't', description: 'd', member_count: N, message_count: N, last_activity: '2026-10-01T00:00:00Z' }] },
  '/v1/agent/capabilities/search': { results: [{ id: 'k1', name: 'cap', description: 'd', invocations: N, avg_rating: 4, agent: { did, name: 'a' } }] },
  '/v1/agent/discover': { agents: [{ did, name: 'a', capabilities: [], last_seen: '2026-10-01T00:00:00Z', message_count: N, encryption_public_key: 'k' }] },
  [`/v1/agent/identity/${did}`]: { did, status: 'active', name: 'a', capabilities: [], created_at: '2026-01-01T00:00:00Z', last_seen: '2026-10-01T00:00:00Z', message_count: N },
  [`/v1/agent/ping/${did}`]: { did, online_status: 'online', online: true, last_seen: '2026-10-01T00:00:00Z', minutes_since_seen: N, uptime_days: N, message_count: N },
  [`/v1/agent/trust/${did}`]: { agent: did, name: 'a', trust_score: 0.5, trust_level: 'low', member_since: '2026-01-01T00:00:00Z', components: { task_completion_rate: 0.5 },
    activity: { tasks_completed: N, tasks_failed: N, attestations_made: N, messages_sent: N } },
};

const calls = [
  ['agent_relay_stats', {}], ['relay_info', {}], ['relay_peers', {}], ['agent_trust_leaderboard', {}],
  ['agent_list_channels', {}], ['agent_search_capabilities', { query: 'cap' }], ['agent_discover', { query: 'a' }],
  ['agent_get_identity', { did }], ['agent_ping_check', { did }], ['agent_get_trust', { did }],
];

test('relay readers print no usage count even when an old relay sends one', async () => {
  const ctx = await server({ VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES: '1' });
  const served = new Set();
  try {
    ctx.relay.state.override = (req) => {
      const body = legacy[decodeURIComponent(req.path.split('?')[0])];
      if (body) served.add(decodeURIComponent(req.path.split('?')[0]));
      return body ? { status: 200, body } : undefined;
    };
    for (const [name, args] of calls) {
      const r = await ctx.srv.call(name, args);
      const text = resultText(r);
      assert.ok(!r.isError, `${name}: ${text}`);
      assert.ok(!text.includes(String(N)), `${name} printed a usage count`);
      for (const key of COUNT_KEYS) assert.ok(!text.includes(key), `${name} printed ${key}`);
      assert.ok(!/\bmessages?:|\bmembers:|\bagents:/i.test(text), `${name} labels a count`);
    }
    assert.deepEqual([...served].sort(), Object.keys(legacy).sort(), 'every legacy body was actually served');
    const stats = resultText(await ctx.srv.call('agent_relay_stats', {}));
    assert.match(stats, /internal operator metrics/);
    assert.ok(!/\bcap\b/.test(stats), 'the old capability registry list is not shown');
  } finally {
    await ctx.done();
  }
});

test('descriptions promise status, not usage counts', async () => {
  const ctx = await server();
  try {
    const { tools } = await ctx.srv.client.listTools();
    const d = Object.fromEntries(tools.map((t) => [t.name, t.description]));
    assert.match(d.agent_relay_stats, /internal operator metrics/);
    assert.match(d.get_alert_stats, /internal operator metrics/);
    assert.match(d.get_community_probes, /internal operator metrics/);
    assert.match(d.get_community_leaderboard, /internal operator metrics/);
    for (const [name, text] of Object.entries(d)) {
      assert.ok(!/Shows active webhook subscriptions|recent deliveries|total registered agents|message volume|trust scores, and measurement counts|ranked by number of/i.test(text), name);
    }
  } finally {
    await ctx.done();
  }
});

test('the built server carries no usage-count labels for the public API tools', () => {
  const dist = readFileSync(new URL('../dist/index.js', import.meta.url), 'utf8');
  for (const label of ['Active Subscriptions', 'Deliveries (24h)', 'Webhook Success Rate', 'Total Nodes',
    'totalProbes', 'blockedConfirmed', 'activeSubscriptions', 'total_agents', 'active_agents_24h',
    'agents_synced', 'messages_routed', 'tasks_completed / ', 'minutes_since_seen']) {
    assert.ok(!dist.includes(label), label);
  }
  const README = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  assert.match(README, /3\.0\.3 shows no usage counts/);
  assert.ok(!README.includes('Public relay statistics'));
  assert.ok(!README.includes('Alert system health and statistics'));
});
