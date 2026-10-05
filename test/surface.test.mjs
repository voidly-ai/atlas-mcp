// Published surface: the exact tool list, the environment variables the build
// reads, strings the build must not carry, and the claims the README makes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, startServer, tempHome } from './helpers.mjs';

// Sorted. A change here is a change to the published tool surface.
const TOOLS = [
  'agent_analytics',
  'agent_broadcast_task',
  'agent_corroborate',
  'agent_create_attestation',
  'agent_create_channel',
  'agent_create_task',
  'agent_delete_capability',
  'agent_delete_message',
  'agent_discover',
  'agent_export_data',
  'agent_get_attestation',
  'agent_get_broadcast',
  'agent_get_consensus',
  'agent_get_identity',
  'agent_get_profile',
  'agent_get_task',
  'agent_get_trust',
  'agent_invite_to_channel',
  'agent_join_channel',
  'agent_key_pin',
  'agent_key_pins',
  'agent_key_verify',
  'agent_list_broadcasts',
  'agent_list_capabilities',
  'agent_list_channels',
  'agent_list_invites',
  'agent_list_tasks',
  'agent_list_webhooks',
  'agent_mark_read',
  'agent_mark_read_batch',
  'agent_memory_delete',
  'agent_memory_get',
  'agent_memory_list',
  'agent_memory_namespaces',
  'agent_memory_set',
  'agent_ping',
  'agent_ping_check',
  'agent_post_to_channel',
  'agent_query_attestations',
  'agent_read_channel',
  'agent_receive_messages',
  'agent_register',
  'agent_register_capability',
  'agent_register_webhook',
  'agent_relay_stats',
  'agent_resolve_username',
  'agent_respond_invite',
  'agent_search_capabilities',
  'agent_send_message',
  'agent_trust_leaderboard',
  'agent_unread_count',
  'agent_update_profile',
  'agent_update_task',
  'agent_verify_message',
  'check_domain_blocked',
  'check_domain_probes',
  'check_service_accessibility',
  'check_vpn_accessibility',
  'compare_countries',
  'get_active_incidents',
  'get_alert_stats',
  'get_censorship_index',
  'get_community_leaderboard',
  'get_community_probes',
  'get_country_status',
  'get_domain_history',
  'get_domain_status',
  'get_election_risk',
  'get_high_risk_countries',
  'get_incident_detail',
  'get_incident_evidence',
  'get_incident_report',
  'get_incident_stats',
  'get_incidents_since',
  'get_isp_risk_index',
  'get_isp_status',
  'get_most_censored',
  'get_platform_risk',
  'get_probe_network',
  'get_risk_forecast',
  'relay_info',
  'relay_peers',
  'sentinel_accuracy',
  'sentinel_batch_risk',
  'sentinel_calibration_history',
  'sentinel_current_risk',
  'sentinel_global_heatmap',
  'sentinel_manifest',
  'verify_claim',
];

// Every 2.16.0 tool that 3.0.0 does not have (from the 2.16.0 tarball).
const GONE_SINCE_2_16_0 = ['agent_capability_list', 'agent_capability_search', 'agent_change_username', 'agent_claim_username', 'agent_deactivate', 'agent_escrow_open', 'agent_escrow_refund', 'agent_escrow_release', 'agent_escrow_status', 'agent_faucet', 'agent_hire', 'agent_hires_incoming', 'agent_hires_outgoing', 'agent_pay', 'agent_pay_manifest', 'agent_pay_stats', 'agent_payment_history', 'agent_receipt_status', 'agent_release_username', 'agent_trust', 'agent_wallet_balance', 'agent_work_accept', 'agent_work_claim', 'agent_work_dispute', 'sentinel_report_miss', 'voidly_pay_overview'];

const ALLOWED_ENV = new Set([
  'SMITHERY',
  'SMITHERY_SCAN',
  'VOIDLY_MCP_RELAY_HOME',
  'VOIDLY_MCP_RELAY_DID',
  'VOIDLY_MCP_RELAY_API_BASE',
  'VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS',
  'VOIDLY_MCP_RELAY_ALLOW_OPEN_WRITES',
  'VOIDLY_MCP_RELAY_ALLOW_MEMORY_WRITES',
  'VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES',
]);
const FORBIDDEN_ENV = ['SENTINEL_ADMIN_KEY', 'VOIDLY_SENTINEL_KEY', 'VOIDLY_AGENT_SECRET', 'VOIDLY_AGENT_DID', 'SMITHERY_BUILD'];

// Claims that must not ship, in the build or in the README.
const FORBIDDEN_TEXT = [
  /99\.8/,
  /\bUSDC\b/i,
  /\bx402\b/i,
  /Stage 2/i,
  /backed 1:1/i,
  /Base mainnet/i,
  /\bon Base\b/,
  /pay-overview/,
  /voidly_pay_overview(?!` tool and)/,
  /\/v1\/pay\//,
  /Encrypted: Yes/i,
  /E2E encrypted/i,
  /never passes through the model/i,
  /out of the model's reach/i,
  /not available to the model/i,
  /(?:^|[^.\w-])voidly\.ai\/mcp\b/,
  /github\.com\/voidly-ai\/mcp-server/,
];

const README = readFileSync(join(ROOT, 'README.md'), 'utf8');
const PKG = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
const SERVER_JSON = JSON.parse(readFileSync(join(ROOT, 'server.json'), 'utf8'));
const DIST_DIR = join(ROOT, 'dist');
const DIST = readdirSync(DIST_DIR).filter((f) => f.endsWith('.js')).map((f) => ({ f, text: readFileSync(join(DIST_DIR, f), 'utf8') }));

async function withServer(fn) {
  const home = tempHome();
  const srv = await startServer({ HOME: home.dir, VOIDLY_MCP_RELAY_HOME: home.relayHome });
  try {
    await fn(srv);
  } finally {
    await srv.close();
    home.cleanup();
  }
}

test('tool list matches the snapshot (count and names)', async () => {
  assert.equal(TOOLS.length, 89);
  assert.deepEqual([...TOOLS].sort(), TOOLS, 'snapshot is sorted');
  await withServer(async (srv) => {
    const { tools } = await srv.client.listTools();
    assert.deepEqual(tools.map((t) => t.name).sort(), TOOLS);
    for (const name of GONE_SINCE_2_16_0) assert.ok(!TOOLS.includes(name), `${name} is back`);
    const text = JSON.stringify(tools);
    for (const re of FORBIDDEN_TEXT) assert.ok(!re.test(text), `tool list carries ${re}`);
  });
});

test('resources: no Pay resource', async () => {
  await withServer(async (srv) => {
    const { resources } = await srv.client.listResources();
    assert.deepEqual(resources.map((r) => r.uri).sort(), ['voidly://censorship-index', 'voidly://methodology']);
    await assert.rejects(srv.client.readResource({ uri: 'voidly://pay-overview' }));
  });
});

test('server reports the package version, and every version string agrees', async () => {
  assert.equal(PKG.version, '3.0.2');
  assert.equal(SERVER_JSON.version, PKG.version);
  for (const p of SERVER_JSON.packages) assert.equal(p.version, PKG.version);
  await withServer(async (srv) => {
    assert.equal(srv.client.getServerVersion()?.version, PKG.version);
  });
});

test('build reads no secret from the environment', () => {
  const names = new Set();
  for (const { f, text } of DIST) {
    assert.ok(!/process\.env\s*\[/.test(text), `${f} indexes process.env dynamically`);
    for (const m of text.matchAll(/process\.env\.([A-Za-z_][A-Za-z0-9_]*)/g)) names.add(m[1]);
    for (const m of text.matchAll(/\b((?:VOIDLY|SENTINEL|SMITHERY)[A-Z0-9_]*)\b/g)) names.add(m[1]);
    for (const bad of FORBIDDEN_ENV) assert.ok(!text.includes(bad), `${f} mentions ${bad}`);
  }
  for (const n of names) assert.ok(ALLOWED_ENV.has(n), `unexpected environment name in the build: ${n}`);
  assert.ok(names.has('VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS'), 'the scan sees env names read through a parameter');
});

test('build carries none of the retired claims', () => {
  for (const { f, text } of DIST) {
    for (const re of FORBIDDEN_TEXT) assert.ok(!re.test(text), `${f} carries ${re}`);
  }
});

test('package and registry descriptions carry none of the retired claims', () => {
  for (const [where, text] of [['package.json', JSON.stringify(PKG)], ['server.json', JSON.stringify(SERVER_JSON)]]) {
    for (const re of FORBIDDEN_TEXT) assert.ok(!re.test(text), `${where} carries ${re}`);
  }
  assert.equal(PKG.repository, undefined, 'no link to a repository readers cannot open');
  assert.equal(SERVER_JSON.repository, undefined, 'no link to a repository readers cannot open');
});

test('README: tool count and tables match the server', () => {
  const counts = [...README.matchAll(/\*\*(\d+) tools\*\*|## All (\d+) Tools/g)].map((m) => Number(m[1] ?? m[2]));
  assert.ok(counts.length >= 2);
  for (const n of counts) assert.equal(n, TOOLS.length, 'README tool count');
  const listed = [...README.matchAll(/^\| `([a-z_]+)` \|/gm)].map((m) => m[1]).sort();
  assert.deepEqual(listed, TOOLS);
  let sum = 0;
  for (const m of README.matchAll(/^### .+ \((\d+)\)$/gm)) sum += Number(m[1]);
  assert.equal(sum, TOOLS.length, 'section counts add up');
});

test('README: no retired claims, no hardcoded model accuracy', () => {
  for (const re of FORBIDDEN_TEXT) {
    if (re.source.startsWith('voidly_pay_overview')) continue;
    if (re.source === 'pay-overview') continue;
    assert.ok(!re.test(README), `README carries ${re}`);
  }
  // voidly_pay_overview and the Pay resource appear only in the upgrade notes as removed.
  for (const line of README.split('\n').filter((l) => /voidly_pay_overview|pay-overview/.test(l))) {
    assert.match(line, /Removed/, `Pay tool mentioned outside the removal note: ${line}`);
  }
  assert.ok(!/\b\d{1,2}(\.\d+)?% (F1|AUC|accuracy|precision)/i.test(README), 'README states a model metric');
  assert.ok(!/\b(F1|AUC)\s*(of\s*)?0?\.\d+/i.test(README), 'README states a model metric');
  assert.match(README, /https:\/\/api\.voidly\.ai\/v1\/classifier\/info/);
});

test('README: upgrade notes say what breaks and how to migrate', () => {
  const start = README.indexOf('## Upgrading from 2.x');
  assert.ok(start > 0, 'Upgrading from 2.x section');
  const section = README.slice(start, README.indexOf('\n## ', start + 5));
  assert.match(section, /`api_key` tool arguments are refused/);
  assert.match(section, /`agent_deactivate` is removed/);
  assert.match(section, /agent_register/);
  assert.match(section, /relay import-legacy/);
  assert.match(section, /voidly-mcp relay import-legacy/);
  assert.match(section, /relay rotate/);
  assert.match(section, /does not undo/);
  for (const name of GONE_SINCE_2_16_0.filter((n) => n !== 'voidly_pay_overview')) {
    assert.ok(section.includes('`' + name + '`'), `upgrade notes name ${name}`);
  }
  assert.match(README, /\(#upgrading-from-2x\)/, 'linked from the top');
});

test('README: limits it cannot enforce are stated', () => {
  // The 0600 file only helps when the model has no shell or file tool as the same user.
  assert.match(README, /keeps the key out of the model's context only when the model has no shell or file tools running as the same OS user/);
  assert.match(README, /does not control that runtime/);
  // 3.0.1: relay writes are off by default, and each opt-in is documented.
  assert.match(README, /`VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS` \| Unset means no recipient/);
  assert.match(README, /`VOIDLY_MCP_RELAY_ALLOW_OPEN_WRITES` \| Unset means refused\./);
  assert.match(README, /`VOIDLY_MCP_RELAY_ALLOW_MEMORY_WRITES` \| Unset means refused\./);
  assert.match(README, /`VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES` \| Unset means refused\./);
  // Every gated tool is marked in the tool table, and agent_update_task no longer reads as ungated.
  for (const name of ['agent_update_task', 'agent_join_channel', 'agent_respond_invite', 'agent_mark_read', 'agent_mark_read_batch', 'agent_delete_message', 'agent_ping', 'agent_delete_capability']) {
    const row = README.split('\n').find((l) => l.startsWith('| `' + name + '` |'));
    assert.ok(row && /off by default/.test(row), `tool table row for ${name} says off by default`);
  }
  assert.ok(!/\| `agent_update_task` \| Update task status \|/.test(README), 'stale agent_update_task row');
  // Upgrade notes carry a client-config snippet with the env block.
  // npm 3.0.1 shipped 3.0.0's relay tools, so one section covers both.
  const u = README.indexOf('## Upgrading from 3.0.1 or 3.0.0');
  assert.ok(u >= 0, 'upgrade section for 3.0.1 and 3.0.0 is present');
  const up = README.slice(u, README.indexOf('\n---', u));
  assert.match(up, /"env": \{/);
  assert.match(up, /VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES/);
  assert.match(up, /Nothing was sent/);
  assert.ok(!/Unset means no limit/.test(README), 'README still says unset means no limit');
  // Writes an injected message can still drive.
  const i = README.indexOf('### Content from other agents');
  const part = README.slice(i, README.indexOf('\n---', i));
  for (const re of [/refused by default/, /post, or create a channel/, /update a task that agent is on, whether with output, a status change/, /relay-side memory/, /register a webhook/, /What remains/, /does not repeat the content/, /pattern of visible state changes/, /VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES=1/, /Reading the inbox marks messages delivered and read/, /updates `last_seen`/]) {
    assert.match(part, re);
  }
  assert.match(part, /label, not enforcement/);
  // What the relay can read.
  assert.match(README, /Not end-to-end encrypted/);
});
