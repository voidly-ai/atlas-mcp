// 3.0.1 write policy: every relay write that another party can read is refused
// by default, before any request, with a refusal that does not repeat the
// content; allowlisted behaviour is unchanged; no key or secret is returned.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startMockRelay, startServer, tempHome, resultText, assertNoLeak, fakeDid, fakeKey } from './helpers.mjs';

const CANARY = 'CANARY-writepolicy-7f3a9c1e';

async function registered(extraEnv = {}) {
  const relay = await startMockRelay();
  const home = tempHome();
  const env = { HOME: home.dir, VOIDLY_MCP_RELAY_HOME: home.relayHome, VOIDLY_MCP_RELAY_API_BASE: relay.base, ...extraEnv };
  const srv = await startServer(env);
  const r = await srv.call('agent_register', {});
  assert.ok(!r.isError, resultText(r));
  return {
    relay,
    srv,
    async done() {
      await srv.close();
      await relay.close();
      home.cleanup();
    },
  };
}

/** Every write that puts model-chosen content where another party can read it. */
function writes(other) {
  return [
    ['agent_send_message', { to_did: other, message: `exfil ${CANARY}` }, /recipient_allowlist_unset/],
    ['agent_create_task', { to: other, input: `exfil ${CANARY}` }, /recipient_allowlist_unset/],
    ['agent_invite_to_channel', { channel_id: 'c1', did: other, message: `exfil ${CANARY}` }, /recipient_allowlist_unset/],
    ['agent_update_task', { task_id: 't1', status: 'completed', output: `exfil ${CANARY}` }, /recipient_allowlist_unset/],
    ['agent_broadcast_task', { capability: 'research', input: `exfil ${CANARY}` }, /recipient_allowlist_unset/],
    ['agent_register_webhook', { webhook_url: `https://collector.example/${CANARY}` }, /webhook_not_allowed/],
    ['agent_post_to_channel', { channel_id: 'c1', message: `exfil ${CANARY}` }, /open_write_not_allowed/],
    ['agent_create_channel', { name: 'chan', description: `exfil ${CANARY}` }, /open_write_not_allowed/],
    ['agent_update_profile', { name: `exfil ${CANARY}` }, /open_write_not_allowed/],
    ['agent_register_capability', { name: 'cap', description: `exfil ${CANARY}` }, /open_write_not_allowed/],
    ['agent_create_attestation', { claim_type: 'domain-blocked', claim_data: { note: CANARY } }, /open_write_not_allowed/],
    ['agent_corroborate', { attestation_id: 'a1', vote: 'corroborate', signature: 'c2ln', comment: CANARY }, /open_write_not_allowed/],
    ['agent_memory_set', { namespace: 'x', key: 'k', value: CANARY }, /memory_write_not_allowed/],
  ];
}

function assertRefusedClean(r, word, ctx, where) {
  const text = resultText(r);
  assert.ok(r.isError, `${where} was not refused: ${text}`);
  assert.match(text, word, where);
  assert.match(text, /Nothing was sent/, `${where} says nothing was sent`);
  assert.ok(!text.includes(CANARY), `${where} echoes the refused content`);
  assertNoLeak(assert, text, [ctx.relay.state.key, ctx.relay.state.webhookSecret], where);
}

function assertNoCanaryReachedRelay(ctx) {
  for (const q of ctx.relay.state.requests) {
    assert.ok(!q.raw.includes(CANARY) && !q.rawUrl.includes(CANARY), `content reached the relay: ${q.method} ${q.path}`);
  }
}

test('default: every relay write is refused, with no request and no echo', async () => {
  const ctx = await registered();
  try {
    const before = ctx.relay.state.requests.length;
    for (const [tool, args, word] of writes(ctx.relay.state.other)) {
      assertRefusedClean(await ctx.srv.call(tool, args), word, ctx, tool);
    }
    assert.equal(ctx.relay.state.requests.length, before, 'no request was made for a refused write');
    assertNoCanaryReachedRelay(ctx);
    assertNoLeak(assert, ctx.srv.logs.text, [ctx.relay.state.key], 'server stderr');
    // Reads still work.
    for (const [tool, args] of [
      ['agent_receive_messages', {}],
      ['agent_get_task', { task_id: 't1' }],
      ['agent_list_invites', {}],
      ['agent_read_channel', { channel_id: 'c1' }],
      ['agent_unread_count', {}],
      ['agent_ping_check', { did: ctx.relay.state.other }],
      ['agent_memory_get', { namespace: 'x', key: 'k' }],
    ]) {
      const r = await ctx.srv.call(tool, args);
      assert.ok(!r.isError, `${tool}: ${resultText(r)}`);
    }
  } finally {
    await ctx.done();
  }
});

test('default: tool descriptions say each write is off by default', async () => {
  const ctx = await registered();
  try {
    const { tools } = await ctx.srv.client.listTools();
    const byName = new Map(tools.map((t) => [t.name, t.description]));
    for (const [tool] of writes(ctx.relay.state.other)) {
      assert.match(byName.get(tool), /Off by default/, `${tool} description`);
    }
  } finally {
    await ctx.done();
  }
});

test('DID list: only listed recipients; broadcast and webhook still refused (unchanged from 3.0.0)', async () => {
  const listed = fakeDid();
  const ctx = await registered({ VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS: `${listed}, not-a-did` });
  try {
    const other = ctx.relay.state.other; // not on the list
    const before = ctx.relay.state.requests.length;
    for (const [tool, args, word] of [
      ['agent_send_message', { to_did: other, message: CANARY }, /recipient_not_allowed/],
      ['agent_create_task', { to: other, input: CANARY }, /recipient_not_allowed/],
      ['agent_invite_to_channel', { channel_id: 'c1', did: other, message: CANARY }, /recipient_not_allowed/],
      ['agent_broadcast_task', { capability: 'c', input: CANARY }, /recipient_not_allowed/],
      ['agent_register_webhook', { webhook_url: `https://collector.example/${CANARY}` }, /webhook_not_allowed/],
    ]) {
      assertRefusedClean(await ctx.srv.call(tool, args), word, ctx, tool);
    }
    assert.equal(ctx.relay.state.requests.length, before, 'no request for a refused write');

    // Task output goes to the task's creator (the mock says `other`): read, then refused.
    const out = await ctx.srv.call('agent_update_task', { task_id: 't1', output: CANARY });
    assertRefusedClean(out, /recipient_not_allowed/, ctx, 'agent_update_task output to unlisted creator');
    assert.ok(!ctx.relay.state.requests.some((q) => q.method === 'PATCH'), 'no task update was sent');

    for (const [tool, args, path] of [
      ['agent_send_message', { to_did: listed, message: 'hello' }, '/v1/agent/send'],
      ['agent_create_task', { to: listed, input: 'do it' }, '/v1/agent/tasks'],
      ['agent_invite_to_channel', { channel_id: 'c1', did: listed }, '/v1/agent/channels/c1/invite'],
    ]) {
      const r = await ctx.srv.call(tool, args);
      assert.ok(!r.isError, `${tool}: ${resultText(r)}`);
      assert.ok(ctx.relay.state.requests.some((q) => q.path === path && q.method === 'POST'), `${tool} reached the relay`);
      assertNoLeak(assert, resultText(r), [ctx.relay.state.key], tool);
    }
    assertNoCanaryReachedRelay(ctx);
  } finally {
    await ctx.done();
  }
});

test('DID list: task output is allowed when the task creator is listed', async () => {
  // The mock's task creator is `state.other`; list it.
  const relay = await startMockRelay();
  const home = tempHome();
  const srv = await startServer({
    HOME: home.dir,
    VOIDLY_MCP_RELAY_HOME: home.relayHome,
    VOIDLY_MCP_RELAY_API_BASE: relay.base,
    VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS: relay.state.other,
  });
  try {
    assert.ok(!(await srv.call('agent_register', {})).isError);
    const r = await srv.call('agent_update_task', { task_id: 't1', status: 'completed', output: 'the result' });
    assert.ok(!r.isError, resultText(r));
    const patch = relay.state.requests.find((q) => q.method === 'PATCH');
    assert.equal(patch.body.output, 'the result');
    // A creator the relay does not name is refused.
    relay.state.override = (req) => (req.method === 'GET' && req.path === '/v1/agent/tasks/t2' ? { status: 200, body: { id: 't2' } } : undefined);
    const unknown = await srv.call('agent_update_task', { task_id: 't2', output: 'x' });
    assert.ok(unknown.isError);
    assert.match(resultText(unknown), /recipient_unknown/);
  } finally {
    await srv.close();
    await relay.close();
    home.cleanup();
  }
});

test('explicit *: any recipient, broadcast and webhook allowed; secret still not returned', async () => {
  const ctx = await registered({ VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS: '*' });
  try {
    const other = ctx.relay.state.other;
    for (const [tool, args] of [
      ['agent_send_message', { to_did: other, message: 'hi' }],
      ['agent_create_task', { to: fakeDid(), input: 'do it' }],
      ['agent_broadcast_task', { capability: 'c', input: 'x' }],
      ['agent_register_webhook', { webhook_url: 'https://example.com/hook' }],
      ['agent_update_task', { task_id: 't1', output: 'done' }],
    ]) {
      const r = await ctx.srv.call(tool, args);
      assert.ok(!r.isError, `${tool}: ${resultText(r)}`);
      assertNoLeak(assert, resultText(r), [ctx.relay.state.key, ctx.relay.state.webhookSecret], tool);
    }
    // `*` does not open channel, public or memory writes.
    assertRefusedClean(await ctx.srv.call('agent_post_to_channel', { channel_id: 'c1', message: CANARY }), /open_write_not_allowed/, ctx, 'post under *');
    assertRefusedClean(await ctx.srv.call('agent_memory_set', { namespace: 'x', key: 'k', value: CANARY }), /memory_write_not_allowed/, ctx, 'memory under *');
  } finally {
    await ctx.done();
  }
});

test('open writes opt-in allows channel and public writes only', async () => {
  const ctx = await registered({ VOIDLY_MCP_RELAY_ALLOW_OPEN_WRITES: '1' });
  try {
    for (const [tool, args] of [
      ['agent_post_to_channel', { channel_id: 'c1', message: 'post' }],
      ['agent_create_channel', { name: 'chan', description: 'd' }],
      ['agent_update_profile', { name: 'me2' }],
      ['agent_register_capability', { name: 'cap' }],
      ['agent_create_attestation', { claim_type: 'domain-blocked', claim_data: { domain: 'x.com' } }],
      ['agent_corroborate', { attestation_id: 'a1', vote: 'corroborate', signature: 'c2ln' }],
    ]) {
      const r = await ctx.srv.call(tool, args);
      assert.ok(!r.isError, `${tool}: ${resultText(r)}`);
    }
    assertRefusedClean(await ctx.srv.call('agent_send_message', { to_did: ctx.relay.state.other, message: CANARY }), /recipient_allowlist_unset/, ctx, 'send with only open writes');
  } finally {
    await ctx.done();
  }
});

test('memory: opt-in allows plain values; credential-shaped values are always refused', async () => {
  const ctx = await registered({ VOIDLY_MCP_RELAY_ALLOW_MEMORY_WRITES: '1' });
  try {
    const ok = await ctx.srv.call('agent_memory_set', { namespace: 'notes', key: 'k', value: 'plain note' });
    assert.ok(!ok.isError, resultText(ok));
    const before = ctx.relay.state.requests.length;
    const key = ctx.relay.state.key;
    const otherKey = fakeKey();
    const shaped = [
      key, // the key this process holds
      key.toUpperCase(),
      Array.from(key).join('​'),
      `prefix ${otherKey} suffix`, // any 64-hex key shape
      Array.from(otherKey).join('‍'),
      '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----',
      'sk-' + 'A'.repeat(40),
      'ghp_' + 'b'.repeat(36),
      'AKIA' + 'ABCDEFGHIJKLMNOP',
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl',
      'vmo_' + 'Z'.repeat(24),
      { nested: { deeper: [otherKey] } },
    ];
    for (const value of shaped) {
      const r = await ctx.srv.call('agent_memory_set', { namespace: 'x', key: 'k', value });
      const text = resultText(r);
      assert.ok(r.isError, `accepted a credential-shaped value: ${JSON.stringify(value).slice(0, 40)}`);
      assert.match(text, /secret_in_content|secret_shaped_content_refused/);
      assertNoLeak(assert, text, [key, otherKey], 'memory refusal');
    }
    // A secret in the key name is refused too.
    const inName = await ctx.srv.call('agent_memory_set', { namespace: 'x', key: otherKey, value: 'v' });
    assert.ok(inName.isError);
    assert.equal(ctx.relay.state.requests.length, before, 'no request for a refused memory write');
  } finally {
    await ctx.done();
  }
});

test('held key or webhook secret in content is refused on every write, even when allowed', async () => {
  const ctx = await registered({
    VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS: '*',
    VOIDLY_MCP_RELAY_ALLOW_OPEN_WRITES: '1',
  });
  try {
    await ctx.srv.call('agent_register_webhook', { webhook_url: 'https://example.com/hook' });
    const key = ctx.relay.state.key;
    const secret = ctx.relay.state.webhookSecret;
    const before = ctx.relay.state.requests.length;
    const other = ctx.relay.state.other;
    for (const leak of [key, key.toUpperCase(), Array.from(key).join('​'), secret]) {
      for (const [tool, args] of [
        ['agent_send_message', { to_did: other, message: `k=${leak}` }],
        ['agent_create_task', { to: other, input: `k=${leak}` }],
        ['agent_broadcast_task', { capability: 'c', input: `k=${leak}` }],
        ['agent_post_to_channel', { channel_id: 'c1', message: `k=${leak}` }],
        ['agent_create_attestation', { claim_type: 'domain-blocked', claim_data: { k: leak } }],
        ['agent_update_task', { task_id: 't1', output: `k=${leak}` }],
      ]) {
        const r = await ctx.srv.call(tool, args);
        assert.ok(r.isError, `${tool} sent a held secret`);
        assert.match(resultText(r), /secret_in_content/, tool);
        assertNoLeak(assert, resultText(r), [key, secret], tool);
      }
    }
    assert.equal(ctx.relay.state.requests.length, before, 'no request carried a held secret');
    for (const q of ctx.relay.state.requests) assertNoLeak(assert, q.raw, [key, secret], `request body ${q.path}`);
  } finally {
    await ctx.done();
  }
});

// ── 3.0.1 B1: state changes another party can see, chosen by the model ─────

/** Content-free writes whose effect another party sees (a covert channel). */
function stateChanges(other) {
  return [
    ['agent_update_task', { task_id: 't1', status: 'accepted' }, /recipient_allowlist_unset/, 'PATCH', /^\/v1\/agent\/tasks\/t1$/],
    ['agent_update_task', { task_id: 't1', status: 'in_progress' }, /recipient_allowlist_unset/, 'PATCH', /^\/v1\/agent\/tasks\/t1$/],
    ['agent_update_task', { task_id: 't1', status: 'completed' }, /recipient_allowlist_unset/, 'PATCH', /^\/v1\/agent\/tasks\/t1$/],
    ['agent_update_task', { task_id: 't1', status: 'failed' }, /recipient_allowlist_unset/, 'PATCH', /^\/v1\/agent\/tasks\/t1$/],
    ['agent_update_task', { task_id: 't1', status: 'cancelled' }, /recipient_allowlist_unset/, 'PATCH', /^\/v1\/agent\/tasks\/t1$/],
    ['agent_update_task', { task_id: 't1', rating: 5 }, /recipient_allowlist_unset/, 'PATCH', /^\/v1\/agent\/tasks\/t1$/],
    ['agent_join_channel', { channel_id: 'c1' }, /state_change_not_allowed/, 'POST', /^\/v1\/agent\/channels\/c1\/join$/],
    ['agent_respond_invite', { invite_id: 'i1', action: 'accept' }, /state_change_not_allowed/, 'POST', /^\/v1\/agent\/invites\/i1\/respond$/],
    ['agent_respond_invite', { invite_id: 'i1', action: 'decline' }, /state_change_not_allowed/, 'POST', /^\/v1\/agent\/invites\/i1\/respond$/],
    ['agent_mark_read', { message_id: 'm1' }, /state_change_not_allowed/, 'POST', /^\/v1\/agent\/messages\/m1\/read$/],
    ['agent_mark_read_batch', { message_ids: ['m1', 'm2'] }, /state_change_not_allowed/, 'POST', /^\/v1\/agent\/messages\/read-batch$/],
    ['agent_delete_message', { message_id: 'm1' }, /state_change_not_allowed/, 'DELETE', /^\/v1\/agent\/messages\/m1$/],
    ['agent_ping', {}, /state_change_not_allowed/, 'POST', /^\/v1\/agent\/ping$/],
    ['agent_delete_capability', { capability_id: 'cap1' }, /state_change_not_allowed/, 'DELETE', /^\/v1\/agent\/capabilities\/cap1$/],
  ];
}

function reached(ctx, method, path, from = 0) {
  return ctx.relay.state.requests.slice(from).some((q) => q.method === method && path.test(q.path));
}

test('default: every visible state change is refused before any request', async () => {
  const ctx = await registered();
  try {
    const before = ctx.relay.state.requests.length;
    for (const [tool, args, word] of stateChanges(ctx.relay.state.other)) {
      assertRefusedClean(await ctx.srv.call(tool, args), word, ctx, `${tool} ${JSON.stringify(args)}`);
    }
    assert.equal(ctx.relay.state.requests.length, before, 'no request was made for a refused state change');
  } finally {
    await ctx.done();
  }
});

test('default: descriptions say each state change is off by default', async () => {
  const ctx = await registered();
  try {
    const { tools } = await ctx.srv.client.listTools();
    const byName = new Map(tools.map((t) => [t.name, t.description]));
    for (const [tool] of stateChanges(ctx.relay.state.other)) {
      assert.match(byName.get(tool), /Off by default/, `${tool} description`);
    }
    assert.match(byName.get('agent_receive_messages'), /marks the returned messages as read/);
  } finally {
    await ctx.done();
  }
});

test('open writes and memory opt-ins do not open state changes', async () => {
  const ctx = await registered({ VOIDLY_MCP_RELAY_ALLOW_OPEN_WRITES: '1', VOIDLY_MCP_RELAY_ALLOW_MEMORY_WRITES: '1' });
  try {
    const before = ctx.relay.state.requests.length;
    for (const [tool, args, word] of stateChanges(ctx.relay.state.other)) {
      assertRefusedClean(await ctx.srv.call(tool, args), word, ctx, tool);
    }
    assert.equal(ctx.relay.state.requests.length, before);
  } finally {
    await ctx.done();
  }
});

test('state-changes opt-in allows join, invites, read marks, deletes and ping, but not task updates', async () => {
  const ctx = await registered({ VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES: '1' });
  try {
    for (const [tool, args, word, method, path] of stateChanges(ctx.relay.state.other)) {
      const start = ctx.relay.state.requests.length;
      const r = await ctx.srv.call(tool, args);
      if (tool === 'agent_update_task') {
        assertRefusedClean(r, word, ctx, `${tool} under state opt-in`);
        assert.equal(ctx.relay.state.requests.length, start, 'task update made no request');
      } else {
        assert.ok(!r.isError, `${tool}: ${resultText(r)}`);
        assert.ok(reached(ctx, method, path, start), `${tool} reached the relay`);
        assertNoLeak(assert, resultText(r), [ctx.relay.state.key], tool);
      }
    }
    // Other writes stay off.
    assertRefusedClean(await ctx.srv.call('agent_post_to_channel', { channel_id: 'c1', message: CANARY }), /open_write_not_allowed/, ctx, 'post under state opt-in');
    assertRefusedClean(await ctx.srv.call('agent_send_message', { to_did: ctx.relay.state.other, message: CANARY }), /recipient_allowlist_unset/, ctx, 'send under state opt-in');
  } finally {
    await ctx.done();
  }
});

test('opt-in value must be exactly 1', async () => {
  for (const v of ['', '0', 'true', 'yes', '11']) {
    const ctx = await registered({ VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES: v });
    try {
      assertRefusedClean(await ctx.srv.call('agent_join_channel', { channel_id: 'c1' }), /state_change_not_allowed/, ctx, `join with ${JSON.stringify(v)}`);
    } finally {
      await ctx.done();
    }
  }
});

test('DID list: task updates on an assigned task go only when its creator is listed', async () => {
  // Mock task t1 is created by state.other; list state.other.
  const relay = await startMockRelay();
  const home = tempHome();
  const srv = await startServer({
    HOME: home.dir,
    VOIDLY_MCP_RELAY_HOME: home.relayHome,
    VOIDLY_MCP_RELAY_API_BASE: relay.base,
    VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS: relay.state.other,
  });
  try {
    assert.ok(!(await srv.call('agent_register', {})).isError);
    for (const status of ['accepted', 'in_progress', 'completed', 'failed']) {
      const r = await srv.call('agent_update_task', { task_id: 't1', status });
      assert.ok(!r.isError, `${status}: ${resultText(r)}`);
    }
    const patches = relay.state.requests.filter((q) => q.method === 'PATCH');
    assert.deepEqual(patches.map((q) => q.body.status), ['accepted', 'in_progress', 'completed', 'failed']);

    // A task assigned here whose creator is NOT listed is refused, whether the
    // update is a status change or a rating; the only request made is the task
    // read. (Tasks this identity created: see receipts302.test.mjs.)
    const stranger = fakeDid();
    relay.state.override = (req) =>
      req.method === 'GET' && req.path === '/v1/agent/tasks/t9' ? { status: 200, body: { id: 't9', from: stranger, to: relay.state.did } } : undefined;
    const beforePatch = relay.state.requests.filter((q) => q.method === 'PATCH').length;
    for (const args of [{ task_id: 't9', rating: 1 }, { task_id: 't9', status: 'cancelled' }]) {
      const r = await srv.call('agent_update_task', args);
      assert.ok(r.isError, resultText(r));
      assert.match(resultText(r), /recipient_not_allowed/);
      assert.match(resultText(r), /Nothing was sent/);
    }
    // A task whose agents the relay does not name is refused as recipient_unknown.
    relay.state.override = (req) =>
      req.method === 'GET' && req.path === '/v1/agent/tasks/t8' ? { status: 200, body: { id: 't8' } } : undefined;
    const r8 = await srv.call('agent_update_task', { task_id: 't8', status: 'accepted' });
    assert.match(resultText(r8), /recipient_unknown/);
    assert.equal(relay.state.requests.filter((q) => q.method === 'PATCH').length, beforePatch, 'no refused update was sent');
  } finally {
    await srv.close();
    await relay.close();
    home.cleanup();
  }
});

test('DID list: task status to an unlisted task creator is refused after one read', async () => {
  const ctx = await registered({ VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS: fakeDid() });
  try {
    const start = ctx.relay.state.requests.length;
    const r = await ctx.srv.call('agent_update_task', { task_id: 't1', status: 'completed' });
    assertRefusedClean(r, /recipient_not_allowed/, ctx, 'status to unlisted creator');
    const later = ctx.relay.state.requests.slice(start);
    assert.deepEqual(later.map((q) => `${q.method} ${q.path}`), ['GET /v1/agent/tasks/t1'], 'only the task read was made');
  } finally {
    await ctx.done();
  }
});

test('explicit *: task status changes are allowed', async () => {
  const ctx = await registered({ VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS: '*' });
  try {
    const r = await ctx.srv.call('agent_update_task', { task_id: 't1', status: 'accepted' });
    assert.ok(!r.isError, resultText(r));
    assert.ok(reached(ctx, 'PATCH', /^\/v1\/agent\/tasks\/t1$/));
    // `*` does not open the state-change tools.
    assertRefusedClean(await ctx.srv.call('agent_join_channel', { channel_id: 'c1' }), /state_change_not_allowed/, ctx, 'join under *');
  } finally {
    await ctx.done();
  }
});
