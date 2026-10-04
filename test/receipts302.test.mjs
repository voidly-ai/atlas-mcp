// 3.0.2: (1) agent_receive_messages is not model-steerable by default: it
// always reads the oldest unread page in relay order, so the model cannot pick
// which messages the relay marks delivered/read (senders see those marks).
// (2) Task updates in DID-list mode are checked against the other agent on the
// task: the assignee when this identity created it, the creator otherwise.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startMockRelay, startServer, tempHome, resultText, fakeDid } from './helpers.mjs';

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

const receives = (ctx) => ctx.relay.state.requests.filter((q) => q.method === 'GET' && q.path === '/v1/agent/receive');
const patches = (ctx) => ctx.relay.state.requests.filter((q) => q.method === 'PATCH');

test('receive, default: a fixed oldest-unread page; since and limit are refused before any request', async () => {
  const ctx = await registered();
  try {
    const r = await ctx.srv.call('agent_receive_messages', {});
    assert.ok(!r.isError, resultText(r));
    assert.deepEqual(receives(ctx).map((q) => q.query), [{ unread: 'true', limit: '50' }]);

    for (const args of [
      { since: '2026-09-24T10:00:00Z' },
      { limit: 1 },
      { since: '2026-09-24T10:00:00Z', limit: 1 },
    ]) {
      const before = ctx.relay.state.requests.length;
      const x = await ctx.srv.call('agent_receive_messages', args);
      const text = resultText(x);
      assert.ok(x.isError, `${JSON.stringify(args)} was not refused: ${text}`);
      assert.match(text, /receive_filter_not_allowed/);
      assert.match(text, /VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES=1/);
      assert.match(text, /No message was read or marked/);
      assert.ok(!text.includes('2026-09-24T10:00:00Z'), 'refusal does not echo since');
      assert.equal(ctx.relay.state.requests.length, before, 'no request for a refused receive');
    }

    // A has_more page points at the next plain call, not at since.
    ctx.relay.state.override = (req) =>
      req.method === 'GET' && req.path === '/v1/agent/receive'
        ? { status: 200, body: { messages: [{ id: 'm1', from: ctx.relay.state.other, content: 'hi', timestamp: '2026-09-24 10:00:00' }], count: 1, has_more: true } }
        : undefined;
    const more = resultText(await ctx.srv.call('agent_receive_messages', {}));
    assert.match(more, /call again with no arguments/);
    assert.doesNotMatch(more, /since set to/);
  } finally {
    await ctx.done();
  }
});

test('receive, state-changes opt-in: since and limit are passed as given', async () => {
  const ctx = await registered({ VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES: '1' });
  try {
    const r = await ctx.srv.call('agent_receive_messages', { since: '2026-09-24T10:00:00Z', limit: 1 });
    assert.ok(!r.isError, resultText(r));
    const r2 = await ctx.srv.call('agent_receive_messages', {});
    assert.ok(!r2.isError, resultText(r2));
    assert.deepEqual(receives(ctx).map((q) => q.query), [
      { since: '2026-09-24T10:00:00Z', limit: '1' },
      { unread: 'true', limit: '50' },
    ]);
  } finally {
    await ctx.done();
  }
});

test('receive: the description says the model cannot choose which messages are marked', async () => {
  const ctx = await registered();
  try {
    const { tools } = await ctx.srv.client.listTools();
    const d = tools.find((t) => t.name === 'agent_receive_messages').description;
    assert.match(d, /oldest unread/);
    assert.match(d, /VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES=1/);
  } finally {
    await ctx.done();
  }
});

function taskOverride(ctx, tasks) {
  ctx.relay.state.override = (req) => {
    const m = req.method === 'GET' && req.path.match(/^\/v1\/agent\/tasks\/([^/]+)$/);
    if (m && tasks[m[1]]) return { status: 200, body: { id: m[1], status: 'pending', ...tasks[m[1]] } };
    return undefined;
  };
}

test('DID list: cancel and rating on a task this identity created are checked against the assignee', async () => {
  const other = fakeDid();
  const stranger = fakeDid();
  const ctx = await registered({ VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS: other });
  try {
    const self = ctx.relay.state.did;
    taskOverride(ctx, {
      mine: { from: self, to: other },
      mineStranger: { from: self, to: stranger },
      theirs: { from: other, to: self },
      noAssignee: { from: self },
      notMine: { from: other, to: stranger },
    });

    // Created by this identity, assignee listed: cancel and rating go.
    for (const args of [{ task_id: 'mine', status: 'cancelled' }, { task_id: 'mine', rating: 5 }]) {
      const r = await ctx.srv.call('agent_update_task', args);
      assert.ok(!r.isError, `${JSON.stringify(args)}: ${resultText(r)}`);
    }
    assert.equal(patches(ctx).length, 2);

    // Created by this identity, assignee not listed: refused after one read.
    for (const args of [{ task_id: 'mineStranger', status: 'cancelled' }, { task_id: 'mineStranger', rating: 1 }]) {
      const before = ctx.relay.state.requests.length;
      const r = await ctx.srv.call('agent_update_task', args);
      assert.ok(r.isError, resultText(r));
      assert.match(resultText(r), /recipient_not_allowed/);
      assert.match(resultText(r), /Nothing was sent/);
      assert.deepEqual(ctx.relay.state.requests.slice(before).map((q) => `${q.method} ${q.path}`), ['GET /v1/agent/tasks/mineStranger']);
    }

    // Created by the listed agent and assigned here: assignee statuses go.
    const r = await ctx.srv.call('agent_update_task', { task_id: 'theirs', status: 'accepted' });
    assert.ok(!r.isError, resultText(r));
    assert.equal(patches(ctx).length, 3);

    // Counterparty cannot be read, or this identity is not on the task: fail closed.
    for (const id of ['noAssignee', 'notMine']) {
      const x = await ctx.srv.call('agent_update_task', { task_id: id, status: 'cancelled' });
      assert.ok(x.isError, resultText(x));
      assert.match(resultText(x), /recipient_unknown/);
      assert.match(resultText(x), /Nothing was sent/);
    }
    assert.equal(patches(ctx).length, 3, 'no refused update was sent');
  } finally {
    await ctx.done();
  }
});

test('DID list: listing only this identity does not open cancel or rating to any assignee', async () => {
  const relay = await startMockRelay();
  const home = tempHome();
  const self = relay.state.did;
  const srv = await startServer({
    HOME: home.dir,
    VOIDLY_MCP_RELAY_HOME: home.relayHome,
    VOIDLY_MCP_RELAY_API_BASE: relay.base,
    VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS: self,
  });
  try {
    assert.ok(!(await srv.call('agent_register', {})).isError);
    const stranger = fakeDid();
    relay.state.override = (req) =>
      req.method === 'GET' && req.path === '/v1/agent/tasks/t7' ? { status: 200, body: { id: 't7', from: self, to: stranger, status: 'pending' } } : undefined;
    for (const args of [{ task_id: 't7', status: 'cancelled' }, { task_id: 't7', rating: 1 }]) {
      const r = await srv.call('agent_update_task', args);
      assert.ok(r.isError, resultText(r));
      assert.match(resultText(r), /recipient_not_allowed/);
    }
    assert.equal(relay.state.requests.filter((q) => q.method === 'PATCH').length, 0);
  } finally {
    await srv.close();
    await relay.close();
    home.cleanup();
  }
});

test('README states the 3.0.2 receive and task-counterparty rules', async () => {
  const { readFileSync } = await import('node:fs');
  const README = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  assert.match(README, /the assignee when this identity created the task, the creator otherwise/);
  assert.match(README, /The model cannot choose which messages are marked\./);
  assert.match(README, /so it can signal about one bit per message/);
  assert.doesNotMatch(README, /can still signal a little/);
  assert.match(README, /## Upgrading from 3\.0\.1/);
  assert.match(README, /and the `since` and `limit` arguments of `agent_receive_messages`/);
});
