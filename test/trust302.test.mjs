// Looking up a trust score makes the relay recalculate it
// when it has no row or a row older than 10 minutes, and the response publishes
// last_recalculated. A model-chosen DID lookup therefore leaves a public,
// readable-back timestamp. agent_get_trust is off by default and allowed only
// with VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES=1.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startMockRelay, startServer, tempHome, resultText, fakeDid } from './helpers.mjs';

async function server(extraEnv = {}) {
  const relay = await startMockRelay();
  const home = tempHome();
  const srv = await startServer({ HOME: home.dir, VOIDLY_MCP_RELAY_HOME: home.relayHome, VOIDLY_MCP_RELAY_API_BASE: relay.base, ...extraEnv });
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

const trustCalls = (ctx) => ctx.relay.state.requests.filter((q) => /^\/v1\/agent\/trust\/did/.test(q.path));

test('agent_get_trust: refused by default, before any request, without echoing the DID', async () => {
  const ctx = await server();
  try {
    const did = fakeDid();
    const r = await ctx.srv.call('agent_get_trust', { did });
    const text = resultText(r);
    assert.ok(r.isError, text);
    assert.match(text, /state_change_not_allowed/);
    assert.match(text, /VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES=1/);
    assert.ok(!text.includes(did), 'refusal echoes the DID');
    assert.equal(trustCalls(ctx).length, 0);
    assert.equal(ctx.relay.state.requests.length, 0);
    // Other values of the opt-in are not 1.
  } finally {
    await ctx.done();
  }
  for (const v of ['0', 'true', 'yes', ' 2']) {
    const c = await server({ VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES: v });
    try {
      const r = await c.srv.call('agent_get_trust', { did: fakeDid() });
      assert.ok(r.isError, `opt-in ${JSON.stringify(v)} allowed a lookup`);
      assert.equal(trustCalls(c).length, 0);
    } finally {
      await c.done();
    }
  }
});

test('agent_get_trust: allowed with VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES=1', async () => {
  const ctx = await server({ VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES: '1' });
  try {
    const did = fakeDid();
    const r = await ctx.srv.call('agent_get_trust', { did });
    assert.ok(!r.isError, resultText(r));
    assert.equal(trustCalls(ctx).length, 1);
    assert.equal(trustCalls(ctx)[0].headers['x-agent-key'], undefined, 'still unauthenticated');
  } finally {
    await ctx.done();
  }
});

test('agent_get_trust: the description and README say why it is gated', async () => {
  const ctx = await server();
  try {
    const { tools } = await ctx.srv.client.listTools();
    const d = tools.find((t) => t.name === 'agent_get_trust').description;
    assert.match(d, /last_recalculated/);
    assert.match(d, /VOIDLY_MCP_RELAY_ALLOW_STATE_CHANGES=1/);
  } finally {
    await ctx.done();
  }
  const { readFileSync } = await import('node:fs');
  const README = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const row = README.split('\n').find((l) => l.startsWith('| `agent_get_trust` |'));
  assert.ok(row && /off by default/.test(row), row);
  assert.match(README, /`agent_ping`, `agent_delete_capability` and `agent_get_trust`/);
  assert.match(README, /recalculates that agent's score and publishes the time/);
  assert.match(README, /changes the assignee's public trust score and capability rating/);
});
