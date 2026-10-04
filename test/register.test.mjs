// 3.0.1 agent_register: the display name and capabilities are published in the
// relay directory, so a chosen name or any capability is refused unless the
// human owner set VOIDLY_MCP_RELAY_ALLOW_OPEN_WRITES=1. Without it the tool
// registers with a fixed name and no capabilities. Credential-shaped text is
// refused either way. Refusals make no request and do not repeat the text.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startMockRelay, startServer, tempHome, resultText, assertNoLeak } from './helpers.mjs';

const CANARY = 'CANARY-register-4b1d8e2a';

async function setup(extraEnv = {}) {
  const relay = await startMockRelay();
  const home = tempHome();
  const env = { HOME: home.dir, VOIDLY_MCP_RELAY_HOME: home.relayHome, VOIDLY_MCP_RELAY_API_BASE: relay.base, ...extraEnv };
  const srv = await startServer(env);
  return {
    relay,
    srv,
    registerCalls: () => relay.state.requests.filter((q) => q.path === '/v1/agent/register'),
    async done() {
      await srv.close();
      await relay.close();
      home.cleanup();
    },
  };
}

function assertRefused(r, word, where) {
  const text = resultText(r);
  assert.ok(r.isError, `${where} was not refused: ${text}`);
  assert.match(text, word, where);
  assert.ok(!text.includes(CANARY), `${where} echoes the refused text`);
}

test('default: a chosen name or any capability is refused, with no request and no echo', async () => {
  const ctx = await setup();
  try {
    for (const [args, where] of [
      [{ name: `agent ${CANARY}` }, 'name'],
      [{ name: CANARY.toLowerCase().slice(0, 20) }, 'short fixed-looking name'],
      [{ capabilities: [CANARY] }, 'capabilities'],
      [{ name: 'mcp-agent', capabilities: [`research ${CANARY}`] }, 'default name + capability'],
      [{ name: `mcp-agent ${CANARY}` }, 'default name with suffix'],
    ]) {
      assertRefused(await ctx.srv.call('agent_register', args), /register_text_not_allowed/, where);
    }
    assert.equal(ctx.registerCalls().length, 0, 'no registration request was made');
    for (const q of ctx.relay.state.requests) assert.ok(!q.raw.includes(CANARY) && !q.rawUrl.includes(CANARY), `text reached the relay: ${q.path}`);
    assert.ok(!ctx.srv.logs.text.includes(CANARY), 'server stderr repeats the text');
    // No identity was created: a default registration still works.
    const ok = await ctx.srv.call('agent_register', {});
    assert.ok(!ok.isError, resultText(ok));
  } finally {
    await ctx.done();
  }
});

test('default: no arguments registers the fixed name and no capabilities', async () => {
  const ctx = await setup();
  try {
    const r = await ctx.srv.call('agent_register', {});
    assert.ok(!r.isError, resultText(r));
    const [q] = ctx.registerCalls();
    assert.deepEqual(q.body, { name: 'mcp-agent' });
    assertNoLeak(assert, resultText(r), [ctx.relay.state.key], 'register result');
  } finally {
    await ctx.done();
  }
});

test('default: the fixed name and an empty capability list are accepted as given', async () => {
  const ctx = await setup();
  try {
    const r = await ctx.srv.call('agent_register', { name: 'mcp-agent', capabilities: [] });
    assert.ok(!r.isError, resultText(r));
    assert.deepEqual(ctx.registerCalls()[0].body, { name: 'mcp-agent' });
  } finally {
    await ctx.done();
  }
});

test('open-writes opt-in: the chosen name and capabilities are sent', async () => {
  const ctx = await setup({ VOIDLY_MCP_RELAY_ALLOW_OPEN_WRITES: '1' });
  try {
    const r = await ctx.srv.call('agent_register', { name: 'research bot', capabilities: ['research', 'analysis'] });
    assert.ok(!r.isError, resultText(r));
    assert.deepEqual(ctx.registerCalls()[0].body, { name: 'research bot', capabilities: ['research', 'analysis'] });
  } finally {
    await ctx.done();
  }
});

test('open-writes opt-in: no name still registers the fixed name', async () => {
  const ctx = await setup({ VOIDLY_MCP_RELAY_ALLOW_OPEN_WRITES: '1' });
  try {
    const r = await ctx.srv.call('agent_register', {});
    assert.ok(!r.isError, resultText(r));
    assert.equal(ctx.registerCalls()[0].body.name, 'mcp-agent');
  } finally {
    await ctx.done();
  }
});

test('credential-shaped name or capability is refused with and without the opt-in', async () => {
  for (const extra of [{}, { VOIDLY_MCP_RELAY_ALLOW_OPEN_WRITES: '1' }]) {
    const ctx = await setup(extra);
    try {
      for (const args of [
        { name: 'sk-' + 'a'.repeat(30) },
        { name: 'mcp-agent', capabilities: ['ghp_' + 'b'.repeat(36)] },
        { name: 'c'.repeat(64) },
      ]) {
        const r = await ctx.srv.call('agent_register', args);
        assert.ok(r.isError, `accepted ${JSON.stringify(args).slice(0, 30)} with ${JSON.stringify(extra)}`);
        assert.match(resultText(r), /secret_shaped_content_refused/);
        assert.ok(!resultText(r).includes('a'.repeat(30)) && !resultText(r).includes('b'.repeat(36)), 'refusal echoes the value');
      }
      assert.equal(ctx.registerCalls().length, 0, 'no registration request for credential-shaped text');
    } finally {
      await ctx.done();
    }
  }
});

test('opt-in values other than 1 do not open registration text', async () => {
  for (const v of ['true', 'yes', '0', ' ']) {
    const ctx = await setup({ VOIDLY_MCP_RELAY_ALLOW_OPEN_WRITES: v });
    try {
      assertRefused(await ctx.srv.call('agent_register', { name: `n ${CANARY}` }), /register_text_not_allowed/, `OPEN_WRITES=${JSON.stringify(v)}`);
      assert.equal(ctx.registerCalls().length, 0);
    } finally {
      await ctx.done();
    }
  }
});

test('tool description and schema say name and capabilities are off by default', async () => {
  const ctx = await setup();
  try {
    const { tools } = await ctx.srv.client.listTools();
    const t = tools.find((x) => x.name === 'agent_register');
    assert.match(t.description, /off by default/);
    assert.match(t.description, /VOIDLY_MCP_RELAY_ALLOW_OPEN_WRITES=1/);
    assert.ok(!(t.inputSchema.required ?? []).includes('name'), 'name is not required');
  } finally {
    await ctx.done();
  }
});
