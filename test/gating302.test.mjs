// 3.0.2 release gate for containment gap 7. The published npm 3.0.1 shipped
// 3.0.0's relay tools, where an unset VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS meant
// "no limit". These pin the default-deny for the three writes named in the gap
// (agent_send_message, agent_broadcast_task, agent_memory_set) and the
// listed-recipients-only rule when the variable is set. Synthetic values only.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { startMockRelay, startServer, tempHome, resultText, fakeDid } from './helpers.mjs';

const CANARY = 'CANARY-gating302-5b1d0e7a';

async function registered(extraEnv) {
  const relay = await startMockRelay();
  const home = tempHome();
  const srv = await startServer({
    HOME: home.dir,
    VOIDLY_MCP_RELAY_HOME: home.relayHome,
    VOIDLY_MCP_RELAY_API_BASE: relay.base,
    ...extraEnv,
  });
  const done = async () => {
    await srv.close();
    await relay.close();
    home.cleanup();
  };
  // The fixed default name is accepted with no opt-in, and is also a valid
  // explicit name for 3.0.0/3.0.1 (where name was required), so these tests
  // can be run against an older dist as a negative control.
  const r = await srv.call('agent_register', { name: 'mcp-agent' });
  if (r.isError) {
    await done();
    assert.fail(`agent_register failed: ${resultText(r)}`);
  }
  return { relay, srv, done };
}

function assertRefused(r, code, where) {
  const text = resultText(r);
  assert.equal(r.isError, true, `${where} was not refused: ${text}`);
  assert.match(text, code, where);
  assert.match(text, /Nothing was sent/, where);
  assert.ok(!text.includes(CANARY), `${where} echoes the refused content`);
}

function assertNothingReachedRelay(ctx, before, where) {
  assert.equal(ctx.relay.state.requests.length, before, `${where}: a request was made`);
  for (const q of ctx.relay.state.requests) {
    assert.ok(!q.raw.includes(CANARY) && !q.rawUrl.includes(CANARY), `${where}: content reached the relay (${q.method} ${q.path})`);
  }
}

const threeWrites = (to) => [
  ['agent_send_message', { to_did: to, message: `exfil ${CANARY}` }],
  ['agent_broadcast_task', { capability: 'research', input: `exfil ${CANARY}` }],
  ['agent_memory_set', { namespace: 'notes', key: 'k', value: `exfil ${CANARY}` }],
];

// Absent, empty and whitespace-only all mean unset.
for (const [label, extraEnv] of [
  ['absent', {}],
  ['empty', { VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS: '' }],
  ['whitespace', { VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS: '  \t ' }],
]) {
  test(`recipients ${label}: send, broadcast and memory_set are refused before any request`, async () => {
    const ctx = await registered(extraEnv);
    try {
      const before = ctx.relay.state.requests.length;
      const expected = {
        agent_send_message: /recipient_allowlist_unset/,
        agent_broadcast_task: /recipient_allowlist_unset/,
        agent_memory_set: /memory_write_not_allowed/,
      };
      for (const [tool, args] of threeWrites(ctx.relay.state.other)) {
        assertRefused(await ctx.srv.call(tool, args), expected[tool], `${tool} (${label})`);
      }
      assertNothingReachedRelay(ctx, before, label);
    } finally {
      await ctx.done();
    }
  });
}

test('recipients set to a DID list: send goes only to listed DIDs; broadcast and memory_set stay refused', async () => {
  const listed = fakeDid();
  const ctx = await registered({ VOIDLY_MCP_RELAY_ALLOWED_RECIPIENTS: listed });
  try {
    const unlisted = ctx.relay.state.other;
    const before = ctx.relay.state.requests.length;
    assertRefused(
      await ctx.srv.call('agent_send_message', { to_did: unlisted, message: `exfil ${CANARY}` }),
      /recipient_not_allowed/,
      'send to unlisted DID',
    );
    assertRefused(
      await ctx.srv.call('agent_broadcast_task', { capability: 'research', input: `exfil ${CANARY}` }),
      /recipient_not_allowed/,
      'broadcast under a DID list',
    );
    // The recipient list does not open relay-side memory; it has its own opt-in.
    assertRefused(
      await ctx.srv.call('agent_memory_set', { namespace: 'notes', key: 'k', value: `exfil ${CANARY}` }),
      /memory_write_not_allowed/,
      'memory_set under a DID list',
    );
    assertNothingReachedRelay(ctx, before, 'refusals under a DID list');

    const ok = await ctx.srv.call('agent_send_message', { to_did: listed, message: 'hello listed agent' });
    assert.ok(!ok.isError, resultText(ok));
    const sends = ctx.relay.state.requests.slice(before).filter((q) => q.method === 'POST' && q.path === '/v1/agent/send');
    assert.equal(sends.length, 1, 'exactly one send reached the relay');
    assert.equal(sends[0].body.to, listed, 'the send went to the listed DID');
  } finally {
    await ctx.done();
  }
});

test('README does not claim the published 3.0.1 gated relay writes', () => {
  const README = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  assert.match(README, /relay writes are not gated in 3\.0\.1/);
  assert.match(README, /\*\*3\.0\.2 turns relay writes off by default\.\*\*/);
  assert.doesNotMatch(README, /3\.0\.1 turns (relay writes )?off/);
  assert.doesNotMatch(README, /Since 3\.0\.1 each of these routes is refused/);
  assert.doesNotMatch(README, /In 3\.0\.1 the check always used the creator/);
});
