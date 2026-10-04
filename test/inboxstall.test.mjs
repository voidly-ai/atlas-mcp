// Messages the relay cannot decrypt must not pin the
// head of the default unread page. The relay's /receive drops them without
// marking them, so they stay unread and are selected first on every call; 50 of
// them (two throwaway identities) would stall the inbox. The tool itself, not
// the model, acknowledges rows the relay confirms it cannot read, and reports
// only how many it skipped. The mock relay implements the worker's unread
// semantics (see helpers.mjs, state.inbox).

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

const hex = (prefix, n) => `${prefix}${String(n).padStart(6, '0')}`;
const at = (sec) => {
  const d = new Date(Date.UTC(2026, 8, 24, 9, 0, 0) + sec * 1000);
  return d.toISOString().slice(0, 19).replace('T', ' ');
};

/** `garbage` undecryptable rows first, then `legit` readable ones. */
function fill(state, garbage, legit, { attacker = fakeDid(), friend = state.other } = {}) {
  const rows = [];
  let t = 0;
  for (let i = 0; i < garbage; i++) {
    rows.push({ id: hex('dead', i), from: attacker, content: `GARBAGE-CONTENT-${i}`, created_at: at(t++), decryptable: false, read_at: null, delivered: 0 });
  }
  for (let i = 0; i < legit; i++) {
    rows.push({ id: hex('a11e', i), from: friend, content: `legit message ${i}`, created_at: at(t++), decryptable: true, read_at: null, delivered: 0 });
  }
  state.inbox = rows;
  return rows;
}

const batches = (ctx) =>
  ctx.relay.state.requests.filter((q) => q.method === 'POST' && q.path === '/v1/agent/messages/read-batch').flatMap((q) => q.body?.message_ids ?? []);

test('stall: 60 unreadable rows at the head do not hide readable messages', async () => {
  const ctx = await registered();
  try {
    const rows = fill(ctx.relay.state, 60, 3);
    const r = await ctx.srv.call('agent_receive_messages', {});
    assert.ok(!r.isError, resultText(r));
    const text = resultText(r);
    for (let i = 0; i < 3; i++) assert.match(text, new RegExp(`legit message ${i}`), `legit ${i} returned in the first call`);
    assert.doesNotMatch(text, /Inbox empty/);
    assert.equal(r.structuredContent.count, 3);
    assert.equal(r.structuredContent.skipped_unreadable, 50);
    assert.match(text, /50 message\(s\) the relay could not decrypt were skipped/);
    // Nothing about the skipped rows reaches the model but their number.
    assert.doesNotMatch(text, /GARBAGE|CIPHERTEXT|dead0000/);

    // Only unreadable rows were acknowledged, only through read-batch, never a readable one.
    const acked = batches(ctx);
    assert.equal(acked.length, 50);
    for (const id of acked) assert.ok(id.startsWith('dead'), `acked ${id}`);
    for (const row of rows.filter((x) => x.decryptable)) assert.ok(!acked.includes(row.id));
  } finally {
    await ctx.done();
  }
});

test('stall: 120 unreadable rows are cleared within bounded calls, and an empty page never says "Inbox empty" while more wait', async () => {
  const ctx = await registered();
  try {
    fill(ctx.relay.state, 120, 2);
    const first = await ctx.srv.call('agent_receive_messages', {});
    const t1 = resultText(first);
    assert.ok(!first.isError, t1);
    assert.equal(first.structuredContent.count, 0);
    assert.equal(first.structuredContent.has_more, true);
    assert.equal(first.structuredContent.skipped_unreadable, 100);
    assert.doesNotMatch(t1, /Inbox empty/);
    assert.match(t1, /call again with no arguments/);

    const second = await ctx.srv.call('agent_receive_messages', {});
    const t2 = resultText(second);
    assert.match(t2, /legit message 0/);
    assert.match(t2, /legit message 1/);
    // /receive, not the tool's acknowledgement, marked the readable ones.
    assert.ok(batches(ctx).every((id) => id.startsWith('dead')));
    // Per call: at most two receive rounds.
    const receives = ctx.relay.state.requests.filter((q) => q.path === '/v1/agent/receive');
    assert.ok(receives.length <= 4, `receives: ${receives.length}`);
    for (const q of receives) assert.deepEqual(q.query, { unread: 'true', limit: '50' });
  } finally {
    await ctx.done();
  }
});

test('stall: a readable message that races into the head is not acknowledged', async () => {
  const ctx = await registered();
  try {
    const rows = fill(ctx.relay.state, 55, 0);
    let injected = false;
    ctx.relay.state.afterReceive = () => {
      if (injected) return;
      injected = true;
      // Arrives between /receive and the raw read, and sorts first (expires soon).
      rows.push({ id: 'beef000001', from: ctx.relay.state.other, content: 'urgent legit', created_at: at(500), urgent: true, decryptable: true, read_at: null, delivered: 0 });
    };
    const r = await ctx.srv.call('agent_receive_messages', {});
    assert.ok(!r.isError, resultText(r));
    assert.ok(!batches(ctx).includes('beef000001'), 'readable message was acknowledged unread');
    // It is shown to the model by /receive, in this call or the next.
    let text = resultText(r);
    if (!/urgent legit/.test(text)) text = resultText(await ctx.srv.call('agent_receive_messages', {}));
    assert.match(text, /urgent legit/);
  } finally {
    await ctx.done();
  }
});

test('stall: a row whose sender identity is gone (404 on get) is skipped too', async () => {
  const ctx = await registered();
  try {
    const rows = fill(ctx.relay.state, 0, 2);
    for (let i = 0; i < 50; i++) rows.unshift({ id: hex('ab5e', i), from: fakeDid(), content: 'x', created_at: at(-100 + i), decryptable: true, sender_missing: true, read_at: null, delivered: 0 });
    const r = await ctx.srv.call('agent_receive_messages', {});
    const text = resultText(r);
    assert.match(text, /legit message 0/);
    assert.equal(r.structuredContent.skipped_unreadable, 50);
  } finally {
    await ctx.done();
  }
});

test('stall: a rare relay failure on get-by-id acknowledges nothing and the page says why', async () => {
  const ctx = await registered();
  try {
    fill(ctx.relay.state, 50, 1);
    ctx.relay.state.override = (req) =>
      req.method === 'GET' && /^\/v1\/agent\/messages\/dead/.test(req.path) ? { status: 500, body: { error: 'boom' } } : undefined;
    const r = await ctx.srv.call('agent_receive_messages', {});
    const text = resultText(r);
    assert.ok(!r.isError, text);
    assert.equal(batches(ctx).length, 0);
    assert.equal(r.structuredContent.skipped_unreadable, 0);
    assert.doesNotMatch(text, /Inbox empty/);
    assert.match(text, /could not decrypt are blocking this page/);
  } finally {
    await ctx.done();
  }
});

// A 5xx on get-by-id is not only a rare relay failure. It is
// the NORMAL answer for a malformed row (non-base64 ciphertext, or a nonce that
// is not 24 bytes), which /send/encrypted accepts because it checks only
// lengths. /receive drops such a row without marking it; the worker's
// handleAgentGetMessage does not catch the decode error. So the relay never
// confirms it, the tool never skips it, and enough of them still block the
// default page until they expire. This test pins that limit: blocked, not
// skipped, and the page says so instead of "Inbox empty".
test('stall: malformed rows (5xx on get-by-id) are blocked, not skipped, and the page says so', async () => {
  const ctx = await registered();
  try {
    const rows = fill(ctx.relay.state, 0, 2);
    for (let i = 0; i < 50; i++) rows.unshift({ id: hex('bad0', i), from: fakeDid(), content: 'x', created_at: at(-100 + i), decryptable: false, malformed: true, read_at: null, delivered: 0 });
    const r = await ctx.srv.call('agent_receive_messages', {});
    const text = resultText(r);
    assert.ok(!r.isError, text);
    // Blocked: nothing acknowledged, nothing counted as skipped, readable ones still behind.
    assert.equal(batches(ctx).length, 0);
    assert.equal(r.structuredContent.skipped_unreadable, 0);
    assert.equal(r.structuredContent.count, 0);
    assert.equal(r.structuredContent.has_more, true);
    assert.doesNotMatch(text, /legit message/);
    assert.doesNotMatch(text, /Inbox empty/);
    assert.doesNotMatch(text, /were skipped/);
    assert.match(text, /No readable message on this page\./);
    assert.match(text, /blocking this page and could not be skipped; call again later/);
    // The check stops at the first unconfirmed row: one get, not fifty.
    const gets = ctx.relay.state.requests.filter((q) => q.method === 'GET' && /^\/v1\/agent\/messages\/bad0/.test(q.path));
    assert.equal(gets.length, 1);
    // A second call is still blocked: the tool cannot clear them; only expiry or a relay fix can.
    const again = await ctx.srv.call('agent_receive_messages', {});
    assert.equal(again.structuredContent.count, 0);
    assert.equal(again.structuredContent.skipped_unreadable, 0);
    assert.match(resultText(again), /blocking this page/);
    // Nothing about the rows reaches the model.
    assert.doesNotMatch(text + resultText(again), /bad0000|CIPHERTEXT/);
  } finally {
    await ctx.done();
  }
});

test('stall: the tool takes no argument that picks which rows are acknowledged', async () => {
  const ctx = await registered();
  try {
    const { tools } = await ctx.srv.client.listTools();
    const t = tools.find((x) => x.name === 'agent_receive_messages');
    assert.deepEqual(Object.keys(t.inputSchema.properties).sort(), ['limit', 'since']);
    assert.match(t.description, /confirms it cannot decrypt/);
    assert.match(t.description, /malformed messages the relay cannot parse are never confirmed/);
    assert.doesNotMatch(t.description, /Messages the relay could not decrypt are marked read/);
    // Normal inbox: no extra requests beyond the one receive.
    fill(ctx.relay.state, 0, 2);
    const before = ctx.relay.state.requests.length;
    const r = await ctx.srv.call('agent_receive_messages', {});
    assert.ok(!r.isError, resultText(r));
    assert.deepEqual(ctx.relay.state.requests.slice(before).map((q) => q.path), ['/v1/agent/receive']);
    assert.equal(r.structuredContent.skipped_unreadable, 0);
  } finally {
    await ctx.done();
  }
});

test('README: the stall and its handling are stated', async () => {
  const { readFileSync } = await import('node:fs');
  const README = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  assert.match(README, /Messages the relay cannot decrypt are acknowledged by the tool/);
  assert.doesNotMatch(README, /and the next call returns the next unread page\./);
  // F3: only rows the relay confirms are skippable; malformed rows are never confirmed.
  assert.doesNotMatch(README, /the relay cannot decrypt no longer hold up the inbox/);
  assert.doesNotMatch(README, /Messages the relay cannot decrypt are marked read by the tool/);
  assert.match(README, /Malformed messages the relay cannot parse are never confirmed and can still hold it until they expire/);
  assert.match(README, /messages the relay confirms it cannot decrypt no longer hold up the inbox/);
  assert.match(README, /never confirmed/);
  assert.match(README, /handleAgentGetMessage/);
});

test('stall: a failing unreadable check never loses the messages the relay already marked read', async () => {
  const ctx = await registered();
  try {
    fill(ctx.relay.state, 30, 20);
    ctx.relay.state.override = (req) => (req.path === '/v1/agent/receive/raw' ? { status: 503, body: { error: 'unavailable' } } : undefined);
    const r = await ctx.srv.call('agent_receive_messages', {});
    const text = resultText(r);
    assert.ok(!r.isError, text);
    assert.equal(r.structuredContent.count, 20);
    for (let i = 0; i < 20; i++) assert.match(text, new RegExp(`legit message ${i}\\b`));
    assert.match(text, /blocking this page/);
    assert.equal(batches(ctx).length, 0);
  } finally {
    await ctx.done();
  }
});

test('stall: never acknowledges more rows than /receive dropped, even if the relay returns more', async () => {
  const ctx = await registered();
  try {
    fill(ctx.relay.state, 55, 1);
    ctx.relay.state.rawIgnoresLimit = true;
    const r = await ctx.srv.call('agent_receive_messages', {});
    assert.ok(!r.isError, resultText(r));
    assert.equal(batches(ctx).length, 50);
    assert.equal(r.structuredContent.skipped_unreadable, 50);
    assert.match(resultText(r), /legit message 0/);
  } finally {
    await ctx.done();
  }
});

// Follow-up to 3.0.2: skipped_unreadable is the relay's own read-batch
// `updated` count and nothing else. When the relay omits it (or sends something
// that is not a whole non-negative number) the tool must not report the number
// of ids it asked to mark as a confirmed skip count; it reports 0 and says the
// result is unconfirmed. When the relay reports fewer than were asked, only
// that many are counted.
function readBatchAnswers(ctx, shape) {
  ctx.relay.state.override = (req) => {
    if (req.method !== 'POST' || req.path !== '/v1/agent/messages/read-batch') return undefined;
    const ids = Array.isArray(req.body?.message_ids) ? req.body.message_ids : [];
    for (const r of ctx.relay.state.inbox) if (ids.includes(r.id) && !r.read_at) r.read_at = '2026-09-24 10:00:00';
    return { status: 200, body: shape(ids) };
  };
}

for (const [label, shape] of [
  ['omits updated', (ids) => ({ read: true, total_requested: ids.length })],
  ['sends updated as a string', (ids) => ({ read: true, updated: String(ids.length), total_requested: ids.length })],
  ['sends a negative updated', (ids) => ({ read: true, updated: -1, total_requested: ids.length })],
  ['sends a fractional updated', (ids) => ({ read: true, updated: 2.5, total_requested: ids.length })],
]) {
  test(`skip count: read-batch that ${label} is not counted as confirmed skips`, async () => {
    const ctx = await registered();
    try {
      fill(ctx.relay.state, 60, 3);
      readBatchAnswers(ctx, shape);
      const r = await ctx.srv.call('agent_receive_messages', {});
      const text = resultText(r);
      assert.ok(!r.isError, text);
      assert.equal(batches(ctx).length, 50, 'the tool still asked to mark the confirmed-unreadable rows');
      assert.equal(r.structuredContent.skipped_unreadable, 0, 'count fabricated from the attempted ids');
      assert.equal(r.structuredContent.skip_unconfirmed, true);
      assert.doesNotMatch(text, /were skipped/);
      assert.match(text, /relay did not confirm how many/);
      assert.doesNotMatch(text, /GARBAGE|CIPHERTEXT|dead0000/);
    } finally {
      await ctx.done();
    }
  });
}

test('skip count: read-batch reporting fewer updated than attempted counts only those', async () => {
  const ctx = await registered();
  try {
    fill(ctx.relay.state, 60, 3);
    readBatchAnswers(ctx, (ids) => ({ read: true, updated: 7, total_requested: ids.length }));
    const r = await ctx.srv.call('agent_receive_messages', {});
    const text = resultText(r);
    assert.ok(!r.isError, text);
    assert.equal(batches(ctx).length, 50);
    assert.equal(r.structuredContent.skipped_unreadable, 7);
    assert.equal(r.structuredContent.skip_unconfirmed, undefined);
    assert.match(text, /\b7 message\(s\) the relay could not decrypt were skipped/);
    assert.doesNotMatch(text, /\b50 message\(s\)/);
  } finally {
    await ctx.done();
  }
});

test('skip count: read-batch reporting more updated than attempted is capped at attempted', async () => {
  const ctx = await registered();
  try {
    fill(ctx.relay.state, 60, 3);
    readBatchAnswers(ctx, (ids) => ({ read: true, updated: ids.length + 40, total_requested: ids.length }));
    const r = await ctx.srv.call('agent_receive_messages', {});
    assert.ok(!r.isError, resultText(r));
    assert.equal(r.structuredContent.skipped_unreadable, 50);
    assert.equal(r.structuredContent.skip_unconfirmed, undefined);
  } finally {
    await ctx.done();
  }
});

// Follow-up S1: an unconfirmed read-batch answer also stops the same-call
// re-read. Before this follow-up a missing `updated` counted as every id sent,
// so the tool read /receive a second time in the same call. Now the tool counts
// 0 confirmed skips, so it stops after one round and asks the caller to call
// again. Nothing is lost: the next call returns the readable messages.
test('skip count: read-batch without updated stops the same-call re-read; the next call returns the readable messages', async () => {
  const ctx = await registered();
  try {
    const rows = fill(ctx.relay.state, 60, 3);
    readBatchAnswers(ctx, (ids) => ({ read: true, total_requested: ids.length }));
    const receives = () => ctx.relay.state.requests.filter((q) => q.method === 'GET' && q.path === '/v1/agent/receive').length;

    const first = await ctx.srv.call('agent_receive_messages', {});
    const t1 = resultText(first);
    assert.ok(!first.isError, t1);
    assert.equal(receives(), 1, 'one /receive round in the first call');
    assert.equal(first.structuredContent.count, 0);
    assert.equal(first.structuredContent.has_more, true);
    assert.equal(first.structuredContent.skipped_unreadable, 0);
    assert.equal(first.structuredContent.skip_unconfirmed, true);
    assert.equal(batches(ctx).length, 50, 'the tool still asked to mark the confirmed-unreadable rows');
    assert.match(t1, /No readable message on this page/);
    assert.match(t1, /call again with no arguments/);
    assert.doesNotMatch(t1, /Inbox empty/);
    assert.doesNotMatch(t1, /GARBAGE|CIPHERTEXT|dead0000/);
    // The readable messages are still unread and were never sent to read-batch.
    for (const row of rows.filter((x) => x.decryptable)) {
      assert.equal(row.read_at, null, `${row.id} marked in the first call`);
      assert.ok(!batches(ctx).includes(row.id));
    }

    const second = await ctx.srv.call('agent_receive_messages', {});
    const t2 = resultText(second);
    assert.ok(!second.isError, t2);
    assert.equal(receives(), 2, 'one more /receive round in the second call');
    assert.equal(second.structuredContent.count, 3);
    for (let i = 0; i < 3; i++) assert.match(t2, new RegExp(`legit message ${i}`));
    assert.equal(second.structuredContent.skipped_unreadable, 0);
    assert.equal(second.structuredContent.skip_unconfirmed, undefined);
    assert.doesNotMatch(t2, /GARBAGE|CIPHERTEXT|dead0000/);
    assert.ok(batches(ctx).every((id) => id.startsWith('dead')), 'only unreadable rows were ever sent to read-batch');
  } finally {
    await ctx.done();
  }
});
