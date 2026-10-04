// Sentinel tools and agent_resolve_username: public GETs only, no key header,
// no secret read from the environment, input checked before any request.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startMockRelay, startServer, tempHome, resultText, assertNoLeak } from './helpers.mjs';

const SENTINEL_CALLS = [
  ['sentinel_current_risk', { country_code: 'ir' }, ['/v1/sentinel/current_risk/IR']],
  ['sentinel_global_heatmap', { min_risk: 0.1 }, ['/v1/sentinel/global_heatmap']],
  ['sentinel_accuracy', { window_days: 14 }, ['/v1/sentinel/accuracy']],
  ['sentinel_manifest', {}, ['/v1/sentinel/manifest.json']],
  ['sentinel_calibration_history', {}, ['/v1/sentinel/calibration/history']],
  ['sentinel_batch_risk', { country_codes: ['IR', 'cn', 'IR', 'RU'] }, ['/v1/sentinel/current_risk/IR', '/v1/sentinel/current_risk/CN', '/v1/sentinel/current_risk/RU']],
];

// Values a 2.16.0 install might still have in its environment. None may be sent.
const OLD_SECRETS = {
  SENTINEL_ADMIN_KEY: 'sentinel-admin-' + 'a1b2c3d4e5f6a7b8',
  VOIDLY_SENTINEL_KEY: 'sentinel-sub-' + 'f0e1d2c3b4a59687',
  VOIDLY_AGENT_SECRET: 'agent-secret-' + '0011223344556677',
};

async function setup(extraEnv = {}) {
  const relay = await startMockRelay();
  const home = tempHome();
  const env = { HOME: home.dir, VOIDLY_MCP_RELAY_HOME: home.relayHome, VOIDLY_MCP_RELAY_API_BASE: relay.base, ...extraEnv };
  const srv = await startServer(env);
  return { relay, home, srv, done: async () => { await srv.close(); await relay.close(); home.cleanup(); } };
}

function assertPublicGet(req, where) {
  assert.equal(req.method, 'GET', `${where}: method`);
  assert.equal(req.raw, '', `${where}: no body`);
  assert.equal(req.headers['x-agent-key'], undefined, `${where}: no X-Agent-Key`);
  for (const h of Object.keys(req.headers)) {
    assert.ok(!/key|secret|auth|token/i.test(h), `${where}: unexpected header ${h}`);
  }
}

test('sentinel tools: one public GET per expected path, no key header even with an identity and old secrets set', async () => {
  const t = await setup(OLD_SECRETS);
  try {
    const reg = await t.srv.call('agent_register', {});
    assert.ok(!reg.isError, resultText(reg));
    for (const [name, args, paths] of SENTINEL_CALLS) {
      const before = t.relay.state.requests.length;
      const r = await t.srv.call(name, args);
      assert.ok(!r.isError, `${name}: ${resultText(r)}`);
      const reqs = t.relay.state.requests.slice(before);
      assert.deepEqual(reqs.map((q) => q.path).sort(), [...paths].sort(), `${name}: paths`);
      for (const q of reqs) assertPublicGet(q, name);
      const text = resultText(r);
      assertNoLeak(assert, text, [t.relay.state.key], name);
      for (const v of Object.values(OLD_SECRETS)) assert.ok(!text.includes(v), `${name} output carries an env secret`);
    }
    const all = JSON.stringify(t.relay.state.requests);
    for (const v of Object.values(OLD_SECRETS)) assert.ok(!all.includes(v), 'an env secret reached the network');
  } finally {
    await t.done();
  }
});

test('sentinel tools: query values are passed and output reflects the response', async () => {
  const t = await setup();
  try {
    await t.srv.call('sentinel_global_heatmap', { min_risk: 0.1 });
    await t.srv.call('sentinel_accuracy', { window_days: 14 });
    const q = t.relay.state.requests;
    assert.equal(q.find((x) => x.path === '/v1/sentinel/global_heatmap').query.min_risk, '0.1');
    assert.equal(q.find((x) => x.path === '/v1/sentinel/accuracy').query.window_days, '14');

    const acc = resultText(await t.srv.call('sentinel_accuracy', {}));
    assert.match(acc, /Degraded: YES \(mock degraded\)/);
    assert.match(acc, /mock warning/);
    assert.match(acc, /not evidence of live performance/);
    const risk = resultText(await t.srv.call('sentinel_current_risk', { country_code: 'IR' }));
    assert.match(risk, /10\.00%/);
    assert.match(risk, /sentinel_accuracy/);
  } finally {
    await t.done();
  }
});

test('sentinel tools: bad input is refused before any request', async () => {
  const t = await setup();
  try {
    const bad = [
      ['sentinel_current_risk', {}],
      ['sentinel_current_risk', { country_code: '../agent/profile' }],
      ['sentinel_current_risk', { country_code: 'IRN' }],
      ['sentinel_global_heatmap', { min_risk: 5 }],
      ['sentinel_accuracy', { window_days: 'x' }],
      ['sentinel_batch_risk', { country_codes: [] }],
      ['sentinel_batch_risk', { country_codes: ['IR', 'I/R'] }],
      ['sentinel_batch_risk', { country_codes: Array.from({ length: 51 }, () => 'IR') }],
    ];
    for (const [name, args] of bad) {
      const r = await t.srv.call(name, args);
      assert.ok(r.isError, `${name} ${JSON.stringify(args)} should be refused`);
    }
    assert.equal(t.relay.state.requests.length, 0, 'no request was made');
  } finally {
    await t.done();
  }
});

test('sentinel tools: an API error is reported without a crash, batch keeps going', async () => {
  const t = await setup();
  try {
    t.relay.state.override = (req) => (req.path.endsWith('/CN') ? { status: 503, body: { error: 'down' } } : undefined);
    const single = await t.srv.call('sentinel_current_risk', { country_code: 'CN' });
    assert.ok(single.isError);
    assert.match(resultText(single), /HTTP 503/);
    const batch = await t.srv.call('sentinel_batch_risk', { country_codes: ['IR', 'CN'] });
    assert.ok(!batch.isError);
    assert.match(resultText(batch), /CN \| unavailable/);
    assert.match(resultText(batch), /Country IR \(IR\)/);
  } finally {
    await t.done();
  }
});

test('agent_resolve_username: public GET, no key header, marked untrusted, checked input', async () => {
  const t = await setup();
  try {
    await t.srv.call('agent_register', {});
    const before = t.relay.state.requests.length;
    const r = await t.srv.call('agent_resolve_username', { username: '@SomeOne' });
    assert.ok(!r.isError, resultText(r));
    const reqs = t.relay.state.requests.slice(before);
    assert.equal(reqs.length, 1);
    assert.equal(reqs[0].path, '/v1/agent/username/someone');
    assertPublicGet(reqs[0], 'agent_resolve_username');
    assert.equal(r.structuredContent.trust, 'untrusted-remote');
    const text = r.content[0].text;
    const open = text.indexOf('<untrusted-data');
    assert.ok(open > 0 && text.indexOf(t.relay.state.inbound) > open, 'display name is inside the marked block');

    const missing = await t.srv.call('agent_resolve_username', { username: 'missing_user' });
    assert.ok(!missing.isError);
    assert.match(resultText(missing), /not registered/);

    const n = t.relay.state.requests.length;
    for (const username of ['ab', 'has-dash', 'a/../b', 'x'.repeat(33), '']) {
      const bad = await t.srv.call('agent_resolve_username', { username });
      assert.ok(bad.isError, `${username} should be refused`);
    }
    assert.equal(t.relay.state.requests.length, n, 'no request for refused usernames');
  } finally {
    await t.done();
  }
});
