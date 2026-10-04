// Owner command line: import, rotate, list, export, deactivate. Keys never on
// argv, never printed except by `export`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { startMockRelay, startServer, tempHome, runCli, assertNoLeak, resultText } from './helpers.mjs';

async function ctx() {
  const relay = await startMockRelay();
  const home = tempHome();
  const env = { HOME: home.dir, VOIDLY_MCP_RELAY_HOME: home.relayHome, VOIDLY_MCP_RELAY_API_BASE: relay.base };
  return { relay, home, env, async done() { await relay.close(); home.cleanup(); } };
}

test('import-legacy reads the key from stdin, stores it 0600, prints no key', async () => {
  const c = await ctx();
  try {
    const key = c.relay.state.key;
    const r = await runCli(['import-legacy'], c.env, `${key}\n`);
    assert.equal(r.code, 0, r.stderr);
    assertNoLeak(assert, r.stdout + r.stderr, [key], 'import-legacy output');
    assert.match(r.stdout, /relay rotate --did/);
    const suffix = c.relay.state.did.slice('did:voidly:'.length);
    const path = join(c.home.relayHome, 'identities', `${suffix}.json`);
    assert.equal(lstatSync(path).mode & 0o777, 0o600);
    assert.equal(JSON.parse(readFileSync(path, 'utf8')).api_key, key);
    const profile = c.relay.state.requests.find((q) => q.path === '/v1/agent/profile');
    assert.equal(profile.headers['x-agent-key'], key);

    // The MCP tools now work with it.
    const srv = await startServer(c.env);
    try {
      const p = await srv.call('agent_get_profile', {});
      assert.ok(!p.isError, resultText(p));
    } finally {
      await srv.close();
    }

    const bad = await runCli(['import-legacy'], c.env, 'not-a-key\n');
    assert.equal(bad.code, 1);
    assert.match(bad.stderr, /not a relay API key/);
  } finally {
    await c.done();
  }
});

test('rotate replaces the key on the relay and in the file, prints neither key', async () => {
  const c = await ctx();
  try {
    const srv = await startServer(c.env);
    const reg = await srv.call('agent_register', {});
    await srv.close();
    const oldKey = c.relay.state.key;
    const r = await runCli(['rotate'], c.env);
    assert.equal(r.code, 0, r.stderr);
    const newKey = c.relay.state.key;
    assert.notEqual(newKey, oldKey);
    assertNoLeak(assert, r.stdout + r.stderr, [oldKey, newKey], 'rotate output');
    assert.match(r.stdout, /Rotated the API key/);
    assert.match(r.stdout, /1 webhook/);
    const rot = c.relay.state.requests.find((q) => q.path === '/v1/agent/rotate-api-key');
    assert.equal(rot.headers['x-agent-key'], oldKey);
    const path = reg.structuredContent.credentials_path;
    const stored = JSON.parse(readFileSync(path, 'utf8'));
    assert.equal(stored.api_key, newKey);
    assert.equal(stored.api_key_version, 1);
    assert.equal(lstatSync(path).mode & 0o777, 0o600);
    assert.ok(!readFileSync(path, 'utf8').includes(oldKey), 'old key is gone from the file');

    // Tools pick up the new key without a restart of anything else.
    const srv2 = await startServer(c.env);
    try {
      const p = await srv2.call('agent_get_profile', {});
      assert.ok(!p.isError, resultText(p));
      assertNoLeak(assert, resultText(p) + srv2.logs.text, [oldKey, newKey], 'tool after rotate');
    } finally {
      await srv2.close();
    }
  } finally {
    await c.done();
  }
});

test('list shows DIDs and paths only; export writes a new 0600 file', async () => {
  const c = await ctx();
  try {
    const srv = await startServer(c.env);
    await srv.call('agent_register', {});
    await srv.close();
    const key = c.relay.state.key;
    const l = await runCli(['list'], c.env);
    assert.equal(l.code, 0, l.stderr);
    assert.ok(l.stdout.includes(c.relay.state.did));
    assertNoLeak(assert, l.stdout + l.stderr, [key], 'list output');

    const outPath = join(c.home.dir, 'export.json');
    const e = await runCli(['export', '--out', outPath], c.env);
    assert.equal(e.code, 0, e.stderr);
    assertNoLeak(assert, e.stdout + e.stderr, [key], 'export --out output');
    assert.equal(lstatSync(outPath).mode & 0o777, 0o600);
    assert.equal(JSON.parse(readFileSync(outPath, 'utf8')).api_key, key);
    const again = await runCli(['export', '--out', outPath], c.env);
    assert.equal(again.code, 1, 'export never overwrites');
  } finally {
    await c.done();
  }
});

test('deactivate needs confirmation, then marks the file and clears the selection', async () => {
  const c = await ctx();
  try {
    const srv = await startServer(c.env);
    const reg = await srv.call('agent_register', {});
    await srv.close();
    const noYes = await runCli(['deactivate'], c.env);
    assert.equal(noYes.code, 1);
    assert.ok(!c.relay.state.requests.some((q) => q.path === '/v1/agent/deactivate'));
    const r = await runCli(['deactivate', '--yes'], c.env);
    assert.equal(r.code, 0, r.stderr);
    assertNoLeak(assert, r.stdout + r.stderr, [c.relay.state.key], 'deactivate output');
    assert.equal(JSON.parse(readFileSync(reg.structuredContent.credentials_path, 'utf8')).status, 'deactivated');
    assert.equal(readFileSync(join(c.home.relayHome, 'active'), 'utf8').trim(), '');
    const srv2 = await startServer(c.env);
    try {
      const p = await srv2.call('agent_get_profile', {});
      assert.ok(p.isError);
      assert.match(resultText(p), /no_identity/);
    } finally {
      await srv2.close();
    }
  } finally {
    await c.done();
  }
});

test('key on argv is not a thing: unknown flags do not read keys', async () => {
  const c = await ctx();
  try {
    const r = await runCli(['import-legacy', '--key', c.relay.state.key], c.env, '');
    assert.equal(r.code, 1);
    assertNoLeak(assert, r.stdout + r.stderr, [c.relay.state.key], 'argv key');
  } finally {
    await c.done();
  }
});
