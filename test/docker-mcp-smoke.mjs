// Run against the image built from this PR. No MCP tool call or resource read is made.
import { spawn, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const image = process.argv[2];
if (!image) {
  console.error('Usage: node test/docker-mcp-smoke.mjs IMAGE');
  process.exit(2);
}

const packageVersion = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const canary = `ATLAS_CI_SYNTHETIC_CANARY_${process.pid}`;
const containerName = `atlas-mcp-ci-${process.pid}-${Date.now()}`;
const MAX_STDOUT = 4 * 1024 * 1024;
const MAX_STDERR = 64 * 1024;
const REQUEST_MS = 8_000;
const OVERALL_MS = 45_000;
const pending = new Map();
let nextId = 1;
let stdout = '';
let stderr = '';
let lineBuffer = '';
let terminalError;

const child = spawn('docker', [
  'run', '--rm', '-i', '--pull=never', '--name', containerName,
  '--network', 'none', '--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev',
  '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
  '--env', `VOIDLY_AGENT_SECRET=${canary}`,
  image,
], { stdio: ['pipe', 'pipe', 'pipe'] });

function check(ok, reason) {
  if (!ok) throw new Error(reason);
}

function fail(reason) {
  if (terminalError) return;
  terminalError = new Error(reason);
  for (const [id, waiter] of pending) {
    clearTimeout(waiter.timer);
    pending.delete(id);
    waiter.reject(terminalError);
  }
}

child.on('error', () => fail('container process could not start'));
child.on('close', () => fail('container exited before protocol check completed'));
child.stdin.on('error', () => fail('container stdin closed'));
child.stdout.on('data', (chunk) => {
  stdout += chunk.toString('utf8');
  if (Buffer.byteLength(stdout) > MAX_STDOUT) return fail('stdout limit exceeded');
  lineBuffer += chunk.toString('utf8');
  let newline;
  while ((newline = lineBuffer.indexOf('\n')) !== -1) {
    const line = lineBuffer.slice(0, newline).trim();
    lineBuffer = lineBuffer.slice(newline + 1);
    if (!line) continue;
    let message;
    try { message = JSON.parse(line); }
    catch { return fail('server wrote non-JSON to stdout'); }
    if (message.jsonrpc !== '2.0') return fail('server wrote invalid JSON-RPC');
    const waiter = pending.get(message.id);
    if (waiter) {
      clearTimeout(waiter.timer);
      pending.delete(message.id);
      waiter.resolve(message);
    }
  }
});
child.stderr.on('data', (chunk) => {
  stderr += chunk.toString('utf8');
  if (Buffer.byteLength(stderr) > MAX_STDERR) fail('stderr limit exceeded');
});

const overallTimer = setTimeout(() => fail('overall deadline exceeded'), OVERALL_MS);

function request(method, params = {}) {
  if (terminalError) return Promise.reject(terminalError);
  const id = nextId++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => fail(`${method} deadline exceeded`), REQUEST_MS);
    pending.set(id, { resolve, reject, timer });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n', (error) => {
      if (error) fail('container stdin write failed');
    });
  });
}

function notify(method) {
  check(!terminalError, 'container unavailable');
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method }) + '\n', (error) => {
    if (error) fail('container stdin write failed');
  });
}

async function list(method, key, maxPages) {
  const entries = [];
  let cursor;
  for (let page = 0; page < maxPages; page++) {
    const reply = await request(method, cursor ? { cursor } : {});
    check(!reply.error && Array.isArray(reply.result?.[key]), `${method} returned no ${key} list`);
    entries.push(...reply.result[key]);
    cursor = reply.result.nextCursor;
    if (!cursor) return entries;
    check(typeof cursor === 'string', `${method} returned invalid cursor`);
  }
  throw new Error(`${method} exceeded page limit`);
}

try {
  const initialized = await request('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'atlas-docker-ci', version: '1.0.0' },
  });
  check(!initialized.error && initialized.result, 'initialize failed');
  check(initialized.result.protocolVersion === '2025-06-18', 'protocol version mismatch');
  check(initialized.result.serverInfo?.version === packageVersion, 'server version mismatch');
  check(initialized.result.capabilities?.tools && initialized.result.capabilities?.resources, 'missing advertised capabilities');
  check(!initialized.result.capabilities?.prompts, 'unexpected prompts capability');
  notify('notifications/initialized');

  const tools = await list('tools/list', 'tools', 5);
  const names = tools.map((tool) => tool.name);
  check(names.length === 89 && new Set(names).size === 89, 'tool catalog count or uniqueness changed');
  check(tools.every((tool) => typeof tool.name === 'string' && tool.inputSchema?.type === 'object'), 'tool catalog schema invalid');
  for (const name of ['get_censorship_index', 'sentinel_current_risk', 'agent_register']) {
    check(names.includes(name), 'expected tool missing');
  }
  check(!names.includes('voidly_pay_overview'), 'retired Pay tool returned');

  const resources = await list('resources/list', 'resources', 3);
  check(JSON.stringify(resources.map((resource) => resource.uri).sort()) === JSON.stringify([
    'voidly://censorship-index', 'voidly://methodology',
  ]), 'resource catalog changed');

  const prompts = await request('prompts/list');
  check(prompts.error?.code === -32601, 'unsupported prompts/list did not return method-not-found');
  check(typeof prompts.error.message === 'string' && prompts.error.message.length <= 160, 'unsupported-method message is unbounded');
  check(/method not found/i.test(prompts.error.message)
    && !/[\r\n]/.test(prompts.error.message)
    && !/\bat\s+\S+:\d+:\d+|\/app\//i.test(prompts.error.message)
    && !prompts.error.message.includes(canary), 'unsupported-method message is not sanitized');
  check(!stdout.includes(canary) && !stderr.includes(canary), 'synthetic canary reached protocol output');
  check(!terminalError, 'container failed during protocol check');

  console.log(`Atlas Docker MCP smoke passed: ${names.length} tools, ${resources.length} resources, prompts unsupported`);
} catch (error) {
  // All errors above have fixed text. Never print raw server output or error responses.
  console.error(`Atlas Docker MCP smoke failed: ${error.message}`);
  process.exitCode = 1;
} finally {
  clearTimeout(overallTimer);
  child.stdin.end();
  child.kill('SIGTERM');
  spawnSync('docker', ['rm', '-f', containerName], { stdio: 'ignore', timeout: 5_000 });
}
