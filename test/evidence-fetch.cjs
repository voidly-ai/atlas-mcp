// Test-only fetch fixture for get_incident_evidence. Never contacts the network.
const { readFileSync } = require('node:fs');

const expected = 'https://api.voidly.ai/data/incidents/synthetic-incident/evidence';
globalThis.fetch = async (input, options = {}) => {
  if (String(input) !== expected || (options.method && options.method !== 'GET')) {
    throw new Error(`Unexpected evidence test request: ${String(input)}`);
  }
  const fixture = JSON.parse(readFileSync(process.env.MCP3_TEST_EVIDENCE_FIXTURE, 'utf8'));
  return new Response(JSON.stringify(fixture.body), {
    status: fixture.status,
    headers: { 'content-type': 'application/json' },
  });
};
