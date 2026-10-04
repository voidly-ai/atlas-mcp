// Client-visible evidence result shape from synthetic REST responses only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, startServer, tempHome } from './helpers.mjs';

test('incident evidence shows reported versus returned rows and labels source context honestly', async () => {
  const home = tempHome();
  const fixturePath = join(home.dir, 'evidence.json');
  const setFixture = (status, body) => writeFileSync(fixturePath, JSON.stringify({ status, body }));
  setFixture(200, { incident_id: '06c57cac68c4', count: 97, evidence: [{
    source: 'ooni', kind: 'measurement', sourceUrl: 'https://example.org/source-context',
    sourceRef: 'sample-ref-1', observedAt: '2026-09-24T10:00:00Z',
    retrievedAt: '2026-09-25T11:00:00Z', confidence: 0.8,
  }], corroboration: { sampledSources: 3 } });
  const srv = await startServer({
    HOME: home.dir,
    VOIDLY_MCP_RELAY_HOME: home.relayHome,
    NODE_OPTIONS: `--require=${join(ROOT, 'test/evidence-fetch.cjs')}`,
    MCP3_TEST_EVIDENCE_FIXTURE: fixturePath,
  });
  try {
    const call = () => srv.call('get_incident_evidence', { incident_id: 'synthetic-incident' });
    const current = await call();
    assert.ok(!current.isError, JSON.stringify(current));
    const text = current.content[0].text;
    assert.match(text, /Evidence for Incident: 06c57cac68c4/);
    assert.match(text, /Total Evidence Items \(API-reported\):\*\* 97/);
    assert.match(text, /Rows returned \/ shown:\*\* 1 \/ 1/);
    assert.match(text, /Source reference: sample-ref-1/);
    assert.match(text, /Observed: 2026-09-24T10:00:00Z/);
    assert.match(text, /Retrieved: 2026-09-25T11:00:00Z/);
    assert.match(text, /Source context URL \(record scope not verified\): https:\/\/example.org\/source-context/);
    assert.match(text, /Corroboration \(uninterpreted API data\)/);
    assert.doesNotMatch(text, /\bundefined\b|Permalink field: https:\/\/example.org\/source-context/);
    const { tools } = await srv.client.listTools();
    const evidenceTool = tools.find((tool) => tool.name === 'get_incident_evidence');
    assert.match(evidenceTool.description, /Source context URLs are not necessarily exact measurement permalinks/);

    setFixture(200, { incidentId: 'legacy-id', evidenceCount: 1, evidence: [{
      source: 'ioda', kind: 'outage', permalink: 'https://example.org/exact-record',
      observedAt: '2026-09-24T10:00:00Z', confidence: 0.9,
    }] });
    const legacy = await call();
    assert.ok(!legacy.isError, JSON.stringify(legacy));
    assert.match(legacy.content[0].text, /Permalink field \(record scope not verified\): https:\/\/example.org\/exact-record/);

    setFixture(200, { incident_id: 'empty-id', count: 5, evidence: [] });
    const empty = await call();
    assert.ok(!empty.isError, JSON.stringify(empty));
    assert.match(empty.content[0].text, /Rows returned \/ shown:\*\* 0 \/ 0/);
    assert.match(empty.content[0].text, /this alone does not establish that no other evidence exists/);

    setFixture(200, { incident_id: 'no-link', count: 1, evidence: [{ source: 'ooni' }] });
    const noLink = await call();
    assert.ok(!noLink.isError, JSON.stringify(noLink));
    assert.match(noLink.content[0].text, /Source link: not provided/);
    assert.doesNotMatch(noLink.content[0].text, /\bundefined\b|\bNaN%\b/);

    setFixture(200, { incident_id: 'many', count: 97, evidence: Array.from({ length: 11 }, (_, i) => ({
      source: 'ooni', kind: 'measurement', sourceRef: `row-${i + 1}`,
    })) });
    const many = await call();
    assert.ok(!many.isError, JSON.stringify(many));
    assert.match(many.content[0].text, /Rows returned \/ shown:\*\* 11 \/ 10/);
    assert.match(many.content[0].text, /1 more OONI items not shown/);
    assert.doesNotMatch(many.content[0].text, /Source reference: row-11/);

    setFixture(200, { incident_id: 'invalid', count: 1 });
    const invalid = await call();
    assert.equal(invalid.isError, true);
    assert.match(invalid.content[0].text, /missing valid evidence rows/);

    for (const status of [404, 429, 503]) {
      setFixture(status, { error: `synthetic ${status}` });
      const failed = await call();
      assert.equal(failed.isError, true, `HTTP ${status}`);
      assert.match(failed.content[0].text, new RegExp(`API request failed: ${status}`));
    }
  } finally {
    await srv.close();
    home.cleanup();
  }
});
