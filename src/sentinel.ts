// Read-only Sentinel forecast tools.
//
// Every call here is an unauthenticated GET to a public /v1/sentinel/ endpoint.
// No environment variable holding a key is read and no key header is sent.
// Figures in the output come from the API response; this file states none of
// its own.

import { relayBase } from './relay/client.js';
import { cleanString } from './relay/untrusted.js';

const TIMEOUT_MS = 30_000;
const CC_RE = /^[A-Za-z]{2}$/;
const BATCH_MAX = 50;
const BATCH_CONCURRENCY = 5;

export class SentinelInputError extends Error {}

type Args = Record<string, unknown>;

export interface SentinelTool {
  name: string;
  description: string;
  inputSchema: { type: 'object'; properties: Record<string, unknown>; required?: string[] };
  handler: (args: Args) => Promise<string>;
}

/** GET a public Sentinel path. The method is fixed; there is no body and no auth header. */
async function sentinelGet(path: string, query: Record<string, string | number> = {}): Promise<any> {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) params.set(k, String(v));
  const qs = params.toString();
  // relayBase() is https://api.voidly.ai unless a loopback test origin is set.
  const url = `${relayBase()}${path}${qs ? `?${qs}` : ''}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(url, { method: 'GET', headers: { Accept: 'application/json' }, redirect: 'error', signal: controller.signal });
  } catch (error: any) {
    if (error?.name === 'AbortError') throw new Error(`Sentinel: ${path} did not answer within 30 seconds.`);
    throw new Error(`Sentinel: could not reach ${path}.`);
  } finally {
    clearTimeout(timer);
  }
  if (!response.ok) throw new Error(`Sentinel: ${path} answered HTTP ${response.status}.`);
  try {
    return await response.json();
  } catch {
    throw new Error(`Sentinel: ${path} did not return JSON.`);
  }
}

// ── Formatting helpers ──────────────────────────────────────────────────

const isNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
const pct = (v: unknown, digits = 2) => (isNum(v) ? `${(v * 100).toFixed(digits)}%` : 'n/a');
const fixed = (v: unknown, digits = 4) => (isNum(v) ? v.toFixed(digits) : 'n/a');
const txt = (v: unknown, fallback = 'n/a') => (typeof v === 'string' && v.trim() ? v.trim() : isNum(v) ? String(v) : fallback);
const list = (v: unknown): any[] => (Array.isArray(v) ? v : []);
/** One table cell: no pipes or line breaks from the response. */
const cell = (v: unknown) => txt(v).replace(/[|\r\n]+/g, ' ');

function countryCode(value: unknown, field = 'country_code'): string {
  if (typeof value !== 'string' || !CC_RE.test(value.trim())) {
    throw new SentinelInputError(`${field} must be a two-letter ISO 3166-1 code, for example IR.`);
  }
  return value.trim().toUpperCase();
}

function optNumber(args: Args, field: string, min: number, max: number, fallback: number): number {
  const v = args[field];
  if (v === undefined || v === null) return fallback;
  if (!isNum(v) || v < min || v > max) throw new SentinelInputError(`${field} must be a number from ${min} to ${max}.`);
  return v;
}

const BEFORE_ACTING =
  'Before acting on a forecast, read `sentinel_accuracy`: it reports the model\'s live error rates and whether the model is currently marked degraded.';

// ── Tools ───────────────────────────────────────────────────────────────

async function currentRisk(args: Args): Promise<string> {
  const cc = countryCode(args.country_code);
  const d = await sentinelGet(`/v1/sentinel/current_risk/${cc}`);
  const trust = d?.trust ?? {};
  const honest = d?.honest_forecast ?? {};
  const summary = d?.forecast_summary ?? {};
  const probability = isNum(trust.probability) ? trust.probability : isNum(honest.probability) ? honest.probability : summary.max_risk;
  const interval = list(trust.interval_90);
  const lines = [
    `# Voidly Sentinel: current risk for ${txt(d?.country_name, cc)} (${cc})`,
    '',
    `Issued: ${txt(d?.issued_at)}`,
    `Model: ${txt(trust.model_version ?? d?.model_version)}`,
    '',
    '## 7-day forecast',
    `- Probability of an event in the next 7 days: ${pct(probability)}`,
    `- 90% interval: [${pct(interval[0])}, ${pct(interval[1])}] (coverage reported by the API: ${pct(trust.conformal_coverage, 1)})`,
    `- Risk band: ${txt(honest.risk_band)}; alert threshold: ${txt(honest.recommended_threshold)}`,
    `- Peak day: +${txt(summary.max_risk_day)}`,
  ];
  const drivers = list(summary.key_drivers).filter((x) => typeof x === 'string');
  if (drivers.length) lines.push(`- Drivers: ${drivers.join(', ')}`);

  const features = list(trust.top_features);
  if (features.length) {
    lines.push('', '## Largest feature contributions');
    for (const f of features) lines.push(`- ${f?.direction === 'up' ? 'raises' : 'lowers'} risk: \`${txt(f?.name)}\` (${fixed(f?.contribution)})`);
  }
  const similar = trust.similar_incident;
  if (similar) {
    lines.push('', '## Most similar past incident', `- ${txt(similar.readable_id)} (${txt(similar.severity, 'severity unknown')})`, `- ${txt(similar.url)}`);
  }
  const evidence = list(trust.evidence_permalinks).slice(0, 5);
  if (evidence.length) {
    lines.push('', '## Recent evidence');
    for (const e of evidence) lines.push(`- ${txt(e?.source)} · ${txt(e?.signal_type)} · ${txt(e?.observed_at)}: ${txt(e?.permalink)}`);
  }
  lines.push('', BEFORE_ACTING, '', `Source: https://api.voidly.ai/v1/sentinel/current_risk/${cc} (CC BY 4.0)`);
  return lines.join('\n');
}

async function globalHeatmap(args: Args): Promise<string> {
  const minRisk = optNumber(args, 'min_risk', 0, 1, 0);
  const d = await sentinelGet('/v1/sentinel/global_heatmap', { min_risk: minRisk });
  const countries = list(d?.countries);
  const lines = [
    '# Voidly Sentinel: global risk heatmap',
    '',
    `As of: ${txt(d?.eval_date)}`,
    `Countries with risk >= ${minRisk}: ${txt(d?.n, String(countries.length))}`,
    '',
    '| # | Country | 7-day risk | Peak day | Above threshold |',
    '|---|---------|------------|----------|-----------------|',
  ];
  countries.slice(0, 30).forEach((c, i) => {
    lines.push(`| ${i + 1} | ${cell(c?.country_name)} (${cell(c?.country)}) | ${pct(c?.max_risk)} | +${cell(c?.max_risk_day)} | ${c?.above_threshold ? 'yes' : ''} |`);
  });
  if (countries.length > 30) lines.push('', `${countries.length - 30} more not shown.`);
  lines.push('', `Alert threshold reported by the API: ${txt(countries[0]?.threshold)}`);
  if (typeof d?.honest_caveat === 'string') lines.push('', `Note from the API: ${d.honest_caveat}`);
  lines.push('', 'For one country: `sentinel_current_risk`. ' + BEFORE_ACTING);
  return lines.join('\n');
}

async function accuracy(args: Args): Promise<string> {
  const windowDays = Math.floor(optNumber(args, 'window_days', 1, 365, 30));
  const d = await sentinelGet('/v1/sentinel/accuracy', { window_days: windowDays });
  const lines = [
    '# Voidly Sentinel: accuracy',
    '',
    `Window: last ${windowDays} days`,
    `Degraded: ${d?.degraded ? `YES (${txt(d?.degradation_reason, 'no reason given')})` : 'no'}`,
  ];
  if (typeof d?.published_warning === 'string') lines.push(`Warning published with these figures: ${d.published_warning}`);

  const p = d?.prod_rolling ?? {};
  lines.push('', `## Live outcomes (${txt(p.n_evaluated, '0')} evaluated)`);
  if (isNum(p.n_evaluated) && p.n_evaluated >= 30) {
    lines.push(
      `- Precision: ${pct(p.precision, 1)}`,
      `- Recall: ${pct(p.recall, 1)}`,
      `- Accuracy: ${pct(p.accuracy, 1)}`,
      `- Brier score: ${fixed(p.brier_score)}`,
      `- Calibration MAE: ${fixed(p.calibration_mae)}`,
    );
    const c = p.confusion;
    if (c) lines.push(`- Confusion: TP=${txt(c.true_positive)} FP=${txt(c.false_positive)} TN=${txt(c.true_negative)} FN=${txt(c.false_negative)}`);
  } else {
    lines.push('Fewer than 30 resolved outcomes in this window, so live figures are not informative yet.');
  }

  const h = d?.training_holdout;
  if (h) {
    lines.push(
      '',
      '## Training holdout',
      'A split from the last training run. It checks the model; it is not evidence of live performance.',
      `- ROC AUC: ${fixed(h.roc_auc)} · F1: ${fixed(h.f1)} · precision: ${fixed(h.precision)} · recall: ${fixed(h.recall)}`,
      `- Samples: ${txt(h.samples)} (${pct(h.positive_rate, 1)} positive)`,
    );
    const loco = h.split_loco;
    if (loco && isNum(loco.f1_median)) {
      lines.push(`- Leave-one-country-out median F1: ${fixed(loco.f1_median)} over ${txt(loco.n_countries_evaluated)} countries`);
    }
  }
  if (typeof d?.notes === 'string') lines.push('', `Notes from the API: ${d.notes}`);
  lines.push('', `Source: https://api.voidly.ai/v1/sentinel/accuracy?window_days=${windowDays}`);
  return lines.join('\n');
}

async function manifest(): Promise<string> {
  const d = await sentinelGet('/v1/sentinel/manifest.json');
  const endpoints = list(d?.endpoints);
  const lines = [
    '# Voidly Sentinel: service manifest',
    '',
    `Stage: ${txt(d?.stage)}`,
    `License: data ${txt(d?.license?.data)}, code ${txt(d?.license?.code)}`,
    '',
    txt(d?.description, ''),
    '',
    `## Endpoints (${endpoints.length})`,
  ];
  for (const e of endpoints) {
    lines.push(`- \`${txt(e?.method)} ${txt(e?.path)}\`: ${txt(e?.summary, '')}`);
  }
  const tools = list(d?.mcp_tools).map((t) => txt(t?.name, '')).filter(Boolean);
  if (tools.length) {
    lines.push(
      '',
      '## Tool names in the manifest',
      tools.join(', '),
      'This server exposes only the read-only sentinel_* tools in its own tool list.',
    );
  }
  if (typeof d?.reliability_commitment === 'string') lines.push('', `Reliability commitment (from the API): ${d.reliability_commitment}`);
  lines.push('', 'Source: https://api.voidly.ai/v1/sentinel/manifest.json');
  return lines.join('\n');
}

async function calibrationHistory(): Promise<string> {
  const d = await sentinelGet('/v1/sentinel/calibration/history');
  const history = list(d?.history);
  const lines = [`# Voidly Sentinel: calibration history (${history.length} snapshots)`, ''];
  if (history.length === 0) {
    lines.push('No snapshots yet.');
    return lines.join('\n');
  }
  lines.push('| Date | q90 | Empirical coverage | Holdout n | Drift alert | Drift delta |', '|------|-----|--------------------|-----------|-------------|-------------|');
  for (const h of history.slice(0, 30)) {
    lines.push(`| ${cell(h?.date)} | ${fixed(h?.q90)} | ${pct(h?.empirical_coverage, 1)} | ${cell(h?.n_holdout)} | ${h?.drift_alert ? 'yes' : '-'} | ${pct(h?.drift_delta, 1)} |`);
  }
  const latest = history[0];
  lines.push(
    '',
    latest?.drift_alert
      ? 'The latest snapshot has a drift alert: the 90% intervals may not cover 90% of outcomes right now.'
      : `Latest empirical coverage: ${pct(latest?.empirical_coverage, 1)} (nominal 90%).`,
    '',
    'Source: https://api.voidly.ai/v1/sentinel/calibration/history',
  );
  return lines.join('\n');
}

async function batchRisk(args: Args): Promise<string> {
  const raw = args.country_codes;
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > BATCH_MAX) {
    throw new SentinelInputError(`country_codes must be a list of 1-${BATCH_MAX} two-letter codes.`);
  }
  const codes = [...new Set(raw.map((v) => countryCode(v, 'each country code')))];

  const rows: string[] = new Array(codes.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < codes.length) {
      const i = next++;
      const cc = codes[i];
      try {
        const d = await sentinelGet(`/v1/sentinel/current_risk/${cc}`);
        const t = d?.trust ?? {};
        const iv = list(t.interval_90);
        rows[i] = `| ${cell(d?.country_name ?? cc)} (${cc}) | ${pct(t.probability)} | [${pct(iv[0], 1)}, ${pct(iv[1], 1)}] | ${cell(d?.honest_forecast?.risk_band)} | +${cell(d?.forecast_summary?.max_risk_day)} |`;
      } catch (error) {
        rows[i] = `| ${cc} | unavailable | ${cell(error instanceof Error ? error.message : 'error')} | | |`;
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(BATCH_CONCURRENCY, codes.length) }, worker));

  return [
    `# Voidly Sentinel: risk for ${codes.length} countries`,
    '',
    '| Country | 7-day probability | 90% interval | Risk band | Peak day |',
    '|---------|-------------------|--------------|-----------|----------|',
    ...rows,
    '',
    BEFORE_ACTING,
  ].join('\n');
}

// ── Tool table ──────────────────────────────────────────────────────────

export const SENTINEL_TOOLS: SentinelTool[] = [
  {
    name: 'sentinel_current_risk',
    description:
      '7-day censorship-event forecast for one country from Voidly Sentinel: probability, 90% interval, risk band, largest feature contributions, the most similar past incident and recent evidence links. Read-only public GET.',
    inputSchema: { type: 'object', properties: { country_code: { type: 'string', description: 'ISO 3166-1 alpha-2 code (e.g. IR, CN, RU)' } }, required: ['country_code'] },
    handler: currentRisk,
  },
  {
    name: 'sentinel_global_heatmap',
    description:
      'Current Sentinel forecast for every watched country, sorted by 7-day risk, with the alert threshold in use. Answers "which countries are most at risk right now?" in one call. Read-only public GET.',
    inputSchema: { type: 'object', properties: { min_risk: { type: 'number', description: 'Only countries at or above this risk, 0-1 (default 0)' } } },
    handler: globalHeatmap,
  },
  {
    name: 'sentinel_accuracy',
    description:
      "Sentinel's published accuracy: live precision, recall, Brier score and calibration over a rolling window, whether the model is marked degraded, and the training holdout labelled as such. Read this before acting on a forecast. Read-only public GET.",
    inputSchema: { type: 'object', properties: { window_days: { type: 'number', description: 'Rolling window in days, 1-365 (default 30)' } } },
    handler: accuracy,
  },
  {
    name: 'sentinel_manifest',
    description: 'The Sentinel service manifest: endpoints, response schemas, license and reliability commitment. Read-only public GET.',
    inputSchema: { type: 'object', properties: {} },
    handler: manifest,
  },
  {
    name: 'sentinel_calibration_history',
    description:
      "Daily calibration snapshots: the q90 conformal width and empirical coverage, with drift alerts. Use it to check whether Sentinel's 90% intervals still cover 90% of outcomes. Read-only public GET.",
    inputSchema: { type: 'object', properties: {} },
    handler: calibrationHistory,
  },
  {
    name: 'sentinel_batch_risk',
    description: `sentinel_current_risk for up to ${BATCH_MAX} countries in one call, as a table. Runs one public GET per country.`,
    inputSchema: {
      type: 'object',
      properties: { country_codes: { type: 'array', items: { type: 'string' }, description: `ISO 3166-1 alpha-2 codes (max ${BATCH_MAX})` } },
      required: ['country_codes'],
    },
    handler: batchRisk,
  },
];

export const SENTINEL_TOOL_MAP = new Map(SENTINEL_TOOLS.map((t) => [t.name, t]));

/** Run a Sentinel tool. Output is cleaned of control and bidi characters. */
export async function runSentinelTool(tool: SentinelTool, args: Args): Promise<string> {
  return cleanString(await tool.handler(args));
}
