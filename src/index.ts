/**
 * Voidly MCP Server
 *
 * Model Context Protocol server for Voidly's internet censorship data, plus
 * agent relay tools. Relay tools read the API key from a local credential file;
 * no tool takes it as an argument or returns it. See src/relay/.
 *
 * Owner actions (import a legacy key, rotate the key, export, deactivate) are a
 * separate command line: `voidly-mcp relay <command>`. They are not MCP tools.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { RELAY_TOOLS, RELAY_TOOL_MAP, refuseKeyArguments, refusalWord } from './relay/tools.js';
import { redact, redactDeep } from './relay/redact.js';
import { SENTINEL_TOOLS, SENTINEL_TOOL_MAP, runSentinelTool } from './sentinel.js';

// Voidly API endpoints
const VOIDLY_API = 'https://api.voidly.ai';
const VOIDLY_DATA_API = 'https://api.voidly.ai/data';

// Country metadata for enriching responses
const COUNTRY_NAMES: Record<string, string> = {
  CN: 'China', IR: 'Iran', RU: 'Russia', VE: 'Venezuela', CU: 'Cuba',
  MM: 'Myanmar', BY: 'Belarus', SA: 'Saudi Arabia', AE: 'UAE', EG: 'Egypt',
  MX: 'Mexico', VN: 'Vietnam', PH: 'Philippines', IN: 'India', PK: 'Pakistan',
  BD: 'Bangladesh', CO: 'Colombia', BR: 'Brazil', HT: 'Haiti', TR: 'Turkey',
  TH: 'Thailand', ID: 'Indonesia', MY: 'Malaysia', KZ: 'Kazakhstan', UA: 'Ukraine',
  YE: 'Yemen', IQ: 'Iraq', DZ: 'Algeria', NG: 'Nigeria', KE: 'Kenya',
  GH: 'Ghana', ZA: 'South Africa', AR: 'Argentina', CL: 'Chile', PE: 'Peru',
  EC: 'Ecuador', US: 'United States', GB: 'United Kingdom', DE: 'Germany',
  FR: 'France', ES: 'Spain', IT: 'Italy', CA: 'Canada', AU: 'Australia',
  JP: 'Japan', KR: 'South Korea', NL: 'Netherlands', CH: 'Switzerland',
  NZ: 'New Zealand', HK: 'Hong Kong', TW: 'Taiwan', SG: 'Singapore' };

// MCP server version — used in User-Agent and server metadata
const MCP_VERSION = '3.0.2';

// Fetch helper with error handling and timeout
async function fetchJson<T>(url: string): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);
  try {
    const response = await fetch(url, {
      headers: {
        'Accept': 'application/json' },
      signal: controller.signal });

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(`API request failed: ${response.status} ${response.statusText}${body ? ` — ${body.slice(0, 200)}` : ''}`);
    }

    return response.json() as Promise<T>;
  } finally {
    clearTimeout(timeout);
  }
}

// Agent relay fetch helper with timeout, auth, and safe error handling
async function agentFetch(url: string, options: RequestInit & { headers?: Record<string, string> } = {}): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);
  try {
    const headers = {
      ...options.headers };
    const response = await fetch(url, { ...options, headers, signal: controller.signal });
    return response;
  } catch (err: any) {
    if (err.name === 'AbortError') throw new Error(`Request timed out after 30s: ${url.replace(VOIDLY_API, '')}`);
    throw err;
  } finally {
    clearTimeout(timeout);
  }
}

// Safe JSON parse from response — handles HTML error pages from Cloudflare
async function safeJson(response: Response): Promise<any> {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return { error: text.slice(0, 200) };
  }
}

// Tool implementations
async function getCensorshipIndex(): Promise<string> {
  const data = await fetchJson<{
    timestamp: string;
    summary: {
      fullOutage: number;
      partialOutage: number;
      degraded: number;
      normal: number;
      unknown: number;
    };
    countries: Array<{
      country: string;
      name: string;
      status: string;
      ooni?: {
        anomalyRate: number;
        measurementCount: number;
      };
    }>;
  }>(`${VOIDLY_API}/v1/censorship-index`);

  const { summary, countries } = data;

  // Format response for AI consumption
  let result = `# Voidly Global Censorship Index\n`;
  result += `Updated: ${data.timestamp}\n\n`;
  result += `## Summary\n`;
  result += `- Full Outage: ${summary.fullOutage} countries\n`;
  result += `- Partial Outage: ${summary.partialOutage} countries\n`;
  result += `- Degraded: ${summary.degraded} countries\n`;
  result += `- Normal: ${summary.normal} countries\n`;
  result += `- Unknown: ${summary.unknown} countries\n\n`;

  // Top censored countries by anomaly rate
  const withData = countries
    .filter(c => c.ooni && c.ooni.measurementCount > 0)
    .sort((a, b) => (b.ooni?.anomalyRate || 0) - (a.ooni?.anomalyRate || 0));

  result += `## Most Censored Countries (by anomaly rate)\n`;
  withData.slice(0, 10).forEach((c, i) => {
    const pct = ((c.ooni?.anomalyRate || 0) * 100).toFixed(1);
    result += `${i + 1}. ${c.name} (${c.country}): ${pct}% anomaly rate, ${c.ooni?.measurementCount.toLocaleString()} measurements\n`;
  });

  result += `\n## Data Source\n`;
  result += `Source: Voidly Research Global Censorship Index\n`;
  result += `Based on OONI (Open Observatory of Network Interference) measurements\n`;
  result += `URL: https://voidly.ai/censorship-index\n`;
  result += `License: CC BY 4.0\n`;

  return result;
}

async function getCountryStatus(countryCode: string): Promise<string> {
  const code = countryCode.toUpperCase();
  const name = COUNTRY_NAMES[code] || code;

  const data = await fetchJson<{
    country: string;
    name: string;
    status: string;
    ooni?: {
      status: string;
      anomalyRate: number;
      confirmedRate: number;
      measurementCount: number;
      affectedServices: string[];
      lastUpdated: string;
    };
    activeIncidents?: Array<{
      title: string;
      severity: string;
    }>;
  }>(`${VOIDLY_API}/v1/censorship-index/${code}`);

  let result = `# Censorship Status: ${name} (${code})\n\n`;

  if (data.ooni) {
    const { ooni } = data;
    result += `## Current Status: ${ooni.status.toUpperCase()}\n\n`;
    result += `### Metrics\n`;
    result += `- Anomaly Rate: ${(ooni.anomalyRate * 100).toFixed(1)}%\n`;
    result += `- Confirmed Censorship Rate: ${(ooni.confirmedRate * 100).toFixed(2)}%\n`;
    result += `- Total Measurements: ${ooni.measurementCount.toLocaleString()}\n`;
    result += `- Last Updated: ${ooni.lastUpdated}\n\n`;

    if (ooni.affectedServices && ooni.affectedServices.length > 0) {
      result += `### Affected Services\n`;
      ooni.affectedServices.forEach(s => {
        result += `- ${s}\n`;
      });
      result += '\n';
    }
  } else {
    result += `## Status: No recent data available\n\n`;
  }

  if (data.activeIncidents && data.activeIncidents.length > 0) {
    result += `### Active Incidents\n`;
    data.activeIncidents.forEach(i => {
      result += `- [${i.severity.toUpperCase()}] ${i.title}\n`;
    });
    result += '\n';
  }

  result += `## Interpretation\n`;
  if (data.ooni?.anomalyRate && data.ooni.anomalyRate > 0.5) {
    result += `${name} shows significant internet censorship with over 50% of measurements detecting anomalies. `;
    result += `This indicates widespread blocking of websites and services.\n`;
  } else if (data.ooni?.anomalyRate && data.ooni.anomalyRate > 0.2) {
    result += `${name} shows moderate internet censorship with ${(data.ooni.anomalyRate * 100).toFixed(0)}% of measurements detecting anomalies. `;
    result += `Some websites and services may be blocked.\n`;
  } else if (data.ooni?.anomalyRate) {
    result += `${name} shows relatively low censorship levels. Most internet services are accessible.\n`;
  }

  result += `\n## Source\n`;
  result += `Data: Voidly Research Global Censorship Index\n`;
  result += `URL: https://voidly.ai/censorship-index/${code.toLowerCase()}\n`;

  return result;
}

async function checkDomainBlocked(domain: string, countryCode: string): Promise<string> {
  const code = countryCode.toUpperCase();
  const name = COUNTRY_NAMES[code] || code;

  // For now, we provide general country status since domain-level data
  // requires the Hydra API with authentication
  const countryStatus = await getCountryStatus(code);

  let result = `# Domain Block Check: ${domain} in ${name}\n\n`;
  result += `## Note\n`;
  result += `Domain-specific blocking data requires the Voidly Hydra API.\n`;
  result += `Below is the general censorship status for ${name}.\n\n`;
  result += `---\n\n`;
  result += countryStatus;

  return result;
}

async function getMostCensored(limit: number = 10): Promise<string> {
  const data = await fetchJson<{
    countries: Array<{
      country: string;
      name: string;
      ooni?: {
        anomalyRate: number;
        measurementCount: number;
        affectedServices: string[];
      };
    }>;
  }>(`${VOIDLY_API}/v1/censorship-index`);

  const ranked = data.countries
    .filter(c => c.ooni && c.ooni.measurementCount > 100)
    .sort((a, b) => (b.ooni?.anomalyRate || 0) - (a.ooni?.anomalyRate || 0))
    .slice(0, limit);

  let result = `# Most Censored Countries (Top ${limit})\n\n`;
  result += `Based on OONI measurement anomaly rates from the past 7 days.\n\n`;

  ranked.forEach((c, i) => {
    const pct = ((c.ooni?.anomalyRate || 0) * 100).toFixed(1);
    result += `## ${i + 1}. ${c.name} (${c.country})\n`;
    result += `- Anomaly Rate: ${pct}%\n`;
    result += `- Measurements: ${c.ooni?.measurementCount.toLocaleString()}\n`;
    if (c.ooni?.affectedServices && c.ooni.affectedServices.length) {
      result += `- Affected: ${c.ooni.affectedServices.slice(0, 5).join(', ')}\n`;
    }
    result += '\n';
  });

  result += `## Source\n`;
  result += `Data: Voidly Research Global Censorship Index\n`;
  result += `Methodology: Based on OONI network interference measurements\n`;
  result += `URL: https://voidly.ai/censorship-index\n`;

  return result;
}

async function getActiveIncidents(): Promise<string> {
  const data = await fetchJson<{
    count: number;
    incidents: Array<{
      id: string;
      country: string;
      countryName: string;
      title: string;
      description: string;
      severity: string;
      status: string;
      startTime: string;
      affectedServices: string[];
    }>;
  }>(`${VOIDLY_DATA_API}/incidents?status=active&limit=50`);

  let result = `# Active Censorship Incidents\n\n`;
  result += `Total: ${data.count} incidents\n\n`;

  if (data.incidents.length === 0) {
    result += `No active incidents currently reported.\n`;
  } else {
    data.incidents.slice(0, 20).forEach(i => {
      result += `## ${i.countryName}: ${i.title}\n`;
      result += `- Severity: ${i.severity.toUpperCase()}\n`;
      result += `- Status: ${i.status}\n`;
      result += `- Started: ${i.startTime}\n`;
      if (i.affectedServices.length) {
        result += `- Affected Services: ${i.affectedServices.join(', ')}\n`;
      }
      if (i.description) {
        result += `- Details: ${i.description.slice(0, 200)}${i.description.length > 200 ? '...' : ''}\n`;
      }
      result += '\n';
    });
  }

  result += `## Source\n`;
  result += `Data: Voidly Research Incident Tracker\n`;
  result += `URL: https://voidly.ai/censorship-index\n`;

  return result;
}

async function checkVpnAccessibility(countryCode?: string, provider?: string): Promise<string> {
  // Build query params
  const params = new URLSearchParams();
  if (countryCode) params.set('country', countryCode.toUpperCase());
  if (provider) params.set('provider', provider.toLowerCase());

  const data = await fetchJson<{
    query: { country?: string; provider?: string };
    stats: {
      total_probes: number;
      probe_nodes: number;
      targets_tested: number;
      total_accessible: number;
      total_blocked: number;
    };
    by_provider: Array<{
      provider: string;
      total_probes: number;
      accessible: number;
      blocked: number;
      accessibility_rate: number;
      targets: Array<{
        host: string;
        location: string;
        accessible_rate: number;
        blocked_rate: number;
        block_types: string[];
      }>;
    }>;
    updated_at: string;
  }>(`${VOIDLY_API}/v1/vpn-accessibility?${params}`);

  let result = `# VPN Accessibility Report\n\n`;
  result += `**Updated:** ${data.updated_at}\n\n`;

  if (countryCode) {
    const name = COUNTRY_NAMES[countryCode.toUpperCase()] || countryCode;
    result += `**Testing from:** ${name}\n\n`;
  }

  // Overall stats
  result += `## Summary\n`;
  result += `- Total Probes (24h): ${data.stats.total_probes.toLocaleString()}\n`;
  result += `- Probe Nodes: ${data.stats.probe_nodes}\n`;
  result += `- VPN Endpoints Tested: ${data.stats.targets_tested}\n`;
  result += `- Accessible: ${data.stats.total_accessible}\n`;
  result += `- Blocked: ${data.stats.total_blocked}\n\n`;

  // By provider
  result += `## Accessibility by Provider\n\n`;

  for (const prov of data.by_provider) {
    const accessPct = (prov.accessibility_rate * 100).toFixed(1);
    const status = prov.accessibility_rate > 0.8 ? '✅' : prov.accessibility_rate > 0.3 ? '⚠️' : '❌';

    result += `### ${status} ${prov.provider.charAt(0).toUpperCase() + prov.provider.slice(1)}\n`;
    result += `- Accessibility Rate: ${accessPct}%\n`;
    result += `- Probes: ${prov.total_probes} (${prov.accessible} accessible, ${prov.blocked} blocked)\n\n`;

    // Show blocked endpoints
    const blocked = prov.targets.filter(t => t.blocked_rate > 0.5);
    if (blocked.length > 0) {
      result += `**Blocked Endpoints:**\n`;
      for (const t of blocked.slice(0, 5)) {
        result += `- ${t.location}: ${t.block_types.join(', ') || 'blocked'}\n`;
      }
      result += '\n';
    }
  }

  result += `## Interpretation\n`;
  const overallRate = data.stats.total_accessible / Math.max(data.stats.total_accessible + data.stats.total_blocked, 1);
  if (overallRate > 0.9) {
    result += `VPN services are generally accessible. Most endpoints can be reached without interference.\n`;
  } else if (overallRate > 0.5) {
    result += `VPN services are partially blocked. Some endpoints are inaccessible, indicating selective VPN blocking.\n`;
  } else {
    result += `VPN services are heavily blocked. Most endpoints cannot be reached, indicating comprehensive VPN censorship.\n`;
  }

  result += `\n## Source\n`;
  result += `Data: Voidly Probe Network\n`;
  result += `Unique: Only Voidly provides global VPN accessibility data\n`;
  result += `License: CC BY 4.0\n`;

  return result;
}

async function verifyClaim(claim: string, requireEvidence: boolean = false): Promise<string> {
  // Use POST for verify-claim
  const response = await agentFetch(`${VOIDLY_API}/verify-claim`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json' },
    body: JSON.stringify({ claim, require_evidence: requireEvidence }) });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`API request failed: ${response.status} ${response.statusText}${body ? ` — ${body.slice(0, 200)}` : ''}`);
  }

  const data = await response.json() as {
    claim: string;
    verdict: string;
    confidence: number;
    reason: string;
    parsed: {
      country: string | null;
      country_code: string | null;
      service: string | null;
      date: string | null;
      date_range: { start: string; end: string } | null;
    };
    incidents: Array<{
      id: string;
      title: string;
      type: string;
      severity: string;
      confidence: number;
      status: string;
      startTime: string;
      permalink: string;
    }>;
    evidence?: Array<{
      source: string;
      kind: string;
      permalink: string;
      observedAt: string;
      claim: string;
      confidence: number;
    }>;
    citation?: string;
  };

  let result = `# Claim Verification\n\n`;
  result += `**Claim:** "${data.claim}"\n\n`;

  // Verdict with emoji
  const verdictEmoji: Record<string, string> = {
    confirmed: '✅',
    likely: '🟡',
    unconfirmed: '❓',
    no_data: '⚪',
    insufficient_data: '⚠️' };
  result += `## Verdict: ${verdictEmoji[data.verdict] || ''} ${data.verdict.toUpperCase()}\n\n`;
  result += `**Confidence:** ${(data.confidence * 100).toFixed(0)}%\n`;
  result += `**Reason:** ${data.reason}\n\n`;

  // Parsed components
  result += `## Parsed Claim\n`;
  if (data.parsed.country) {
    result += `- Country: ${data.parsed.country} (${data.parsed.country_code})\n`;
  }
  if (data.parsed.service) {
    result += `- Service: ${data.parsed.service}\n`;
  }
  if (data.parsed.date) {
    result += `- Date: ${data.parsed.date}\n`;
  }
  if (data.parsed.date_range) {
    result += `- Date Range: ${data.parsed.date_range.start} to ${data.parsed.date_range.end}\n`;
  }
  result += '\n';

  // Matching incidents
  if (data.incidents && data.incidents.length > 0) {
    result += `## Supporting Incidents\n\n`;
    data.incidents.forEach((inc, i) => {
      result += `### ${i + 1}. ${inc.title}\n`;
      result += `- ID: ${inc.id}\n`;
      result += `- Status: ${inc.status}\n`;
      result += `- Severity: ${inc.severity}\n`;
      result += `- Confidence: ${(inc.confidence * 100).toFixed(0)}%\n`;
      result += `- Started: ${inc.startTime.slice(0, 10)}\n`;
      result += `- Permalink: ${inc.permalink}\n\n`;
    });
  }

  // Evidence if requested
  if (data.evidence && data.evidence.length > 0) {
    result += `## Evidence Chain\n\n`;
    data.evidence.forEach((ev, i) => {
      result += `${i + 1}. **${ev.source.toUpperCase()}** (${ev.kind})\n`;
      result += `   - Observed: ${ev.observedAt.slice(0, 10)}\n`;
      result += `   - Confidence: ${(ev.confidence * 100).toFixed(0)}%\n`;
      if (ev.permalink) {
        result += `   - Verify: ${ev.permalink}\n`;
      }
      result += '\n';
    });
  }

  // Citation
  if (data.citation) {
    result += `## Citation\n\n`;
    result += `${data.citation}\n\n`;
  }

  result += `## Source\n`;
  result += `Data: Voidly Research Claim Verification API\n`;
  result += `License: CC BY 4.0\n`;

  return result;
}

async function getIspStatus(countryCode: string): Promise<string> {
  const code = countryCode.toUpperCase();
  const countryName = COUNTRY_NAMES[code] || code;

  const data = await fetchJson<{
    country: string;
    generated: string;
    period: string;
    summary: {
      total_isps: number;
      critical_isps: number;
      high_isps: number;
      medium_isps: number;
      low_isps: number;
      average_block_rate: number;
    };
    isps: Array<{
      asn: string;
      name: string;
      block_rate: number;
      threat_level: string;
      measurements: number;
      blocked_count: number;
      top_blocked_domains: Array<{ domain: string; block_rate: number; measurements: number }>;
    }>;
  }>(`${VOIDLY_DATA_API}/country/${code}/isps`);

  let result = `# ISP Blocking Status: ${countryName}\n\n`;
  result += `**Period:** ${data.period}\n`;
  result += `**Generated:** ${data.generated}\n\n`;

  // Summary
  result += `## Summary\n`;
  result += `- Total ISPs monitored: ${data.summary.total_isps}\n`;
  result += `- Critical (>70% blocking): ${data.summary.critical_isps}\n`;
  result += `- High (50-70% blocking): ${data.summary.high_isps}\n`;
  result += `- Medium (30-50% blocking): ${data.summary.medium_isps}\n`;
  result += `- Low (<30% blocking): ${data.summary.low_isps}\n`;
  result += `- Average block rate: ${(data.summary.average_block_rate * 100).toFixed(1)}%\n\n`;

  // ISP breakdown
  result += `## ISP Breakdown\n\n`;

  const sortedISPs = data.isps.sort((a, b) => b.block_rate - a.block_rate);

  for (const isp of sortedISPs.slice(0, 10)) {
    const emoji = isp.threat_level === 'critical' ? '🔴' :
                  isp.threat_level === 'high' ? '🟠' :
                  isp.threat_level === 'medium' ? '🟡' : '🟢';

    result += `### ${emoji} ${isp.name} (${isp.asn})\n`;
    result += `- Block Rate: ${(isp.block_rate * 100).toFixed(1)}%\n`;
    result += `- Threat Level: ${isp.threat_level}\n`;
    result += `- Measurements: ${isp.measurements}\n`;

    if (isp.top_blocked_domains.length > 0) {
      result += `- Top Blocked: ${isp.top_blocked_domains.slice(0, 5).map(d => d.domain).join(', ')}\n`;
    }
    result += '\n';
  }

  if (data.isps.length > 10) {
    result += `\n*${data.isps.length - 10} more ISPs not shown*\n`;
  }

  result += `\n## Interpretation\n`;
  if (data.summary.critical_isps > data.summary.total_isps / 2) {
    result += `Majority of ISPs show heavy blocking - indicates nationwide censorship policy.\n`;
  } else if (data.summary.critical_isps > 0) {
    result += `Some ISPs block more than others - may indicate selective or ISP-level blocking.\n`;
  } else {
    result += `Low blocking across ISPs - country has relatively open internet.\n`;
  }

  result += `\n## Source\n`;
  result += `Data: Voidly ISP Monitoring (via OONI measurements)\n`;
  result += `Unique: ISP-level granularity for censorship analysis\n`;
  result += `License: CC BY 4.0\n`;

  return result;
}

async function getDomainStatus(domain: string): Promise<string> {
  const data = await fetchJson<{
    domain: string;
    generated: string;
    period: string;
    status: string;
    summary: {
      blocked_in_countries: number;
      total_blocking_isps: number;
    };
    blocked_in: Array<{
      country: string;
      isps: Array<{ asn: string; name: string; block_rate: number; measurements: number }>;
    }>;
  }>(`${VOIDLY_DATA_API}/domain/${encodeURIComponent(domain)}`);

  let result = `# Domain Status: ${data.domain}\n\n`;
  result += `**Period:** ${data.period}\n`;
  result += `**Generated:** ${data.generated}\n\n`;

  // Overall status
  const statusEmoji = data.status === 'blocked' ? '🚫' : '✅';
  result += `## Status: ${statusEmoji} ${data.status.toUpperCase()}\n\n`;

  result += `### Summary\n`;
  result += `- Blocked in: ${data.summary.blocked_in_countries} countries\n`;
  result += `- By ${data.summary.total_blocking_isps} ISPs total\n\n`;

  if (data.blocked_in.length === 0) {
    result += `This domain appears accessible worldwide based on recent measurements.\n`;
  } else {
    result += `## Countries Blocking This Domain\n\n`;

    for (const country of data.blocked_in.slice(0, 15)) {
      const countryName = COUNTRY_NAMES[country.country] || country.country;
      result += `### ${countryName} (${country.country})\n`;
      result += `- Blocking ISPs: ${country.isps.length}\n`;

      const topISPs = country.isps.slice(0, 3);
      if (topISPs.length > 0) {
        result += `- ISPs: ${topISPs.map(i => i.name).join(', ')}`;
        if (country.isps.length > 3) {
          result += ` (+${country.isps.length - 3} more)`;
        }
        result += '\n';
      }
      result += '\n';
    }

    if (data.blocked_in.length > 15) {
      result += `*${data.blocked_in.length - 15} more countries not shown*\n\n`;
    }
  }

  result += `## Source\n`;
  result += `Data: Voidly Domain Monitoring (via OONI + CensoredPlanet)\n`;
  result += `License: CC BY 4.0\n`;

  return result;
}

async function getDomainHistory(domain: string, days: number = 30, countryCode?: string): Promise<string> {
  const url = `${VOIDLY_DATA_API}/domain/${encodeURIComponent(domain)}/history?days=${days}${countryCode ? `&country=${countryCode}` : ''}`;

  const data = await fetchJson<{
    domain: string;
    period: string;
    currentStatus: string;
    summary: {
      totalDataPoints: number;
      countriesEverBlocked: number;
      countriesCurrentlyBlocking: number;
    };
    countriesBlocking: string[];
    timeline: Array<{
      date: string;
      countries: Record<string, { status: string; blockRate: number; measurements: number }>;
      total_measurements: number;
      total_blocked: number;
    }>;
    generated: string;
  }>(url);

  let result = `# Domain History: ${data.domain}\n\n`;
  result += `**Period:** ${data.period}\n`;
  result += `**Current Status:** ${data.currentStatus === 'blocked' ? '🚫 Blocked' : '✅ Accessible'}\n\n`;

  result += `## Summary\n`;
  result += `- Data points: ${data.summary.totalDataPoints}\n`;
  result += `- Countries ever blocked: ${data.summary.countriesEverBlocked}\n`;
  result += `- Currently blocking: ${data.summary.countriesCurrentlyBlocking}\n\n`;

  if (data.countriesBlocking.length > 0) {
    result += `## Countries That Have Blocked This Domain\n`;
    result += data.countriesBlocking.map(c => `- ${COUNTRY_NAMES[c] || c} (${c})`).join('\n');
    result += '\n\n';
  }

  if (data.timeline.length > 0) {
    result += `## Recent Timeline (Last ${Math.min(7, data.timeline.length)} Days)\n\n`;

    for (const day of data.timeline.slice(0, 7)) {
      const countries = Object.entries(day.countries);
      const blocked = countries.filter(([_, c]) => c.status === 'blocked');
      const accessible = countries.filter(([_, c]) => c.status === 'accessible');

      result += `### ${day.date}\n`;
      result += `- Total measurements: ${day.total_measurements}\n`;
      if (blocked.length > 0) {
        result += `- 🚫 Blocked in: ${blocked.map(([code, _]) => COUNTRY_NAMES[code] || code).join(', ')}\n`;
      }
      if (accessible.length > 0) {
        result += `- ✅ Accessible in: ${accessible.slice(0, 5).map(([code, _]) => COUNTRY_NAMES[code] || code).join(', ')}`;
        if (accessible.length > 5) result += ` (+${accessible.length - 5} more)`;
        result += '\n';
      }
      result += '\n';
    }
  }

  result += `## Source\n`;
  result += `Data: Voidly Historical Evidence Database\n`;
  result += `License: CC BY 4.0\n`;

  return result;
}

async function getRiskForecast(countryCode: string): Promise<string> {
  const code = countryCode.toUpperCase();
  const countryName = COUNTRY_NAMES[code] || code;

  const data = await fetchJson<{
    country: string;
    country_name: string;
    forecast: Array<{
      day: number;
      date: string;
      risk: number;
      drivers: string[];
    }>;
    summary: {
      max_risk: number;
      max_risk_day: number;
      avg_risk: number;
      key_drivers: string[];
    };
    confidence: number;
    model_version: string;
    generated_at: string;
  }>(`${VOIDLY_API}/v1/forecast/${code}/7day`);

  let result = `# 7-Day Risk Forecast: ${countryName}\n\n`;
  result += `**Generated:** ${data.generated_at}\n`;
  result += `**Model Confidence:** ${(data.confidence * 100).toFixed(0)}%\n\n`;

  // Summary
  result += `## Summary\n`;
  result += `- Peak Risk: ${(data.summary.max_risk * 100).toFixed(1)}% (Day ${data.summary.max_risk_day})\n`;
  result += `- Average Risk: ${(data.summary.avg_risk * 100).toFixed(1)}%\n`;

  if (data.summary.key_drivers.length > 0) {
    result += `- Risk Drivers: ${data.summary.key_drivers.join(', ')}\n`;
  }
  result += '\n';

  // Daily forecast
  result += `## Daily Forecast\n\n`;
  result += `| Day | Date | Risk | Drivers |\n`;
  result += `|-----|------|------|--------|\n`;

  for (const day of data.forecast) {
    const riskEmoji = day.risk >= 0.5 ? '🔴' : day.risk >= 0.3 ? '🟠' : day.risk >= 0.15 ? '🟡' : '🟢';
    const drivers = day.drivers.length > 0 ? day.drivers.join(', ') : '-';
    result += `| ${day.day === 0 ? 'Today' : `+${day.day}`} | ${day.date} | ${riskEmoji} ${(day.risk * 100).toFixed(1)}% | ${drivers} |\n`;
  }

  // Interpretation
  result += `\n## Risk Interpretation\n`;
  if (data.summary.max_risk >= 0.5) {
    result += `⚠️ **CRITICAL RISK**: High probability of censorship events in the next 7 days. `;
    if (data.summary.key_drivers.length > 0) {
      result += `Key drivers: ${data.summary.key_drivers.join(', ')}.`;
    }
    result += '\n';
  } else if (data.summary.max_risk >= 0.3) {
    result += `⚡ **ELEVATED RISK**: Moderate probability of censorship activity. Monitor closely.\n`;
  } else if (data.summary.max_risk >= 0.15) {
    result += `📊 **NORMAL RISK**: Typical censorship levels expected for this country.\n`;
  } else {
    result += `✅ **LOW RISK**: Below-average censorship activity expected.\n`;
  }

  result += `\n## Source\n`;
  result += `Data: Voidly Predictive Risk Model (${data.model_version})\n`;
  result += `Trained on: Historical shutdowns, election calendars, protest patterns\n`;
  result += `License: CC BY 4.0\n`;

  return result;
}

async function getHighRiskCountries(threshold: number = 0.2): Promise<string> {
  const data = await fetchJson<{
    high_risk_countries: Array<{
      country: string;
      country_name: string;
      max_risk: number;
      max_risk_day: number;
      drivers: string[];
    }>;
    count: number;
    threshold: number;
    generated_at: string;
  }>(`${VOIDLY_API}/v1/forecast/high-risk?threshold=${threshold}`);

  let result = `# High-Risk Countries (7-Day Forecast)\n\n`;
  result += `**Threshold:** ${(data.threshold * 100).toFixed(0)}%+ risk\n`;
  result += `**Countries at Risk:** ${data.count}\n`;
  result += `**Generated:** ${data.generated_at}\n\n`;

  if (data.high_risk_countries.length === 0) {
    result += `No countries currently exceed the ${(threshold * 100).toFixed(0)}% risk threshold.\n`;
  } else {
    result += `## Countries at Elevated Risk\n\n`;

    for (const country of data.high_risk_countries.slice(0, 15)) {
      const riskEmoji = country.max_risk >= 0.5 ? '🔴' : country.max_risk >= 0.3 ? '🟠' : '🟡';

      result += `### ${riskEmoji} ${country.country_name} (${country.country})\n`;
      result += `- Peak Risk: ${(country.max_risk * 100).toFixed(1)}%\n`;
      result += `- Peak Day: +${country.max_risk_day} days\n`;
      if (country.drivers.length > 0) {
        result += `- Drivers: ${country.drivers.join(', ')}\n`;
      }
      result += '\n';
    }

    if (data.high_risk_countries.length > 15) {
      result += `*${data.high_risk_countries.length - 15} more countries not shown*\n\n`;
    }
  }

  result += `## Source\n`;
  result += `Data: Voidly Predictive Risk Model\n`;
  result += `Features: Election calendars, protest anniversaries, historical patterns\n`;
  result += `License: CC BY 4.0\n`;

  return result;
}

async function compareCountries(country1: string, country2: string): Promise<string> {
  // Fetch both country statuses
  const [status1, status2] = await Promise.all([
    fetchJson<any>(`${VOIDLY_DATA_API}/country/${country1.toUpperCase()}`),
    fetchJson<any>(`${VOIDLY_DATA_API}/country/${country2.toUpperCase()}`),
  ]);

  const name1 = COUNTRY_NAMES[country1.toUpperCase()] || country1;
  const name2 = COUNTRY_NAMES[country2.toUpperCase()] || country2;

  let result = `# Censorship Comparison: ${name1} vs ${name2}\n\n`;

  // Risk levels
  const getRiskEmoji = (score: number) => {
    if (score >= 0.8) return '🔴 Critical';
    if (score >= 0.6) return '🟠 High';
    if (score >= 0.4) return '🟡 Medium';
    if (score >= 0.2) return '🟢 Low';
    return '⚪ Minimal';
  };

  result += `## Risk Levels\n\n`;
  result += `| Country | Score | Risk Level |\n`;
  result += `|---------|-------|------------|\n`;
  result += `| ${name1} | ${(status1.score || 0).toFixed(2)} | ${getRiskEmoji(status1.score || 0)} |\n`;
  result += `| ${name2} | ${(status2.score || 0).toFixed(2)} | ${getRiskEmoji(status2.score || 0)} |\n\n`;

  // Measurement coverage
  result += `## Data Coverage\n\n`;
  result += `| Country | Measurements | Anomaly Rate |\n`;
  result += `|---------|--------------|---------------|\n`;
  result += `| ${name1} | ${(status1.ooni?.measurementCount || 0).toLocaleString()} | ${((status1.ooni?.anomalyRate || 0) * 100).toFixed(1)}% |\n`;
  result += `| ${name2} | ${(status2.ooni?.measurementCount || 0).toLocaleString()} | ${((status2.ooni?.anomalyRate || 0) * 100).toFixed(1)}% |\n\n`;

  // Comparison summary
  const scoreDiff = Math.abs((status1.score || 0) - (status2.score || 0));
  const moreRestrictive = (status1.score || 0) > (status2.score || 0) ? name1 : name2;

  result += `## Comparison Summary\n\n`;
  if (scoreDiff < 0.1) {
    result += `Both countries have similar censorship levels.\n`;
  } else if (scoreDiff < 0.3) {
    result += `${moreRestrictive} is somewhat more restrictive.\n`;
  } else {
    result += `${moreRestrictive} has significantly higher censorship levels.\n`;
  }

  result += `\n## Source\n`;
  result += `Data: Voidly Global Censorship Index\n`;
  result += `License: CC BY 4.0\n`;

  return result;
}

async function getPlatformRisk(platform: string, countryCode?: string): Promise<string> {
  const p = platform.toLowerCase();
  let data: any;

  if (countryCode) {
    data = await fetchJson<any>(`${VOIDLY_API}/v1/platform/${p}/risk/${countryCode.toUpperCase()}`);
  } else {
    data = await fetchJson<any>(`${VOIDLY_API}/v1/platform/${p}/risk`);
  }

  let result = `# Platform Risk: ${data.label || platform}\n\n`;

  if (countryCode && data.country) {
    result += `**Country:** ${data.countryName}\n`;
    result += `**Risk Score:** ${(data.score * 100).toFixed(1)}%\n`;
    result += `**Block Rate:** ${(data.blockRate * 100).toFixed(1)}%\n`;
    result += `**Methods:** ${data.methods?.join(', ') || 'none detected'}\n`;
    result += `**Evidence:** ${data.evidenceCount} measurements\n`;
  } else {
    result += `**Global Score:** ${((data.globalScore || 0) * 100).toFixed(1)}%\n`;
    result += `**Countries Blocking:** ${data.countriesBlocking || 0}\n\n`;

    if (data.blockedIn && data.blockedIn.length > 0) {
      result += `## Top Countries Blocking ${data.label}\n\n`;
      result += `| Country | Score | Block Rate | Methods |\n`;
      result += `|---------|-------|------------|--------|\n`;
      for (const c of data.blockedIn.slice(0, 15)) {
        result += `| ${c.countryName} | ${(c.score * 100).toFixed(0)}% | ${(c.blockRate * 100).toFixed(0)}% | ${c.methods?.join(', ') || '-'} |\n`;
      }
    }
  }

  result += `\n## Source\nData: Voidly Platform Risk Index\nLicense: CC BY 4.0\n`;
  return result;
}

async function getIspRiskIndex(countryCode: string): Promise<string> {
  const cc = countryCode.toUpperCase();
  const data = await fetchJson<any>(`${VOIDLY_API}/v1/isp/index?country=${cc}`);

  let result = `# ISP Risk Index: ${data.countryName || cc}\n\n`;
  result += `**ISPs Analyzed:** ${data.ispCount || 0}\n\n`;

  if (data.isps && data.isps.length > 0) {
    result += `## ISP Rankings\n\n`;
    result += `| Rank | ISP | Score | Block Rate | Methods | Categories |\n`;
    result += `|------|-----|-------|------------|---------|------------|\n`;
    data.isps.slice(0, 20).forEach((isp: any, i: number) => {
      result += `| ${i + 1} | ${isp.name || `AS${isp.asn}`} | ${isp.compositeScore?.toFixed(1)} | ${(isp.blockRate * 100).toFixed(0)}% | ${isp.methods?.slice(0, 2).join(', ') || '-'} | ${isp.blockedCategories?.slice(0, 3).join(', ') || '-'} |\n`;
    });
  } else {
    result += `No ISP censorship data available for ${cc}.\n`;
  }

  result += `\n## Source\nData: Voidly ISP Risk Index\nLicense: CC BY 4.0\n`;
  return result;
}

async function checkServiceAccessibility(domain: string, countryCode: string): Promise<string> {
  const cc = countryCode.toUpperCase();
  const data = await fetchJson<any>(`${VOIDLY_API}/v1/accessibility/check?domain=${encodeURIComponent(domain)}&country=${cc}`);

  const statusEmoji = data.status === 'accessible' ? '✅' : data.status === 'blocked' ? '🚫' : data.status === 'partially_blocked' ? '⚠️' : '❓';

  let result = `# Service Accessibility: ${domain} in ${data.countryName || cc}\n\n`;
  result += `**Status:** ${statusEmoji} ${data.status?.toUpperCase()}\n`;
  if (data.accessibilityScore !== null) {
    result += `**Accessibility Score:** ${(data.accessibilityScore * 100).toFixed(0)}%\n`;
  }
  if (data.blockingMethod) {
    result += `**Blocking Method:** ${data.blockingMethod}\n`;
  }
  result += `**Confidence:** ${((data.confidence || 0) * 100).toFixed(0)}%\n`;
  result += `**Evidence:** ${data.evidenceCount || 0} measurements\n`;
  result += `**Checked:** ${data.checkedAt}\n`;

  result += `\n## Source\nData: Voidly Service Accessibility API\nLicense: CC BY 4.0\n`;
  return result;
}

async function getElectionRisk(countryCode: string): Promise<string> {
  const cc = countryCode.toUpperCase();
  const data = await fetchJson<any>(`${VOIDLY_API}/v1/elections/${cc}/briefing`);

  let result = `# Election Risk Briefing: ${data.countryName || cc}\n\n`;

  // Risk assessment
  const riskEmoji = data.riskAssessment?.level === 'critical' ? '🔴' : data.riskAssessment?.level === 'elevated' ? '🟠' : '🟢';
  result += `**Risk Level:** ${riskEmoji} ${data.riskAssessment?.level?.toUpperCase() || 'UNKNOWN'}\n`;
  result += `**Risk Tier:** ${data.riskTier || 0}/4\n\n`;

  // Upcoming elections
  if (data.upcomingElections && data.upcomingElections.length > 0) {
    result += `## Upcoming Elections\n\n`;
    for (const e of data.upcomingElections) {
      result += `- **${e.title || e.type}** on ${e.date} (importance: ${e.importance})\n`;
    }
    result += '\n';
  } else {
    result += `No upcoming elections found for ${cc} in the next 180 days.\n\n`;
  }

  // Historical pattern
  if (data.historicalPattern) {
    const hp = data.historicalPattern;
    result += `## Historical Election Pattern\n\n`;
    result += `- Past elections tracked: ${hp.past_elections}\n`;
    result += `- Incidents around elections: ${hp.incidents_around_elections}\n`;
    result += `- Avg incidents per election: ${hp.avg_incidents_per_election}\n`;
    result += `- Historical risk: ${hp.historical_risk}\n\n`;
  }

  // Risk factors
  if (data.riskAssessment?.factors && data.riskAssessment.factors.length > 0) {
    result += `## Risk Factors\n\n`;
    for (const f of data.riskAssessment.factors) {
      result += `- ${f}\n`;
    }
    result += '\n';
  }

  // 7-day forecast summary
  if (data.forecastSummary) {
    result += `## 7-Day Forecast\n\n`;
    result += `- Peak risk: ${(data.forecastSummary.max_risk * 100).toFixed(1)}% (day ${data.forecastSummary.max_risk_day})\n`;
    result += `- Average risk: ${(data.forecastSummary.avg_risk * 100).toFixed(1)}%\n`;
    if (data.forecastSummary.key_drivers?.length > 0) {
      result += `- Drivers: ${data.forecastSummary.key_drivers.join(', ')}\n`;
    }
  }

  result += `\n## Source\nData: Voidly Election Risk Model\nLicense: CC BY 4.0\n`;
  return result;
}

async function getProbeNetwork(): Promise<string> {
  const data = await fetchJson<{
    active_nodes: number;
    total_nodes: number;
    coverage_regions: string[];
    probes_24h: number;
    nodes: Array<{
      id: string;
      city: string;
      country: string;
      status: string;
      avg_latency_ms: number;
    }>;
  }>(`${VOIDLY_API}/v1/probe/network`);

  let result = `# Voidly Probe Network Status\n\n`;
  result += `**Active Nodes:** ${data.active_nodes} / ${data.total_nodes}\n`;
  result += `**Coverage Regions:** ${data.coverage_regions.join(', ')}\n`;
  result += `**Probes (24h):** ${data.probes_24h.toLocaleString()}\n\n`;

  result += `## Node Status\n\n`;
  result += `| Node | City | Country | Status | Avg Latency |\n`;
  result += `|------|------|---------|--------|-------------|\n`;

  for (const node of data.nodes) {
    const statusEmoji = node.status === 'active' ? '🟢' : node.status === 'degraded' ? '🟡' : '🔴';
    result += `| ${node.id} | ${node.city} | ${node.country} | ${statusEmoji} ${node.status} | ${node.avg_latency_ms}ms |\n`;
  }

  result += `\n## Source\n`;
  result += `Data: Voidly Probe Network\n`;
  result += `License: CC BY 4.0\n`;

  return result;
}

async function checkDomainProbes(domain: string): Promise<string> {
  const data = await fetchJson<{
    domain: string;
    total_probes_24h: number;
    blocked_count: number;
    nodes: Array<{
      node_id: string;
      country: string;
      status: string;
      latency_ms: number;
      blocking_method: string | null;
      blocking_entity: string | null;
      sni_blocked: boolean;
      dns_poisoned: boolean;
      blocking_type: string;
    }>;
    attribution: {
      methods_seen: string[];
      entities_detected: string[];
      geographic_consensus: string;
      sni_detected: number;
      dns_poisoning_detected: number;
      cert_anomalies: boolean;
      blocking_types: string[];
    };
  }>(`${VOIDLY_API}/v1/probe/domain/${encodeURIComponent(domain)}`);

  let result = `# Probe Results: ${data.domain}\n\n`;
  result += `**Total Probes (24h):** ${data.total_probes_24h}\n`;
  result += `**Blocked:** ${data.blocked_count}\n\n`;

  result += `## Per-Node Breakdown\n\n`;
  result += `| Node | Country | Status | Latency | Blocking Method | Entity | SNI Blocked | DNS Poisoned | Blocking Type |\n`;
  result += `|------|---------|--------|---------|-----------------|--------|-------------|--------------|---------------|\n`;

  for (const node of data.nodes) {
    const statusEmoji = node.status === 'accessible' ? '✅' : node.status === 'blocked' ? '🚫' : '⚠️';
    result += `| ${node.node_id} | ${node.country} | ${statusEmoji} ${node.status} | ${node.latency_ms}ms | ${node.blocking_method || '-'} | ${node.blocking_entity || '-'} | ${node.sni_blocked ? 'Yes' : 'No'} | ${node.dns_poisoned ? 'Yes' : 'No'} | ${node.blocking_type || '-'} |\n`;
  }

  result += `\n## Attribution Summary\n\n`;
  if (data.attribution.methods_seen.length > 0) {
    result += `- **Methods Seen:** ${data.attribution.methods_seen.join(', ')}\n`;
  }
  if (data.attribution.entities_detected.length > 0) {
    result += `- **Entities Detected:** ${data.attribution.entities_detected.join(', ')}\n`;
  }
  result += `- **Geographic Consensus:** ${data.attribution.geographic_consensus}\n`;
  result += `- **SNI Blocking Detected:** ${data.attribution.sni_detected} nodes\n`;
  result += `- **DNS Poisoning Detected:** ${data.attribution.dns_poisoning_detected} nodes\n`;
  result += `- **Cert Anomalies:** ${data.attribution.cert_anomalies ? 'Yes' : 'No'}\n`;
  if (data.attribution.blocking_types.length > 0) {
    result += `- **Blocking Types:** ${data.attribution.blocking_types.join(', ')}\n`;
  }

  result += `\n## Source\n`;
  result += `Data: Voidly Probe Network\n`;
  result += `License: CC BY 4.0\n`;

  return result;
}


async function getIncidentDetail(incidentId: string): Promise<string> {
  const data = await fetchJson<{
    id: string;
    hashId: string;
    country: string;
    countryName: string;
    title: string;
    description: string;
    severity: string;
    incidentType: string;
    confidence: number;
    domains: string[];
    blockingMethods: string[];
    evidenceCount: number;
    createdAt: string;
    updatedAt: string;
  }>(`${VOIDLY_DATA_API}/incidents/${encodeURIComponent(incidentId)}`);

  let result = `# Incident: ${data.title}\n\n`;
  result += `**ID:** ${data.hashId} (${data.id})\n`;
  result += `**Country:** ${data.countryName} (${data.country})\n`;
  result += `**Severity:** ${data.severity.toUpperCase()}\n`;
  result += `**Type:** ${data.incidentType}\n`;
  result += `**Confidence:** ${(data.confidence * 100).toFixed(0)}%\n`;
  result += `**Created:** ${data.createdAt}\n`;
  result += `**Updated:** ${data.updatedAt}\n\n`;

  if (data.description) {
    result += `## Description\n${data.description}\n\n`;
  }

  if (data.domains && data.domains.length > 0) {
    result += `## Affected Domains\n`;
    data.domains.forEach(d => { result += `- ${d}\n`; });
    result += '\n';
  }

  if (data.blockingMethods && data.blockingMethods.length > 0) {
    result += `## Blocking Methods\n`;
    data.blockingMethods.forEach(m => { result += `- ${m}\n`; });
    result += '\n';
  }

  result += `**Evidence Items:** ${data.evidenceCount}\n`;
  result += `**Report:** https://voidly.ai/censorship-index/incidents/${data.hashId}\n\n`;
  result += `## Source\nData: Voidly Incident Database\nLicense: CC BY 4.0\n`;

  return result;
}

async function getIncidentEvidence(incidentId: string): Promise<string> {
  const data = await fetchJson<Record<string, unknown>>(
    `${VOIDLY_DATA_API}/incidents/${encodeURIComponent(incidentId)}/evidence`
  );
  if (!data || !Array.isArray(data.evidence) ||
      data.evidence.some(e => !e || typeof e !== 'object' || Array.isArray(e))) {
    throw new Error('Evidence response is missing valid evidence rows');
  }
  const evidence = data.evidence as Array<Record<string, unknown>>;
  const field = (value: unknown): string | null =>
    typeof value === 'string' && value.trim() ? value.trim() : null;
  const httpsLink = (value: unknown): string | null => {
    const raw = field(value);
    if (!raw) return null;
    try {
      const url = new URL(raw);
      return url.protocol === 'https:' && !url.username && !url.password ? url.toString() : null;
    } catch { return null; }
  };
  const reported = data.count ?? data.evidenceCount;
  const reportedCount = typeof reported === 'number' && Number.isSafeInteger(reported) && reported >= 0
    ? String(reported) : 'not provided';
  const responseId = field(data.incident_id) ?? field(data.incidentId) ?? incidentId;
  const bySource = new Map<string, Array<Record<string, unknown>>>();
  for (const row of evidence) {
    const source = (field(row.source) ?? 'unknown source').toUpperCase();
    const items = bySource.get(source) ?? [];
    items.push(row);
    bySource.set(source, items);
  }
  const shown = [...bySource.values()].reduce((n, items) => n + Math.min(items.length, 10), 0);

  let result = `# Evidence for Incident: ${responseId}\n\n`;
  result += `**Total Evidence Items (API-reported):** ${reportedCount}\n`;
  result += `**Rows returned / shown:** ${evidence.length} / ${shown}\n\n`;

  if (evidence.length === 0) {
    result += `No evidence rows were returned in this response; this alone does not establish that no other evidence exists.\n\n`;
  } else {
    for (const [source, items] of bySource) {
      result += `## ${source} (${items.length} items)\n\n`;
      items.slice(0, 10).forEach((e, i) => {
        const confidence = typeof e.confidence === 'number' && Number.isFinite(e.confidence) &&
          e.confidence >= 0 && e.confidence <= 1 ? `${(e.confidence * 100).toFixed(0)}%` : 'not provided';
        result += `${i + 1}. **${field(e.kind) ?? 'unspecified kind'}**\n`;
        result += `   Observed: ${field(e.observedAt) ?? 'not provided'}\n`;
        result += `   Retrieved: ${field(e.retrievedAt) ?? 'not provided'}\n`;
        result += `   Confidence: ${confidence}\n`;
        result += `   Source reference: ${field(e.sourceRef) ?? 'not provided'}\n`;
        const permalink = httpsLink(e.permalink);
        const sourceUrl = httpsLink(e.sourceUrl);
        if (permalink) result += `   Permalink field (record scope not verified): ${permalink}\n`;
        if (sourceUrl) result += `   Source context URL (record scope not verified): ${sourceUrl}\n`;
        if (!permalink && !sourceUrl) result += `   Source link: not provided\n`;
        result += '\n';
      });
      if (items.length > 10) {
        result += `*${items.length - 10} more ${source} items not shown*\n\n`;
      }
    }
  }

  if (data.corroboration !== undefined) {
    const raw = JSON.stringify(data.corroboration);
    if (raw !== undefined) {
      result += `## Corroboration (uninterpreted API data)\n`;
      result += `${raw.slice(0, 2048)}${raw.length > 2048 ? '… [truncated]' : ''}\n\n`;
    }
  } else {
    result += `**Corroboration metadata:** not provided\n\n`;
  }

  result += `## Source\nData: Voidly Evidence Database (OONI, IODA, CensoredPlanet)\n`;
  result += `Source rights vary; check terms for each linked source.\n`;
  return result;
}

async function getIncidentReport(incidentId: string, format: string = 'markdown'): Promise<string> {
  const response = await agentFetch(
    `${VOIDLY_DATA_API}/incidents/${encodeURIComponent(incidentId)}/report?format=${format}`,
    {
      headers: {
        'Accept': format === 'markdown' ? 'text/markdown' : 'text/plain' } }
  );

  if (!response.ok) {
    throw new Error(`API request failed: ${response.status} ${response.statusText}`);
  }

  const text = await response.text();

  let result = `# Incident Report (${format.toUpperCase()})\n\n`;
  result += `\`\`\`${format === 'bibtex' ? 'bibtex' : format === 'ris' ? '' : 'markdown'}\n`;
  result += text;
  result += `\n\`\`\`\n\n`;
  result += `## Source\nData: Voidly Incident Reports\nLicense: CC BY 4.0\n`;

  return result;
}

async function getCommunityProbes(): Promise<string> {
  const data = await fetchJson<{
    total: number;
    nodes: Array<{
      id: string;
      country: string;
      city: string;
      trustScore: number;
      totalProbes: number;
      blockedConfirmed: number;
      lastSeen: string;
      status: string;
    }>;
  }>(`${VOIDLY_API}/v1/community/nodes?limit=50`);

  let result = `# Community Probe Network\n\n`;
  result += `**Total Nodes:** ${data.total}\n\n`;

  if (data.nodes.length === 0) {
    result += `No community probe nodes currently active.\n`;
    result += `\nRun your own: \`pip install voidly-probe && voidly-probe --consent\`\n`;
  } else {
    result += `## Active Nodes\n\n`;
    result += `| Node | Location | Trust | Probes | Confirmed | Status |\n`;
    result += `|------|----------|-------|--------|-----------|--------|\n`;

    for (const node of data.nodes) {
      const countryName = COUNTRY_NAMES[node.country] || node.country;
      const statusEmoji = node.status === 'active' ? '🟢' : '🔴';
      result += `| ${node.id} | ${node.city}, ${countryName} | ${node.trustScore.toFixed(2)} | ${node.totalProbes} | ${node.blockedConfirmed} | ${statusEmoji} ${node.status} |\n`;
    }
  }

  result += `\n## Join the Network\n`;
  result += `- Install: \`pip install voidly-probe\`\n`;
  result += `- Docker: \`docker run -d emperormew2/voidly-probe\`\n`;
  result += `- PyPI: https://pypi.org/project/voidly-probe/\n`;
  result += `\n## Source\nData: Voidly Community Probe Network\nLicense: CC BY 4.0\n`;

  return result;
}

async function getCommunityLeaderboard(): Promise<string> {
  const data = await fetchJson<{
    leaderboard: Array<{
      rank: number;
      nodeId: string;
      country: string;
      totalProbes: number;
      blockedConfirmed: number;
      trustScore: number;
    }>;
  }>(`${VOIDLY_API}/v1/community/leaderboard`);

  let result = `# Community Probe Leaderboard\n\n`;

  if (!data.leaderboard || data.leaderboard.length === 0) {
    result += `No community probes have submitted data yet.\n`;
    result += `Be the first: \`pip install voidly-probe && voidly-probe --consent\`\n`;
  } else {
    result += `## Top Contributors\n\n`;
    result += `| Rank | Node | Country | Probes | Confirmed | Trust |\n`;
    result += `|------|------|---------|--------|-----------|-------|\n`;

    for (const entry of data.leaderboard.slice(0, 20)) {
      const countryName = COUNTRY_NAMES[entry.country] || entry.country;
      result += `| ${entry.rank} | ${entry.nodeId} | ${countryName} | ${entry.totalProbes} | ${entry.blockedConfirmed} | ${entry.trustScore.toFixed(2)} |\n`;
    }
  }

  result += `\n## Source\nData: Voidly Community Probe Network\nLicense: CC BY 4.0\n`;
  return result;
}

async function getIncidentStats(): Promise<string> {
  const data = await fetchJson<{
    totalIncidents: number;
    totalEvidence: number;
    bySeverity: Record<string, number>;
    byCountry: Record<string, number>;
    bySource?: Record<string, number>;
  }>(`${VOIDLY_DATA_API}/incidents/stats`);

  let result = `# Incident Statistics\n\n`;
  result += `**Total Incidents:** ${data.totalIncidents.toLocaleString()}\n`;
  result += `**Total Evidence:** ${data.totalEvidence.toLocaleString()}\n\n`;

  result += `## By Severity\n`;
  for (const [sev, count] of Object.entries(data.bySeverity)) {
    result += `- ${sev.charAt(0).toUpperCase() + sev.slice(1)}: ${count}\n`;
  }
  result += '\n';

  if (data.bySource) {
    result += `## By Evidence Source\n`;
    for (const [src, count] of Object.entries(data.bySource)) {
      result += `- ${src.toUpperCase()}: ${count.toLocaleString()}\n`;
    }
    result += '\n';
  }

  const topCountries = Object.entries(data.byCountry)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  result += `## Top 10 Countries by Incidents\n`;
  topCountries.forEach(([code, count], i) => {
    const name = COUNTRY_NAMES[code] || code;
    result += `${i + 1}. ${name} (${code}): ${count}\n`;
  });

  result += `\n## Source\nData: Voidly Incident Database\nLicense: CC BY 4.0\n`;
  return result;
}

async function getAlertStats(): Promise<string> {
  const data = await fetchJson<{
    activeSubscriptions: number;
    totalDeliveries24h: number;
    webhookSuccessRate: number;
    countriesMonitored: number;
  }>(`${VOIDLY_API}/api/alerts/stats`);

  let result = `# Alert System Statistics\n\n`;
  result += `**Active Subscriptions:** ${data.activeSubscriptions}\n`;
  result += `**Deliveries (24h):** ${data.totalDeliveries24h}\n`;
  result += `**Webhook Success Rate:** ${(data.webhookSuccessRate * 100).toFixed(1)}%\n`;
  result += `**Countries Monitored:** ${data.countriesMonitored}\n\n`;

  result += `## Subscribe\n`;
  result += `Set up webhook alerts at: https://voidly.ai/api-docs#alerts-webhooks\n\n`;

  result += `## Source\nData: Voidly Alert System\nLicense: CC BY 4.0\n`;
  return result;
}

async function getIncidentsSince(since: string): Promise<string> {
  const data = await fetchJson<{
    since: string;
    count: number;
    incidents: Array<{
      id: string;
      hashId: string;
      country: string;
      countryName: string;
      title: string;
      severity: string;
      confidence: number;
      createdAt: string;
    }>;
  }>(`${VOIDLY_DATA_API}/incidents/delta?since=${encodeURIComponent(since)}`);

  let result = `# Incidents Since ${data.since}\n\n`;
  result += `**New/Updated:** ${data.count} incidents\n\n`;

  if (data.incidents.length === 0) {
    result += `No new incidents since the specified timestamp.\n`;
  } else {
    for (const inc of data.incidents.slice(0, 20)) {
      const sevEmoji = inc.severity === 'critical' ? '🔴' : inc.severity === 'high' ? '🟠' : inc.severity === 'medium' ? '🟡' : '🟢';
      result += `## ${sevEmoji} ${inc.countryName}: ${inc.title}\n`;
      result += `- ID: ${inc.hashId}\n`;
      result += `- Severity: ${inc.severity}\n`;
      result += `- Confidence: ${(inc.confidence * 100).toFixed(0)}%\n`;
      result += `- Created: ${inc.createdAt}\n\n`;
    }

    if (data.incidents.length > 20) {
      result += `*${data.incidents.length - 20} more incidents not shown*\n\n`;
    }
  }

  result += `## Source\nData: Voidly Incident Delta Feed\nLicense: CC BY 4.0\n`;
  return result;
}

// Agent relay tools live in ./relay/ (key custody, untrusted-content marking,
// id checks). This file keeps the censorship-data tools.

// Create MCP server
const server = new Server(
  {
    name: 'voidly-censorship-index',
    version: MCP_VERSION },
  {
    capabilities: {
      tools: {},
      resources: {} } }
);

// Register tool handlers
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'get_censorship_index',
      description: 'Get the Voidly Global Censorship Index - a comprehensive overview of internet censorship across the monitored countries. Returns summary statistics and the most censored countries ranked by anomaly rate.',
      inputSchema: {
        type: 'object' as const,
        properties: {},
        required: [] } },
    {
      name: 'get_country_status',
      description: 'Get detailed censorship status for a specific country including anomaly rates, affected services, and active incidents.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          country_code: {
            type: 'string',
            description: 'ISO 3166-1 alpha-2 country code (e.g., CN for China, IR for Iran, RU for Russia)' } },
        required: ['country_code'] } },
    {
      name: 'check_domain_blocked',
      description: 'Check censorship risk for a domain in a specific country. Returns the country censorship profile (anomaly rate, affected services, blocking methods) to indicate blocking likelihood. For real-time domain-specific probing from Voidly probe nodes, use check_domain_probes instead.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          domain: {
            type: 'string',
            description: 'Domain to check (e.g., google.com, twitter.com)' },
          country_code: {
            type: 'string',
            description: 'ISO 3166-1 alpha-2 country code' } },
        required: ['domain', 'country_code'] } },
    {
      name: 'get_most_censored',
      description: 'Get a ranked list of the most censored countries by anomaly rate.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          limit: {
            type: 'number',
            description: 'Number of countries to return (default: 10, max: 50)' } },
        required: [] } },
    {
      name: 'get_active_incidents',
      description: 'Get currently active censorship incidents worldwide including internet shutdowns, social media blocks, and VPN restrictions.',
      inputSchema: {
        type: 'object' as const,
        properties: {},
        required: [] } },
    {
      name: 'verify_claim',
      description: 'Verify a censorship claim with evidence. Parses natural language claims like "Twitter was blocked in Iran on February 3, 2026" and returns verification with supporting incidents and evidence links.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          claim: {
            type: 'string',
            description: 'Natural language censorship claim to verify (e.g., "Is YouTube blocked in China?", "Twitter was blocked in Iran on February 3, 2026")' },
          require_evidence: {
            type: 'boolean',
            description: 'Whether to include detailed evidence chain with source links (default: false)' } },
        required: ['claim'] } },
    {
      name: 'check_vpn_accessibility',
      description: 'Check VPN accessibility from different countries. Answers questions like "Can users in Iran connect to VPNs?" from tests run by Voidly probe nodes.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          country_code: {
            type: 'string',
            description: 'ISO 3166-1 alpha-2 country code to check VPN accessibility FROM (e.g., IR for Iran, CN for China)' },
          provider: {
            type: 'string',
            description: 'VPN provider to filter by (voidly, nordvpn, protonvpn, mullvad)' } },
        required: [] } },
    {
      name: 'get_isp_status',
      description: 'Get ISP-level blocking data for a country. Shows which ISPs are blocking content and what domains they block. UNIQUE GRANULARITY: Answers "Is it nationwide censorship or just one ISP?"',
      inputSchema: {
        type: 'object' as const,
        properties: {
          country_code: {
            type: 'string',
            description: 'ISO 3166-1 alpha-2 country code (e.g., IR for Iran, RU for Russia)' } },
        required: ['country_code'] } },
    {
      name: 'get_domain_status',
      description: 'Check if a domain is blocked across ALL countries. Returns which countries and ISPs block the domain. Answers "Where in the world is twitter.com blocked?"',
      inputSchema: {
        type: 'object' as const,
        properties: {
          domain: {
            type: 'string',
            description: 'Domain to check (e.g., twitter.com, youtube.com, telegram.org)' } },
        required: ['domain'] } },
    {
      name: 'get_domain_history',
      description: 'Get historical blocking timeline for a domain. Shows day-by-day blocking status across countries. Answers "When was Twitter blocked in Iran?" or "Show me the blocking history for YouTube"',
      inputSchema: {
        type: 'object' as const,
        properties: {
          domain: {
            type: 'string',
            description: 'Domain to check (e.g., twitter.com, youtube.com)' },
          days: {
            type: 'number',
            description: 'Number of days of history (default 30, max 365)' },
          country_code: {
            type: 'string',
            description: 'Optional: Filter to specific country (ISO 2-letter code)' } },
        required: ['domain'] } },
    {
      name: 'compare_countries',
      description: 'Compare censorship status between two countries. Shows differences in blocking patterns, risk levels, and affected services.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          country1: {
            type: 'string',
            description: 'First country code (ISO 2-letter code)' },
          country2: {
            type: 'string',
            description: 'Second country code (ISO 2-letter code)' } },
        required: ['country1', 'country2'] } },
    {
      name: 'get_risk_forecast',
      description: 'Get 7-day predictive censorship risk forecast for a country. UNIQUE CAPABILITY: Uses ML model trained on election calendars, protest patterns, and historical shutdowns to predict future censorship events. Answers "What is the shutdown risk in Iran next week?"',
      inputSchema: {
        type: 'object' as const,
        properties: {
          country_code: {
            type: 'string',
            description: 'ISO 3166-1 alpha-2 country code (e.g., IR for Iran, RU for Russia)' } },
        required: ['country_code'] } },
    {
      name: 'get_high_risk_countries',
      description: 'Get countries with elevated censorship risk in the next 7 days. Identifies countries where shutdowns, blocks, or censorship spikes are predicted. Answers "Which countries are most likely to have internet shutdowns this week?"',
      inputSchema: {
        type: 'object' as const,
        properties: {
          threshold: {
            type: 'number',
            description: 'Minimum risk threshold (0.0-1.0, default 0.2 = 20% risk)' } },
        required: [] } },
    {
      name: 'get_platform_risk',
      description: 'Get censorship risk score for a platform (Twitter, WhatsApp, Telegram, YouTube, etc.) globally or in a specific country. Answers "How blocked is WhatsApp?" and "Which platforms are most censored in Turkey?"',
      inputSchema: {
        type: 'object' as const,
        properties: {
          platform: {
            type: 'string',
            description: 'Platform name: twitter, whatsapp, telegram, youtube, signal, facebook, instagram, tiktok, wikipedia, tor, reddit, medium' },
          country_code: {
            type: 'string',
            description: 'Optional 2-letter country code to filter to specific country' } },
        required: ['platform'] } },
    {
      name: 'get_isp_risk_index',
      description: 'Get ranked ISP censorship index for a country. Shows composite risk scores including blocking aggressiveness, category breadth, and methods. Answers "Which ISPs in Iran censor most?" and "How does this ISP compare?"',
      inputSchema: {
        type: 'object' as const,
        properties: {
          country_code: {
            type: 'string',
            description: '2-letter country code' } },
        required: ['country_code'] } },
    {
      name: 'check_service_accessibility',
      description: 'Check if a service or domain is accessible in a specific country right now. Returns blocking status, method, and confidence. Answers "Can users in Iran access WhatsApp?" or "Is twitter.com blocked in China?"',
      inputSchema: {
        type: 'object' as const,
        properties: {
          domain: {
            type: 'string',
            description: 'Domain name or service name (e.g., twitter.com, whatsapp, youtube.com)' },
          country_code: {
            type: 'string',
            description: '2-letter country code' } },
        required: ['domain', 'country_code'] } },
    {
      name: 'get_election_risk',
      description: 'Get censorship risk briefing for upcoming elections in a country. Combines ML forecast with historical election-censorship patterns. Answers "What is the shutdown risk during Iran\'s election?"',
      inputSchema: {
        type: 'object' as const,
        properties: {
          country_code: {
            type: 'string',
            description: '2-letter country code' } },
        required: ['country_code'] } },
    {
      name: 'get_probe_network',
      description: 'Get real-time status of Voidly\'s probe network. Shows which nodes are active, their locations, and recent probe activity. Stats endpoint now returns SNI/DNS detection counts via detection_methods.',
      inputSchema: {
        type: 'object' as const,
        properties: {},
        required: [] } },
    {
      name: 'check_domain_probes',
      description: 'Check Voidly probe results for a specific domain. Shows real-time blocking status from Voidly probe nodes with blocking method and entity attribution. Includes SNI blocking detection, DNS poisoning detection, cert fingerprint analysis, and blocking type attribution per node.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          domain: {
            type: 'string',
            description: 'Domain to check probe results for (e.g., twitter.com, youtube.com, telegram.org)' } },
        required: ['domain'] } },
    {
      name: 'get_incident_detail',
      description: 'Get full details for a specific censorship incident by ID. Accepts human-readable IDs (IR-2026-0142) or hash IDs. Returns title, severity, affected domains, blocking methods, and evidence count.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          incident_id: {
            type: 'string',
            description: 'Incident ID — human-readable (e.g., IR-2026-0142) or hash ID' } },
        required: ['incident_id'] } },
    {
      name: 'get_incident_evidence',
      description: 'Get evidence rows and available source links for a censorship incident. Source context URLs are not necessarily exact measurement permalinks; inspect each source reference and timestamp.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          incident_id: {
            type: 'string',
            description: 'Incident ID — human-readable (e.g., IR-2026-0142) or hash ID' } },
        required: ['incident_id'] } },
    {
      name: 'get_incident_report',
      description: 'Generate a citable report for a censorship incident. Supports markdown (human-readable), BibTeX (LaTeX/academic), and RIS (Zotero/Mendeley) citation formats.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          incident_id: {
            type: 'string',
            description: 'Incident ID — human-readable (e.g., IR-2026-0142) or hash ID' },
          format: {
            type: 'string',
            description: 'Report format: markdown, bibtex, or ris (default: markdown)' } },
        required: ['incident_id'] } },
    {
      name: 'get_community_probes',
      description: 'List active community probe nodes in Voidly\'s open probe network. Shows node locations, trust scores, and measurement counts. Anyone can run a probe via `pip install voidly-probe`.',
      inputSchema: {
        type: 'object' as const,
        properties: {},
        required: [] } },
    {
      name: 'get_community_leaderboard',
      description: 'Get the community probe leaderboard. Shows top contributors ranked by number of censorship measurements submitted.',
      inputSchema: {
        type: 'object' as const,
        properties: {},
        required: [] } },
    {
      name: 'get_incident_stats',
      description: 'Get aggregate statistics about censorship incidents including total counts, breakdown by severity, by country, and by evidence source.',
      inputSchema: {
        type: 'object' as const,
        properties: {},
        required: [] } },
    {
      name: 'get_alert_stats',
      description: 'Get public statistics about Voidly\'s real-time alert system. Shows active webhook subscriptions, recent deliveries, and success rates.',
      inputSchema: {
        type: 'object' as const,
        properties: {},
        required: [] } },
    {
      name: 'get_incidents_since',
      description: 'Get censorship incidents created or updated after a specific timestamp. Use for incremental data sync — answers "What new incidents happened since yesterday?"',
      inputSchema: {
        type: 'object' as const,
        properties: {
          since: {
            type: 'string',
            description: 'ISO 8601 timestamp (e.g., 2026-02-18T00:00:00Z)' } },
        required: ['since'] } },
    ...SENTINEL_TOOLS.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
    ...RELAY_TOOLS.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
      ...(t.outputSchema ? { outputSchema: t.outputSchema } : {}) })),
  ] }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  const sentinelTool = SENTINEL_TOOL_MAP.get(name);
  if (sentinelTool) {
    try {
      return { content: [{ type: 'text', text: await runSentinelTool(sentinelTool, (args ?? {}) as Record<string, unknown>) }] };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return { content: [{ type: 'text', text: `Error: ${message}` }], isError: true };
    }
  }

  const relayTool = RELAY_TOOL_MAP.get(name);
  if (relayTool) {
    try {
      refuseKeyArguments(args as Record<string, unknown> | undefined);
      const out = await relayTool.handler((args ?? {}) as Record<string, unknown>);
      return {
        content: [{ type: 'text', text: redact(out.text) }],
        ...(out.structured ? { structuredContent: redactDeep(out.structured) } : {}) };
    } catch (error) {
      const word = refusalWord(error);
      // Unexpected errors are reported by class only: their text may carry data
      // this code did not choose to show.
      const message = word && error instanceof Error ? error.message : 'Internal error in the relay tool; nothing more is shown.';
      return {
        content: [{ type: 'text', text: redact(`Error${word ? ` (${word})` : ''}: ${message}`) }],
        isError: true };
    }
  }

  try {
    let result: string;

    switch (name) {
      case 'get_censorship_index':
        result = await getCensorshipIndex();
        break;

      case 'get_country_status':
        if (!args?.country_code) {
          throw new Error('country_code is required');
        }
        result = await getCountryStatus(args.country_code as string);
        break;

      case 'check_domain_blocked':
        if (!args?.domain || !args?.country_code) {
          throw new Error('domain and country_code are required');
        }
        result = await checkDomainBlocked(args.domain as string, args.country_code as string);
        break;

      case 'get_most_censored':
        const limit = Math.min(Math.max(1, (args?.limit as number) || 10), 50);
        result = await getMostCensored(limit);
        break;

      case 'get_active_incidents':
        result = await getActiveIncidents();
        break;

      case 'verify_claim':
        if (!args?.claim) {
          throw new Error('claim is required');
        }
        result = await verifyClaim(
          args.claim as string,
          (args?.require_evidence as boolean) || false
        );
        break;

      case 'check_vpn_accessibility':
        result = await checkVpnAccessibility(
          args?.country_code as string | undefined,
          args?.provider as string | undefined
        );
        break;

      case 'get_isp_status':
        if (!args?.country_code) {
          throw new Error('country_code is required');
        }
        result = await getIspStatus(args.country_code as string);
        break;

      case 'get_domain_status':
        if (!args?.domain) {
          throw new Error('domain is required');
        }
        result = await getDomainStatus(args.domain as string);
        break;

      case 'get_domain_history':
        if (!args?.domain) {
          throw new Error('domain is required');
        }
        result = await getDomainHistory(
          args.domain as string,
          (args?.days as number) || 30,
          args?.country_code as string | undefined
        );
        break;

      case 'compare_countries':
        if (!args?.country1 || !args?.country2) {
          throw new Error('country1 and country2 are required');
        }
        result = await compareCountries(
          args.country1 as string,
          args.country2 as string
        );
        break;

      case 'get_risk_forecast':
        if (!args?.country_code) {
          throw new Error('country_code is required');
        }
        result = await getRiskForecast(args.country_code as string);
        break;

      case 'get_high_risk_countries':
        result = await getHighRiskCountries((args?.threshold as number) || 0.2);
        break;

      case 'get_platform_risk':
        if (!args?.platform) {
          throw new Error('platform is required');
        }
        result = await getPlatformRisk(
          args.platform as string,
          args?.country_code as string | undefined
        );
        break;

      case 'get_isp_risk_index':
        if (!args?.country_code) {
          throw new Error('country_code is required');
        }
        result = await getIspRiskIndex(args.country_code as string);
        break;

      case 'check_service_accessibility':
        if (!args?.domain || !args?.country_code) {
          throw new Error('domain and country_code are required');
        }
        result = await checkServiceAccessibility(
          args.domain as string,
          args.country_code as string
        );
        break;

      case 'get_election_risk':
        if (!args?.country_code) {
          throw new Error('country_code is required');
        }
        result = await getElectionRisk(args.country_code as string);
        break;

      case 'get_probe_network':
        result = await getProbeNetwork();
        break;

      case 'check_domain_probes':
        if (!args?.domain) {
          throw new Error('domain is required');
        }
        result = await checkDomainProbes(args.domain as string);
        break;

      case 'get_incident_detail':
        if (!args?.incident_id) {
          throw new Error('incident_id is required');
        }
        result = await getIncidentDetail(args.incident_id as string);
        break;

      case 'get_incident_evidence':
        if (!args?.incident_id) {
          throw new Error('incident_id is required');
        }
        result = await getIncidentEvidence(args.incident_id as string);
        break;

      case 'get_incident_report':
        if (!args?.incident_id) {
          throw new Error('incident_id is required');
        }
        result = await getIncidentReport(
          args.incident_id as string,
          (args?.format as string) || 'markdown'
        );
        break;

      case 'get_community_probes':
        result = await getCommunityProbes();
        break;

      case 'get_community_leaderboard':
        result = await getCommunityLeaderboard();
        break;

      case 'get_incident_stats':
        result = await getIncidentStats();
        break;

      case 'get_alert_stats':
        result = await getAlertStats();
        break;

      case 'get_incidents_since':
        if (!args?.since) {
          throw new Error('since is required (ISO 8601 timestamp)');
        }
        result = await getIncidentsSince(args.since as string);
        break;

      // Relay tools are dispatched before this switch (see RELAY_TOOL_MAP).

      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [
        {
          type: 'text',
          text: result },
      ] };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${message}` },
      ],
      isError: true };
  }
});

// Register resource handlers for direct data access
server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: [
    {
      uri: 'voidly://censorship-index',
      name: 'Global Censorship Index',
      description: 'Complete censorship index data in JSON format',
      mimeType: 'application/json' },
    {
      uri: 'voidly://methodology',
      name: 'Methodology',
      description: 'Data collection and scoring methodology',
      mimeType: 'application/json' },
  ] }));

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;

  switch (uri) {
    case 'voidly://censorship-index':
      const indexData = await fetchJson(`${VOIDLY_API}/v1/censorship-index`);
      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify(indexData, null, 2) },
        ] };

    case 'voidly://methodology':
      const methodData = await fetchJson(`${VOIDLY_DATA_API}/methodology`);
      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify(methodData, null, 2) },
        ] };

    default:
      throw new Error(`Unknown resource: ${uri}`);
  }
});

// Smithery sandbox export for server scanning
export function createSandboxServer() {
  return server;
}

// Start server — only auto-connect when run directly (not imported by Smithery)
const isDirectRun = !process.env.SMITHERY_SCAN && !process.env.SMITHERY;

// Every log line and every outgoing MCP message passes through the redactor,
// which replaces any relay key or webhook secret this process has held.
for (const level of ['log', 'info', 'warn', 'error', 'debug'] as const) {
  const original = console[level].bind(console);
  console[level] = (...parts: unknown[]) =>
    original(...parts.map((p) => redact(typeof p === 'string' ? p : p instanceof Error ? `${p.name}: ${p.message}` : safeStringify(p))));
}

function safeStringify(value: unknown): string {
  try {
    return typeof value === 'object' ? JSON.stringify(value) ?? String(value) : String(value);
  } catch {
    return String(value);
  }
}

async function startStdio(): Promise<void> {
  const transport = new StdioServerTransport();
  const send = transport.send.bind(transport);
  transport.send = (message) => send(redactDeep(message));
  await server.connect(transport);
  console.error('Voidly MCP Server running on stdio');
}

if (isDirectRun) {
  if (process.argv[2] === 'relay') {
    // Owner command line. Loaded only here, never by the MCP server.
    import('./cli.js')
      .then((cli) => cli.main(process.argv.slice(3)))
      .then((code) => process.exit(code))
      .catch((error) => {
        console.error(`voidly-mcp relay: ${error instanceof Error ? error.message : 'failed'}`);
        process.exit(1);
      });
  } else {
    startStdio().catch((error) => {
      console.error('Fatal error:', error instanceof Error ? error.message : 'unknown');
      process.exit(1);
    });
  }
}
