import { SummaryResult, TraceHop, NodeResult, ChainNode, Finding, RecordInfo } from '../types';

export function exportSummaryAsJSON(summary: SummaryResult) {
  const jsonStr = JSON.stringify(summary, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  a.href = url;
  a.download = `dnswatch-${summary.domain}-${timestamp}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function exportSummaryAsHTML(summary: SummaryResult) {
  const dateStr = new Date().toLocaleString();
  const domain = summary.domain;
  const qtype = summary.query_type;

  const traceHops: TraceHop[] = summary.trace?.hops || [];
  const propResults: NodeResult[] = summary.propagation?.results || [];
  const dnssecChain: ChainNode[] = summary.dnssec?.chain || [];
  const auditFindings: Finding[] = summary.audit?.findings || [];

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DNSWatch Report - ${domain}</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --border: #1f2937;
      --text: #f9fafb;
      --muted: #9ca3af;
      --primary: #6366f1;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      padding: 32px 16px;
      line-height: 1.5;
    }
    .container { max-width: 1000px; margin: 0 auto; }
    header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 24px;
      margin-bottom: 32px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      flex-wrap: wrap;
      gap: 16px;
    }
    h1 { font-size: 24px; font-weight: 800; color: #fff; }
    .badge {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 700;
      font-family: monospace;
    }
    .badge-primary { background: rgba(99, 102, 241, 0.2); color: #818cf8; border: 1px solid #4f46e5; }
    .badge-success { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #059669; }
    .badge-warning { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #d97706; }
    .badge-danger { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #dc2626; }
    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 32px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 24px;
    }
    .card-title {
      font-size: 16px;
      font-weight: 700;
      margin-bottom: 16px;
      color: #e5e7eb;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }
    th {
      background: #1f2937;
      color: var(--muted);
      font-weight: 600;
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      text-transform: uppercase;
      font-size: 11px;
    }
    td { padding: 10px 12px; border-bottom: 1px solid #1f2937; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    .footer { text-align: center; color: var(--muted); font-size: 12px; margin-top: 48px; border-top: 1px solid var(--border); padding-top: 24px; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>⚡ DNSWatch Analysis Report</h1>
        <p style="color: var(--muted); font-size: 13px; margin-top: 4px;">Generated on ${dateStr} by DNSWatch Core Engine</p>
      </div>
      <div>
        <span class="badge badge-primary">Domain: ${domain}</span>
        <span class="badge badge-primary">Type: ${qtype}</span>
      </div>
    </header>

    <div class="metrics">
      <div class="card" style="margin-bottom: 0;">
        <div style="font-size: 12px; color: var(--muted); text-transform: uppercase;">Security Score</div>
        <div style="font-size: 32px; font-weight: 800; color: ${summary.audit && summary.audit.score >= 80 ? '#10b981' : '#f59e0b'};">
          ${summary.audit ? summary.audit.score : 'N/A'}/100 <span style="font-size: 20px;">(${summary.audit?.grade || '-'})</span>
        </div>
      </div>
      <div class="card" style="margin-bottom: 0;">
        <div style="font-size: 12px; color: var(--muted); text-transform: uppercase;">Global Propagation</div>
        <div style="font-size: 32px; font-weight: 800; color: #10b981;">
          ${summary.propagation ? summary.propagation.propagation_rate.toFixed(1) + '%' : 'N/A'}
        </div>
      </div>
      <div class="card" style="margin-bottom: 0;">
        <div style="font-size: 12px; color: var(--muted); text-transform: uppercase;">DNSSEC Status</div>
        <div style="font-size: 32px; font-weight: 800; color: ${summary.dnssec?.overall_status === 'SECURE' ? '#10b981' : '#f87171'};">
          ${summary.dnssec?.overall_status || 'N/A'}
        </div>
      </div>
    </div>

    <!-- Recursive Trace -->
    <div class="card">
      <div class="card-title">🌳 1. Recursive Root-to-Authoritative Trace</div>
      <table>
        <thead>
          <tr>
            <th>Hop</th>
            <th>Zone</th>
            <th>Queried Server</th>
            <th>IP Address</th>
            <th>Latency</th>
            <th>DNSSEC</th>
          </tr>
        </thead>
        <tbody class="mono">
          ${traceHops.map((h: TraceHop) => `
            <tr>
              <td><strong>#${h.step}</strong></td>
              <td>${h.zone}</td>
              <td>${h.server_name}</td>
              <td>${h.server_ip}</td>
              <td>${(h.rtt / 1000000).toFixed(1)}ms</td>
              <td><span class="badge ${h.has_dnssec ? 'badge-success' : 'badge-warning'}">${h.has_dnssec ? 'DNSSEC' : 'No RRSIG'}</span></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>

    <!-- Global Edge Propagation -->
    <div class="card">
      <div class="card-title">🌍 2. Global Edge Propagation (25+ DoH Nodes)</div>
      <table>
        <thead>
          <tr>
            <th>Status</th>
            <th>Provider</th>
            <th>Location</th>
            <th>Latency</th>
            <th>Resolved Answer</th>
          </tr>
        </thead>
        <tbody class="mono">
          ${propResults.map((r: NodeResult) => `
            <tr>
              <td><span class="badge ${r.error ? 'badge-danger' : r.matched_consensus ? 'badge-success' : 'badge-warning'}">
                ${r.error ? 'TIMEOUT' : r.matched_consensus ? 'MATCH' : 'DIVERGENT'}
              </span></td>
              <td style="font-family: sans-serif;"><strong>${r.provider.name}</strong></td>
              <td>${r.provider.city}, ${r.provider.country}</td>
              <td>${(r.rtt / 1000000).toFixed(1)}ms</td>
              <td>${r.answers.map((a: RecordInfo) => a.data).join(', ') || r.error || '-'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>

    <!-- DNSSEC Chain -->
    <div class="card">
      <div class="card-title">🔒 3. DNSSEC Cryptographic Validation Chain</div>
      <table>
        <thead>
          <tr>
            <th>Zone</th>
            <th>DS Digest</th>
            <th>RRSIG Valid</th>
            <th>Key Tags</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody class="mono">
          ${dnssecChain.map((c: ChainNode) => {
            const tags = [...(c.ksk_key_tags || []), ...(c.zsk_key_tags || [])].join(', ');
            return `
            <tr>
              <td><strong>${c.zone}</strong></td>
              <td>${c.digest_matched ? '✓ Valid' : '✖ Mismatch'}</td>
              <td>${c.signatures_valid ? '✓ Valid' : '✖ Invalid'}</td>
              <td>${tags || '-'}</td>
              <td><span class="badge ${c.status === 'SECURE' ? 'badge-success' : c.status === 'BOGUS' ? 'badge-danger' : 'badge-warning'}">${c.status}</span></td>
            </tr>
          `;
          }).join('')}
        </tbody>
      </table>
    </div>

    <!-- Audit & Security Findings -->
    <div class="card">
      <div class="card-title">🛡️ 4. Domain Health & Hygiene Findings</div>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Category</th>
            <th>Issue Title</th>
            <th>Recommendation</th>
          </tr>
        </thead>
        <tbody>
          ${auditFindings.map((f: Finding) => `
            <tr>
              <td><span class="badge ${f.severity === 'GOOD' ? 'badge-success' : f.severity === 'CRITICAL' ? 'badge-danger' : 'badge-warning'}">${f.severity}</span></td>
              <td><strong>${f.category}</strong></td>
              <td>${f.title}</td>
              <td style="font-size: 12px; color: var(--muted);">${f.recommendation}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>

    <div class="footer">
      DNSWatch &mdash; Autonomous DNS Tracing, DNSSEC Validation & Worldwide Edge Propagation Studio
    </div>
  </div>
</body>
</html>`;

  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  a.href = url;
  a.download = `dnswatch-${summary.domain}-${timestamp}.html`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
