"""
Auto Recon Framework - HTML Report Generator
Generates a self-contained, interactive HTML report
"""
import json
from datetime import datetime
from pathlib import Path

from core.config import ReconConfig
from core.models import ScanResult, Severity
from reporting.cve_mapper import build_mitre_summary, get_technique_name
from utils.logger import log


SEVERITY_COLOR = {
    Severity.CRITICAL: "#e74c3c",
    Severity.HIGH:     "#e67e22",
    Severity.MEDIUM:   "#f39c12",
    Severity.LOW:      "#3498db",
    Severity.INFO:     "#95a5a6",
    Severity.UNKNOWN:  "#bdc3c7",
}

SEVERITY_BG = {
    Severity.CRITICAL: "#fdecea",
    Severity.HIGH:     "#fef0e7",
    Severity.MEDIUM:   "#fef9e7",
    Severity.LOW:      "#ebf5fb",
    Severity.INFO:     "#f8f9fa",
    Severity.UNKNOWN:  "#f8f9fa",
}


class HtmlReporter:
    """Generates a self-contained interactive HTML report."""

    MODULE = "report"

    def __init__(self, config: ReconConfig):
        self.config = config
        self.reports_dir = config.output.reports_dir

    def generate(self, result: ScanResult) -> str:
        """Generate HTML report and return file path."""
        log.info("Generating HTML report...", self.MODULE)
        Path(self.reports_dir).mkdir(parents=True, exist_ok=True)

        result.update_summary()
        counts = result.severity_counts()
        mitre = build_mitre_summary(result.vulnerabilities)

        html = self._build_html(result, counts, mitre)

        out_file = str(Path(self.reports_dir) / f"{result.scan_id}_report.html")
        with open(out_file, "w") as f:
            f.write(html)

        log.success(f"HTML report: {out_file}", self.MODULE)
        return out_file

    def _build_html(self, result: ScanResult, counts: dict, mitre: dict) -> str:
        ts = result.started_at.strftime("%Y-%m-%d %H:%M UTC")

        vuln_rows = ""
        for v in result.vulnerabilities:
            color = SEVERITY_COLOR.get(v.severity, "#ccc")
            bg    = SEVERITY_BG.get(v.severity, "#fff")
            cves  = ", ".join(v.cve_ids) if v.cve_ids else "—"
            cvss  = str(v.cvss_score) if v.cvss_score else "—"
            vuln_rows += f"""
            <tr style="background:{bg}">
              <td><span class="badge" style="background:{color}">{v.severity.value.upper()}</span></td>
              <td><strong>{v.name}</strong><br><small>{v.description[:100]}...</small></td>
              <td><code>{v.host}</code></td>
              <td><code>{v.matched_at[:60]}</code></td>
              <td>{cves}</td>
              <td><strong>{cvss}</strong></td>
            </tr>"""

        port_rows = "".join(
            f"<tr><td><strong>{p.port}</strong></td><td>{p.protocol.upper()}</td>"
            f"<td>{p.service}</td><td>{p.version[:60]}</td></tr>"
            for p in result.ports
        )

        sub_rows = "".join(
            f"<tr><td>{'✅' if s.alive else '❌'}</td><td><code>{s.subdomain}</code></td>"
            f"<td>{s.ip or '—'}</td><td>{s.title[:40] if s.title else '—'}</td></tr>"
            for s in (result.subdomains or [])[:50]
        )

        http_rows = "".join(
            f"<tr><td><a href='{p.subdomain}' target='_blank'>{p.subdomain[:50]}</a></td>"
            f"<td>{p.status}</td><td>{p.title[:40] or '—'}</td>"
            f"<td>{', '.join(p.technologies[:3]) or '—'}</td></tr>"
            for p in result.http_probes
        )

        mitre_html = ""
        for tactic, techniques in mitre.items():
            mitre_html += f"<div class='mitre-tactic'><h4>🛡 {tactic}</h4><ul>"
            for technique, vulns in techniques.items():
                mitre_html += f"<li><code>{technique}</code> — {', '.join(set(vulns))}</li>"
            mitre_html += "</ul></div>"

        # Serialize chart data
        chart_data = json.dumps({
            "labels": ["Critical", "High", "Medium", "Low", "Info"],
            "data": [counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"]],
            "colors": ["#e74c3c", "#e67e22", "#f39c12", "#3498db", "#95a5a6"],
        })

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Auto Recon Report — {result.target}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --critical: #e74c3c; --high: #e67e22; --medium: #f39c12;
    --low: #3498db; --info: #95a5a6;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: var(--bg); color: var(--text); line-height: 1.6; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}
  header {{ background: linear-gradient(135deg, #1a2332 0%, #0d1b2a 100%);
            border-bottom: 1px solid var(--border); padding: 2rem; margin-bottom: 2rem;
            border-radius: 12px; }}
  header h1 {{ font-size: 2rem; color: var(--accent); margin-bottom: .5rem; }}
  header p {{ color: var(--muted); }}
  .cards {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
           padding: 1.5rem; text-align: center; }}
  .card .num {{ font-size: 2.5rem; font-weight: 700; }}
  .card .label {{ color: var(--muted); font-size: .85rem; text-transform: uppercase; letter-spacing: 1px; }}
  .card.critical .num {{ color: var(--critical); }}
  .card.high .num     {{ color: var(--high); }}
  .card.medium .num   {{ color: var(--medium); }}
  .card.low .num      {{ color: var(--low); }}
  .card.info .num     {{ color: var(--info); }}
  .section {{ background: var(--surface); border: 1px solid var(--border);
              border-radius: 10px; margin-bottom: 1.5rem; overflow: hidden; }}
  .section-header {{ padding: 1rem 1.5rem; cursor: pointer; display: flex;
                     justify-content: space-between; align-items: center;
                     background: rgba(255,255,255,.03); border-bottom: 1px solid var(--border); }}
  .section-header h2 {{ font-size: 1.1rem; }}
  .section-header .count {{ background: var(--accent); color: #000; border-radius: 20px;
                            padding: .2rem .7rem; font-size: .8rem; font-weight: 700; }}
  .section-body {{ padding: 1.5rem; display: none; }}
  .section-body.open {{ display: block; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .9rem; }}
  th {{ text-align: left; padding: .75rem 1rem; border-bottom: 2px solid var(--border);
        color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: 1px; }}
  td {{ padding: .6rem 1rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: rgba(255,255,255,.03); }}
  code {{ background: rgba(99,110,123,.4); padding: .15rem .4rem; border-radius: 4px;
          font-family: "JetBrains Mono", monospace; font-size: .85em; }}
  .badge {{ display: inline-block; padding: .2rem .6rem; border-radius: 4px; color: #fff;
            font-size: .75rem; font-weight: 700; text-transform: uppercase; letter-spacing: .5px; }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .chart-wrap {{ max-width: 400px; margin: 0 auto; }}
  .mitre-tactic {{ margin-bottom: 1rem; padding: 1rem; background: rgba(255,255,255,.03);
                   border-radius: 8px; border-left: 3px solid var(--accent); }}
  .mitre-tactic h4 {{ color: var(--accent); margin-bottom: .5rem; }}
  .mitre-tactic ul {{ list-style: none; padding-left: 1rem; }}
  .mitre-tactic li {{ margin-bottom: .3rem; color: var(--muted); }}
  .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }}
  .meta-item .key {{ color: var(--muted); font-size: .8rem; text-transform: uppercase;
                     letter-spacing: 1px; margin-bottom: .25rem; }}
  .meta-item .val {{ font-weight: 500; }}
  footer {{ text-align: center; color: var(--muted); padding: 2rem; font-size: .85rem; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🔍 Auto Recon Report</h1>
    <p><strong>Target:</strong> {result.target} &nbsp;·&nbsp;
       <strong>Scan ID:</strong> {result.scan_id} &nbsp;·&nbsp;
       <strong>Date:</strong> {ts}</p>
  </header>

  <!-- Severity Cards -->
  <div class="cards">
    <div class="card critical"><div class="num">{counts["critical"]}</div><div class="label">🔴 Critical</div></div>
    <div class="card high">    <div class="num">{counts["high"]}</div>    <div class="label">🟠 High</div></div>
    <div class="card medium">  <div class="num">{counts["medium"]}</div>  <div class="label">🟡 Medium</div></div>
    <div class="card low">     <div class="num">{counts["low"]}</div>     <div class="label">🔵 Low</div></div>
    <div class="card info">    <div class="num">{counts["info"]}</div>    <div class="label">⚪ Info</div></div>
  </div>

  <!-- Chart + Meta -->
  <div style="display:grid;grid-template-columns:1fr 2fr;gap:1.5rem;margin-bottom:1.5rem;">
    <div class="section">
      <div class="section-header" onclick="toggle(this)">
        <h2>📊 Severity Distribution</h2><span>▼</span>
      </div>
      <div class="section-body open">
        <div class="chart-wrap"><canvas id="severityChart"></canvas></div>
      </div>
    </div>
    <div class="section">
      <div class="section-header" onclick="toggle(this)">
        <h2>⚙️ Scan Metadata</h2><span>▼</span>
      </div>
      <div class="section-body open">
        <div class="meta-grid">
          <div class="meta-item"><div class="key">Target</div><div class="val"><code>{result.target}</code></div></div>
          <div class="meta-item"><div class="key">Scan ID</div><div class="val"><code>{result.scan_id}</code></div></div>
          <div class="meta-item"><div class="key">Open Ports</div><div class="val">{result.total_ports}</div></div>
          <div class="meta-item"><div class="key">Subdomains</div><div class="val">{result.total_subdomains}</div></div>
          <div class="meta-item"><div class="key">HTTP Services</div><div class="val">{len(result.http_probes)}</div></div>
          <div class="meta-item"><div class="key">Vulnerabilities</div><div class="val">{result.total_vulnerabilities}</div></div>
          <div class="meta-item"><div class="key">Screenshots</div><div class="val">{result.total_screenshots}</div></div>
          <div class="meta-item"><div class="key">Status</div><div class="val">{result.status.value.upper()}</div></div>
        </div>
      </div>
    </div>
  </div>

  <!-- Vulnerabilities -->
  <div class="section">
    <div class="section-header" onclick="toggle(this)">
      <h2>🐛 Vulnerabilities</h2>
      <span class="count">{result.total_vulnerabilities}</span>
    </div>
    <div class="section-body open">
      {"<p style='color:var(--info)'>✅ No vulnerabilities detected.</p>" if not result.vulnerabilities else f"""
      <table>
        <thead><tr><th>Severity</th><th>Name</th><th>Host</th><th>Matched At</th><th>CVE</th><th>CVSS</th></tr></thead>
        <tbody>{vuln_rows}</tbody>
      </table>"""}
    </div>
  </div>

  <!-- Ports -->
  <div class="section">
    <div class="section-header" onclick="toggle(this)">
      <h2>🔌 Open Ports</h2>
      <span class="count">{result.total_ports}</span>
    </div>
    <div class="section-body">
      <table>
        <thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr></thead>
        <tbody>{port_rows or "<tr><td colspan='4' style='color:var(--muted)'>No ports discovered</td></tr>"}</tbody>
      </table>
    </div>
  </div>

  <!-- Subdomains -->
  <div class="section">
    <div class="section-header" onclick="toggle(this)">
      <h2>🌐 Subdomains</h2>
      <span class="count">{result.total_subdomains}</span>
    </div>
    <div class="section-body">
      <table>
        <thead><tr><th>Live</th><th>Subdomain</th><th>IP</th><th>Title</th></tr></thead>
        <tbody>{sub_rows or "<tr><td colspan='4' style='color:var(--muted)'>No subdomains found</td></tr>"}</tbody>
      </table>
    </div>
  </div>

  <!-- HTTP Services -->
  <div class="section">
    <div class="section-header" onclick="toggle(this)">
      <h2>🕸️ HTTP Services</h2>
      <span class="count">{len(result.http_probes)}</span>
    </div>
    <div class="section-body">
      <table>
        <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Technologies</th></tr></thead>
        <tbody>{http_rows or "<tr><td colspan='4' style='color:var(--muted)'>No HTTP services detected</td></tr>"}</tbody>
      </table>
    </div>
  </div>

  <!-- MITRE ATT&CK -->
  <div class="section">
    <div class="section-header" onclick="toggle(this)">
      <h2>🛡️ MITRE ATT&CK Mapping</h2><span>▼</span>
    </div>
    <div class="section-body">
      {mitre_html or "<p style='color:var(--muted)'>No MITRE mappings available.</p>"}
    </div>
  </div>

  <footer>Generated by Auto Recon Framework · {ts} · nmap · subfinder · httpx · nuclei</footer>
</div>

<script>
// Accordion toggle
function toggle(header) {{
  const body = header.nextElementSibling;
  body.classList.toggle('open');
  header.querySelector('span:last-child').textContent =
    body.classList.contains('open') ? '▲' : '▼';
}}

// Severity donut chart
const data = {chart_data};
new Chart(document.getElementById('severityChart'), {{
  type: 'doughnut',
  data: {{
    labels: data.labels,
    datasets: [{{
      data: data.data,
      backgroundColor: data.colors,
      borderColor: '#161b22',
      borderWidth: 3,
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{
      legend: {{ position: 'bottom', labels: {{ color: '#8b949e', boxWidth: 14 }} }},
      tooltip: {{ callbacks: {{
        label: ctx => ` ${{ctx.label}}: ${{ctx.raw}}`
      }} }}
    }}
  }}
}});
</script>
</body>
</html>"""
