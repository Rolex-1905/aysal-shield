import os
from datetime import datetime
from jinja2 import Template
from securitytool.utils import redact_dict, redact_list

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>TomcatShield Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 5px; }
        h3 { color: #555; }
        .summary { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .executive { background: #eaf4fb; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #3498db; }
        .module { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .check { padding: 10px; margin: 8px 0; border-radius: 5px; }
        .PASS { background: #d4edda; border-left: 4px solid #28a745; }
        .FAIL { background: #f8d7da; border-left: 4px solid #dc3545; }
        .ERROR { background: #fff3cd; border-left: 4px solid #ffc107; }
        .SKIP { background: #e2e3e5; border-left: 4px solid #6c757d; }
        .Critical { background: #f8d7da; border-left: 4px solid #7b0000; }
        .High { background: #f8d7da; border-left: 4px solid #dc3545; }
        .Medium { background: #fff3cd; border-left: 4px solid #ffc107; }
        .Low { background: #cce5ff; border-left: 4px solid #004085; }
        .Informational { background: #f8f9fa; border-left: 4px solid #6c757d; }
        .status { font-weight: bold; }
        .evidence { font-size: 0.85em; color: #666; margin-top: 5px; word-break: break-all; }
        .solution { font-size: 0.85em; color: #444; margin-top: 5px; }
        .description { font-size: 0.85em; color: #333; margin-top: 5px; }
        .affected-urls { font-size: 0.82em; color: #555; margin-top: 8px; padding-left: 10px; }
        .meta { color: #888; font-size: 0.9em; }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 0.85em; font-weight: bold; margin: 2px; }
        .badge-critical { background: #7b0000; color: white; }
        .badge-high { background: #dc3545; color: white; }
        .badge-medium { background: #ffc107; color: black; }
        .badge-low { background: #004085; color: white; }
        .badge-info { background: #6c757d; color: white; }
        .badge-pass { background: #28a745; color: white; }
        .badge-fail { background: #dc3545; color: white; }
        .risk-score { font-size: 2em; font-weight: bold; color: #2c3e50; }
        .severity-grid { display: flex; gap: 10px; flex-wrap: wrap; margin: 10px 0; }
        .severity-box { padding: 10px 20px; border-radius: 8px; text-align: center; min-width: 80px; }
        .url-item { padding: 3px 0; border-bottom: 1px solid #eee; }
    </style>
</head>
<body>
    <h1>TomcatShield Security Report</h1>

    <div class="summary">
        <p class="meta">Generated: {{ generated_at }}</p>
        <p class="meta">Target: {{ target }}</p>

        {% if risk %}
        <div class="severity-grid">
            <div class="severity-box" style="background:#f8d7da">
                <div style="font-size:1.5em;font-weight:bold;color:#7b0000">{{ risk.counts.Critical }}</div>
                <div>Critical</div>
            </div>
            <div class="severity-box" style="background:#f8d7da">
                <div style="font-size:1.5em;font-weight:bold;color:#dc3545">{{ risk.counts.High }}</div>
                <div>High</div>
            </div>
            <div class="severity-box" style="background:#fff3cd">
                <div style="font-size:1.5em;font-weight:bold;color:#856404">{{ risk.counts.Medium }}</div>
                <div>Medium</div>
            </div>
            <div class="severity-box" style="background:#cce5ff">
                <div style="font-size:1.5em;font-weight:bold;color:#004085">{{ risk.counts.Low }}</div>
                <div>Low</div>
            </div>
            <div class="severity-box" style="background:#f8f9fa">
                <div style="font-size:1.5em;font-weight:bold;color:#6c757d">{{ risk.counts.Informational }}</div>
                <div>Info</div>
            </div>
            <div class="severity-box" style="background:#e8f5e9">
                <div class="risk-score">{{ risk.risk_score }}/10</div>
                <div>Risk Score</div>
            </div>
        </div>
        {% endif %}

        {% if tomcat_summary %}
        <p class="meta">Tomcat Checks — 
            Passed: <span class="badge badge-pass">{{ tomcat_summary.passed }}</span>
            Failed: <span class="badge badge-fail">{{ tomcat_summary.failed }}</span>
        </p>
        {% endif %}
    </div>

    {% if executive_summary %}
    <div class="executive">
        <h3>Executive Summary</h3>
        <p>{{ executive_summary }}</p>
    </div>
    {% endif %}

    {% if modules %}
    <h2>Tomcat Hardening Results</h2>
    {% for module in modules %}
    <div class="module">
        <h2>{{ module.module | default("Module") | replace("_", " ") | title }}</h2>
        {% if module.error %}
            <div class="check ERROR">
                <span class="status">ERROR</span>
                <div class="evidence">{{ module.error }}</div>
            </div>
        {% else %}
            <p>Passed: {{ module.summary.passed }} | Failed: {{ module.summary.failed }} | Total: {{ module.summary.total }}</p>
            {% for result in module.results %}
            <div class="check {{ result.status }}">
                <span class="status">{{ result.status }}</span> — {{ result.check }}
                <div class="evidence">{{ result.evidence }}</div>
            </div>
            {% endfor %}
        {% endif %}
    </div>
    {% endfor %}
    {% endif %}

    {% if grouped_findings %}
    <h2>DAST Scan Findings ({{ grouped_findings | length }} unique issues)</h2>
    {% for finding in grouped_findings %}
    <div class="module">
        <div class="check {{ finding.severity }}">
            <span class="status">{{ finding.severity }}</span> — {{ finding.name }}
            <span style="float:right;font-size:0.85em">{{ finding.count }} occurrence(s)</span>
        </div>

        {% if finding.description %}
        <div class="description"><strong>Description:</strong> {{ finding.description }}</div>
        {% endif %}

        {% if finding.solution %}
        <div class="solution"><strong>Solution:</strong> {{ finding.solution }}</div>
        {% endif %}

        {% if finding.cweid and finding.cweid != '-1' %}
        <div class="evidence">
            <strong>CWE:</strong> 
            <a href="https://cwe.mitre.org/data/definitions/{{ finding.cweid }}.html" target="_blank">
                CWE-{{ finding.cweid }}
            </a>
        </div>
        {% endif %}

        {% if finding.reference %}
        <div class="evidence">
            <strong>References:</strong>
            {% for ref in finding.reference.split('\n') %}
                {% if ref.strip() %}
                <a href="{{ ref.strip() }}" target="_blank" style="display:block;font-size:0.8em;margin-top:2px">
                    {{ ref.strip() }}
                </a>
                {% endif %}
            {% endfor %}
        </div>
        {% endif %}

        <div class="affected-urls">
            <strong>Affected URLs ({{ finding.affected_urls | length }}):</strong>
            {% for item in finding.affected_urls %}
            <div class="url-item">
                {{ item.url }}
                {% if item.parameter %} — param: <code>{{ item.parameter }}</code>{% endif %}
                {% if item.evidence %} — evidence: <code>{{ item.evidence[:80] }}</code>{% endif %}
            </div>
            {% endfor %}
        </div>
    </div>
    {% endfor %}
    {% endif %}

</body>
</html>
"""


def generate_executive_summary(risk: dict, tomcat_summary: dict) -> str:
    score = risk.get("risk_score", 0) if risk else 0
    counts = risk.get("counts", {}) if risk else {}
    critical = counts.get("Critical", 0)
    high = counts.get("High", 0)
    medium = counts.get("Medium", 0)

    if critical > 0 or high > 0:
        posture = "HIGH RISK — Immediate attention required."
    elif medium > 0:
        posture = "MEDIUM RISK — Issues should be addressed within the current sprint."
    else:
        posture = "LOW RISK — No critical vulnerabilities detected. Minor misconfigurations present."

    summary = f"Overall security posture: {posture} "
    summary += f"Risk score: {score}/10. "

    if critical > 0:
        summary += f"{critical} critical finding(s) require immediate remediation. "
    if high > 0:
        summary += f"{high} high severity finding(s) detected. "
    if medium > 0:
        summary += f"{medium} medium severity finding(s) should be reviewed. "

    if tomcat_summary:
        failed = tomcat_summary.get("failed", 0)
        if failed > 0:
            summary += f"Tomcat hardening scan found {failed} configuration failure(s)."

    return summary


def save_html_report(data: dict, output_dir: str = "artifacts") -> str:
    from securitytool.dast.parsers import group_findings, calculate_risk_score

    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_report_{timestamp}.html"
    filepath = os.path.join(output_dir, filename)

    modules = redact_dict({"modules": data.get("tomcat_hardening", [])})["modules"]
    raw_findings = redact_list(data.get("dast_scan", {}).get("findings", []))

    grouped = group_findings(raw_findings) if raw_findings else []
    risk = calculate_risk_score(raw_findings) if raw_findings else None

    target = ""
    for m in modules:
        if m.get("target"):
            target = m["target"]
            break
    if not target and data.get("dast_scan", {}).get("target"):
        target = data["dast_scan"]["target"]

    tomcat_summary = None
    if modules:
        total_passed = sum(m.get("summary", {}).get("passed", 0) for m in modules if not m.get("error"))
        total_failed = sum(m.get("summary", {}).get("failed", 0) for m in modules if not m.get("error"))
        tomcat_summary = {"passed": total_passed, "failed": total_failed}

    executive_summary = generate_executive_summary(risk, tomcat_summary)

    template = Template(HTML_TEMPLATE)
    html = template.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target=target,
        modules=modules,
        grouped_findings=grouped,
        risk=risk,
        tomcat_summary=tomcat_summary,
        executive_summary=executive_summary
    )

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    return filepath