import os
from datetime import datetime
from jinja2 import Template

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
        .summary { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .module { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .check { padding: 10px; margin: 8px 0; border-radius: 5px; }
        .PASS { background: #d4edda; border-left: 4px solid #28a745; }
        .FAIL { background: #f8d7da; border-left: 4px solid #dc3545; }
        .ERROR { background: #fff3cd; border-left: 4px solid #ffc107; }
        .Critical { background: #f8d7da; border-left: 4px solid #7b0000; }
        .High { background: #f8d7da; border-left: 4px solid #dc3545; }
        .Medium { background: #fff3cd; border-left: 4px solid #ffc107; }
        .Low { background: #cce5ff; border-left: 4px solid #004085; }
        .Informational { background: #f8f9fa; border-left: 4px solid #6c757d; }
        .status { font-weight: bold; }
        .evidence { font-size: 0.85em; color: #666; margin-top: 5px; word-break: break-all; }
        .solution { font-size: 0.85em; color: #444; margin-top: 5px; }
        .meta { color: #888; font-size: 0.9em; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
        .badge-fail { background: #dc3545; color: white; }
        .badge-pass { background: #28a745; color: white; }
        .badge-high { background: #dc3545; color: white; }
        .badge-medium { background: #ffc107; color: black; }
        .badge-low { background: #004085; color: white; }
        .badge-info { background: #6c757d; color: white; }
    </style>
</head>
<body>
    <h1>TomcatShield Security Report</h1>
    <div class="summary">
        <p class="meta">Generated: {{ generated_at }}</p>
        <p class="meta">Target: {{ target }}</p>
        {% if tomcat_summary %}
        <p class="meta">Tomcat Checks — Passed: 
            <span class="badge badge-pass">{{ tomcat_summary.passed }}</span> 
            Failed: <span class="badge badge-fail">{{ tomcat_summary.failed }}</span>
        </p>
        {% endif %}
        {% if dast_summary %}
        <p class="meta">DAST Findings: 
            <span class="badge badge-high">{{ dast_summary.total }}</span>
        </p>
        {% endif %}
    </div>

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

    {% if findings %}
    <h2>DAST Scan Findings</h2>
    <div class="module">
        <p>Total Findings: {{ findings | length }}</p>
        {% for finding in findings %}
        <div class="check {{ finding.severity }}">
            <span class="status">{{ finding.severity }}</span> — {{ finding.name }}
            <div class="evidence"><strong>URL:</strong> {{ finding.url }}</div>
            {% if finding.evidence %}
            <div class="evidence"><strong>Evidence:</strong> {{ finding.evidence }}</div>
            {% endif %}
            {% if finding.solution %}
            <div class="solution"><strong>Solution:</strong> {{ finding.solution }}</div>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    {% endif %}

</body>
</html>
"""

def save_html_report(data: dict, output_dir: str = "artifacts") -> str:
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_report_{timestamp}.html"
    filepath = os.path.join(output_dir, filename)

    modules = data.get("tomcat_hardening", [])
    findings = data.get("dast_scan", {}).get("findings", [])

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

    dast_summary = None
    if findings:
        dast_summary = {"total": len(findings)}

    template = Template(HTML_TEMPLATE)
    html = template.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target=target,
        modules=modules,
        findings=findings,
        tomcat_summary=tomcat_summary,
        dast_summary=dast_summary
    )

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    return filepath