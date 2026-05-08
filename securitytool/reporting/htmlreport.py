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
        .status { font-weight: bold; }
        .evidence { font-size: 0.85em; color: #666; margin-top: 5px; word-break: break-all; }
        .meta { color: #888; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>TomcatShield Security Report</h1>
    <div class="summary">
        <p class="meta">Generated: {{ generated_at }}</p>
        <p class="meta">Target: {{ target }}</p>
    </div>

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
</body>
</html>
"""

def save_html_report(data: dict, output_dir: str = "artifacts") -> str:
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"tomcat_hardening_{timestamp}.html"
    filepath = os.path.join(output_dir, filename)

    modules = data.get("tomcat_hardening", [])
    target = ""
    for m in modules:
        if m.get("target"):
            target = m["target"]
            break

    template = Template(HTML_TEMPLATE)
    html = template.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target=target,
        modules=modules
    )

    with open(filepath, "w") as f:
        f.write(html)

    return filepath