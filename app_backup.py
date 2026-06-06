import json
from collections import Counter
from pathlib import Path

from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"

app = Flask(__name__)


def load_json_report(filename, default=None):
    if default is None:
        default = []
    path = REPORTS_DIR / filename
    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def load_text_report(filename):
    path = REPORTS_DIR / filename
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return "Daily brief has not been generated yet. Run main.py first."


def count_by_field(items, field):
    return dict(Counter(item.get(field, "UNKNOWN") or "UNKNOWN" for item in items))


def normalize(value):
    return str(value or "").strip().lower()


def matches_filters(item, query="", priority="all", severity="all", exploit="all"):
    if priority != "all" and normalize(item.get("priority")) != priority:
        return False
    if severity != "all" and normalize(item.get("severity")) != severity:
        return False
    if exploit != "all" and normalize(item.get("exploit_confidence")) != exploit:
        return False
    if query:
        searchable = " ".join([
            str(item.get("cve", "")),
            str(item.get("vendor", "")),
            str(item.get("product", "")),
            str(item.get("priority", "")),
            str(item.get("severity", "")),
            str(item.get("exploit_confidence", "")),
            str(item.get("summary", "")),
            " ".join(item.get("threat_references", [])),
        ]).lower()
        if query not in searchable:
            return False
    return True


def build_dashboard_context():
    daily_report = load_json_report("daily_report.json", [])
    trend_report = load_json_report("trend_report.json", [])
    campaign_report = load_json_report("campaign_report.json", [])
    daily_brief = load_text_report("daily_brief.txt")

    daily_report = sorted(daily_report, key=lambda x: x.get("threat_score", 0), reverse=True)

    query = normalize(request.args.get("q", ""))
    selected_priority = normalize(request.args.get("priority", "all")) or "all"
    selected_severity = normalize(request.args.get("severity", "all")) or "all"
    selected_exploit = normalize(request.args.get("exploit", "all")) or "all"

    filtered_report = [
        item for item in daily_report
        if matches_filters(item, query, selected_priority, selected_severity, selected_exploit)
    ]

    priority_counts = count_by_field(daily_report, "priority")
    severity_counts = count_by_field(daily_report, "severity")
    exploit_confidence_counts = count_by_field(daily_report, "exploit_confidence")

    total_github_repositories = sum(item.get("github_repositories", 0) for item in daily_report)
    total_exploitdb_results = sum(item.get("exploitdb_results", 0) for item in daily_report)
    cves_with_github = sum(1 for item in daily_report if item.get("github_repositories", 0) > 0)
    cves_with_exploitdb = sum(1 for item in daily_report if item.get("exploitdb_results", 0) > 0)
    cves_with_threat_refs = sum(1 for item in daily_report if item.get("threat_references"))
    highest_score = max((item.get("threat_score", 0) for item in daily_report), default=0)
    average_score = round(sum(item.get("threat_score", 0) for item in daily_report) / len(daily_report), 1) if daily_report else 0

    new_cves = [item for item in trend_report if item.get("status") == "NEW"]
    score_increases = [item for item in trend_report if item.get("delta") is not None and item.get("delta", 0) > 0]

    top_vendors = Counter(item.get("vendor", "UNKNOWN") or "UNKNOWN" for item in daily_report).most_common(8)
    top_products = Counter(item.get("product", "UNKNOWN") or "UNKNOWN" for item in daily_report).most_common(8)
    top_threat_refs = Counter(ref for item in daily_report for ref in item.get("threat_references", [])).most_common(8)

    stats = {
        "total_cves": len(daily_report),
        "filtered_cves": len(filtered_report),
        "critical_priority": priority_counts.get("CRITICAL", 0),
        "high_priority": priority_counts.get("HIGH", 0),
        "medium_priority": priority_counts.get("MEDIUM", 0),
        "low_priority": priority_counts.get("LOW", 0),
        "highest_score": highest_score,
        "average_score": average_score,
        "total_github_repositories": total_github_repositories,
        "total_exploitdb_results": total_exploitdb_results,
        "cves_with_github": cves_with_github,
        "cves_with_exploitdb": cves_with_exploitdb,
        "cves_with_threat_refs": cves_with_threat_refs,
        "campaign_count": len(campaign_report),
        "new_cves": len(new_cves),
        "score_increases": len(score_increases),
    }

    chart_data = {
        "priority": priority_counts,
        "severity": severity_counts,
        "exploit_confidence": exploit_confidence_counts,
        "top_vendors": {name: count for name, count in top_vendors},
        "top_products": {name: count for name, count in top_products},
        "top_threat_refs": {name: count for name, count in top_threat_refs},
    }

    filters = {
        "q": query,
        "priority": selected_priority,
        "severity": selected_severity,
        "exploit": selected_exploit,
        "priorities": sorted(priority_counts.keys()),
        "severities": sorted(severity_counts.keys()),
        "exploit_confidences": sorted(exploit_confidence_counts.keys()),
    }

    return {
        "daily_report": daily_report,
        "filtered_report": filtered_report,
        "trend_report": trend_report,
        "campaign_report": campaign_report,
        "daily_brief": daily_brief,
        "stats": stats,
        "chart_data": chart_data,
        "filters": filters,
    }


@app.route("/")
def dashboard():
    return render_template("dashboard.html", **build_dashboard_context())


@app.route("/api/reports")
def api_reports():
    context = build_dashboard_context()
    return jsonify({
        "stats": context["stats"],
        "daily_report": context["daily_report"],
        "filtered_report": context["filtered_report"],
        "trend_report": context["trend_report"],
        "campaign_report": context["campaign_report"],
        "chart_data": context["chart_data"],
    })


@app.route("/api/cves/<cve_id>")
def api_cve_detail(cve_id):
    daily_report = load_json_report("daily_report.json", [])
    for item in daily_report:
        if item.get("cve", "").upper() == cve_id.upper():
            return jsonify(item)
    return jsonify({"error": "CVE not found"}), 404


if __name__ == "__main__":
    app.run(debug=True)
