import json
import os
from collectors.exploitdb import search_exploitdb_for_cve
from collectors.cisa_advisories import search_cisa_advisory_text
from collectors.cisa import collect_cisa_kev
from collectors.nvd import get_nvd_cve_details
from collectors.github_intel import search_github_for_cve
from collectors.threat_actor import assess_threat_activity
from collectors.threat_references import find_threat_references
from collectors.rationale import build_assessment_rationale
from collectors.campaign_mapper import infer_campaign
from collectors.campaign_tracker import build_campaign_report
from collectors.cisa_advisories import (
    search_cisa_advisory_text,
    collect_recent_cisa_advisory_text
)
from collectors.history import (
    save_daily_history,
    load_previous_history,
    compare_with_previous_history
)

def extract_cvss(cve):
    metrics = cve.get("metrics", {})

    if "cvssMetricV40" in metrics:
        cvss_data = metrics["cvssMetricV40"][0]["cvssData"]
        return cvss_data["baseScore"], cvss_data["baseSeverity"], "CVSS v4.0"

    if "cvssMetricV31" in metrics:
        cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
        return cvss_data["baseScore"], cvss_data["baseSeverity"], "CVSS v3.1"

    return 0, "UNKNOWN", "NO CVSS"


def calculate_threat_score(cvss_score, github_repo_count, exploitdb_count, in_cisa_kev=True):

    score = 0

    if in_cisa_kev:
        score += 50

    if cvss_score >= 9:
        score += 40
    elif cvss_score >= 7:
        score += 25
    elif cvss_score >= 4:
        score += 10

    if github_repo_count >= 10:
        score += 30
    elif github_repo_count >= 5:
        score += 20
    elif github_repo_count >= 1:
        score += 10

    if exploitdb_count >= 1:
        score += 25

    return score


def get_priority(score):
    if score >= 100:
        return "CRITICAL"
    elif score >= 80:
        return "HIGH"
    elif score >= 50:
        return "MEDIUM"
    else:
        return "LOW"


def get_exploit_confidence(github_repo_count, github_repos):
    total_stars = 0

    for repo in github_repos:
        total_stars += repo["stars"]

    if github_repo_count >= 10 or total_stars >= 50:
        return "HIGH"

    if github_repo_count >= 3 or total_stars >= 10:
        return "MEDIUM"

    if github_repo_count >= 1:
        return "LOW"

    return "NONE"


cisa_data = collect_cisa_kev()
recent_cisa_advisories = collect_recent_cisa_advisory_text()
report = []

for item in cisa_data["vulnerabilities"][:10]:
    cve_id = item["cveID"]

    nvd_data = get_nvd_cve_details(cve_id)
    
    cve = nvd_data["vulnerabilities"][0]["cve"]

    github_data = search_github_for_cve(cve_id)
    github_repo_count = github_data["total_count"]
    github_repos = github_data["repos"]

    exploitdb_data = search_exploitdb_for_cve(cve_id)
    exploitdb_count = exploitdb_data["total_count"]
    exploitdb_exploits = exploitdb_data["exploits"]

    exploit_confidence = get_exploit_confidence(
        github_repo_count,
        github_repos
    )

    cvss_score, severity, cvss_version = extract_cvss(cve)

    threat_score = calculate_threat_score(
        cvss_score,
        github_repo_count,
        exploitdb_count
    )

    threat_activity = assess_threat_activity(
        True,
        github_repo_count,
        exploitdb_count
    )

    priority = get_priority(threat_score)

    description = cve["descriptions"][0]["value"]

    cisa_advisories = search_cisa_advisory_text(cve_id)

    print(
        f"{cve_id}: matched CISA advisories = {len(cisa_advisories)}"
    )

    advisory_text = " ".join(
        advisory["text"] for advisory in cisa_advisories
    )

    recent_advisory_text = " ".join(
        advisory["text"] for advisory in recent_cisa_advisories
    )

    combined_threat_text = (
    description + " " +
    advisory_text + " " +
    recent_advisory_text
    )

    threat_references = find_threat_references(
    combined_threat_text
)

    if not threat_references:
        inferred_actor = infer_campaign(
            item["vendorProject"],
            item["product"]
        )

        if inferred_actor:
            threat_references.append(inferred_actor)

    rationale = build_assessment_rationale(
        cvss_score,
        github_repo_count,
        exploitdb_count,
        threat_references
    )
    report_item = {
        "cve": cve_id,
        "vendor": item["vendorProject"],
        "product": item["product"],
        "date_added_to_kev": item["dateAdded"],
        "cvss": cvss_score,
        "severity": severity,
        "cvss_version": cvss_version,
        "assessment_rationale": rationale,
        "cisa_advisories": cisa_advisories,
        "cisa_advisory_count": len(cisa_advisories),
        "github_repositories": github_repo_count,
        "github_repositories_found": github_repos,
        "exploitdb_results": exploitdb_count,
        "exploitdb_exploits": exploitdb_exploits,
        "exploit_confidence": exploit_confidence,
        "threat_activity": threat_activity,
        "threat_references": threat_references,
        "threat_score": threat_score,
        "priority": priority,
        "summary": description
    }

    report.append(report_item)



report.sort(key=lambda x: x["threat_score"], reverse=True)
critical_count = sum(1 for item in report if item["priority"] == "CRITICAL")
high_count = sum(1 for item in report if item["priority"] == "HIGH")
medium_count = sum(1 for item in report if item["priority"] == "MEDIUM")
low_count = sum(1 for item in report if item["priority"] == "LOW")

github_count = sum(
    1 for item in report
    if item["github_repositories"] > 0
)

highest_score = max(
    (item["threat_score"] for item in report),
    default=0
)

total_vulnerabilities = len(report)
previous_report = load_previous_history()
trend_report = compare_with_previous_history(report, previous_report)
history_path = save_daily_history(report)
campaign_report = build_campaign_report(report)
with open("reports/trend_report.json", "w", encoding="utf-8") as file:
    json.dump(trend_report, file, indent=4)
with open("reports/campaign_report.json", "w", encoding="utf-8") as file:
    json.dump(campaign_report, file, indent=4)
os.makedirs("reports", exist_ok=True)

with open("reports/daily_report.json", "w", encoding="utf-8") as file:
    json.dump(report, file, indent=4)

with open("reports/daily_brief.txt", "w", encoding="utf-8") as file:
    file.write("TOP PRIORITIZED CYBER THREATS\n")
    file.write("=" * 60 + "\n\n")

    file.write("EXECUTIVE SUMMARY\n")
    file.write("-" * 60 + "\n")

    file.write(f"Vulnerabilities Analyzed: {total_vulnerabilities}\n")
    file.write(f"Critical Priority: {critical_count}\n")
    file.write(f"High Priority: {high_count}\n")
    file.write(f"With GitHub Repositories: {github_count}\n")
    file.write(f"Highest Threat Score: {highest_score}\n")
    file.write(f"History Snapshot: {history_path}\n")

    score_increases = [
        trend for trend in trend_report
        if trend["delta"] is not None and trend["delta"] > 0
    ]

    new_cves = [
        trend for trend in trend_report
        if trend["status"] == "NEW"
    ]

    file.write(f"New CVEs Since Previous Run: {len(new_cves)}\n")
    file.write(f"Score Increases Since Previous Run: {len(score_increases)}\n")

    file.write("\n")
    file.write("TREND SUMMARY\n")
    file.write("-" * 60 + "\n")

    if not new_cves and not score_increases:
        file.write("No new CVEs or score increases detected since previous run.\n")

    if new_cves:
        file.write("New CVEs:\n")

        for trend in new_cves:
            file.write(
                f"  - {trend['cve']} "
                f"(Score: {trend['current_score']})\n"
            )

    if score_increases:
        file.write("Score Increases:\n")

        for trend in score_increases:
            file.write(
                f"  - {trend['cve']} "
                f"({trend['previous_score']} -> "
                f"{trend['current_score']}, "
                f"+{trend['delta']})\n"
            )

    file.write("\n")
    file.write("=" * 60 + "\n\n")
    file.write("ACTIVE THREAT ACTOR CAMPAIGNS\n")
    file.write("-" * 60 + "\n")

    if not campaign_report:
        file.write("No threat actor campaign references detected.\n")

    for campaign in campaign_report:
        file.write(
            f"{campaign['actor']} "
            f"({campaign['cve_count']} CVEs, "
            f"Highest Score: {campaign['highest_threat_score']})\n"
        )

        for cve_item in campaign["cves"]:
            file.write(
                f"  - {cve_item['cve']} | "
                f"Priority: {cve_item['priority']} | "
                f"Score: {cve_item['threat_score']} | "
                f"Exploit Confidence: {cve_item['exploit_confidence']}\n"
            )

    file.write("\n")
    file.write("=" * 60 + "\n\n")
    for item in report:
        file.write(f"CVE: {item['cve']}\n")
        file.write(f"Vendor: {item['vendor']}\n")
        file.write(f"Product: {item['product']}\n")
        file.write(f"CVSS: {item['cvss']}\n")
        file.write(f"GitHub Repositories: {item['github_repositories']}\n")
        file.write(f"Exploit-DB Results: {item['exploitdb_results']}\n")
        file.write(f"Exploit Confidence: {item['exploit_confidence']}\n")

        file.write("GitHub Repo Details:\n")

        for repo in item["github_repositories_found"]:
            file.write(
                f"  - {repo['name']} | Stars: {repo['stars']} | Updated: {repo['updated_at']}\n"
            )
            file.write(f"    {repo['url']}\n")

        file.write("Exploit-DB Details:\n")

        for exploit in item["exploitdb_exploits"]:
            file.write(
                f"  - {exploit['description']} "
                f"({exploit['platform']}/{exploit['type']})\n"
            )
            file.write(f"    {exploit['url']}\n")

        file.write(f"Priority: {item['priority']}\n")
        file.write(f"Threat Score: {item['threat_score']}\n")
        file.write("Assessment Rationale:\n")

        for reason in item["assessment_rationale"]:
            file.write(f"  - {reason}\n")

        file.write(f"Summary: {item['summary']}\n")
        file.write("-" * 60 + "\n\n")


print()
print("=" * 60)
print(" TOP PRIORITIZED THREATS ")
print("=" * 60)

for item in report:
    print()
    print("CVE:", item["cve"])
    print("Vendor:", item["vendor"])
    print("Product:", item["product"])
    print("CVSS:", item["cvss"])
    print("GitHub Repositories:", item["github_repositories"])
    print("Exploit Confidence:", item["exploit_confidence"])
    print("Threat Activity:", item["threat_activity"])

    if item["threat_references"]:
        print(
            "Threat References:",
            ", ".join(item["threat_references"])
        )
    else:
        print(
            "Threat References: None"
        )

    print("Priority:", item["priority"])
    print("Threat Score:", item["threat_score"])
    print("-" * 60)

print()
print("Saved report to reports/daily_report.json")
print("Saved brief to reports/daily_brief.txt")