import json
import os
from collectors.exploitdb import search_exploitdb_for_cve
from collectors.cisa import collect_cisa_kev
from collectors.nvd import get_nvd_cve_details
from collectors.github_intel import search_github_for_cve


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

    priority = get_priority(threat_score)
    description = cve["descriptions"][0]["value"]

    report_item = {
        "cve": cve_id,
        "vendor": item["vendorProject"],
        "product": item["product"],
        "date_added_to_kev": item["dateAdded"],
        "cvss": cvss_score,
        "severity": severity,
        "cvss_version": cvss_version,
        "github_repositories": github_repo_count,
        "github_repositories_found": github_repos,
        "exploit_confidence": exploit_confidence,
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
    item["threat_score"]
    for item in report
)

total_vulnerabilities = len(report)

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

    file.write("\n")
    file.write("=" * 60 + "\n\n")

    for item in report:
        file.write(f"CVE: {item['cve']}\n")
        file.write(f"Vendor: {item['vendor']}\n")
        file.write(f"Product: {item['product']}\n")
        file.write(f"CVSS: {item['cvss']}\n")
        file.write(f"GitHub Repositories: {item['github_repositories']}\n")
        file.write(f"Exploit Confidence: {item['exploit_confidence']}\n")
        file.write("GitHub Repo Details:\n")

        for repo in item["github_repositories_found"]:
            file.write(f"  - {repo['name']} | Stars: {repo['stars']} | Updated: {repo['updated_at']}\n")
            file.write(f"    {repo['url']}\n")

        file.write(f"Priority: {item['priority']}\n")
        file.write(f"Threat Score: {item['threat_score']}\n")
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
    print("Priority:", item["priority"])
    print("Threat Score:", item["threat_score"])
    print("-" * 60)

print()
print("Saved report to reports/daily_report.json")
print("Saved brief to reports/daily_brief.txt")