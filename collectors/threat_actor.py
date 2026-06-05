import requests


def search_cisa_threat_activity(cve_id):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    response = requests.get(url)
    data = response.json()

    for vuln in data["vulnerabilities"]:
        if vuln["cveID"] == cve_id:
            return {
                "known_exploited": True,
                "source": "CISA KEV",
                "date_added": vuln["dateAdded"],
                "vendor": vuln["vendorProject"],
                "product": vuln["product"]
            }

    return {
        "known_exploited": False,
        "source": None,
        "date_added": None,
        "vendor": None,
        "product": None
    }
def assess_threat_activity(
    known_exploited,
    github_repo_count,
    exploitdb_count
):
    score = 0

    if known_exploited:
        score += 2

    if github_repo_count >= 5:
        score += 1

    if exploitdb_count >= 1:
        score += 1

    if score >= 4:
        return "HIGH"

    if score >= 2:
        return "MEDIUM"

    return "LOW"