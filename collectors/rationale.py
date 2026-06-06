def build_assessment_rationale(
    cvss_score,
    github_repo_count,
    exploitdb_count,
    threat_references,
    in_kev=True
):
    rationale = []

    if in_kev:
        rationale.append(
            "Included in CISA Known Exploited Vulnerabilities catalog"
        )

    if cvss_score >= 9:
        rationale.append(
            f"Critical CVSS score ({cvss_score})"
        )
    elif cvss_score >= 7:
        rationale.append(
            f"High severity CVSS score ({cvss_score})"
        )

    if github_repo_count > 0:
        rationale.append(
            f"{github_repo_count} GitHub repositories reference this CVE"
        )

    if exploitdb_count > 0:
        rationale.append(
            f"{exploitdb_count} Exploit-DB entries found"
        )

    if threat_references:
        rationale.append(
            "Threat actor references detected: "
            + ", ".join(threat_references)
        )

    return rationale