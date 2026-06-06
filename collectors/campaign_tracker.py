def build_campaign_report(report):
    campaigns = {}

    for item in report:
        cve = item["cve"]
        threat_references = item.get("threat_references", [])

        for actor in threat_references:
            if actor not in campaigns:
                campaigns[actor] = {
                    "actor": actor,
                    "cves": [],
                    "cve_count": 0,
                    "highest_threat_score": 0
                }

            campaigns[actor]["cves"].append({
                "cve": cve,
                "priority": item["priority"],
                "threat_score": item["threat_score"],
                "exploit_confidence": item["exploit_confidence"],
                "threat_activity": item["threat_activity"]
            })

            campaigns[actor]["cve_count"] += 1

            if item["threat_score"] > campaigns[actor]["highest_threat_score"]:
                campaigns[actor]["highest_threat_score"] = item["threat_score"]

    return list(campaigns.values())