import json
import os
from datetime import date


def save_daily_history(report):
    os.makedirs("data/history", exist_ok=True)

    today = date.today().isoformat()
    history_path = f"data/history/{today}.json"

    with open(history_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return history_path


def load_previous_history():
    history_dir = "data/history"

    if not os.path.exists(history_dir):
        return []

    files = sorted(
        file for file in os.listdir(history_dir)
        if file.endswith(".json")
    )

    if len(files) < 1:
        return []

    previous_file = files[-1]
    previous_path = os.path.join(history_dir, previous_file)

    with open(previous_path, "r", encoding="utf-8") as file:
        return json.load(file)


def compare_with_previous_history(current_report, previous_report):
    previous_by_cve = {
        item["cve"]: item
        for item in previous_report
    }

    trends = []

    for item in current_report:
        cve = item["cve"]

        if cve not in previous_by_cve:
            trends.append({
                "cve": cve,
                "status": "NEW",
                "previous_score": None,
                "current_score": item["threat_score"],
                "delta": None
            })
            continue

        previous_score = previous_by_cve[cve]["threat_score"]
        current_score = item["threat_score"]
        delta = current_score - previous_score

        trends.append({
            "cve": cve,
            "status": "CHANGED" if delta != 0 else "UNCHANGED",
            "previous_score": previous_score,
            "current_score": current_score,
            "delta": delta
        })

    return trends