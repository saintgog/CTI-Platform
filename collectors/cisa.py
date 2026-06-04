import requests
import json
import os
from datetime import datetime

def collect_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    response = requests.get(url)
    data = response.json()

    os.makedirs("data", exist_ok=True)

    filename = f"data/cisa_kev_{datetime.now().strftime('%Y-%m-%d')}.json"

    with open(filename, "w") as file:
        json.dump(data, file, indent=4)

    print("Saved CISA KEV data to", filename)

    return data