import requests
import json

url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

response = requests.get(url)

data = response.json()

with open("kev_data.json", "w") as file:
    json.dump(data, file, indent=4)

print("Saved", len(data["vulnerabilities"]), "vulnerabilities")
