import requests


def get_nvd_cve_details(cve_id):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "cveId": cve_id
    }

    response = requests.get(url, params=params)

    data = response.json()

    return data