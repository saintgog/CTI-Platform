import requests


def search_cisa_advisories(cve_id):
    url = "https://www.cisa.gov/news-events/cybersecurity-advisories"

    response = requests.get(url)

    if cve_id.lower() in response.text.lower():
        return {
            "referenced": True,
            "source": "CISA Advisories",
            "url": url
        }

    return {
        "referenced": False,
        "source": "CISA Advisories",
        "url": url
    }