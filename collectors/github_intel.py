import requests
import os
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")


def search_github_for_cve(cve_id):

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    url = "https://api.github.com/search/repositories"

    params = {
        "q": cve_id,
        "sort": "updated",
        "order": "desc"
    }

    response = requests.get(
        url,
        headers=headers,
        params=params
    )

    return response.json()