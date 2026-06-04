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

    response = requests.get(url, headers=headers, params=params)
    data = response.json()

    repos = []

    for repo in data.get("items", [])[:5]:
        repos.append({
            "name": repo["full_name"],
            "url": repo["html_url"],
            "stars": repo["stargazers_count"],
            "updated_at": repo["updated_at"]
        })

    return {
        "total_count": data.get("total_count", 0),
        "repos": repos
    }