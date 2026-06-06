import re
import requests
from html import unescape


def clean_html(html_text):
    text = re.sub(r"<script.*?</script>", " ", html_text, flags=re.DOTALL)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = unescape(text)
    return re.sub(r"\s+", " ", text)


def search_cisa_advisory_text(cve_id):
    base_url = "https://www.cisa.gov"
    index_url = "https://www.cisa.gov/news-events/cybersecurity-advisories"

    response = requests.get(index_url, timeout=20)
    response.raise_for_status()

    links = re.findall(r'href="([^"]+)"', response.text)

    advisory_urls = []

    for link in links:
        if "/news-events/cybersecurity-advisories/" in link:
            if link.startswith("/"):
                link = base_url + link

            if link not in advisory_urls:
                advisory_urls.append(link)

    matched_advisories = []

    for url in advisory_urls[:100]:
        try:
            advisory_response = requests.get(url, timeout=20)
            advisory_response.raise_for_status()

            text = clean_html(advisory_response.text)

            if cve_id.lower() in text.lower():
                matched_advisories.append({
                    "url": url,
                    "text": text
                })

        except requests.RequestException:
            continue

    return matched_advisories
def collect_recent_cisa_advisory_text(limit=100):
    base_url = "https://www.cisa.gov"
    index_url = "https://www.cisa.gov/news-events/cybersecurity-advisories"

    response = requests.get(index_url, timeout=20)
    response.raise_for_status()

    links = re.findall(r'href="([^"]+)"', response.text)

    advisory_urls = []

    for link in links:
        if "/news-events/cybersecurity-advisories/" in link:
            if link.startswith("/"):
                link = base_url + link

            if link not in advisory_urls:
                advisory_urls.append(link)

    texts = []

    for url in advisory_urls[:limit]:
        try:
            advisory_response = requests.get(url, timeout=20)
            advisory_response.raise_for_status()

            text = clean_html(advisory_response.text)

            texts.append({
                "url": url,
                "text": text
            })

        except requests.RequestException:
            continue

    return texts