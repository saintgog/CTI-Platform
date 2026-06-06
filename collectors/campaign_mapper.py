CAMPAIGN_HINTS = {
    "SolarWinds": "APT29",
    "PAN-OS": "Volt Typhoon",
    "WebLogic": "Lazarus",
    "Kernel": "APT28"
}


def infer_campaign(vendor, product):
    text = f"{vendor} {product}".lower()

    for keyword, actor in CAMPAIGN_HINTS.items():
        if keyword.lower() in text:
            return actor

    return None