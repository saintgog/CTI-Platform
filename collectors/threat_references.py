THREAT_GROUP_ALIASES = {
    "Volt Typhoon": [
        "Volt Typhoon"
    ],
    "Salt Typhoon": [
        "Salt Typhoon"
    ],
    "APT41": [
        "APT41",
        "Barium",
        "Wicked Panda"
    ],
    "APT40": [
        "APT40",
        "Leviathan"
    ],
    "APT31": [
        "APT31",
        "Zirconium"
    ],
    "Mustang Panda": [
        "Mustang Panda",
        "Bronze President"
    ],
    "APT28": [
        "APT28",
        "Fancy Bear",
        "Forest Blizzard"
    ],
    "APT29": [
        "APT29",
        "Cozy Bear",
        "Midnight Blizzard"
    ],
    "Sandworm": [
        "Sandworm",
        "Voodoo Bear"
    ],
    "Turla": [
        "Turla",
        "Snake"
    ],
    "Lazarus": [
        "Lazarus",
        "Hidden Cobra"
    ],
    "Kimsuky": [
        "Kimsuky"
    ],
    "Andariel": [
        "Andariel"
    ],
    "APT33": [
        "APT33",
        "Elfin"
    ],
    "APT34": [
        "APT34",
        "OilRig"
    ],
    "APT35": [
        "APT35",
        "Charming Kitten"
    ],
    "LockBit": [
        "LockBit"
    ],
    "Clop": [
        "Clop",
        "Cl0p"
    ],
    "ALPHV": [
        "ALPHV",
        "BlackCat"
    ],
    "Akira": [
        "Akira"
    ],
    "Play": [
        "Play ransomware"
    ],
    "Black Basta": [
        "Black Basta"
    ],
    "Royal": [
        "Royal ransomware"
    ],
    "RansomHub": [
        "RansomHub"
    ],
    "Medusa": [
        "Medusa ransomware"
    ],
    "Scattered Spider": [
        "Scattered Spider",
        "UNC3944"
    ],
    "FIN7": [
        "FIN7"
    ],
    "FIN8": [
        "FIN8"
    ],
    "UNC3886": [
        "UNC3886"
    ],
    "UNC2452": [
        "UNC2452",
        "Nobelium"
    ]
}


def find_threat_references(text):
    matches = []

    text_lower = text.lower()

    for group_name, aliases in THREAT_GROUP_ALIASES.items():
        for alias in aliases:
            if alias.lower() in text_lower:
                matches.append(group_name)
                break

    return matches