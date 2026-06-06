THREAT_ACTORS = {
    "APT29": ["apt29", "midnight blizzard", "cozy bear", "the dukes"],
    "APT28": ["apt28", "fancy bear", "sofacy", "strontium"],
    "LockBit": ["lockbit", "lockbit 3.0"],
    "ALPHV": ["alphv", "blackcat", "noberus"],
    "Scattered Spider": ["scattered spider", "unc3944", "octo tempest", "0ktapus"],
    "Lazarus": ["lazarus", "hidden cobra", "zinc"],
    "Volt Typhoon": ["volt typhoon", "vanguard panda"],
    "Clop": ["clop", "cl0p"],
    "Akira": ["akira ransomware"],
    "Black Basta": ["black basta"],
    "FIN7": ["fin7", "carbanak"],
    "FIN11": ["fin11"],
    "TA505": ["ta505"],
    "Sandworm": ["sandworm", "voodoo bear"],
    "OilRig": ["oilrig", "apt34", "helix kitten"],
    "MuddyWater": ["muddywater", "static kitten", "seedworm"],
    "Kimsuky": ["kimsuky", "velvet chollima"],
    "Turla": ["turla", "snake", "venomous bear"],
    "Mustang Panda": ["mustang panda", "bronze president"],
    "Charming Kitten": ["charming kitten", "apt35", "phosphorus"],
}


def find_threat_references(text):
    if not text:
        return []

    text = text.lower()
    matches = []

    for actor, aliases in THREAT_ACTORS.items():
        for alias in aliases:
            if alias.lower() in text:
                matches.append(actor)
                break

    return matches