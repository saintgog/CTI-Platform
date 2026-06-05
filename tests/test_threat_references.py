import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from collectors.threat_references import find_threat_references

text = """
Microsoft reported activity linked to Midnight Blizzard.
Separately, exploitation attempts were associated with BlackCat
and Scattered Spider.
"""

results = find_threat_references(text)

print(results)