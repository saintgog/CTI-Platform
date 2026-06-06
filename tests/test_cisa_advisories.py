import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from collectors.cisa_advisories import search_cisa_advisories

result = search_cisa_advisories("CVE-2026-9082")

print(result)