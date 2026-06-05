import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from collectors.threat_actor import search_cisa_threat_activity

result = search_cisa_threat_activity("CVE-2026-9082")

print(result)