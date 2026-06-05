import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from collectors.threat_actor import assess_threat_activity

result = assess_threat_activity(
    True,
    9,
    1
)

print(result)