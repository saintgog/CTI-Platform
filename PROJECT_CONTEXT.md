# CTI-Platform Project Context

## Current Version

v0.3

## Purpose

Cyber Threat Intelligence Platform that collects, enriches, correlates, scores, and reports on active vulnerabilities.

## Intelligence Sources

### Vulnerability Intelligence

* CISA KEV
* NVD

### Exploit Intelligence

* GitHub CVE Search
* Exploit-DB

### Threat Intelligence

* Threat Activity Assessment
* Threat Reference Detection
* CISA Advisory Correlation

## Analysis Features

### Threat Scoring

Factors:

* KEV Status
* CVSS Score
* GitHub Repositories
* Exploit-DB Results

### Exploit Confidence

Levels:

* NONE
* LOW
* MEDIUM
* HIGH

### Threat Activity

Levels:

* LOW
* MEDIUM
* HIGH

### Threat References

Alias normalization for:

* APT29 / Midnight Blizzard
* APT28 / Fancy Bear
* ALPHV / BlackCat
* Scattered Spider / UNC3944
* LockBit
* Lazarus
* Volt Typhoon
* Additional groups

## Reports

### JSON

reports/daily_report.json

### Analyst Brief

reports/daily_brief.txt

Includes:

* CVE Details
* Threat Score
* Priority
* Exploit Confidence
* Threat Activity
* Threat References
* GitHub Details
* Exploit-DB Details

## Directory Structure

collectors/

* github_intel.py
* exploitdb.py
* threat_actor.py
* threat_references.py
* cisa_advisories.py

tests/

* test_exploitdb.py
* test_threat_actor.py
* test_threat_references.py
* test_cisa_advisories.py

## Next Planned Features

1. Assessment Rationale
2. Historical Trend Tracking
3. Threat Report Correlation
4. Dashboard (Flask)
5. Threat Actor Campaign Tracking
