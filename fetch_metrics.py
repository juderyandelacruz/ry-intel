#!/usr/bin/env python3

import json
import os
import re
import sys
import time
import urllib.request


def get_json(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def main(path):
    html = open(path, encoding="utf-8").read()

    m = re.search(r"const SNAPSHOT = (\{.*?\});\n", html, re.S)
    if not m:
        sys.exit("Could not find the SNAPSHOT constant in " + path)
    snap = json.loads(m.group(1))
    cves = [v["cve"] for v in snap["recent"]]
    print("Enriching", len(cves), "recent CVEs from", path)

    epss = {}
    for i in range(0, len(cves), 100):
        batch = cves[i:i + 100]
        data = get_json("https://api.first.org/data/v1/epss?cve=" + ",".join(batch))
        for row in data.get("data", []):
            epss[row["cve"]] = round(float(row["epss"]), 5)
        print("EPSS scores so far:", len(epss))

    
    cvss = {}
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    delay = 0.7 if key else 6.5
    for n, cve in enumerate(cves, 1):
        try:
            data = get_json(
                "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve,
                headers,
            )
            vulns = data.get("vulnerabilities", [])
            if vulns:
                met = vulns[0]["cve"].get("metrics", {})
                for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if met.get(k):
                        cvss[cve] = met[k][0]["cvssData"]["baseScore"]
                        break
        except Exception as e:
            print("NVD lookup failed for", cve, "->", e)
        if n % 10 == 0:
            print("CVSS progress:", n, "/", len(cves))
        time.sleep(delay)

    blob = json.dumps({"cvss": cvss, "epss": epss})
    html, count = re.subn(r"const METRICS = \{.*?\};", lambda m: "const METRICS = " + blob + ";", html, count=1)
    if not count:
        sys.exit("Could not find the METRICS constant to update")
    open(path, "w", encoding="utf-8").write(html)
    print("Embedded", len(cvss), "CVSS scores and", len(epss), "EPSS scores into", path)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "ry-intel-dashboard.html")
