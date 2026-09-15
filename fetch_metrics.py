#!/usr/bin/env python3

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request


def get_json(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def get_json_with_body_on_error(url, headers=None):
    """Like get_json, but on an HTTP error it also surfaces whatever body
    NVD sent back (often the real explanation, since NVD is known to return
    misleading status codes like 404 for what's actually a rate limit)."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()[:200]
        except Exception:
            pass
        raise RuntimeError(f"HTTP {e.code}: {e.reason}" + (f" | body: {body}" if body else ""))


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
    delay = 1.5 if key else 8.0
    shown_diagnostic = False
    failures = 0
    for n, cve in enumerate(cves, 1):
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve
        for attempt in range(3):
            try:
                data = get_json(url, headers)
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    met = vulns[0]["cve"].get("metrics", {})
                    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if met.get(k):
                            cvss[cve] = met[k][0]["cvssData"]["baseScore"]
                            break
                break  # success (or a legitimately empty result) - stop retrying
            except Exception as e:
                failures += 1
                if not shown_diagnostic:
                    # only the very first failure gets the full body dump,
                    # so the log stays readable instead of 120 walls of text
                    try:
                        detail = get_json_with_body_on_error(url, headers)
                    except RuntimeError as detailed:
                        print("First NVD failure, full detail:", detailed)
                    shown_diagnostic = True
                if attempt < 2:
                    backoff = 5 * (attempt + 1)
                    time.sleep(backoff)
                else:
                    print("NVD lookup failed for", cve, "after 3 attempts ->", e)
        if n % 10 == 0:
            print("CVSS progress:", n, "/", len(cves))
        time.sleep(delay)

    if failures > len(cves):
        print("WARNING:", failures, "total NVD failures across", len(cves),
              "CVEs. This many retried failures usually means NVD is blocking "
              "or heavily throttling this runner's network, not that the key "
              "or code is wrong. Consider running this script from a normal "
              "computer instead of GitHub Actions if this keeps happening.")

    blob = json.dumps({"cvss": cvss, "epss": epss})
    html, count = re.subn(r"const METRICS = \{.*?\};", lambda m: "const METRICS = " + blob + ";", html, count=1)
    if not count:
        sys.exit("Could not find the METRICS constant to update")
    open(path, "w", encoding="utf-8").write(html)
    print("Embedded", len(cvss), "CVSS scores and", len(epss), "EPSS scores into", path)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "ry-intel-dashboard.html")
