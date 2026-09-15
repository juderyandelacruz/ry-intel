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
    mm = re.search(r"const METRICS = (\{.*?\});", html, re.S)
    existing = json.loads(mm.group(1)) if mm else {"cvss": {}, "epss": {}}
    cvss = dict(existing.get("cvss", {}))
    epss = dict(existing.get("epss", {}))
    print("Starting from", len(cvss), "existing CVSS and", len(epss), "existing EPSS scores")
    for i in range(0, len(cves), 100):
        batch = cves[i:i + 100]
        try:
            data = get_json("https://api.first.org/data/v1/epss?cve=" + ",".join(batch))
            for row in data.get("data", []):
                epss[row["cve"]] = round(float(row["epss"]), 5)
        except Exception as e:
            print("EPSS batch failed, keeping existing scores for it ->", e)
        print("EPSS scores so far:", len(epss))
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    delay = 1.5 if key else 8.0
    shown_diagnostic = False
    consecutive_total_failures = 0
    CIRCUIT_BREAKER = 8
    aborted = False
    for n, cve in enumerate(cves, 1):
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve
        succeeded = False
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
                succeeded = True
                break
            except Exception as e:
                if not shown_diagnostic:
                    try:
                        get_json_with_body_on_error(url, headers)
                    except RuntimeError as detailed:
                        print("First NVD failure, full detail:", detailed)
                    shown_diagnostic = True
                if attempt < 2:
                    time.sleep(5 * (attempt + 1))
                else:
                    print("NVD lookup failed for", cve, "after 3 attempts ->", e)
        consecutive_total_failures = 0 if succeeded else consecutive_total_failures + 1
        if consecutive_total_failures >= CIRCUIT_BREAKER:
            print(f"STOPPING EARLY: the last {CIRCUIT_BREAKER} CVEs all failed every retry. "
                  f"NVD appears to be blocking or rejecting this runner entirely, not just "
                  f"having an off moment. Keeping the {len(cvss)} CVSS scores already embedded "
                  f"from a previous run rather than burning more time on a lookup that isn't "
                  f"going to succeed. If this keeps happening, run this script from a regular "
                  f"computer once instead of GitHub Actions.")
            aborted = True
            break
        if n % 10 == 0:
            print("CVSS progress:", n, "/", len(cves))
        time.sleep(delay)
    blob = json.dumps({"cvss": cvss, "epss": epss})
    html, count = re.subn(r"const METRICS = \{.*?\};", lambda m: "const METRICS = " + blob + ";", html, count=1)
    if not count:
        sys.exit("Could not find the METRICS constant to update")
    open(path, "w", encoding="utf-8").write(html)
    print("Embedded", len(cvss), "CVSS scores and", len(epss), "EPSS scores into", path,
          "(stopped early)" if aborted else "(completed all CVEs)")
if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "ry-intel-dashboard.html")
