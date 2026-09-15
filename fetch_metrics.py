import json
import re
import sys
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

    mm = re.search(r"const METRICS = (\{.*?\});", html, re.S)
    existing = json.loads(mm.group(1)) if mm else {"epss": {}}
    epss = dict(existing.get("epss", {}))
    print("Starting from", len(epss), "existing EPSS scores")

    for i in range(0, len(cves), 100):
        batch = cves[i:i + 100]
        try:
            data = get_json("https://api.first.org/data/v1/epss?cve=" + ",".join(batch))
            for row in data.get("data", []):
                epss[row["cve"]] = round(float(row["epss"]), 5)
        except Exception as e:
            print("EPSS batch failed, keeping existing scores for it ->", e)
        print("EPSS scores so far:", len(epss))

    blob = json.dumps({"epss": epss})
    html, count = re.subn(r"const METRICS = \{.*?\};", lambda m: "const METRICS = " + blob + ";", html, count=1)
    if not count:
        sys.exit("Could not find the METRICS constant to update")
    open(path, "w", encoding="utf-8").write(html)
    print("Embedded", len(epss), "EPSS scores into", path)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "ry-intel-dashboard.html")
