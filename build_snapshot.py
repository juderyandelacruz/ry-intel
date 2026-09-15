import datetime
import json
import re
import sys
def build(raw):
    vulns = raw["vulnerabilities"]
    today = datetime.date.today()
    monthly, vendors = {}, {}
    ransom = last30 = due14 = 0
    for v in vulns:
        month = v["dateAdded"][:7]
        monthly[month] = monthly.get(month, 0) + 1
        vendors[v["vendorProject"]] = vendors.get(v["vendorProject"], 0) + 1
        if v.get("knownRansomwareCampaignUse") == "Known":
            ransom += 1
        added = datetime.date.fromisoformat(v["dateAdded"])
        if (today - added).days <= 30:
            last30 += 1
        due_in = (datetime.date.fromisoformat(v["dueDate"]) - today).days
        if 0 <= due_in <= 14:
            due14 += 1
    recent = sorted(vulns, key=lambda v: v["dateAdded"], reverse=True)[:120]
    recent = [{
        "cve": v["cveID"],
        "vendor": v["vendorProject"],
        "product": v["product"],
        "name": v["vulnerabilityName"],
        "added": v["dateAdded"],
        "due": v["dueDate"],
        "ransom": v.get("knownRansomwareCampaignUse") == "Known",
        "desc": v["shortDescription"],
        "action": v["requiredAction"],
    } for v in recent]
    return {
        "catalogVersion": raw["catalogVersion"],
        "dateReleased": raw["dateReleased"][:10],
        "total": raw["count"],
        "last30": last30,
        "ransom": ransom,
        "vendorCount": len(vendors),
        "due14": due14,
        "monthly": sorted(monthly.items()),
        "topVendors": sorted(vendors.items(), key=lambda kv: -kv[1])[:8],
        "recent": recent,
    }
def main(feed_path, html_path):
    raw = json.load(open(feed_path, encoding="utf-8"))
    snap = build(raw)
    blob = json.dumps(snap, separators=(",", ":"))
    html = open(html_path, encoding="utf-8").read()
    html, count = re.subn(r"const SNAPSHOT = \{.*?\};\n",
                          lambda m: "const SNAPSHOT = " + blob + ";\n",
                          html, count=1, flags=re.S)
    if not count:
        sys.exit("Could not find the SNAPSHOT constant in " + html_path)
    open(html_path, "w", encoding="utf-8").write(html)
    print("Embedded catalog v" + snap["catalogVersion"], "with", snap["total"],
          "entries and", len(snap["recent"]), "recent entries (full text) into", html_path)
if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
