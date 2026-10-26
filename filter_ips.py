#!/usr/bin/env python3
"""
filter_ips.py — drop from an IP list the addresses that belong to third-party
services (CDN, PaaS, SaaS, email, WAF) that are pointless to port-scan, keeping
only the IPs worth a port scan (the target's own infrastructure).

PaaS note (Heroku, Clever Cloud, Scalingo, Netlify, Vercel...): the target's app
does run there, but a PORT scan only reaches the platform's shared edge (and it
is against their ToS) — so the IP is dropped. The application itself of course
stays in scope for web-layer testing.

Ownership is determined with an RDAP lookup (the modern WHOIS, via
https://rdap.org, no API key) that returns the network block's owner; the block
/ organisation name is matched against a provider keyword list.

  <input file>            IP list, one per line ('#' = comment)
  <input file>.filtered   kept IPs (to scan), input order preserved
  <input file>.excluded   dropped IPs + provider/category (for audit)

Dropped by default: CDN, WAF, email, SaaS, PaaS. Large IaaS clouds
(AWS/GCP/Azure/OVH/Hetzner...) and shared hosting are KEPT by default because
the target often runs its own infra there; --drop-cloud / --drop-hosting drop
them too. When in doubt (RDAP silent, unknown category) the IP is KEPT — better
to scan one extra IP than to miss a real target.

Usage:
  pip install requests
  python3 filter_ips.py ips
  python3 filter_ips.py ips --drop-cloud -t 12 -v
  python3 filter_ips.py ips --drop mytenant --keep 51.20.        # manual tuning

For authorized testing only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import os
import sys
import threading
import time

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("[!] pip install requests")

UA = "filter_ips/1.0 (+recon triage)"

# ----------------------------------------------------------------------------
# Classification rules.
#
# (category, [keywords]) — the first keyword found (as a case-insensitive
# substring) in the RDAP "signature" (block name + organisations + handles)
# sets the category. Order matters: email before cloud, so that Amazon SES is
# not filed under the generic cloud.
# ----------------------------------------------------------------------------

RULES = [
    ("email", [
        "mailgun", "sendgrid", "sendgrid.net", "mailchimp", "mandrill", "mailjet",
        "postmark", "sparkpost", "sendinblue", "brevo", "mimecast", "proofpoint",
        "pphosted", "ppe-hosted", "messagelabs", "sailthru", "klaviyo",
        "constantcontact", "campaignmonitor", "elasticemail", "socketlabs",
        "returnpath", "emailsrvr", "mailtrap", "amazon-aes", "amazon ses",
        "amazonses", "mailanyone", "mailhostbox", "dyn-mail", "sparkpostmail",
        "postmarkapp", "sparkmail", "mtasv", "mailsecure",
    ]),
    ("cdn", [
        "cloudflare", "fastly", "akamai", "cloudfront", "edgecast", "stackpath",
        "highwinds", "limelight", "llnw", "cdn77", "cachefly", "keycdn", "bunny",
        "section.io", "gcore", "g-core", "azion", "jsdelivr", "cdnetworks",
        "quantil", "medianova", "arvancloud", "cachenetworks", "verizon-gni",
        "leasewebcdn", "edgio", "edg.io",
    ]),
    ("waf", [
        "incapsula", "imperva", "sucuri", "barracuda", "radware", "zscaler",
        "cloudbric", "reblaze", "wallarm", "stackpath-waf",
    ]),
    ("paas", [
        # application platforms: the target's app runs here but on shared infra
        # behind the platform's edge — a port scan only sees the shared router,
        # and it is against their ToS. Drop.
        "heroku", "herokuapp", "netlify", "vercel", "zeit", "now.sh",
        "render.com", "onrender", "fly.io", "flyio", "clever-cloud",
        "clever cloud", "clevercloud", "cleverapps", "scalingo", "platform.sh",
        "platformsh", "railway", "railway.app", "koyeb", "qovery", "aptible",
        "gigalixir", "engineyard", "engine yard", "northflank", "porter",
        "deta", "glitch", "replit", "repl.it", "pythonanywhere", "back4app",
        "surge.sh", "adaptable", "cyclic", "fdgw", "alwaysdata", "planethoster",
    ]),
    ("saas", [
        "shopify", "shopifycloud", "myshopify", "squarespace", "wix", "automattic",
        "wordpress", "wpengine", "wp-engine", "kinsta", "pantheon", "hubspot",
        "zendesk", "freshdesk", "freshworks", "salesforce", "force.com",
        "atlassian", "github", "gitlab", "statuspage",
        "webflow", "bigcommerce", "cloudinary", "fastspring", "gumroad",
        "intercom", "typeform", "surveymonkey", "stripe", "braintree", "marketo",
        "pardot", "discourse", "zoho", "shopware", "bigcartel", "weebly",
        "godaddy-websites",
    ]),
    ("cloud", [
        "amazon", "aws", "ec2", "google", "googleusercontent", "gcp",
        "microsoft", "azure", "msft", "digitalocean", "linode", "vultr",
        "hetzner", "ovh", "scaleway", "online s.a.s", "contabo", "upcloud",
        "oracle", "ibm cloud", "softlayer", "alibaba", "aliyun", "tencent",
        "rackspace", "leaseweb", "hostwinds", "ionos", "1&1", "gandi",
        "digital ocean", "ovhcloud",
    ]),
    ("hosting", [
        "dreamhost", "godaddy", "namecheap", "hostgator", "bluehost", "siteground",
        "a2 hosting", "inmotion", "digitalpacific", "hostinger", "liquidweb",
        "webhostingpad", "nexcess", "flywheel",
    ]),
]

# categories dropped by default
DEFAULT_DROP = {"email", "cdn", "waf", "saas", "paas"}


class NetCache:
    """Caches classifications per network block, so RDAP is not queried again
    for every IP in the same netblock."""

    def __init__(self):
        self._nets: list[tuple] = []      # (ip_network, result)
        self._lk = threading.Lock()

    def get(self, ip: ipaddress.IPv4Address):
        with self._lk:
            for net, res in self._nets:
                if ip in net:
                    return res
        return None

    def put(self, cidrs: list[str], result: dict):
        with self._lk:
            for c in cidrs:
                try:
                    self._nets.append((ipaddress.ip_network(c, strict=False), result))
                except ValueError:
                    continue


class Rate:
    """Global minimum gap between RDAP requests, independent of thread count."""

    def __init__(self, gap):
        self.gap = max(0.0, gap)
        self._next = 0.0
        self._lk = threading.Lock()

    def wait(self):
        if self.gap <= 0:
            return
        with self._lk:
            now = time.monotonic()
            w = max(0.0, self._next - now)
            self._next = max(now, self._next) + self.gap
        if w:
            time.sleep(w)


def rdap_lookup(ip: str, session: requests.Session, rate: Rate,
                timeout: float, retries: int = 3) -> dict:
    """Return {name, org, cidrs, sig, ok}. sig = the text to classify."""
    url = f"https://rdap.org/ip/{ip}"
    last = ""
    for attempt in range(1, retries + 1):
        rate.wait()
        try:
            r = session.get(url, timeout=timeout,
                            headers={"User-Agent": UA, "Accept": "application/rdap+json"})
        except requests.RequestException as e:
            last = str(e)
            time.sleep(0.5 * attempt)
            continue
        if r.status_code == 429:                 # rate-limited: back off
            time.sleep(1.5 * attempt)
            last = "429"
            continue
        if r.status_code == 404:
            return {"ok": True, "name": "", "org": "", "cidrs": [], "sig": ""}
        if r.status_code >= 400:
            last = f"HTTP {r.status_code}"
            time.sleep(0.4 * attempt)
            continue
        try:
            data = r.json()
        except ValueError:
            last = "bad json"
            continue

        name = (data.get("name") or "").strip()
        # organisations / entities: names and handles
        orgs = []
        for ent in data.get("entities", []) or []:
            h = ent.get("handle")
            if h:
                orgs.append(str(h))
            va = ent.get("vcardArray")
            if isinstance(va, list) and len(va) > 1:
                for item in va[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        orgs.append(str(item[3]))
        remarks = " ".join(
            (rm.get("title", "") + " " + " ".join(rm.get("description", []) or []))
            for rm in (data.get("remarks") or []))
        # covered CIDR blocks (for the cache)
        cidrs = []
        for c in data.get("cidr0_cidrs", []) or []:
            pfx = c.get("v4prefix") or c.get("v6prefix")
            ln = c.get("length")
            if pfx and ln is not None:
                cidrs.append(f"{pfx}/{ln}")
        if not cidrs:
            sa, ea = data.get("startAddress"), data.get("endAddress")
            if sa and ea:
                try:
                    for net in ipaddress.summarize_address_range(
                            ipaddress.ip_address(sa), ipaddress.ip_address(ea)):
                        cidrs.append(str(net))
                except (ValueError, TypeError):
                    pass

        sig = " ".join([name] + orgs + [remarks]).lower()
        return {"ok": True, "name": name, "org": "; ".join(dict.fromkeys(orgs)),
                "cidrs": cidrs, "sig": sig}
    return {"ok": False, "name": "", "org": "", "cidrs": [], "sig": "", "err": last}


def classify(sig: str, extra_drop: list[str], extra_keep: list[str]) -> tuple:
    """Return (category, keyword). category='' when unknown."""
    for kw in extra_keep:
        if kw and kw.lower() in sig:
            return "keep-forced", kw
    for kw in extra_drop:
        if kw and kw.lower() in sig:
            return "drop-forced", kw
    for cat, kws in RULES:
        for kw in kws:
            if kw in sig:
                return cat, kw
    return "", ""


def load_ips(path: str) -> list[str]:
    out, seen = [], set()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.split("#", 1)[0].strip()
            if not s:
                continue
            try:
                ip = str(ipaddress.ip_address(s))
            except ValueError:
                continue
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
    return out


# ----------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="filter_ips.py",
        description="Filter an IP list by dropping third-party services "
                    "(CDN/PaaS/SaaS/email/WAF) that are pointless to port-scan.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Output: <input>.filtered (to scan) and <input>.excluded (audit).")
    ap.add_argument("input", help="IP list file, one per line")
    ap.add_argument("--drop-cloud", action="store_true",
                    help="also drop IaaS clouds (AWS/GCP/Azure/OVH/Hetzner...)")
    ap.add_argument("--drop-hosting", action="store_true",
                    help="also drop shared hosting (GoDaddy, Bluehost...)")
    ap.add_argument("--drop", action="append", default=[], metavar="KW",
                    help="extra keyword to drop (repeatable) — matched against "
                         "the RDAP signature; also accepts an IP prefix")
    ap.add_argument("--keep", action="append", default=[], metavar="KW",
                    help="keyword to always keep, takes precedence (repeatable)")
    ap.add_argument("-t", "--threads", type=int, default=10,
                    help="concurrent RDAP requests (default 10)")
    ap.add_argument("--rate", type=float, default=0.0, metavar="SEC",
                    help="global minimum gap between RDAP requests (default 0)")
    ap.add_argument("--timeout", type=float, default=15.0, help="RDAP timeout (s)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print the classification of every IP")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.input):
        print(f"error: no such file: {args.input}", file=sys.stderr)
        return 2

    ips = load_ips(args.input)
    if not ips:
        print("error: no valid IP in the file", file=sys.stderr)
        return 2

    drop_cats = set(DEFAULT_DROP)
    if args.drop_cloud:
        drop_cats.add("cloud")
    if args.drop_hosting:
        drop_cats.add("hosting")

    # IP prefixes passed to --drop / --keep (e.g. "104.244.43.")
    ip_drop = [k for k in args.drop if k[:1].isdigit()]
    ip_keep = [k for k in args.keep if k[:1].isdigit()]
    kw_drop = [k for k in args.drop if not k[:1].isdigit()]
    kw_keep = [k for k in args.keep if not k[:1].isdigit()]

    print(f"filter_ips — {len(ips)} unique IP(s) | "
          f"dropping: {', '.join(sorted(drop_cats))} | "
          f"threads {args.threads}")

    cache = NetCache()
    rate = Rate(args.rate)
    session = requests.Session()
    results: dict[str, dict] = {}
    lk = threading.Lock()
    done = [0]

    def work(ip: str):
        ipa = ipaddress.ip_address(ip)
        # manual prefixes first (no network request needed)
        for pfx in ip_keep:
            if ip.startswith(pfx):
                res = {"cat": "keep-forced", "kw": pfx, "org": "", "name": ""}
                break
        else:
            for pfx in ip_drop:
                if ip.startswith(pfx):
                    res = {"cat": "drop-forced", "kw": pfx, "org": "", "name": ""}
                    break
            else:
                cached = cache.get(ipa)
                if cached is not None:
                    res = cached
                else:
                    info = rdap_lookup(ip, session, rate, args.timeout)
                    if not info["ok"]:
                        res = {"cat": "error", "kw": info.get("err", ""),
                               "org": "", "name": ""}
                    else:
                        cat, kw = classify(info["sig"], kw_drop, kw_keep)
                        res = {"cat": cat, "kw": kw, "org": info["org"],
                               "name": info["name"]}
                        if info["cidrs"]:
                            cache.put(info["cidrs"], res)
        with lk:
            results[ip] = res
            done[0] += 1
            n = done[0]
        if args.verbose:
            keep = res["cat"] not in drop_cats and not res["cat"].startswith("drop")
            tag = "KEEP" if keep else "drop"
            print(f"  [{n}/{len(ips)}] {tag:4} {ip:16} "
                  f"{res['cat'] or 'unknown':12} {res.get('name') or res.get('org') or ''}"
                  f"{(' ['+res['kw']+']') if res['kw'] else ''}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        list(ex.map(work, ips))

    # per-IP decision, input order preserved
    keep_ips, drop_ips = [], []
    for ip in ips:
        res = results.get(ip, {"cat": "error", "kw": "", "org": "", "name": ""})
        cat = res["cat"]
        if cat == "keep-forced":
            keep = True
        elif cat == "drop-forced":
            keep = False
        elif cat == "":                 # unknown -> keep
            keep = True
        elif cat == "error":            # RDAP silent -> keep
            keep = True
        else:
            keep = cat not in drop_cats
        (keep_ips if keep else drop_ips).append((ip, res))

    out_keep = args.input + ".filtered"
    out_drop = args.input + ".excluded"
    with open(out_keep, "w", encoding="utf-8") as f:
        for ip, _ in keep_ips:
            f.write(ip + "\n")
    with open(out_drop, "w", encoding="utf-8") as f:
        for ip, res in drop_ips:
            label = res.get("name") or res.get("org") or ""
            f.write(f"{ip}\t{res['cat']}\t{res['kw']}\t{label}\n")

    # breakdown by category / provider
    from collections import Counter
    by_cat = Counter(res["cat"] or "unknown" for _, res in drop_ips)
    print(f"\n--- summary ---")
    print(f"total tested : {len(ips)}")
    print(f"to scan      : {len(keep_ips)}  -> {out_keep}")
    print(f"dropped      : {len(drop_ips)}  -> {out_drop}")
    if drop_ips:
        for cat, n in by_cat.most_common():
            provs = Counter((res.get('name') or res.get('org') or res['kw'] or '?')
                            for _, res in drop_ips if (res['cat'] or 'unknown') == cat)
            top = ", ".join(f"{p} ({c})" for p, c in provs.most_common(4))
            print(f"  {cat:12} {n:4}   {top}")
    n_err = sum(1 for _, r in keep_ips if r["cat"] == "error")
    if n_err:
        print(f"  note: {n_err} IP(s) kept for lack of an RDAP answer (verify)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
