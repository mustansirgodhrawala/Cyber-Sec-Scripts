#!/usr/bin/env python3
# ------------------------------------------------------
# Author: Mustansir Godhrawala <me@mustansirg.in>
# WHOIS lookup – compact .in output + rotating log
# ------------------------------------------------------

import os, sys, re, csv, json, argparse, subprocess, requests, logging
from logging.handlers import RotatingFileHandler
from datetime import datetime

AUTHOR = "Mustansir G. (with T3 Chat Assistant)"
LOGFILE = "script.log"

# ------------------------- logging --------------------
logger = logging.getLogger("whois")
logger.setLevel(logging.DEBUG)
rot = RotatingFileHandler(LOGFILE, maxBytes=1_000_000, backupCount=10)
rot.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(rot)

console = logging.StreamHandler(sys.stdout)
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(console)

# --------------------- constants ----------------------
NOT_REGISTERED_PATTERNS = [
    r"\bNo match\b",
    r"\bNOT FOUND\b",
    r"\bNo Data Found\b",
    r"\bStatus:\s*free\b",
    r"\bDomain not registered\b",
    r"\bAVAILABLE\b",
    r"\bNo matching record\b",
]

REGISTRAR_SERVERS = [
]

# ------------------------------------------------------
#  Helper: run system WHOIS
# ------------------------------------------------------
def run_whois(domain, server=None):
    cmd = ["whois"]
    if server:
        cmd += ["-h", server]
    cmd.append(domain)
    logger.debug("WHOIS> %s", " ".join(cmd))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        return p.stdout.strip()
    except Exception as e:
        logger.error("WHOIS subprocess failed: %s", e)
        return None


# ------------------------------------------------------
#  Availability heuristics for plain-text whois
# ------------------------------------------------------
def looks_available(raw: str | None) -> bool:
    if not raw:
        return True
    for pat in NOT_REGISTERED_PATTERNS:
        if re.search(pat, raw, re.I):
            logger.debug("availability pattern matched: %s", pat)
            return True
    return False


# ------------------------------------------------------
#  WhoisXML fallback (JSON; trusts domainAvailability)
# ------------------------------------------------------
def query_whoisxml(domain: str, api_key: str | None):
    if not api_key:
        logger.debug("No API key supplied – skip WhoisXML")
        return None, "UNDETERMINED"

    url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    payload = {
        "apiKey": api_key,
        "domainName": domain,
        "outputFormat": "JSON",
        "da": 2,
    }
    logger.debug("Calling WhoisXML API for %s", domain)
    try:
        r = requests.post(url, json=payload, timeout=15)
        logger.debug("WhoisXML HTTP %s", r.status_code)
        if r.status_code != 200:
            return None, "UNDETERMINED"
        data = r.json()
        record = data.get("WhoisRecord", {})
        availability = (record.get("domainAvailability") or "").upper()
        raw_text = record.get("rawText") or json.dumps(data, indent=2)

        if availability == "AVAILABLE":
            return raw_text, "AVAILABLE"
        if availability == "UNAVAILABLE":
            return raw_text, "REGISTERED"
        return raw_text, "UNDETERMINED"
    except Exception as e:
        logger.error("WhoisXML failure: %s", e)
        return None, "UNDETERMINED"


# ------------------------------------------------------
#  .IN prettifier — keep essentials, drop noise
# ------------------------------------------------------
IN_NOISE_LINES = [
    r"REDACTED FOR PRIVACY",
    r"ICANN RDDS Inaccuracy Complaint Form",
    r"The data in this record is provided by",
    r"This service is intended only for query-based access",
    r"Tucows Registry reserves the right",
    r"For more information on domain status codes",
]

def pretty_in_whois(text: str) -> str:
    clean = []
    skip = False
    for line in text.splitlines():
        l = line.strip()
        if any(re.search(p, l, re.I) for p in IN_NOISE_LINES):
            skip = True
        # stop at first long disclaimer
        if skip:
            continue
        clean.append(line)
        if l.startswith(">>> Last update"):
            break  # stop before disclaimers
    return "\n".join(clean).strip()


# ------------------------------------------------------
#  Summary field extractor
# ------------------------------------------------------
SUMMARY_PATS = {
    "Domain": r"Domain Name:\s*(\S+)",
    "Registrar": r"Registrar:\s*(.+)",
    "Creation": r"Creation Date:\s*(.+)",
    "Expiry": r"(?:Registry Expiry Date|Registrar Registration Expiration Date):\s*(.+)",
    "Updated": r"Updated Date:\s*(.+)",
    "Country": r"Registrant Country:\s*(.+)",
}

def parse_summary(raw: str | None):
    if not raw:
        return {}
    out = {}
    for k, pat in SUMMARY_PATS.items():
        m = re.search(pat, raw, re.I)
        if m:
            out[k] = m.group(1).strip()
    return out


# ------------------------------------------------------
#  Master resolver (default→registrar→API)
# ------------------------------------------------------
def resolve(domain: str, api_key: str | None):
    # 1 default
    raw = run_whois(domain)
    if raw:
        if looks_available(raw):
            return raw, "AVAILABLE"
        return raw, "REGISTERED"

    # 2 registrar servers
    for srv in REGISTRAR_SERVERS:
        raw = run_whois(domain, srv)
        if raw:
            if looks_available(raw):
                return raw, "AVAILABLE"
            return raw, "REGISTERED"

    # 3 paid API
    return query_whoisxml(domain, api_key)


# ------------------------------------------------------
#  CLI
# ------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="WHOIS summary tool (compact .in)")
    ap.add_argument("-f", "--file", help="file with domains")
    ap.add_argument("domains", nargs="*", help="direct domains")
    ap.add_argument("-o", "--output", help=".txt or .csv")
    ap.add_argument("-k", "--apikey", help="WhoisXML key (or env)")
    ap.add_argument("-s", "--sound", action="store_true", help="sound symbols")
    ap.add_argument("-v", "--verbose", action="store_true", help="full WHOIS")
    args = ap.parse_args()

    # domain list
    if args.file:
        try:
            domains = [d.strip() for d in open(args.file) if d.strip()]
        except FileNotFoundError:
            print("file not found:", args.file)
            sys.exit(1)
    else:
        domains = args.domains
    if not domains:
        print("no domains supplied")
        sys.exit(1)

    api_key = args.apikey or os.getenv("WHOIS_API_KEY")

    results, counts = [], {"REGISTERED": 0, "AVAILABLE": 0, "UNDETERMINED": 0}
    for d in domains:
        logger.info("Processing %s", d)
        raw, state = resolve(d, api_key)
        if d.endswith(".in") and raw:
            raw = pretty_in_whois(raw)
        counts[state] += 1
        results.append((d, state, parse_summary(raw), raw))
        if args.sound:
            print({"REGISTERED": "🔒", "AVAILABLE": "✅", "UNDETERMINED": "⚠️"}[state], d)

    # ------------------ output ------------------------
    def write_txt(path):
        with open(path, "w") as f:
            f.write(f"# WHOIS Report (summary)  {datetime.utcnow()} UTC\n")
            f.write(f"# Author: {AUTHOR}\n\n")
            for dom, st, sm, raw in results:
                f.write(f"===== {dom} ({st}) =====\n")
                for k, v in sm.items():
                    if v:
                        f.write(f"{k}: {v}\n")
                if not sm:
                    f.write("Summary not parsed\n")
                if args.verbose and raw:
                    f.write("\n--- FULL WHOIS ---\n")
                    f.write(raw + "\n")
                f.write("\n")
            f.write(
                f"# Stats → Registered={counts['REGISTERED']} | "
                f"Available={counts['AVAILABLE']} | "
                f"Undetermined={counts['UNDETERMINED']} | "
                f"Total={len(domains)}\n"
            )

    def write_csv(path):
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(
                [
                    "Domain",
                    "State",
                    "Registrar",
                    "Creation",
                    "Expiry",
                    "Updated",
                    "Country",
                ]
            )
            for dom, st, sm, _ in results:
                w.writerow(
                    [
                        dom,
                        st,
                        sm.get("Registrar"),
                        sm.get("Creation"),
                        sm.get("Expiry"),
                        sm.get("Updated"),
                        sm.get("Country"),
                    ]
                )
            w.writerow([])
            w.writerow(
                [
                    "# Stats",
                    f"Reg={counts['REGISTERED']}  Avail={counts['AVAILABLE']}  Undet={counts['UNDETERMINED']}  Total={len(domains)}",
                ]
            )
            w.writerow(["# Author", AUTHOR])

    if args.output:
        if args.output.endswith(".csv"):
            write_csv(args.output)
            print("CSV saved →", args.output)
        else:
            write_txt(args.output)
            print("TXT saved →", args.output)
    else:
        # stdout quick view
        for dom, st, sm, _ in results:
            print(f"{dom:30} {st}")
        print(
            f"Registered={counts['REGISTERED']}  "
            f"Available={counts['AVAILABLE']}  "
            f"Undetermined={counts['UNDETERMINED']}"
        )

    logger.info("Run complete")


if __name__ == "__main__":
    main()
