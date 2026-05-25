"""
Auto Recon Framework - CVE & MITRE ATT&CK Mapper
Maps discovered vulnerabilities to CVE details and MITRE tactics/techniques
"""
import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional

from utils.logger import log


# MITRE ATT&CK Enterprise Tactic IDs to names
TACTIC_NAMES = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}

# MITRE technique IDs to names (subset relevant to recon/exploitation)
TECHNIQUE_NAMES = {
    "T1046":     "Network Service Discovery",
    "T1190":     "Exploit Public-Facing Application",
    "T1592":     "Gather Victim Host Information",
    "T1592.002": "Software",
    "T1590":     "Gather Victim Network Information",
    "T1590.001": "Domain Properties",
    "T1590.005": "IP Addresses",
    "T1595":     "Active Scanning",
    "T1595.002": "Vulnerability Scanning",
    "T1083":     "File and Directory Discovery",
    "T1078":     "Valid Accounts",
    "T1078.001": "Default Accounts",
    "T1059.007": "JavaScript",
    "T1203":     "Exploitation for Client Execution",
    "T1090":     "Proxy",
    "T1584":     "Compromise Infrastructure",
}

# CVSS score → risk label
CVSS_LABELS = {
    (9.0, 10.0): ("Critical", "🔴"),
    (7.0, 8.9):  ("High",     "🟠"),
    (4.0, 6.9):  ("Medium",   "🟡"),
    (0.1, 3.9):  ("Low",      "🔵"),
    (0.0, 0.0):  ("None",     "⚪"),
}


@dataclass
class CVEDetail:
    cve_id: str
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: str = ""
    published: str = ""
    references: list = field(default_factory=list)
    cwe: list = field(default_factory=list)


def get_tactic_name(tactic_id: str) -> str:
    return TACTIC_NAMES.get(tactic_id, tactic_id)


def get_technique_name(technique_id: str) -> str:
    return TECHNIQUE_NAMES.get(technique_id, technique_id)


def cvss_to_label(score: float) -> tuple[str, str]:
    """Return (severity_label, emoji) for a CVSS score."""
    for (low, high), (label, emoji) in CVSS_LABELS.items():
        if low <= score <= high:
            return label, emoji
    return "Unknown", "⚪"


def fetch_cve_details(cve_id: str) -> Optional[CVEDetail]:
    """
    Fetch CVE details from the NVD API (v2).
    Returns None on failure.
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AutoRecon/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        cve_data = vulns[0].get("cve", {})

        # Description
        descs = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descs if d.get("lang") == "en"), ""
        )

        # CVSS
        metrics = cve_data.get("metrics", {})
        cvss_score = 0.0
        cvss_vector = ""
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metric_key in metrics:
                m = metrics[metric_key][0]["cvssData"]
                cvss_score  = float(m.get("baseScore", 0.0))
                cvss_vector = m.get("vectorString", "")
                break

        severity, _ = cvss_to_label(cvss_score)

        # References
        refs = [r["url"] for r in cve_data.get("references", [])]

        # CWE
        weaknesses = cve_data.get("weaknesses", [])
        cwe = []
        for w in weaknesses:
            for desc in w.get("description", []):
                if desc.get("lang") == "en":
                    cwe.append(desc["value"])

        return CVEDetail(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            published=cve_data.get("published", ""),
            references=refs[:5],
            cwe=cwe,
        )

    except Exception as e:
        log.debug(f"CVE lookup failed for {cve_id}: {e}", "report")
        return None


def enrich_findings_with_cve(findings, fetch_online: bool = True) -> dict[str, CVEDetail]:
    """
    Fetch CVE details for all CVE IDs found in nuclei results.
    Returns a dict: {cve_id: CVEDetail}
    """
    all_cves = set()
    for f in findings:
        all_cves.update(f.cve_ids)

    cve_details = {}
    if not fetch_online or not all_cves:
        return cve_details

    log.info(f"Fetching details for {len(all_cves)} CVEs from NVD...", "report")
    for cve_id in all_cves:
        detail = fetch_cve_details(cve_id)
        if detail:
            cve_details[cve_id] = detail
            log.debug(f"  {cve_id} — CVSS: {detail.cvss_score} ({detail.severity})", "report")

    return cve_details


def build_mitre_summary(findings) -> dict:
    """
    Build a MITRE ATT&CK summary from all findings.
    Returns: { tactic: { technique: [vuln_names] } }
    """
    summary = {}
    for f in findings:
        for tactic_id in f.mitre_tactics:
            tactic_name = get_tactic_name(tactic_id)
            if tactic_name not in summary:
                summary[tactic_name] = {}
            for technique_id in f.mitre_techniques:
                technique_name = get_technique_name(technique_id)
                key = f"{technique_id}: {technique_name}"
                if key not in summary[tactic_name]:
                    summary[tactic_name][key] = []
                summary[tactic_name][key].append(f.name)
    return summary
