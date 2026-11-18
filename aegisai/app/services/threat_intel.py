import os
import json
import time
import requests
from typing import Dict, Any, List, Optional

KEV_CACHE_FILE = os.path.join(os.path.dirname(__file__), "cisa_kev_cache.json")
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# Built-in baseline of critical high-profile CISA KEV entries (works offline/sandboxed)
BASELINE_KEV = {
    "CVE-2021-44228": {"name": "Apache Log4j Remote Code Execution", "ransomware": True},
    "CVE-2021-26855": {"name": "Microsoft Exchange Server SSRF (ProxyLogon)", "ransomware": True},
    "CVE-2023-34362": {"name": "MOVEit Transfer SQL Injection RCE", "ransomware": True},
    "CVE-2023-22515": {"name": "Atlassian Confluence Broken Access Control", "ransomware": True},
    "CVE-2023-4966": {"name": "Citrix NetScaler Sensitive Memory Information Disclosure", "ransomware": True},
    "CVE-2022-22965": {"name": "Spring Framework RCE (Spring4Shell)", "ransomware": True},
    "CVE-2021-41773": {"name": "Apache HTTP Server Path Traversal and RCE", "ransomware": True},
    "CVE-2023-32243": {"name": "WordPress Essential Addons for Elementor Privilege Escalation", "ransomware": False},
    "CVE-2022-26134": {"name": "Atlassian Confluence OGNL Injection", "ransomware": True},
    "CVE-2020-1472": {"name": "Microsoft Netlogon Privilege Escalation (Zerologon)", "ransomware": True},
    "CVE-2019-11510": {"name": "Pulse Connect Secure Arbitrary File Read", "ransomware": True},
    "CVE-2017-0144": {"name": "Microsoft SMBv1 Remote Code Execution (EternalBlue)", "ransomware": True}
}

class ThreatIntelService:
    """
    Threat Intelligence Synchronization Service:
    - Syncs with CISA Known Exploited Vulnerabilities (KEV) Catalog
    - Enriches findings with real-time exploitation data & EPSS probability
    - Boosts risk priority for actively exploited vulnerabilities
    """
    _kev_set = set(BASELINE_KEV.keys())
    _kev_metadata = BASELINE_KEV.copy()
    _last_sync: float = 0

    @classmethod
    def load_cache(cls):
        """Loads cached KEV catalog from disk if present."""
        if os.path.exists(KEV_CACHE_FILE):
            try:
                with open(KEV_CACHE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    cls._kev_set = set(data.get("cves", []))
                    cls._kev_metadata = data.get("metadata", BASELINE_KEV)
            except Exception:
                pass

    @classmethod
    def sync_cisa_kev(cls) -> int:
        """Downloads latest CISA KEV catalog feed."""
        try:
            res = requests.get(CISA_KEV_URL, timeout=8, headers={"User-Agent": "AegisAI-ThreatIntel/1.0"})
            if res.status_code == 200:
                payload = res.json()
                items = payload.get("vulnerabilities", [])
                new_cves = set()
                new_meta = {}
                for item in items:
                    cve_id = item.get("cveID")
                    if cve_id:
                        new_cves.add(cve_id.upper())
                        new_meta[cve_id.upper()] = {
                            "name": item.get("vulnerabilityName", ""),
                            "product": item.get("product", ""),
                            "ransomware": item.get("knownRansomwareCampaignUse", "").lower() == "known"
                        }
                if new_cves:
                    cls._kev_set = new_cves
                    cls._kev_metadata = new_meta
                    cls._last_sync = time.time()
                    # Save to local cache
                    with open(KEV_CACHE_FILE, "w", encoding="utf-8") as f:
                        json.dump({"cves": list(new_cves), "metadata": new_meta, "synced_at": time.time()}, f)
                    return len(new_cves)
        except Exception:
            pass
        return len(cls._kev_set)

    @classmethod
    def fetch_epss(cls, cve_id: str) -> float:
        """Fetches EPSS probability score from FIRST.org API."""
        if not cve_id or not cve_id.upper().startswith("CVE-"):
            return 0.0
        try:
            res = requests.get(f"{EPSS_API_URL}?cve={cve_id.upper()}", timeout=3, headers={"User-Agent": "AegisAI/1.0"})
            if res.status_code == 200:
                data = res.json()
                rows = data.get("data", [])
                if rows:
                    return float(rows[0].get("epss", 0.0))
        except Exception:
            pass
        # Fallback heuristic: if in KEV, default high exploitation probability
        return 0.75 if cve_id.upper() in cls._kev_set else 0.05

    @classmethod
    def enrich_finding(cls, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enriches a finding dictionary with CISA KEV flags, EPSS probability,
        and recalculates the Section 5 risk priority score.
        """
        raw_cves = finding.get("cve") or []
        if isinstance(raw_cves, str):
            try:
                raw_cves = json.loads(raw_cves)
            except Exception:
                raw_cves = [raw_cves] if raw_cves and raw_cves != "[]" else []

        is_kev = False
        highest_epss = float(finding.get("epss") or 0.0)

        for cve in raw_cves:
            cve_clean = str(cve).strip().upper()
            if cve_clean in cls._kev_set:
                is_kev = True
                meta = cls._kev_metadata.get(cve_clean, {})
                ransomware_note = " [Known Ransomware Campaign Vector]" if meta.get("ransomware") else ""
                finding["title"] += f" (CISA KEV Active Exploit{ransomware_note})"
                finding["description"] += f" | WARNING: {cve_clean} is listed on the CISA Known Exploited Vulnerabilities catalog."
            
            # Fetch or update EPSS if not set
            if highest_epss <= 0.01:
                highest_epss = max(highest_epss, cls.fetch_epss(cve_clean))

        finding["kev"] = is_kev
        finding["epss"] = round(highest_epss, 4)

        # Composite Priority Score: CVSS + KEV Boost (+3.0) + EPSS
        cvss = float(finding.get("cvss") or 0.0)
        kev_boost = 3.0 if is_kev else 0.0
        finding["priority_score"] = round(cvss + kev_boost + highest_epss, 2)

        return finding

# Initialize cache on import
ThreatIntelService.load_cache()
