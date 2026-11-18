from typing import List, Dict, Any
from app.services.threat_intel import ThreatIntelService

class FindingDeduplicator:
    """
    Section 5 Unified Finding Deduplication & Risk Prioritization:
    - Groups findings by canonical fingerprint_hash
    - Merges evidence excerpts from multiple tools
    - Raises confidence ('likely' -> 'confirmed') when 2+ distinct tools agree
    - Enriches with CISA KEV real-time exploitation data & EPSS probability
    - Calculates Risk Priority score: CVSS + KEV Boost (+3.0) + EPSS
    """

    @classmethod
    def deduplicate_and_prioritize(cls, raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: Dict[str, Dict[str, Any]] = {}

        for f in raw_findings:
            fp = f.get("fingerprint_hash")
            if not fp:
                continue

            if fp not in deduped:
                # Initialize new finding
                record = f.copy()
                record["tools_agreed"] = [f["tool"]]
                deduped[fp] = record
            else:
                existing = deduped[fp]
                # Merge evidence
                existing_tool = existing.get("tool", "")
                new_tool = f.get("tool", "")
                if new_tool not in existing.get("tools_agreed", []):
                    existing["tools_agreed"].append(new_tool)
                    # Raise confidence when 2+ independent tools agree
                    existing["confidence"] = "confirmed"
                    existing["evidence"] += f" | Corroborated by {new_tool}: {f.get('evidence', '')[:200]}"

                # Keep highest severity
                sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
                if sev_order.get(f.get("severity", "info"), 0) > sev_order.get(existing.get("severity", "info"), 0):
                    existing["severity"] = f["severity"]
                    existing["title"] = f["title"]

        final_findings = []
        for item in deduped.values():
            # Real-time Threat Intel Enrichment (CISA KEV + EPSS)
            enriched = ThreatIntelService.enrich_finding(item)
            final_findings.append(enriched)

        # Sort by priority score (CVSS + KEV + EPSS)
        def priority_key(item):
            cvss = float(item.get("cvss", 0.0) or 0.0)
            kev_boost = 3.0 if item.get("kev") else 0.0
            epss = float(item.get("epss", 0.0) or 0.0)
            return cvss + kev_boost + epss

        final_findings.sort(key=priority_key, reverse=True)
        return final_findings
