import os
import json
import requests
from urllib.parse import urljoin
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

# Comprehensive modern API Documentation, Schema, and Specification endpoints
API_SPEC_ENDPOINTS = [
    # OpenAPI / Swagger JSON & YAML endpoints
    ("/openapi.json", "OpenAPI 3.0 Specification JSON", "medium", "CWE-200"),
    ("/swagger.json", "Swagger 2.0 API Specification JSON", "medium", "CWE-200"),
    ("/v2/api-docs", "SpringFox Swagger v2 API Specification", "medium", "CWE-200"),
    ("/v3/api-docs", "SpringDoc OpenAPI v3 Specification", "medium", "CWE-200"),
    ("/v3/api-docs/swagger-config", "OpenAPI v3 Swagger Config Definition", "low", "CWE-200"),
    ("/api/v1/openapi.json", "Versioned OpenAPI Specification JSON", "medium", "CWE-200"),
    ("/api/v2/openapi.json", "Versioned OpenAPI v2 Specification JSON", "medium", "CWE-200"),
    ("/api/v3/openapi.json", "Versioned OpenAPI v3 Specification JSON", "medium", "CWE-200"),
    ("/api-docs", "Generic API Documentation JSON", "medium", "CWE-200"),
    ("/docs/openapi.json", "Documentation OpenAPI Specification", "medium", "CWE-200"),
    ("/docs/swagger.json", "Documentation Swagger Specification", "medium", "CWE-200"),
    ("/api/swagger.json", "API Path Swagger Specification", "medium", "CWE-200"),
    ("/openapi.yaml", "OpenAPI Specification in YAML Format", "medium", "CWE-200"),
    ("/swagger.yaml", "Swagger Specification in YAML Format", "medium", "CWE-200"),

    # Interactive API Explorer UIs
    ("/swagger/index.html", "Swagger UI Interactive Console", "medium", "CWE-200"),
    ("/swagger-ui.html", "SpringFox Swagger UI Interactive Console", "medium", "CWE-200"),
    ("/swagger-ui/index.html", "Swagger UI Explorer Web Console", "medium", "CWE-200"),
    ("/docs", "FastAPI / ReDoc Documentation Web Interface", "low", "CWE-200"),
    ("/redoc", "ReDoc OpenAPI Documentation Interface", "low", "CWE-200"),
    ("/api/docs", "API Documentation Console", "low", "CWE-200"),
    ("/api/explorer", "LoopBack / Express API Explorer Console", "medium", "CWE-200"),

    # Exported API Client Collections
    ("/postman.json", "Exported Postman Collection JSON", "high", "CWE-200"),
    ("/postman_collection.json", "Postman API Collection Export", "high", "CWE-200"),
    ("/insomnia.json", "Insomnia REST Client Collection", "high", "CWE-200"),
    ("/api-collection.json", "API Client Collection Definition", "high", "CWE-200"),

    # SOAP / Web Services WSDL
    ("/?wsdl", "SOAP Web Service WSDL Definition", "medium", "CWE-200"),
    ("/ws?wsdl", "SOAP Web Service Endpoint WSDL", "medium", "CWE-200"),
    ("/service.asmx?wsdl", "ASP.NET ASMX Web Service WSDL", "medium", "CWE-200")
]

GRAPHQL_PROBE_QUERY = {"query": "{ __schema { types { name } } }"}

GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/graphiql",
    "/v1/graphql",
    "/api/graphql",
    "/graphql/console",
    "/altair",
    "/playground"
]

class ApiSecurityPlugin(BaseScannerPlugin):
    """
    API Security & Specification Exposure Auditor:
    - Probes for publicly accessible OpenAPI / Swagger documentation endpoints
    - Probes for unauthenticated GraphQL Introspection disclosure across multiple paths
    - Probes for exported Postman / Insomnia collections and SOAP WSDL specifications
    """
    name = "api_security"
    tier = "T1"
    docker_image = "python:3.11-slim"
    timeout_seconds = 60
    category = "Information Disclosure"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "api_security.jsonl")

    def run_scan(self, target_url: str, out_dir: str, tenant_id: str, scan_id: str, target_id: str) -> List[Dict[str, Any]]:
        findings = self.parse("", target_url, tenant_id, scan_id, target_id)
        out_file = self.get_output_path(out_dir)
        try:
            with open(out_file, "w", encoding="utf-8") as f:
                for f_item in findings:
                    f.write(json.dumps(f_item) + "\n")
        except Exception:
            pass
        return findings

    def parse(self, raw_output_path: str, target_url: str, tenant_id: str, scan_id: str, target_id: str) -> List[Dict[str, Any]]:
        findings = []
        session = requests.Session()
        session.headers.update({"User-Agent": "AegisAI-APISecurity/2.0"})

        # 1. Probe for OpenAPI / Swagger / WSDL / Collections
        for path, label, severity, cwe in API_SPEC_ENDPOINTS:
            full_url = urljoin(target_url + "/", path.lstrip("/"))
            try:
                res = session.get(full_url, verify=False, timeout=2.5, allow_redirects=False)
                if res.status_code == 200 and len(res.content) > 50:
                    text_sample = res.text[:2048].lower()
                    
                    is_valid = False
                    if "openapi" in path or "swagger" in path or "api-doc" in path:
                        if any(k in text_sample for k in ["swagger", "openapi", "paths", "swagger-ui"]):
                            is_valid = True
                    elif "postman" in path or "insomnia" in path:
                        if any(k in text_sample for k in ["info", "item", "request", "resources"]):
                            is_valid = True
                    elif "wsdl" in path:
                        if any(k in text_sample for k in ["wsdl:definitions", "definitions", "schemalocation"]):
                            is_valid = True
                    elif "docs" in path or "redoc" in path or "explorer" in path:
                        if any(k in text_sample for k in ["swagger", "redoc", "openapi", "api"]):
                            is_valid = True

                    if is_valid:
                        fp = compute_fingerprint_hash(self.category, target_url, path, f"API_SPEC_{path}")
                        findings.append({
                            "scan_id": scan_id,
                            "tenant_id": tenant_id,
                            "target_id": target_id,
                            "tool": self.name,
                            "rule_id": f"API_SPEC_{path.strip('/').replace('/', '_').replace('.', '_').replace('?', '_').upper()}",
                            "title": f"API Documentation & Specification Exposed: {label} ({path})",
                            "description": f"The endpoint '{path}' exposes interactive API schema definitions ({label}). Unauthenticated callers can inspect complete route paths, model structures, parameters, and authentication schemes.",
                            "severity": severity,
                            "confidence": "confirmed",
                            "category": self.category,
                            "cwe": cwe,
                            "cve": "[]",
                            "cvss": 5.3 if severity == "medium" else (6.5 if severity == "high" else 3.5),
                            "epss": 0.05,
                            "kev": False,
                            "url": full_url,
                            "host": target_url,
                            "port": None,
                            "parameter": path,
                            "evidence": redact_evidence(f"HTTP 200 OK at {full_url}. Content preview: {res.text[:180]}"),
                            "remediation": "Restrict API documentation endpoints in production behind authentication or firewall access controls.",
                            "references": json.dumps(["https://cwe.mitre.org/data/definitions/200.html"]),
                            "status": "open",
                            "fingerprint_hash": fp
                        })
            except Exception:
                pass

        # 2. Probe for GraphQL Introspection Disclosures across multiple endpoints
        for gql_path in GRAPHQL_ENDPOINTS:
            gql_url = urljoin(target_url + "/", gql_path.lstrip("/"))
            try:
                res_gql = session.post(
                    gql_url,
                    json=GRAPHQL_PROBE_QUERY,
                    verify=False,
                    timeout=3
                )
                if res_gql.status_code == 200:
                    data = res_gql.json()
                    if isinstance(data, dict) and "data" in data and "__schema" in data["data"]:
                        types = data["data"]["__schema"].get("types", [])
                        type_names = [t.get("name") for t in types if isinstance(t, dict)][:8]
                        fp = compute_fingerprint_hash(self.category, target_url, gql_path, "GRAPHQL_INTROSPECTION_ENABLED")
                        findings.append({
                            "scan_id": scan_id,
                            "tenant_id": tenant_id,
                            "target_id": target_id,
                            "tool": self.name,
                            "rule_id": f"GRAPHQL_INTROSPECTION_ENABLED_{gql_path.strip('/').replace('/', '_').upper()}",
                            "title": f"GraphQL Schema Introspection Enabled on '{gql_path}'",
                            "description": f"GraphQL endpoint '{gql_path}' allows unauthenticated schema introspection. Attackers can query the complete GraphQL schema, mapping all queries, mutations, fields, and types.",
                            "severity": "medium",
                            "confidence": "confirmed",
                            "category": self.category,
                            "cwe": "CWE-200",
                            "cve": "[]",
                            "cvss": 5.3,
                            "epss": 0.08,
                            "kev": False,
                            "url": gql_url,
                            "host": target_url,
                            "port": None,
                            "parameter": gql_path,
                            "evidence": redact_evidence(f"Introspection query succeeded at {gql_url}. Exposed types include: {type_names}"),
                            "remediation": "Disable schema introspection in production environments (e.g., introspection: false in Apollo Server).",
                            "references": json.dumps(["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#introspection"]),
                            "status": "open",
                            "fingerprint_hash": fp
                        })
            except Exception:
                pass

        return findings
