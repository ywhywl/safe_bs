#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import dump_json, load_json, make_base_record


SERVER_SIDE_HINTS = ("server", "daemon", "openssh", "proftpd", "vsftpd", "freesshd", "filezilla")
CLIENT_SIDE_HINTS = ("client", "professional", "smartftp", "ultraedit", "ws_ftp")


def is_relevant_result(item: dict, detected_products: list[dict], query: str) -> bool:
    title = (item.get("title") or item.get("Title") or "").lower()
    if any(keyword in title for keyword in CLIENT_SIDE_HINTS):
        return False
    if detected_products:
        product_tokens = {product.get("product", "").lower() for product in detected_products if product.get("product")}
        return any(token and token in title for token in product_tokens)
    return any(keyword in title for keyword in SERVER_SIDE_HINTS) or query.lower().startswith(("sftp", "ssh"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task1" / "json"
    facts = load_json(json_dir / "task1_recon_facts.json", {})
    matches = load_json(json_dir / "task1_searchsploit_matches.json", {})

    record = make_base_record(run_dir.name, "task1", "build_hypotheses.py")
    candidates = []
    detected_products = facts.get("detected_products", [])
    sftp_ports = facts.get("sftp_candidate_ports", [])

    if any(product.get("product") == "ProFTPD" and product.get("version", "").startswith("1.3.5") for product in detected_products):
        candidates.append(
            {
                "name": "ProFTPD 1.3.5 family mod_copy issue",
                "cve_or_ref": "CVE-2015-3306",
                "match_reasons": [
                    "Service candidate includes ProFTPD",
                    "Local exploit intelligence references ProFTPD 1.3.5 family",
                ],
                "required_preconditions": [
                    "Vulnerable module or affected build path exists",
                    "Behavioral indicators align during authorized validation",
                ],
                "expected_impact": "Unauthorized file copy or web reachable artifact creation depending on target setup",
                "disqualifiers": ["Service is not ProFTPD", "Required module not present"],
                "priority": "high",
                "confidence": "medium",
            }
        )

    seen_titles = {item["name"] for item in candidates}
    for query_result in matches.get("matches", []):
        query = query_result.get("query", "")
        for item in query_result.get("results", []):
            summary = {
                "title": item.get("Title", ""),
                "edb_id": item.get("EDB-ID", ""),
                "codes": item.get("Codes", ""),
                "path": item.get("Path", ""),
                "verified": item.get("Verified", ""),
                "type": item.get("Type", ""),
            }
            if not summary["title"] or summary["title"] in seen_titles:
                continue
            if not is_relevant_result(summary, detected_products, query):
                continue
            seen_titles.add(summary["title"])
            priority = "medium"
            confidence = "low"
            if any(product.get("version") and product.get("version") in summary["title"] for product in detected_products):
                priority = "high"
                confidence = "medium"
            candidates.append(
                {
                    "name": summary["title"],
                    "cve_or_ref": summary["codes"] or summary["edb_id"],
                    "match_reasons": [
                        f"Detected service family aligns with query '{query}'",
                        f"SFTP/SSH candidate ports: {[port.get('port') for port in sftp_ports]}",
                    ],
                    "required_preconditions": [
                        "Detected product/version truly matches the imported scan result",
                        "Issue is reachable in the exposed configuration and within authorized scope",
                    ],
                    "expected_impact": "Potential unauthorized access, file manipulation, or denial of service depending on the matched issue.",
                    "disqualifiers": ["Imported scan result is inaccurate", "Exploit is client-side or not applicable to the server role"],
                    "priority": priority,
                    "confidence": confidence,
                    "supporting_query": query,
                    "searchsploit_ref": summary,
                }
            )
    record.update(
        {
            "service_identity_judgment": facts.get("service_candidates", ["unknown"])[0],
            "sftp_candidate_ports": sftp_ports,
            "candidate_vulnerabilities": candidates,
        }
    )
    dump_json(json_dir / "task1_vuln_hypotheses.json", record)


if __name__ == "__main__":
    main()
