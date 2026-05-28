#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
from pathlib import Path

from lib import dump_json, make_base_record, read_text


NMAP_LINE_RE = re.compile(r"^(?P<port>\d+)\/(?P<proto>\w+)\s+(?P<state>\S+)\s+(?P<service>\S+)(?:\s+(?P<details>.+))?$")
GNMAP_PORT_RE = re.compile(r"(?P<port>\d+)\/(?P<state>open)\/(?P<proto>\w+)\/\/(?P<service>[^\/]*)\/\/(?P<details>[^\/]*)\/")
PRODUCT_PATTERNS = [
    ("OpenSSH", re.compile(r"OpenSSH[\s_/:-]*(?P<version>[0-9][^\s,\)]*)", re.IGNORECASE)),
    ("ProFTPD", re.compile(r"ProFTPD[\s_/:-]*(?P<version>[0-9][^\s,\)]*)?", re.IGNORECASE)),
    ("vsftpd", re.compile(r"vsftpd[\s_/:-]*(?P<version>[0-9][^\s,\)]*)?", re.IGNORECASE)),
    ("freeSSHd", re.compile(r"freeSSHd[\s_/:-]*(?P<version>[0-9][^\s,\)]*)?", re.IGNORECASE)),
    ("FileZilla Server", re.compile(r"FileZilla(?: Server)?[\s_/:-]*(?P<version>[0-9][^\s,\)]*)?", re.IGNORECASE)),
]
CLIENT_SIDE_KEYWORDS = ("client", "professional", "smartftp", "core ftp le", "ultraedit", "ws_ftp")


def parse_nmap(path: Path) -> dict:
    if not path.exists():
        return {"available": False, "services": [], "raw_excerpt": ""}

    content = read_text(path)
    services = []
    for line in content.splitlines():
        match = NMAP_LINE_RE.match(line.strip())
        if not match or match.group("state") != "open":
            continue
        details = (match.group("details") or "").strip()
        product, version = extract_product_and_version(" ".join(filter(None, [match.group("service"), details])))
        services.append(
            {
                "port": match.group("port"),
                "proto": match.group("proto"),
                "state": match.group("state"),
                "service": match.group("service"),
                "details": details,
                "product": product,
                "version": version,
                "raw": line.strip(),
            }
        )
    return {"available": True, "services": services, "raw_excerpt": content[:4000]}


def parse_gnmap(path: Path) -> dict:
    if not path.exists():
        return {"available": False, "services": [], "raw_excerpt": ""}

    content = read_text(path)
    services = []
    for line in content.splitlines():
        for match in GNMAP_PORT_RE.finditer(line):
            details = (match.group("details") or "").strip()
            service = (match.group("service") or "").strip() or "unknown"
            product, version = extract_product_and_version(" ".join(filter(None, [service, details])))
            services.append(
                {
                    "port": match.group("port"),
                    "proto": match.group("proto"),
                    "state": match.group("state"),
                    "service": service,
                    "details": details,
                    "product": product,
                    "version": version,
                    "raw": match.group(0),
                }
            )
    return {"available": True, "services": services, "raw_excerpt": content[:4000]}


def extract_product_and_version(text: str) -> tuple[str, str]:
    for product, pattern in PRODUCT_PATTERNS:
        match = pattern.search(text or "")
        if match:
            return product, (match.groupdict().get("version") or "").strip()
    lowered = (text or "").lower()
    if "ssh" in lowered:
        return "SSH service", ""
    if "sftp" in lowered:
        return "SFTP service", ""
    return "", ""


def load_banner_observations(raw_dir: Path) -> tuple[list[dict], dict[str, str]]:
    files = []
    by_port: dict[str, str] = {}
    for path in sorted(raw_dir.glob("*.txt")):
        if not (
            path.name.startswith("ssh_banner")
            or path.name.startswith("ftp_banner")
            or path.name.startswith("port_")
            or path.name.startswith("sftp_banner")
        ):
            continue
        content = read_text(path).strip()
        port = ""
        stem = path.stem
        if stem == "ssh_banner":
            port = "22"
        elif stem == "ftp_banner":
            port = "21"
        elif "_" in stem:
            port = stem.split("_", 1)[1]
        files.append({"file": path.name, "port": port, "content": content[:400]})
        if port and content:
            by_port[port] = content
    return files, by_port


def merge_services(*service_sets: list[dict]) -> list[dict]:
    merged = {}
    for services in service_sets:
        for service in services:
            key = (service.get("port"), service.get("proto"))
            if key not in merged or len(service.get("details", "")) > len(merged[key].get("details", "")):
                merged[key] = service
    return sorted(merged.values(), key=lambda item: (int(item.get("port", 0)), item.get("proto", "")))


def build_service_candidates(services: list[dict], banners_by_port: dict[str, str]) -> tuple[list[str], list[dict], list[str], list[str]]:
    candidate_labels = []
    sftp_ports = []
    version_hints = []
    search_queries = []

    for service in services:
        port = service.get("port", "")
        details = " ".join(filter(None, [service.get("service", ""), service.get("details", ""), service.get("product", ""), service.get("version", ""), banners_by_port.get(port, "")]))
        lowered = details.lower()
        product = service.get("product", "")
        version = service.get("version", "")

        if product:
            label = f"{product} on {port}/{service.get('proto', 'tcp')}"
            if label not in candidate_labels:
                candidate_labels.append(label)
        elif service.get("service"):
            label = f"{service.get('service')} on {port}/{service.get('proto', 'tcp')}"
            if label not in candidate_labels:
                candidate_labels.append(label)

        if version:
            version_hint = f"{product} {version}".strip()
            if version_hint not in version_hints:
                version_hints.append(version_hint)

        if "openssh" in lowered and version:
            search_queries.append(f"OpenSSH {version}")
        elif "openssh" in lowered:
            search_queries.append("OpenSSH")

        if "proftpd" in lowered and version:
            search_queries.append(f"ProFTPD {version}")
        elif "proftpd" in lowered:
            search_queries.append("ProFTPD")
        if "mod_sftp" in lowered:
            search_queries.append("ProFTPD mod_sftp")
        if "vsftpd" in lowered and version:
            search_queries.append(f"vsftpd {version}")
        elif "vsftpd" in lowered:
            search_queries.append("vsftpd")

        if any(token in lowered for token in ("ssh-", " ssh ", "openssh", "sftp", "mod_sftp")) or service.get("service") == "ssh":
            confidence = "medium"
            reason = "SSH transport detected; SFTP usually runs as SSH subsystem."
            if "sftp" in lowered or "mod_sftp" in lowered:
                confidence = "high"
                reason = "Scan evidence explicitly references SFTP or mod_sftp."
            sftp_ports.append(
                {
                    "port": port,
                    "proto": service.get("proto", "tcp"),
                    "service": service.get("service", ""),
                    "product": product,
                    "version": version,
                    "confidence": confidence,
                    "reason": reason,
                }
            )

    if not candidate_labels:
        candidate_labels.append("unknown")
    if not search_queries:
        search_queries.extend(["SFTP server", "SSH server"])
    deduped_queries = []
    for query in search_queries:
        if query and query not in deduped_queries:
            deduped_queries.append(query)
    return candidate_labels, sftp_ports, version_hints, deduped_queries


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    raw_dir = run_dir / "task1" / "raw"
    json_dir = run_dir / "task1" / "json"
    record = make_base_record(run_dir.name, "task1", "parse_recon.py")

    nmap_path = raw_dir / "nmap.txt"
    if not nmap_path.exists():
        candidates = sorted(raw_dir.glob("*nmap*.txt"))
        if candidates:
            nmap_path = candidates[0]
    gnmap_path = raw_dir / "nmap.gnmap"
    if not gnmap_path.exists():
        candidates = sorted(raw_dir.glob("*nmap*.gnmap"))
        if candidates:
            gnmap_path = candidates[0]

    nmap_data = parse_nmap(nmap_path)
    gnmap_data = parse_gnmap(gnmap_path)
    banner_files, banners_by_port = load_banner_observations(raw_dir)
    services = merge_services(nmap_data.get("services", []), gnmap_data.get("services", []))
    service_candidates, sftp_candidate_ports, version_hints, search_queries = build_service_candidates(services, banners_by_port)

    detected_products = []
    for service in services:
        product = service.get("product")
        if not product:
            continue
        item = {"product": product, "version": service.get("version", ""), "port": service.get("port", ""), "service": service.get("service", "")}
        if item not in detected_products:
            detected_products.append(item)

    record.update(
        {
            "service_candidates": service_candidates,
            "sftp_candidate_ports": sftp_candidate_ports,
            "banner_observations": {"files": banner_files, "by_port": banners_by_port},
            "protocol_observations": {
                "nmap_available": nmap_data.get("available", False) or gnmap_data.get("available", False),
                "nmap_sources": [str(path.name) for path in [nmap_path, gnmap_path] if path.exists()],
                "raw_excerpt": "\n".join(filter(None, [nmap_data.get("raw_excerpt", ""), gnmap_data.get("raw_excerpt", "")]))[:4000],
            },
            "port_observations": services,
            "tls_observations": {},
            "http_side_observations": {},
            "error_message_observations": [],
            "filesystem_leakage_hints": [],
            "module_hints": ["mod_sftp suspected"] if any("mod_sftp" in port.get("reason", "").lower() or "mod_sftp" in (port.get("product", "") + port.get("service", "")).lower() for port in sftp_candidate_ports) else [],
            "version_hints": version_hints,
            "detected_products": detected_products,
            "recommended_search_queries": search_queries,
            "contradictions": [],
            "tool_intel": {},
            "exploit_intel_summary": {},
        }
    )
    dump_json(json_dir / "task1_recon_facts.json", record)


if __name__ == "__main__":
    main()
