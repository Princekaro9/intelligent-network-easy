"""Préparation des exports JSON et CSV des analyses INPA."""

import csv
import io
import json
from datetime import datetime


def build_report(analysis: dict, capture: dict) -> dict:
    """Produit un rapport agrégé qui exclut les listes de paquets."""
    observations = []
    seen = set()
    sources = [
        analysis.get("observations", []),
        analysis.get("behavior_observations", []),
        (analysis.get("baseline_comparison") or {}).get("observations", []),
    ]
    for group in sources:
        for item in (group if isinstance(group, list) else []):
            if not isinstance(item, dict):
                continue
            key = (
                item.get("type"),
                item.get("title"),
                item.get("observed_fact"),
            )
            if key in seen:
                continue
            seen.add(key)
            observations.append(item)

    communications = []
    for flow in analysis.get("flows", []):
        if not isinstance(flow, dict):
            continue
        communications.append({
            key: flow.get(key)
            for key in (
                "id", "protocol", "sources", "destinations",
                "source_ports", "destination_ports", "packet_count",
                "total_bytes", "first_seen", "last_seen", "duration_seconds",
            )
        })

    report_capture = {
        key: capture.get(key)
        for key in (
            "status", "interface", "started_at", "ended_at", "duration_seconds",
            "total_packet_count",
        )
    }
    return {
        "application": "INPA",
        "report_version": 1,
        "generated_at": datetime.now().astimezone().isoformat(),
        "capture": report_capture,
        "summary": {
            "packet_count": int(analysis.get("packet_count") or 0),
            "analyzed_packet_count": int(analysis.get("packet_count") or 0),
            "captured_packet_count": int(
                report_capture.get("total_packet_count")
                if report_capture.get("total_packet_count") is not None
                else analysis.get("packet_count") or 0
            ),
            "total_bytes": int(analysis.get("total_bytes") or 0),
            "communication_count": len(communications),
            "observation_count": len(observations),
        },
        "protocols": analysis.get("protocols") or {},
        "communications": communications,
        "observations": observations,
        "baseline_comparison": analysis.get("baseline_comparison") or {
            "available": False,
            "observations": [],
        },
    }


def serialize_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)


def serialize_csv(report: dict, section: str | None = None) -> str:
    """Aplatit le rapport complet ou une section dans un CSV."""
    output = io.StringIO(newline="")
    fields = [
        "categorie", "type", "niveau", "titre", "protocole",
        "sources", "destinations", "ports_source", "ports_destination",
        "paquets", "octets", "duree_secondes", "fait_observe",
        "interpretation", "hypothese", "interface", "debut", "fin",
        "statut", "communications", "observations",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, delimiter=";")
    writer.writeheader()

    def safe(value):
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        else:
            value = str(value)
        if value.startswith(("=", "+", "-", "@", "\t", "\r")):
            value = "'" + value
        return value

    capture = report.get("capture") or {}
    summary = report.get("summary") or {}
    if section in (None, "capture"):
        writer.writerow({
            "categorie": "capture",
            "type": "métadonnées",
            "paquets": safe(summary.get("captured_packet_count", summary.get("packet_count"))),
            "octets": safe(summary.get("total_bytes")),
            "duree_secondes": safe(capture.get("duration_seconds")),
            "interface": safe(capture.get("interface")),
            "debut": safe(capture.get("started_at")),
            "fin": safe(capture.get("ended_at")),
            "statut": safe(capture.get("status")),
            "communications": safe(summary.get("communication_count")),
            "observations": safe(summary.get("observation_count")),
        })

    for protocol, packet_count in (
        (report.get("protocols") or {}).items()
        if section in (None, "protocols") else ()
    ):
        writer.writerow({
            "categorie": "protocole",
            "type": "répartition",
            "protocole": safe(protocol),
            "paquets": safe(packet_count),
        })

    for flow in (
        report.get("communications", [])
        if section in (None, "communications") else ()
    ):
        writer.writerow({
            "categorie": "communication",
            "type": "flux",
            "protocole": safe(flow.get("protocol")),
            "sources": safe(flow.get("sources")),
            "destinations": safe(flow.get("destinations")),
            "ports_source": safe(flow.get("source_ports")),
            "ports_destination": safe(flow.get("destination_ports")),
            "paquets": safe(flow.get("packet_count")),
            "octets": safe(flow.get("total_bytes")),
            "duree_secondes": safe(flow.get("duration_seconds")),
        })

    for item in (
        report.get("observations", [])
        if section in (None, "observations") else ()
    ):
        writer.writerow({
            "categorie": "observation",
            "type": safe(item.get("type")),
            "niveau": safe(item.get("severity")),
            "titre": safe(item.get("title")),
            "fait_observe": safe(item.get("observed_fact")),
            "interpretation": safe(item.get("interpretation")),
            "hypothese": safe(item.get("hypothesis")),
        })

    return "\ufeff" + output.getvalue()
