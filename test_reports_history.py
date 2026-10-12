import asyncio
import json

import httpx

from backend.database.history import AnalysisHistory
from backend.analyzer.behavior import behavior_analyzer
from backend.reports import build_report, serialize_csv, serialize_json


def sample_analysis():
    return {
        "packet_count": 2,
        "total_bytes": 180,
        "protocols": {"TCP": 2},
        "flows": [{
            "id": 1,
            "protocol": "TCP",
            "sources": ["192.0.2.10"],
            "destinations": ["198.51.100.20"],
            "source_ports": [50000],
            "destination_ports": [443],
            "packet_count": 2,
            "total_bytes": 180,
            "first_seen": "2026-10-12T10:00:00",
            "last_seen": "2026-10-12T10:00:01",
            "duration_seconds": 1.0,
            "packets": [{"payload": "must not persist"}],
        }],
        "observations": [{
            "type": "traffic_volume",
            "severity": "INFO",
            "title": "Trafic observé",
            "observed_fact": "2 paquets analysés.",
            "interpretation": "Un échange a été observé.",
            "hypothesis": "Cela peut correspondre à une activité normale.",
            "evidence": {"packet_count": 2},
        }],
        "behavior_observations": [],
        "baseline_comparison": {"available": False, "observations": []},
    }


def sample_report():
    return build_report(sample_analysis(), {
        "status": "completed",
        "interface": "Ethernet",
        "started_at": "2026-10-12T10:00:00+00:00",
        "ended_at": "2026-10-12T10:00:01+00:00",
        "duration_seconds": 1.0,
        "total_packet_count": 3,
    })


def test_report_exports_aggregates_without_packet_objects():
    report = sample_report()
    assert report["summary"]["analyzed_packet_count"] == 2
    assert report["summary"]["captured_packet_count"] == 3
    assert report["communications"][0]["packet_count"] == 2
    assert "packets" not in report["communications"][0]
    assert "must not persist" not in serialize_json(report)
    assert "observation" in serialize_csv(report)
    assert "communication" in serialize_csv(report)


def test_history_survives_reopening_and_marks_interrupted_sessions(tmp_path):
    database = tmp_path / "history.sqlite3"
    history = AnalysisHistory(database)
    history.initialize()
    complete_id = history.start("Ethernet")
    assert history.finish(complete_id, sample_report())
    interrupted_id = history.start("Wi-Fi")

    restarted = AnalysisHistory(database)
    restarted.initialize()
    restarted.mark_interrupted_sessions()
    completed = restarted.get(complete_id)
    interrupted = restarted.get(interrupted_id)

    assert completed["status"] == "completed"
    assert completed["packet_count"] == 3
    assert "report" in completed
    assert interrupted["status"] == "interrupted"
    assert interrupted.get("report") is None


def test_history_routes_require_token_and_serve_json_csv(tmp_path, monkeypatch):
    from backend import main

    history = AnalysisHistory(tmp_path / "api-history.sqlite3")
    history.initialize()
    analysis_id = history.start("Ethernet")
    history.finish(analysis_id, sample_report())
    monkeypatch.setattr(main, "history_store", history)
    monkeypatch.setattr(main, "ACCESS_TOKEN", "test-access-token")
    asyncio.run(main.initialize_history())

    async def exercise_routes():
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            assert (await client.get("/api/history")).status_code == 401
            headers = {"X-INPA-Token": "test-access-token"}
            listing = await client.get("/api/history", headers=headers)
            assert listing.status_code == 200
            assert listing.json()["analyses"][0]["id"] == analysis_id

            json_response = await client.get(
                f"/api/history/{analysis_id}/report?format=json", headers=headers
            )
            assert json_response.status_code == 200
            assert json.loads(json_response.content)["summary"]["captured_packet_count"] == 3
            assert ".json" in json_response.headers["content-disposition"]

            csv_response = await client.get(
                f"/api/history/{analysis_id}/report?format=csv", headers=headers
            )
            assert csv_response.status_code == 200
            assert "text/csv" in csv_response.headers["content-type"]
            assert "Trafic observé" in csv_response.content.decode("utf-8-sig")

    asyncio.run(exercise_routes())


def test_report_route_returns_clear_error_for_missing_current_data(tmp_path, monkeypatch):
    from backend import main

    history = AnalysisHistory(tmp_path / "empty-history.sqlite3")
    history.initialize()
    monkeypatch.setattr(main, "history_store", history)
    monkeypatch.setattr(main, "ACCESS_TOKEN", "test-access-token")
    asyncio.run(main.initialize_history())

    async def request_empty_report():
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.get(
                "/api/reports/current?format=json",
                headers={"X-INPA-Token": "test-access-token"},
            )

    response = asyncio.run(request_empty_report())
    assert response.status_code == 404
    assert "Aucune donnée" in response.json()["detail"]


def test_repeated_packets_in_single_https_flow_do_not_create_false_alert():
    packets = []
    for index in range(24):
        if index % 2:
            source, source_port = "1.1.1.1", 443
            destination, destination_port = "10.0.0.5", 62445
        else:
            source, source_port = "10.0.0.5", 62445
            destination, destination_port = "1.1.1.1", 443
        packets.append({
            "source": source,
            "destination": destination,
            "protocol": "TCP",
            "source_port": source_port,
            "destination_port": destination_port,
            "is_multicast": False,
            "is_broadcast": False,
        })

    assert behavior_analyzer._detect_repeated_connections(packets) == []


def test_repeated_connection_detector_counts_distinct_tcp_flows():
    packets = [{
        "source": "10.0.0.5",
        "destination": "1.1.1.1",
        "protocol": "TCP",
        "source_port": 50000 + index,
        "destination_port": 443,
        "is_multicast": False,
        "is_broadcast": False,
    } for index in range(20)]

    observations = behavior_analyzer._detect_repeated_connections(packets)
    assert len(observations) == 1
    assert observations[0]["evidence"]["communication_count"] == 20
    assert observations[0]["evidence"]["service_port"] == 443
