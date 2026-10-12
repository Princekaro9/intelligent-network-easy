"""
Reconstruction des communications réseau INPA.

Plusieurs paquets appartenant à la même communication
sont regroupés dans un même flux.
"""

from collections import defaultdict
from datetime import datetime


def _flow_key(packet: dict) -> tuple:
    """
    Construit une clé bidirectionnelle de communication.

    Cela permet de considérer :

    A -> B

    et

    B -> A

    comme appartenant au même flux.
    """

    source = packet.get("source")
    destination = packet.get("destination")

    source_port = packet.get(
        "source_port"
    )

    destination_port = packet.get(
        "destination_port"
    )

    protocol = packet.get(
        "protocol",
        "UNKNOWN",
    )

    endpoint_a = (
        str(source),
        source_port,
    )

    endpoint_b = (
        str(destination),
        destination_port,
    )

    endpoints = sorted(
        [endpoint_a, endpoint_b]
    )

    return (
        protocol,
        endpoints[0],
        endpoints[1],
    )


def build_flows(
    packets: list[dict],
) -> list[dict]:
    """
    Regroupe les paquets par communication.
    """

    grouped = defaultdict(list)

    for packet in packets:

        # Les paquets sans IP ne peuvent pas encore
        # être reconstruits comme flux IP.
        if (
            not packet.get("source")
            or not packet.get("destination")
        ):
            continue

        key = _flow_key(packet)

        grouped[key].append(packet)

    flows = []

    for flow_id, (
        key,
        flow_packets,
    ) in enumerate(
        grouped.items(),
        start=1,
    ):

        protocol = key[0]

        timestamps = []

        total_bytes = 0

        source_addresses = set()
        destination_addresses = set()

        source_ports = set()
        destination_ports = set()

        for packet in flow_packets:

            timestamp = packet.get(
                "timestamp"
            )

            if timestamp:
                try:
                    timestamps.append(
                        datetime.fromisoformat(
                            timestamp
                        )
                    )
                except ValueError:
                    pass

            total_bytes += int(
                packet.get("size") or 0
            )

            if packet.get("source"):
                source_addresses.add(
                    packet["source"]
                )

            if packet.get("destination"):
                destination_addresses.add(
                    packet["destination"]
                )

            if packet.get("source_port") is not None:
                source_ports.add(
                    packet["source_port"]
                )

            if packet.get(
                "destination_port"
            ) is not None:
                destination_ports.add(
                    packet["destination_port"]
                )

        first_seen = (
            min(timestamps).isoformat()
            if timestamps
            else None
        )

        last_seen = (
            max(timestamps).isoformat()
            if timestamps
            else None
        )

        duration = 0.0

        if len(timestamps) >= 2:

            duration = (
                max(timestamps)
                - min(timestamps)
            ).total_seconds()

        flows.append(
            {
                "id": flow_id,

                "protocol": protocol,

                "sources": sorted(
                    source_addresses
                ),

                "destinations": sorted(
                    destination_addresses
                ),

                "source_ports": sorted(
                    source_ports
                ),

                "destination_ports": sorted(
                    destination_ports
                ),

                "packet_count": len(
                    flow_packets
                ),

                "total_bytes": total_bytes,

                "first_seen": first_seen,

                "last_seen": last_seen,

                "duration_seconds": duration,

                "packets": flow_packets,
            }
        )

    # Les communications les plus importantes
    # apparaissent en premier.
    flows.sort(
        key=lambda flow: flow["packet_count"],
        reverse=True,
    )

    return flows