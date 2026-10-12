from collections import Counter, defaultdict

from datetime import datetime

import ipaddress

class NetworkProfileBuilder:

    """

    Construit un profil comportemental du trafic réseau observé.

    Important :

    Ce profil décrit uniquement la fenêtre de paquets fournie.

    Il ne constitue pas encore une comparaison avec un historique.

    """

    def build(self, packets: list[dict]) -> dict:

        if not packets:

            return self._empty_profile()

        timestamps = self._extract_timestamps(packets)

        sources = Counter()

        destinations = Counter()

        protocols = Counter()

        services = Counter()

        service_ports = Counter()

        source_ports = Counter()

        destination_ports = Counter()

        source_destinations = defaultdict(set)

        source_protocols = defaultdict(Counter)

        multicast_count = 0

        broadcast_count = 0

        private_to_private = 0

        private_to_external = 0

        external_to_private = 0

        total_bytes = 0

        for packet in packets:

            source = packet.get("source")

            destination = packet.get("destination")

            protocol = str(packet.get("protocol", "UNKNOWN")).upper()
            network_layer = str(packet.get("network_layer") or "").upper()

            # Les cibles ARP/Ethernet ne sont pas des destinations IP.
            # Si la couche réseau est connue, seules IPv4 et IPv6 comptent ici.
            # Sans cette information, on exclut explicitement ARP et Ethernet.
            is_ip_packet = (
                network_layer in {"IPV4", "IPV6"}
                if network_layer
                else protocol not in {"ARP", "ETHERNET"}
            )

            if source:
                sources[source] += 1

            if destination and is_ip_packet:
                destinations[destination] += 1

            protocols[protocol] += 1

            total_bytes += self._safe_int(packet.get("size"))

            service = packet.get("probable_service")

            if service:

                services[service] += 1

            service_port = packet.get("service_port")

            if service_port is not None:

                service_ports[str(service_port)] += 1

            source_port = packet.get("source_port")

            if source_port is not None:

                source_ports[str(source_port)] += 1

            destination_port = packet.get("destination_port")

            if destination_port is not None:

                destination_ports[str(destination_port)] += 1

            if source and destination and is_ip_packet:
                source_destinations[source].add(destination)

            if source:

                source_protocols[source][protocol] += 1

            if packet.get("is_multicast"):

                multicast_count += 1

            if packet.get("is_broadcast"):

                broadcast_count += 1

            communication_type = self._classify_communication(

                source,

                destination,

            )

            if communication_type == "private_to_private":

                private_to_private += 1

            elif communication_type == "private_to_external":

                private_to_external += 1

            elif communication_type == "external_to_private":

                external_to_private += 1

        first_seen = min(timestamps).isoformat() if timestamps else None

        last_seen = max(timestamps).isoformat() if timestamps else None

        duration_seconds = 0.0

        if len(timestamps) >= 2:

            duration_seconds = (

                max(timestamps) - min(timestamps)

            ).total_seconds()

        profile = {

            "summary": {

                "packet_count": len(packets),

                "total_bytes": total_bytes,

                "first_seen": first_seen,

                "last_seen": last_seen,

                "duration_seconds": duration_seconds,

            },

            "devices": {

                "observed_sources": len(sources),

                "sources": self._counter_to_list(sources),

                "destinations": self._counter_to_list(destinations),

            },

            "protocols": {

                "unique": len(protocols),

                "distribution": self._counter_to_list(protocols),

            },

            "services": {

                "unique": len(services),

                "distribution": self._counter_to_list(services),

            },

            "ports": {

                "service_ports": self._counter_to_list(service_ports),

                "source_ports": self._counter_to_list(source_ports),

                "destination_ports": self._counter_to_list(destination_ports),

            },

            "communications": {

                "private_to_private": private_to_private,

                "private_to_external": private_to_external,

                "external_to_private": external_to_private,

            },

            "network_discovery": {

                "multicast_packets": multicast_count,

                "broadcast_packets": broadcast_count,

            },

            "source_activity": self._build_source_activity(

                sources,

                source_destinations,

                source_protocols,

            ),

            "interpretation": self._build_interpretation(

                packets,

                sources,

                destinations,

                protocols,

                services,

                multicast_count,

                broadcast_count,

                private_to_private,

                private_to_external,

                external_to_private,

            ),

        }

        return profile

    # ---------------------------------------------------------

    # Extraction

    # ---------------------------------------------------------

    @staticmethod

    def _extract_timestamps(packets: list[dict]) -> list[datetime]:

        timestamps = []

        for packet in packets:

            timestamp = packet.get("timestamp")

            if not timestamp:

                continue

            try:

                timestamps.append(datetime.fromisoformat(timestamp))

            except (ValueError, TypeError):

                continue

        return timestamps

    # ---------------------------------------------------------

    # Communication classification

    # ---------------------------------------------------------

    @staticmethod

    def _classify_communication(

        source: str | None,

        destination: str | None,

    ) -> str:

        if not source or not destination:

            return "unknown"

        source_private = NetworkProfileBuilder._is_private(source)

        destination_private = NetworkProfileBuilder._is_private(destination)

        if source_private and destination_private:

            return "private_to_private"

        if source_private and not destination_private:

            return "private_to_external"

        if not source_private and destination_private:

            return "external_to_private"

        return "external_to_external"

    @staticmethod

    def _is_private(address: str) -> bool:

        try:

            return ipaddress.ip_address(address).is_private

        except ValueError:

            return False

    # ---------------------------------------------------------

    # Source activity

    # ---------------------------------------------------------

    @staticmethod

    def _build_source_activity(

        sources: Counter,

        source_destinations: dict,

        source_protocols: dict,

    ) -> list[dict]:

        activity = []

        for source, packet_count in sources.most_common():

            destinations = source_destinations.get(source, set())

            protocols = source_protocols.get(source, Counter())

            activity.append(

                {

                    "source": source,

                    "packet_count": packet_count,

                    "unique_destinations": len(destinations),

                    "destinations": sorted(destinations),

                    "protocols": dict(protocols),

                }

            )

        return activity

    # ---------------------------------------------------------

    # Interpretation

    # ---------------------------------------------------------

    @staticmethod

    def _build_interpretation(

        packets,

        sources,

        destinations,

        protocols,

        services,

        multicast_count,

        broadcast_count,

        private_to_private,

        private_to_external,

        external_to_private,

    ) -> dict:

        observations = []

        if sources:

            observations.append(

                {

                    "observed_fact": (

                        f"{len(sources)} source(s) réseau ont été observées."

                    ),

                    "interpretation": (

                        "Le trafic provient de plusieurs appareils ou "

                        "interfaces observés pendant la capture."

                    ),

                    "hypothesis": (

                        "Ces sources peuvent représenter plusieurs appareils "

                        "actifs sur le réseau local."

                    ),

                }

            )

        if destinations:

            observations.append(

                {

                    "observed_fact": (

                        f"{len(destinations)} destination(s) distincte(s) "

                        "ont été observées."

                    ),

                    "interpretation": (

                        "Le trafic comporte plusieurs communications vers "

                        "des destinations différentes."

                    ),

                    "hypothesis": (

                        "Cela peut correspondre à de la navigation, des "

                        "services réseau, des mises à jour ou de la découverte "

                        "de services."

                    ),

                }

            )

        if protocols:

            observations.append(

                {

                    "observed_fact": (

                        f"{len(protocols)} protocole(s) distinct(s) "

                        "ont été observés."

                    ),

                    "interpretation": (

                        "Le réseau utilise plusieurs mécanismes de "

                        "communication pendant la période observée."

                    ),

                    "hypothesis": (

                        "La diversité des protocoles peut correspondre "

                        "au fonctionnement normal de plusieurs services."

                    ),

                }

            )

        if services:

            observations.append(

                {

                    "observed_fact": (

                        f"{len(services)} service(s) probable(s) "

                        "ont été identifiés."

                    ),

                    "interpretation": (

                        "Certains ports et protocoles correspondent à "

                        "des services réseau connus."

                    ),

                    "hypothesis": (

                        "Les services identifiés peuvent représenter des "

                        "applications ou services réseau actifs."

                    ),

                }

            )

        if multicast_count:

            observations.append(

                {

                    "observed_fact": (

                        f"{multicast_count} paquet(s) multicast observé(s)."

                    ),

                    "interpretation": (

                        "Une partie du trafic utilise une communication "

                        "destinée à plusieurs hôtes."

                    ),

                    "hypothesis": (

                        "Cela peut correspondre à de la découverte de "

                        "services comme mDNS ou SSDP."

                    ),

                }

            )

        if broadcast_count:

            observations.append(

                {

                    "observed_fact": (

                        f"{broadcast_count} paquet(s) broadcast observé(s)."

                    ),

                    "interpretation": (

                        "Le réseau contient des communications destinées "

                        "à l'ensemble du segment local."

                    ),

                    "hypothesis": (

                        "Cela peut correspondre à des mécanismes normaux "

                        "de découverte ou de configuration réseau."

                    ),

                }

            )

        return {

            "observations": observations,

            "communication_summary": {

                "private_to_private": private_to_private,

                "private_to_external": private_to_external,

                "external_to_private": external_to_private,

            },

        }

    # ---------------------------------------------------------

    # Helpers

    # ---------------------------------------------------------

    @staticmethod

    def _counter_to_list(counter: Counter) -> list[dict]:

        return [

            {

                "value": key,

                "count": value,

            }

            for key, value in counter.most_common()

        ]

    @staticmethod

    def _safe_int(value) -> int:

        try:

            return int(value or 0)

        except (ValueError, TypeError):

            return 0

    @staticmethod

    def _empty_profile() -> dict:

        return {

            "summary": {

                "packet_count": 0,

                "total_bytes": 0,

                "first_seen": None,

                "last_seen": None,

                "duration_seconds": 0.0,

            },

            "devices": {

                "observed_sources": 0,

                "sources": [],

                "destinations": [],

            },

            "protocols": {

                "unique": 0,

                "distribution": [],

            },

            "services": {

                "unique": 0,

                "distribution": [],

            },

            "ports": {

                "service_ports": [],

                "source_ports": [],

                "destination_ports": [],

            },

            "communications": {

                "private_to_private": 0,

                "private_to_external": 0,

                "external_to_private": 0,

            },

            "network_discovery": {

                "multicast_packets": 0,

                "broadcast_packets": 0,

            },

            "source_activity": [],

            "interpretation": {

                "observations": [],

                "communication_summary": {

                    "private_to_private": 0,

                    "private_to_external": 0,

                    "external_to_private": 0,

                },

            },

        }

network_profile_builder = NetworkProfileBuilder()
