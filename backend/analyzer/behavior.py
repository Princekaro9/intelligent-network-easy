from collections import Counter, defaultdict

from datetime import datetime, timezone

class BehaviorAnalyzer:

    """

    Moteur d'analyse comportementale d'INPA.

    IMPORTANT :

    Ce moteur distingue toujours :

    1. FAIT OBSERVÉ

    2. INTERPRÉTATION

    3. HYPOTHÈSE

    Une anomalie comportementale n'est jamais considérée

    automatiquement comme une attaque.

    Le moteur cherche surtout à réduire les faux positifs

    liés aux protocoles réseau normaux :

        - ARP

        - DHCP

        - mDNS

        - SSDP

        - ICMP

        - ICMPv6

        - multicast

        - broadcast

        - ports éphémères

    """

    # =========================================================

    # CONFIGURATION

    # =========================================================

    # Nombre de destinations externes différentes à partir

    # duquel l'activité devient intéressante à observer.

    MULTIPLE_DESTINATIONS_THRESHOLD = 10

    # Nombre de communications répétées vers une même

    # destination avant observation.

    REPEATED_CONNECTION_THRESHOLD = 20

    # Nombre minimum de paquets multicast avant de signaler

    # une activité multicast importante.

    MULTICAST_THRESHOLD = 100

    # Nombre minimum de paquets broadcast avant de signaler

    # une activité broadcast importante.

    BROADCAST_THRESHOLD = 50

    # Fenêtre utilisée pour la détection de trafic rapide.

    RAPID_ACTIVITY_WINDOW_SECONDS = 10

    # Nombre de paquets minimum dans cette fenêtre.

    RAPID_ACTIVITY_THRESHOLD = 250

    # Une activité rapide ne sera évaluée comme intéressante

    # que si la capture dispose d'une durée suffisante.

    MIN_CAPTURE_DURATION_SECONDS = 10

    # ---------------------------------------------------------

    # Ports de services connus

    # ---------------------------------------------------------

    COMMON_PORTS = {

        20,

        21,

        22,

        23,

        25,

        53,

        67,

        68,

        80,

        110,

        123,

        143,

        443,

        445,

        465,

        546,

        547,

        587,

        993,

        995,

        1433,

        1900,

        3306,

        3389,

        5353,

        5432,

        5900,

        8080,

        8443,

    }

    # ---------------------------------------------------------

    # Protocoles de découverte / contrôle considérés comme

    # normaux lorsqu'ils sont observés dans leur contexte.

    # ---------------------------------------------------------

    EXPECTED_PROTOCOLS = {

        "ARP",

        "ICMP",

        "ICMPV6",

    }

    DISCOVERY_SERVICES = {

        "MDNS",

        "SSDP/UPNP",

        "SSDP",

    }

    DHCP_PORTS = {

        67,

        68,

        546,

        547,

    }

    # ---------------------------------------------------------

    # Ports éphémères.

    #

    # Cette plage correspond à la plage dynamique généralement

    # utilisée par de nombreux systèmes.

    #

    # IMPORTANT :

    # ce n'est PAS une preuve qu'un port est légitime.

    # Cela permet simplement d'éviter de le considérer comme

    # un service inhabituel uniquement à cause de son numéro.

    # ---------------------------------------------------------

    EPHEMERAL_PORT_MIN = 49152

    EPHEMERAL_PORT_MAX = 65535

    # =========================================================

    # POINT D'ENTRÉE

    # =========================================================

    def analyze(self, packets: list[dict]) -> list[dict]:

        """

        Analyse les comportements observables dans les paquets.

        """

        if not packets:

            return []

        observations = []

        observations.extend(

            self._detect_multiple_external_destinations(

                packets

            )

        )

        observations.extend(

            self._detect_repeated_connections(

                packets

            )

        )

        observations.extend(

            self._detect_unusual_ports(

                packets

            )

        )

        observations.extend(

            self._detect_multicast_activity(

                packets

            )

        )

        observations.extend(

            self._detect_broadcast_activity(

                packets

            )

        )

        observations.extend(

            self._detect_rapid_activity(

                packets

            )

        )

        return observations

    # =========================================================

    # OUTILS

    # =========================================================

    @staticmethod

    def _is_ephemeral_port(port) -> bool:

        """

        Détermine si un port appartient à la plage

        généralement utilisée pour les ports dynamiques.

        """

        if port is None:

            return False

        try:

            port = int(port)

        except (TypeError, ValueError):

            return False

        return (

            BehaviorAnalyzer.EPHEMERAL_PORT_MIN

            <= port

            <= BehaviorAnalyzer.EPHEMERAL_PORT_MAX

        )

    @staticmethod

    def _protocol(packet: dict) -> str:

        """

        Retourne le protocole de transport ou réseau.

        """

        return str(

            packet.get("transport_protocol")

            or packet.get("protocol")

            or "UNKNOWN"

        ).upper()

    @staticmethod

    def _is_multicast(packet: dict) -> bool:

        """

        Détermine si le paquet est multicast.

        Compatible avec les données produites par le nouveau

        capture.py et avec les anciennes données.

        """

        if packet.get("is_multicast"):

            return True

        context = packet.get(

            "context",

            {},

        )

        return bool(

            context.get(

                "is_multicast",

                False,

            )

        )

    @staticmethod

    def _is_broadcast(packet: dict) -> bool:

        """

        Détermine si le paquet est broadcast.

        """

        if packet.get("is_broadcast"):

            return True

        context = packet.get(

            "context",

            {},

        )

        return bool(

            context.get(

                "is_broadcast",

                False,

            )

        )

    @staticmethod

    def _is_private_source(packet: dict) -> bool:

        """

        Récupère l'information de réseau privé.

        Compatible avec :

            packet["is_private_source"]

        et l'ancien format :

            packet["context"]["is_private_source"]

        """

        if "is_private_source" in packet:

            return bool(

                packet.get(

                    "is_private_source"

                )

            )

        context = packet.get(

            "context",

            {},

        )

        return bool(

            context.get(

                "is_private_source",

                False,

            )

        )

    @staticmethod

    def _is_private_destination(packet: dict) -> bool:

        """

        Récupère l'information de réseau privé.

        """

        if "is_private_destination" in packet:

            return bool(

                packet.get(

                    "is_private_destination"

                )

            )

        context = packet.get(

            "context",

            {},

        )

        return bool(

            context.get(

                "is_private_destination",

                False,

            )

        )

    def _is_expected_control_traffic(

        self,

        packet: dict,

    ) -> bool:

        """

        Détermine si le paquet appartient à une catégorie

        de trafic réseau généralement normale et qui ne doit

        pas être traitée comme une connexion répétée classique.

        """

        protocol = self._protocol(packet)

        destination_port = packet.get(

            "destination_port"

        )

        source_port = packet.get(

            "source_port"

        )

        # -----------------------------------------------------

        # ARP

        # -----------------------------------------------------

        if protocol == "ARP":

            return True

        # -----------------------------------------------------

        # ICMP / ICMPv6

        # -----------------------------------------------------

        if protocol in {

            "ICMP",

            "ICMPV6",

        }:

            return True

        # -----------------------------------------------------

        # DHCP

        # -----------------------------------------------------

        if (

            destination_port in self.DHCP_PORTS

            or source_port in self.DHCP_PORTS

        ):

            return True

        # -----------------------------------------------------

        # mDNS

        # -----------------------------------------------------

        if (

            destination_port == 5353

            or source_port == 5353

        ):

            return True

        # -----------------------------------------------------

        # SSDP / UPnP

        # -----------------------------------------------------

        if (

            destination_port == 1900

            or source_port == 1900

        ):

            return True

        # -----------------------------------------------------

        # Multicast / broadcast

        # -----------------------------------------------------

        if self._is_multicast(packet):

            return True

        if self._is_broadcast(packet):

            return True

        # -----------------------------------------------------
        # IPv6 link-local sans protocole de transport identifié
        # -----------------------------------------------------
        # Ces paquets peuvent appartenir au fonctionnement normal
        # du réseau local. Sans ports ni transport identifié, ils
        # ne doivent pas être assimilés à une connexion répétée.
        source = str(packet.get("source") or "").lower()
        destination = str(packet.get("destination") or "").lower()

        if (
            protocol in {"IPV6", "IP"}
            and source.startswith("fe80:")
            and destination.startswith("fe80:")
            and source_port is None
            and destination_port is None
        ):
            return True

        return False

    # =========================================================

    # 1. DESTINATIONS EXTERNES MULTIPLES

    # =========================================================

    def _detect_multiple_external_destinations(

        self,

        packets: list[dict],

    ) -> list[dict]:

        """

        Détecte lorsqu'une adresse privée communique avec

        un nombre important de destinations publiques.

        Le trafic multicast/broadcast est volontairement

        exclu afin d'éviter de confondre la découverte

        réseau avec une grande diversité de destinations.

        """

        destinations_by_source = defaultdict(set)

        for packet in packets:

            source = packet.get(

                "source"

            )

            destination = packet.get(

                "destination"

            )

            if not source or not destination:

                continue

            if self._is_multicast(packet):

                continue

            if self._is_broadcast(packet):

                continue

            source_private = (

                self._is_private_source(

                    packet

                )

            )

            destination_private = (

                self._is_private_destination(

                    packet

                )

            )

            if (

                source_private

                and not destination_private

            ):

                destinations_by_source[

                    source

                ].add(destination)

        observations = []

        for source, destinations in (

            destinations_by_source.items()

        ):

            count = len(

                destinations

            )

            if (

                count

                < self.MULTIPLE_DESTINATIONS_THRESHOLD

            ):

                continue

            observations.append(

                {

                    "type": (

                        "MULTIPLE_EXTERNAL_DESTINATIONS"

                    ),

                    "severity": "MEDIUM",

                    "title": (

                        "Diversité élevée des "

                        "destinations externes"

                    ),

                    "observed_fact": (

                        f"L'adresse {source} a communiqué "

                        f"avec {count} destinations "

                        "externes différentes."

                    ),

                    "interpretation": (

                        "L'hôte présente une diversité "

                        "élevée de communications "

                        "sortantes pendant la période observée."

                    ),

                    "hypothesis": (

                        "Cela peut correspondre à une activité "

                        "normale d'applications, à des services "

                        "cloud, à des synchronisations, à de la "

                        "navigation ou à une activité automatisée. "

                        "Des informations supplémentaires sont "

                        "nécessaires pour déterminer la cause."

                    ),

                    "evidence": {

                        "source": source,

                        "destination_count": count,

                        "destinations": sorted(

                            destinations

                        ),

                    },

                }

            )

        return observations

    # =========================================================

    # 2. COMMUNICATIONS RÉPÉTÉES

    # =========================================================

    def _detect_repeated_connections(

        self,

        packets: list[dict],

    ) -> list[dict]:

        """

        Détecte les communications répétées.

        Les protocoles de découverte, de contrôle réseau,

        multicast et broadcast sont exclus afin d'éviter

        les faux positifs.

        """

        counters = defaultdict(set)

        for packet in packets:

            if self._is_expected_control_traffic(

                packet

            ):

                continue

            source = packet.get(

                "source"

            )

            destination = packet.get(

                "destination"

            )

            protocol = self._protocol(

                packet

            )

            destination_port = packet.get(

                "destination_port"

            )

            if not source or not destination:

                continue

            source_port = packet.get("source_port")

            if protocol == "TCP":
                try:
                    source_port = int(source_port)
                    destination_port = int(destination_port)
                except (TypeError, ValueError):
                    # Sans les deux ports, les paquets ne peuvent pas être
                    # attribués de façon fiable à un flux TCP.
                    continue

                source_endpoint = (source, source_port)
                destination_endpoint = (destination, destination_port)
                if source_endpoint <= destination_endpoint:
                    flow = (source_endpoint, destination_endpoint)
                else:
                    flow = (destination_endpoint, source_endpoint)

                # Le port de service est celui qui n'est pas éphémère.
                # Il reste identique dans les deux sens du flux.
                if source_port >= self.EPHEMERAL_PORT_MIN:
                    service_port = destination_port
                elif destination_port >= self.EPHEMERAL_PORT_MIN:
                    service_port = source_port
                else:
                    service_port = min(source_port, destination_port)

                address_pair = tuple(sorted((source, destination)))
                key = (address_pair[0], address_pair[1], protocol, service_port)
                counters[key].add(flow)
            else:
                # Préserver le comptage existant pour les autres protocoles.
                key = (source, destination, protocol, destination_port)
                counters[key].add(("packet", id(packet)))

        observations = []

        for (

            source,

            destination,

            protocol,

            destination_port,

        ), flows in counters.items():
            count = len(flows)

            if (

                count

                < self.REPEATED_CONNECTION_THRESHOLD

            ):

                continue

            port_text = (

                str(destination_port)

                if destination_port is not None

                else "aucun"

            )

            if protocol == "TCP":
                observed_fact = (
                    f"{source} et {destination} ont établi "
                    f"{count} flux TCP distinct(s), associé(s) "
                    f"au port de service {port_text}."
                )
            else:
                observed_fact = (
                    f"{source} a envoyé ou reçu "
                    f"{count} communication(s) distincte(s) avec "
                    f"{destination} via {protocol}, "
                    f"port destination {port_text}."
                )

            observations.append(

                {

                    "type": (

                        "REPEATED_CONNECTIONS"

                    ),

                    "severity": "LOW",

                    "title": (

                        "Communication répétée "

                        "observée"

                    ),

                    "observed_fact": observed_fact,

                    "interpretation": (

                        "Une communication répétée "

                        "vers la même destination a été "

                        "observée en dehors des principaux "

                        "protocoles de découverte et de "

                        "contrôle réseau."

                    ),

                    "hypothesis": (

                        "Cela peut correspondre au comportement "

                        "normal d'une connexion persistante, "

                        "d'une application, d'un service réseau "

                        "ou d'un mécanisme de synchronisation. "

                        "Une répétition seule ne permet pas "

                        "de conclure à une activité malveillante."

                    ),

                    "evidence": {

                        "source": source,

                        "destination": destination,

                        "protocol": protocol,

                        "destination_port": (

                            destination_port

                        ),

                        "service_port": (
                            destination_port if protocol == "TCP" else None
                        ),

                        "communication_count": count,

                    },

                }

            )

        return observations

    # =========================================================

    # 3. PORTS INHABITUELS

    # =========================================================

    def _detect_unusual_ports(

        self,

        packets: list[dict],

    ) -> list[dict]:

        """

        Recherche des ports qui nécessitent une interprétation.

        IMPORTANT :

        Un port élevé n'est pas automatiquement inhabituel.

        Exemple :

            64263

        peut simplement être un port éphémère utilisé

        par le système comme port client.

        On recherche donc principalement :

            client -> port de destination non standard

        lorsque le port ne correspond pas à une plage

        éphémère et n'appartient pas aux protocoles attendus.

        """

        observations = []

        counters = Counter()

        for packet in packets:

            source = packet.get(

                "source"

            )

            destination = packet.get(

                "destination"

            )

            protocol = self._protocol(

                packet

            )

            source_port = packet.get(

                "source_port"

            )

            destination_port = packet.get(

                "destination_port"

            )

            if not source or not destination:

                continue

            # -------------------------------------------------

            # ARP / ICMP / ICMPv6

            # -------------------------------------------------

            if protocol in self.EXPECTED_PROTOCOLS:

                continue

            # -------------------------------------------------

            # Multicast / broadcast

            # -------------------------------------------------

            if self._is_multicast(packet):

                continue

            if self._is_broadcast(packet):

                continue

            # -------------------------------------------------

            # DHCP

            # -------------------------------------------------

            if (

                source_port in self.DHCP_PORTS

                or destination_port in self.DHCP_PORTS

            ):

                continue

            # -------------------------------------------------

            # mDNS

            # -------------------------------------------------

            if (

                source_port == 5353

                or destination_port == 5353

            ):

                continue

            # -------------------------------------------------

            # SSDP

            # -------------------------------------------------

            if (

                source_port == 1900

                or destination_port == 1900

            ):

                continue

            # -------------------------------------------------

            # Pas de port

            # -------------------------------------------------

            if destination_port is None:

                continue

            try:

                destination_port = int(

                    destination_port

                )

            except (

                TypeError,

                ValueError,

            ):

                continue

            # -------------------------------------------------

            # Port connu

            # -------------------------------------------------

            if destination_port in self.COMMON_PORTS:

                continue

            # -------------------------------------------------

            # Port éphémère

            #

            # Très important :

            # on ne le considère pas automatiquement

            # comme un service inhabituel.

            # -------------------------------------------------

            if self._is_ephemeral_port(

                destination_port

            ):

                continue

            # -------------------------------------------------

            # Port dynamique mais hors plage classique

            #

            # Il peut toujours être légitime.

            # On le conserve comme observation faible

            # uniquement s'il est répété.

            # -------------------------------------------------

            key = (

                source,

                destination,

                protocol,

                destination_port,

            )

            counters[key] += 1

        # -----------------------------------------------------

        # Générer les observations uniquement lorsque le

        # comportement est suffisamment répétitif.

        # -----------------------------------------------------

        for (

            source,

            destination,

            protocol,

            destination_port,

        ), count in counters.items():

            if count < 3:

                continue

            observations.append(

                {

                    "type": "UNUSUAL_PORT",

                    "severity": "INFO",

                    "title": (

                        "Port non courant observé"

                    ),

                    "observed_fact": (

                        f"Le port destination "

                        f"{destination_port} a été observé "

                        f"{count} fois dans des communications "

                        f"{protocol} entre {source} et "

                        f"{destination}."

                    ),

                    "interpretation": (

                        "Le port observé ne correspond pas "

                        "à un port de service courant connu "

                        "par INPA et ne correspond pas à une "

                        "plage de port éphémère classique."

                    ),

                    "hypothesis": (

                        "Il peut s'agir d'un service légitime "

                        "utilisant un port personnalisé, d'une "

                        "application particulière ou d'un service "

                        "local. Une analyse supplémentaire est "

                        "nécessaire avant toute conclusion."

                    ),

                    "evidence": {

                        "source": source,

                        "destination": destination,

                        "protocol": protocol,

                        "destination_port": (

                            destination_port

                        ),

                        "packet_count": count,

                    },

                }

            )

        return observations

    # =========================================================

    # 4. MULTICAST

    # =========================================================

    def _detect_multicast_activity(
        self,
        packets: list[dict],
    ) -> list[dict]:
        """
        Évalue le multicast selon son volume, sa proportion, sa durée
        et le contexte des services observés.

        Une activité multicast importante reste informative : elle ne
        constitue pas, à elle seule, une preuve d'attaque.
        """
        multicast_packets = [
            packet for packet in packets
            if self._is_multicast(packet)
        ]

        count = len(multicast_packets)
        total_packets = len(packets)

        if count < self.MULTICAST_THRESHOLD or total_packets == 0:
            return []

        proportion = count / total_packets

        # Normaliser les dates en UTC pour éviter les erreurs de fuseau.
        timestamps = []
        for packet in packets:
            raw_timestamp = packet.get("timestamp")
            if not raw_timestamp:
                continue

            try:
                if isinstance(raw_timestamp, datetime):
                    timestamp = raw_timestamp
                else:
                    timestamp = datetime.fromisoformat(
                        str(raw_timestamp).replace("Z", "+00:00")
                    )

                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                else:
                    timestamp = timestamp.astimezone(timezone.utc)

                timestamps.append(timestamp)
            except (TypeError, ValueError, OverflowError):
                continue

        capture_duration = None
        packets_per_second = None

        if len(timestamps) >= 2:
            capture_duration = (
                max(timestamps) - min(timestamps)
            ).total_seconds()

            if capture_duration > 0:
                packets_per_second = count / capture_duration

        # Les seuils décrivent une activité importante, pas une attaque.
        notable_proportion = proportion >= 0.20
        notable_rate = (
            packets_per_second is not None
            and packets_per_second >= 10
        )

        if not notable_proportion and not notable_rate:
            return []

        destinations = sorted({
            str(packet.get("destination"))
            for packet in multicast_packets
            if packet.get("destination")
        })

        sources = sorted({
            str(packet.get("source"))
            for packet in multicast_packets
            if packet.get("source")
        })

        services = sorted({
            str(packet.get("probable_service"))
            for packet in multicast_packets
            if packet.get("probable_service")
            and str(packet.get("probable_service")).upper() != "INCONNU"
        })

        protocols = dict(Counter(
            self._protocol(packet)
            for packet in multicast_packets
        ))

        # Déduire les services probables des ports si le classificateur
        # n'a pas renseigné le champ probable_service.
        service_ports = set()
        for packet in multicast_packets:
            for field in ("source_port", "destination_port"):
                try:
                    port = int(packet.get(field))
                except (TypeError, ValueError):
                    continue

                if port == 5353:
                    service_ports.add("mDNS (5353)")
                elif port == 1900:
                    service_ports.add("SSDP/UPnP (1900)")
                elif port in self.DHCP_PORTS:
                    service_ports.add("DHCP")

        context_indicators = sorted(set(services) | service_ports)

        # Destinations de découverte courantes. Leur présence est un indice
        # de contexte, pas une preuve que tout le trafic est légitime.
        discovery_destinations = {
            "224.0.0.251",       # mDNS IPv4
            "239.255.255.250",   # SSDP IPv4
            "ff02::fb",          # mDNS IPv6
            "ff02::c",           # SSDP IPv6
        }
        normalized_destinations = {
            destination.strip().lower()
            for destination in destinations
        }
        known_discovery_destinations = sorted(
            normalized_destinations & discovery_destinations
        )

        has_discovery_context = bool(
            context_indicators or known_discovery_destinations
        )

        if context_indicators:
            context_text = (
                "Des indices compatibles avec des services de découverte "
                "ou de contrôle ont été observés : "
                + ", ".join(context_indicators[:8])
                + "."
            )
        elif known_discovery_destinations:
            context_text = (
                "Des destinations multicast courantes de découverte "
                "de services ont été observées : "
                + ", ".join(known_discovery_destinations)
                + "."
            )
        else:
            context_text = (
                "Les services associés ne sont pas suffisamment identifiés "
                "pour attribuer une cause précise à cette activité."
            )

        duration_text = (
            f"{capture_duration:.2f} seconde(s)"
            if capture_duration is not None
            else "durée indéterminée (horodatages insuffisants)"
        )
        rate_text = (
            f"{packets_per_second:.2f} paquet(s)/seconde"
            if packets_per_second is not None
            else "débit non calculable"
        )

        observed_fact = (
            f"{count} paquets multicast sur {total_packets} paquets "
            f"analysés ({proportion:.1%} du trafic). "
            f"Durée de capture : {duration_text} ; rythme multicast : "
            f"{rate_text}."
        )

        if notable_rate and notable_proportion:
            interpretation = (
                "Le multicast représente une part importante du trafic "
                "et présente également un rythme élevé dans la capture."
            )
        elif notable_rate:
            interpretation = (
                "Le rythme des paquets multicast est élevé, même si leur "
                "proportion dans l'ensemble de la capture est plus limitée."
            )
        else:
            interpretation = (
                "Le multicast représente une part notable du trafic capturé. "
                "La proportion seule ne permet pas de conclure à une anomalie."
            )

        if has_discovery_context:
            contextual_assessment = (
                "Le contexte observé est compatible avec des mécanismes "
                "légitimes de découverte ou de contrôle réseau. Il faut "
                "néanmoins vérifier si ce volume et ce rythme sont habituels "
                "sur ce réseau."
            )
        else:
            contextual_assessment = (
                "Aucun indice courant de découverte n'a été identifié dans "
                "les services et destinations observés. Examiner les sources, "
                "les destinations et les protocoles avant de qualifier "
                "l'activité d'anormale."
            )

        hypothesis = (
            context_text
            + " "
            + contextual_assessment
            + " Une activité multicast élevée peut correspondre à mDNS, "
            "à SSDP/UPnP, à ICMPv6 multicast ou à d'autres mécanismes réseau "
            "légitimes. Une comparaison avec une référence établie sur des "
            "captures de durée comparable aide à repérer les changements. "
            "Le multicast élevé ne prouve pas, à lui seul, une attaque."
        )

        evidence = {
            "packet_count": count,
            "total_packet_count": total_packets,
            "packet_percentage": round(proportion * 100, 2),
            "capture_duration_seconds": (
                round(capture_duration, 2)
                if capture_duration is not None
                else None
            ),
            "multicast_packets_per_second": (
                round(packets_per_second, 2)
                if packets_per_second is not None
                else None
            ),
            "destinations": destinations,
            "source_count": len(sources),
            "sources": sources[:50],
            "probable_services": services,
            "context_indicators": context_indicators,
            "protocol_distribution": protocols,
            "known_discovery_destinations": known_discovery_destinations,
            "discovery_context_detected": has_discovery_context,
            "notable_proportion": notable_proportion,
            "notable_rate": notable_rate,
            "thresholds": {
                "minimum_multicast_packets": self.MULTICAST_THRESHOLD,
                "notable_proportion": 20,
                "notable_rate_packets_per_second": 10,
            },
        }

        return [{
            "type": "HIGH_MULTICAST_ACTIVITY",
            "severity": "LOW",
            "title": "Activité multicast importante",
            "observed_fact": observed_fact,
            "interpretation": interpretation,
            "hypothesis": hypothesis,
            "evidence": evidence,
        }]

    def _detect_broadcast_activity(

        self,

        packets: list[dict],

    ) -> list[dict]:

        """

        Détecte une activité broadcast importante.

        Cette observation est informative.

        """

        broadcast_packets = []

        for packet in packets:

            if self._is_broadcast(

                packet

            ):

                broadcast_packets.append(

                    packet

                )

        count = len(

            broadcast_packets

        )

        if (

            count

            < self.BROADCAST_THRESHOLD

        ):

            return []

        destinations = sorted(

            {

                packet.get(

                    "destination"

                )

                for packet in broadcast_packets

                if packet.get(

                    "destination"

                )

            }

        )

        return [

            {

                "type": (

                    "HIGH_BROADCAST_ACTIVITY"

                ),

                "severity": "LOW",

                "title": (

                    "Activité broadcast importante"

                ),

                "observed_fact": (

                    f"{count} paquets broadcast "

                    "ont été observés."

                ),

                "interpretation": (

                    "Une quantité importante de "

                    "communications broadcast a été "

                    "observée sur la période analysée."

                ),

                "hypothesis": (

                    "Cela peut être lié à ARP, DHCP, "

                    "à la découverte réseau ou à d'autres "

                    "mécanismes normaux du réseau local. "

                    "Des informations supplémentaires "

                    "sont nécessaires pour déterminer "

                    "si cette activité est anormale."

                ),

                "evidence": {

                    "packet_count": count,

                    "destinations": destinations,

                },

            }

        ]

    # =========================================================

    # 6. ACTIVITÉ RAPIDE

    # =========================================================

    def _detect_rapid_activity(

        self,

        packets: list[dict],

    ) -> list[dict]:

        """

        Détecte une concentration importante de trafic

        dans une courte fenêtre temporelle.

        La détection évite le faux positif causé par une

        simple analyse des 1000 derniers paquets.

        Si tous les paquets ont été capturés en moins de

        10 secondes, nous ne concluons pas automatiquement

        qu'il existe une activité anormale.

        """

        timestamps = []

        for packet in packets:

            timestamp = packet.get(

                "timestamp"

            )

            if not timestamp:

                continue

            try:

                timestamps.append(

                    datetime.fromisoformat(

                        timestamp

                    )

                )

            except (

                ValueError,

                TypeError,

            ):

                continue

        if len(timestamps) < 2:

            return []

        timestamps.sort()

        capture_duration = (

            timestamps[-1]

            - timestamps[0]

        ).total_seconds()

        # -----------------------------------------------------

        # Capture trop courte

        #

        # Important :

        # l'endpoint /api/analyzer analyse actuellement

        # jusqu'à 1000 paquets.

        #

        # Si ces 1000 paquets ont été capturés très vite,

        # cela ne suffit pas à caractériser une anomalie.

        # -----------------------------------------------------

        if (

            capture_duration

            < self.MIN_CAPTURE_DURATION_SECONDS

        ):

            return []

        max_packets = 0

        window_start = 0

        for window_end in range(

            len(timestamps)

        ):

            while (

                timestamps[window_end]

                - timestamps[window_start]

            ).total_seconds() > (

                self.RAPID_ACTIVITY_WINDOW_SECONDS

            ):

                window_start += 1

            current_count = (

                window_end

                - window_start

                + 1

            )

            if (

                current_count

                > max_packets

            ):

                max_packets = (

                    current_count

                )

        if (

            max_packets

            < self.RAPID_ACTIVITY_THRESHOLD

        ):

            return []

        packets_per_second = (

            max_packets

            / self.RAPID_ACTIVITY_WINDOW_SECONDS

        )

        return [

            {

                "type": (

                    "RAPID_NETWORK_ACTIVITY"

                ),

                "severity": "INFO",

                "title": (

                    "Forte concentration de trafic"

                ),

                "observed_fact": (

                    f"Jusqu'à {max_packets} paquets "

                    f"ont été observés dans une fenêtre "

                    f"de {self.RAPID_ACTIVITY_WINDOW_SECONDS} "

                    "secondes."

                ),

                "interpretation": (

                    "Une quantité importante de trafic "

                    "a été concentrée sur une courte "

                    "période dans une capture disposant "

                    "d'une durée suffisante pour cette analyse."

                ),

                "hypothesis": (

                    "Cette concentration peut correspondre "

                    "à une activité normale comme le chargement "

                    "d'une page, une synchronisation, un "

                    "téléchargement ou une communication "

                    "automatisée. Elle ne permet pas à elle "

                    "seule d'identifier une attaque."

                ),

                "evidence": {

                    "max_packets_in_window": (

                        max_packets

                    ),

                    "window_seconds": (

                        self.RAPID_ACTIVITY_WINDOW_SECONDS

                    ),

                    "estimated_packets_per_second": (

                        round(

                            packets_per_second,

                            2,

                        )

                    ),

                    "capture_duration_seconds": (

                        round(

                            capture_duration,

                            2,

                        )

                    ),

                },

            }

        ]

# =============================================================

# INSTANCE GLOBALE

# =============================================================

behavior_analyzer = BehaviorAnalyzer()
