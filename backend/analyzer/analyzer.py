from collections import Counter

from backend.analyzer.classifier import classify_packet
from backend.analyzer.flows import build_flows
from backend.analyzer.behavior import behavior_analyzer
from backend.analyzer.profile import network_profile_builder
from backend.analyzer.baseline import (
    baseline_manager,
    baseline_comparator,
)


class NetworkAnalyzer:
    """
    Analyseur principal d'INPA.

    Pipeline :

        PAQUETS BRUTS
            ↓
        CLASSIFICATION
            ↓
        FLOWS
            ↓
        PROFIL RÉSEAU
            ↓
        ANALYSE COMPORTEMENTALE
            ↓
        COMPARAISON BASELINE
            ↓
        EXPLICATION STRUCTURÉE

    INPA distingue toujours :

        FAIT OBSERVÉ
        INTERPRÉTATION
        HYPOTHÈSE

    Une différence avec la baseline n'est jamais considérée
    automatiquement comme une attaque.
    """

    # =========================================================
    # ANALYSE PRINCIPALE
    # =========================================================

    def analyze(
        self,
        packets: list[dict],
    ) -> dict:
        """
        Analyse une liste de paquets capturés.
        """

        # =====================================================
        # AUCUN PAQUET
        # =====================================================

        if not packets:

            empty_profile = (
                network_profile_builder.build(
                    []
                )
            )

            baseline = (
                baseline_manager.get_baseline()
            )

            baseline_comparison = (
                baseline_comparator.compare(
                    baseline,
                    empty_profile,
                )
                if baseline
                else {
                    "available": False,
                    "message": (
                        "Aucune baseline disponible."
                    ),
                    "observations": [],
                }
            )

            return {
                "packet_count": 0,
                "total_bytes": 0,
                "protocols": {},
                "flows": [],
                "observations": [],
                "behavior_observations": [],
                "baseline_comparison": (
                    baseline_comparison
                ),
                "profile": empty_profile,
                "packets": [],
            }

        # =====================================================
        # CLASSIFICATION
        # =====================================================

        classified_packets = []

        for packet in packets:

            try:

                classified = (
                    classify_packet(
                        packet
                    )
                )

                enriched_packet = {
                    **packet,
                    **classified,
                }

                classified_packets.append(
                    enriched_packet
                )

            except Exception as error:

                fallback_packet = {
                    **packet,

                    "observed": True,

                    "observed_fact": (
                        "Paquet capturé mais "
                        "classification impossible."
                    ),

                    "interpretation": (
                        "Les informations réseau "
                        "disponibles pour ce paquet "
                        "sont insuffisantes."
                    ),

                    "hypothesis": (
                        "Le paquet peut utiliser une "
                        "structure ou un protocole "
                        "qui n'est pas encore pris "
                        "en charge."
                    ),

                    "classification_error": str(
                        error
                    ),
                }

                classified_packets.append(
                    fallback_packet
                )

        # =====================================================
        # STATISTIQUES GÉNÉRALES
        # =====================================================

        protocol_counter = Counter()

        total_bytes = 0

        broadcast_count = 0

        private_to_private_count = 0
        private_to_external_count = 0
        external_to_private_count = 0

        for packet in classified_packets:

            protocol = str(
                packet.get(
                    "protocol",
                    "UNKNOWN",
                )
            ).upper()

            protocol_counter[
                protocol
            ] += 1

            try:

                total_bytes += int(
                    packet.get(
                        "size"
                    )
                    or 0
                )

            except (
                ValueError,
                TypeError,
            ):

                pass

            # -------------------------------------------------
            # BROADCAST
            # -------------------------------------------------

            if packet.get(
                "is_broadcast"
            ):

                broadcast_count += 1

            # -------------------------------------------------
            # COMMUNICATIONS INTERNES
            # -------------------------------------------------

            source_private = packet.get(
                "is_private_source"
            )

            destination_private = packet.get(
                "is_private_destination"
            )

            if (
                source_private
                and destination_private
            ):

                private_to_private_count += 1

            elif (
                source_private
                and destination_private is False
            ):

                private_to_external_count += 1

            elif (
                source_private is False
                and destination_private
            ):

                external_to_private_count += 1

        # =====================================================
        # FLOWS
        # =====================================================

        flows = build_flows(
            classified_packets
        )

        # =====================================================
        # OBSERVATIONS GÉNÉRALES
        # =====================================================

        observations = []

        # -----------------------------------------------------
        # VOLUME
        # -----------------------------------------------------

        observations.append(
            {
                "type": "traffic_volume",
                "severity": "INFO",
                "title": (
                    "Trafic réseau observé"
                ),
                "observed_fact": (
                    f"{len(classified_packets)} "
                    "paquet(s) ont été analysés."
                ),
                "interpretation": (
                    "La capture contient des "
                    "données réseau exploitables "
                    "pour une analyse comportementale."
                ),
                "hypothesis": (
                    "Le trafic observé représente "
                    "une partie de l'activité réseau "
                    "pendant la période capturée."
                ),
                "evidence": {
                    "packet_count": (
                        len(
                            classified_packets
                        )
                    ),
                    "total_bytes": (
                        total_bytes
                    ),
                },
            }
        )

        # -----------------------------------------------------
        # PROTOCOLES
        # -----------------------------------------------------

        if protocol_counter:

            observations.append(
                {
                    "type": (
                        "protocol_distribution"
                    ),
                    "severity": "INFO",
                    "title": (
                        "Protocoles observés"
                    ),
                    "observed_fact": (
                        f"{len(protocol_counter)} "
                        "protocole(s) réseau "
                        "ont été observés."
                    ),
                    "interpretation": (
                        "Le trafic utilise plusieurs "
                        "mécanismes de communication "
                        "réseau."
                    ),
                    "hypothesis": (
                        "Cette diversité peut correspondre "
                        "aux applications, services et "
                        "mécanismes réseau actifs."
                    ),
                    "evidence": {
                        "protocols": dict(
                            protocol_counter
                        ),
                    },
                }
            )

        # Les compteurs multicast restent dans le profil réseau. On ne crée
        # pas une observation générique à chaque capture : les changements
        # significatifs sont évalués par le comparateur de baseline.

        # -----------------------------------------------------
        # BROADCAST
        # -----------------------------------------------------

        if broadcast_count:

            observations.append(
                {
                    "type": "broadcast",
                    "severity": "INFO",
                    "title": (
                        "Trafic broadcast observé"
                    ),
                    "observed_fact": (
                        f"{broadcast_count} paquet(s) "
                        "broadcast ont été observés."
                    ),
                    "interpretation": (
                        "Certains paquets sont destinés "
                        "à plusieurs hôtes du réseau local."
                    ),
                    "hypothesis": (
                        "Cela peut correspondre à ARP, "
                        "DHCP, à la découverte réseau ou "
                        "à d'autres mécanismes normaux."
                    ),
                    "evidence": {
                        "broadcast_packets": (
                            broadcast_count
                        ),
                    },
                }
            )

        # -----------------------------------------------------
        # INTERNE
        # -----------------------------------------------------

        if private_to_private_count:

            observations.append(
                {
                    "type": (
                        "internal_communication"
                    ),
                    "severity": "INFO",
                    "title": (
                        "Communications internes"
                    ),
                    "observed_fact": (
                        f"{private_to_private_count} "
                        "paquet(s) impliquent des "
                        "adresses privées des deux côtés."
                    ),
                    "interpretation": (
                        "Une partie du trafic circule "
                        "à l'intérieur des réseaux "
                        "privés observés."
                    ),
                    "hypothesis": (
                        "Ces communications peuvent "
                        "correspondre à des échanges "
                        "entre appareils ou services "
                        "du réseau local."
                    ),
                    "evidence": {
                        "private_to_private_packets": (
                            private_to_private_count
                        ),
                    },
                }
            )

        # -----------------------------------------------------
        # SORTIE
        # -----------------------------------------------------

        if private_to_external_count:

            observations.append(
                {
                    "type": (
                        "external_communication"
                    ),
                    "severity": "INFO",
                    "title": (
                        "Communications vers l'extérieur"
                    ),
                    "observed_fact": (
                        f"{private_to_external_count} "
                        "paquet(s) vont d'une adresse "
                        "privée vers une destination externe."
                    ),
                    "interpretation": (
                        "Des appareils du réseau privé "
                        "communiquent avec des destinations "
                        "situées à l'extérieur du réseau privé."
                    ),
                    "hypothesis": (
                        "Cela peut correspondre à de la "
                        "navigation web, des services cloud, "
                        "des mises à jour ou d'autres "
                        "services Internet."
                    ),
                    "evidence": {
                        "private_to_external_packets": (
                            private_to_external_count
                        ),
                    },
                }
            )

        # -----------------------------------------------------
        # ENTRÉE
        # -----------------------------------------------------

        if external_to_private_count:

            observations.append(
                {
                    "type": (
                        "external_to_private"
                    ),
                    "severity": "INFO",
                    "title": (
                        "Communications externes vers "
                        "le réseau privé"
                    ),
                    "observed_fact": (
                        f"{external_to_private_count} "
                        "paquet(s) impliquent une source "
                        "externe et une destination privée."
                    ),
                    "interpretation": (
                        "Des paquets provenant d'adresses "
                        "non privées ont été observés vers "
                        "des destinations privées."
                    ),
                    "hypothesis": (
                        "Cela peut correspondre à des réponses "
                        "à des communications initiées localement, "
                        "à des services exposés ou à d'autres "
                        "mécanismes réseau. Le contexte complet "
                        "est nécessaire pour déterminer leur origine."
                    ),
                    "evidence": {
                        "external_to_private_packets": (
                            external_to_private_count
                        ),
                    },
                }
            )

        # =====================================================
        # ANALYSE COMPORTEMENTALE
        # =====================================================

        behavior_observations = (
            behavior_analyzer.analyze(
                classified_packets
            )
        )

        # =====================================================
        # PROFIL ACTUEL
        # =====================================================

        profile = (
            network_profile_builder.build(
                classified_packets
            )
        )

        # =====================================================
        # COMPARAISON AVEC LA BASELINE
        # =====================================================

        baseline = (
            baseline_manager.get_baseline()
        )

        if baseline is None:

            baseline_comparison = {
                "available": False,
                "message": (
                    "Aucune baseline disponible. "
                    "Crée une baseline pour comparer "
                    "les futurs comportements réseau."
                ),
                "observations": [],
            }

        else:

            baseline_comparison = (
                baseline_comparator.compare(
                    baseline,
                    profile,
                )
            )

        # =====================================================
        # RÉSULTAT FINAL
        # =====================================================

        return {

            # -------------------------------------------------
            # STATISTIQUES
            # -------------------------------------------------

            "packet_count": (
                len(
                    classified_packets
                )
            ),

            "total_bytes": total_bytes,

            "protocols": dict(
                protocol_counter
            ),

            # -------------------------------------------------
            # FLOWS
            # -------------------------------------------------

            "flows": flows,

            # -------------------------------------------------
            # OBSERVATIONS GÉNÉRALES
            # -------------------------------------------------

            "observations": observations,

            # -------------------------------------------------
            # COMPORTEMENT
            # -------------------------------------------------

            "behavior_observations": (
                behavior_observations
            ),

            # -------------------------------------------------
            # BASELINE
            # -------------------------------------------------

            "baseline_comparison": (
                baseline_comparison
            ),

            # -------------------------------------------------
            # PROFIL
            # -------------------------------------------------

            "profile": profile,

            # -------------------------------------------------
            # PAQUETS
            # -------------------------------------------------

            "packets": classified_packets,
        }


# =============================================================
# INSTANCE GLOBALE
# =============================================================

network_analyzer = NetworkAnalyzer()