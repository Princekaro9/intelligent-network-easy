from collections import Counter
import copy
import hashlib
import ipaddress
import json
from datetime import datetime
from pathlib import Path


# ============================================================
# CONFIGURATION BASELINE V4
# ============================================================

# Ports correspondant à des services réseau courants.
# Ils ne sont pas considérés comme "nouveaux" simplement
# parce qu'ils n'étaient pas présents dans une fenêtre courte.
COMMON_SERVICE_PORTS = {
    20,      # FTP-DATA
    21,      # FTP
    22,      # SSH
    23,      # TELNET
    25,      # SMTP
    53,      # DNS
    67,      # DHCP
    68,      # DHCP
    80,      # HTTP
    110,     # POP3
    123,     # NTP
    143,     # IMAP
    443,     # HTTPS
    445,     # SMB
    465,     # SMTPS
    546,     # DHCPv6
    547,     # DHCPv6
    587,     # SMTP Submission
    993,     # IMAPS
    995,     # POP3S
    1433,    # MSSQL
    1900,    # SSDP
    3306,    # MySQL
    3389,    # RDP
    5353,    # mDNS
    5432,    # PostgreSQL
    5900,    # VNC
    8080,    # HTTP alternatif
    8443,    # HTTPS alternatif
}


# Plage classique des ports éphémères.
# Ils ne doivent pas être signalés comme nouveaux ports
# sans contexte supplémentaire.
EPHEMERAL_PORT_MIN = 49152
EPHEMERAL_PORT_MAX = 65535


# Une nouvelle destination doit apparaître plusieurs fois
# avant d'être considérée comme intéressante.
MIN_NEW_DESTINATION_COUNT = 5


# Un nouveau service doit également être observé plusieurs fois.
MIN_NEW_SERVICE_COUNT = 5


# Un nouveau protocole doit être observé plusieurs fois.
MIN_NEW_PROTOCOL_COUNT = 5


# Un nouveau port non standard doit être observé plusieurs fois.
MIN_NEW_PORT_COUNT = 5


# Seuil de variation de fréquence.
#
# Exemple :
#
# baseline = 5 %
# actuel   = 15 %
#
# ratio = 3
#
# Une augmentation >= 2x est considérée comme significative.
SIGNIFICANT_RATIO = 2.0


# Variation absolue minimale de proportion.
#
# Exemple :
#
# baseline = 5 %
# actuel   = 5.5 %
#
# Même si le ratio est supérieur à 1, l'écart est trop faible.
MIN_PERCENTAGE_POINT_CHANGE = 0.10


# ============================================================
# CONFIGURATION BASELINE V4
# ============================================================

# Progression minimale entre deux fenêtres de persistance acceptées.
PERSISTENCE_MIN_ADVANCE_SECONDS = 10

# Services courants : leur absence dans une baseline courte ne suffit
# pas à produire une observation « nouveau service ».
COMMON_SERVICE_NAMES = {
    "DNS", "DNS-OVER-TCP", "DHCP", "DHCPV6", "HTTP", "HTTP-ALT",
    "HTTPS/TLS", "QUIC/UDP-443", "NTP", "MDNS", "SSDP", "SSDP/UPNP",
    "SSH", "ARP", "ICMP", "ICMPV6", "FTP", "FTP-DATA", "SMTP",
    "SMTP-SUBMISSION", "SMTPS", "POP3", "POP3S", "IMAP", "IMAPS",
    "SMB", "RDP", "MYSQL", "MSSQL", "POSTGRESQL", "VNC",
}


# ============================================================
# OUTILS GÉNÉRAUX
# ============================================================

def _safe_int(value, default=0):
    """
    Convertit une valeur en entier sans provoquer d'erreur.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value, default=0.0):
    """
    Convertit une valeur en float sans provoquer d'erreur.
    """
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _is_ephemeral_port(port):
    """
    Vérifie si le port appartient à la plage des ports éphémères.
    """
    port = _safe_int(port)

    return (
        EPHEMERAL_PORT_MIN
        <= port
        <= EPHEMERAL_PORT_MAX
    )


def _is_common_service_port(port):
    """
    Vérifie si le port correspond à un service réseau connu.
    """
    port = _safe_int(port)

    return port in COMMON_SERVICE_PORTS


def _is_valid_ip(value):
    """
    Vérifie si la valeur est une adresse IPv4 ou IPv6 valide.
    """
    if not value:
        return False

    try:
        ipaddress.ip_address(str(value))
        return True

    except ValueError:
        return False


def _is_private_ip(value):
    """
    Vérifie si une adresse IP est privée.
    """
    if not value:
        return False

    try:
        return ipaddress.ip_address(
            str(value)
        ).is_private

    except ValueError:
        return False


def _is_link_local_ip(value):
    """Vérifie si une adresse IP est link-local (IPv4 ou IPv6)."""
    if not _is_valid_ip(value):
        return False
    try:
        return ipaddress.ip_address(str(value)).is_link_local
    except ValueError:
        return False


def _is_multicast_ip(value):
    """Vérifie si une adresse IP est une adresse multicast."""
    if not _is_valid_ip(value):
        return False
    try:
        return ipaddress.ip_address(str(value)).is_multicast
    except ValueError:
        return False


def _is_external_ip(value):
    """
    Ne considère comme externe qu'une adresse IP globalement routable.

    Les adresses privées, link-local, multicast, loopback, réservées,
    non spécifiées et les autres adresses non globales ne sont pas externes.
    """
    if not _is_valid_ip(value):
        return False
    try:
        address = ipaddress.ip_address(str(value))
        return bool(address.is_global and not address.is_multicast)
    except ValueError:
        return False


# ============================================================
# EXTRACTION DES DONNÉES DU PROFILE
# ============================================================

def _get_profile_section(
    profile,
    section_name,
):
    """
    Récupère une section du profil en toute sécurité.
    """
    if not isinstance(profile, dict):
        return {}

    section = profile.get(
        section_name,
        {},
    )

    if not isinstance(section, dict):
        return {}

    return section


def _get_counter(
    profile,
    section_name,
    field_name,
):
    """
    Transforme une liste de :

        [
            {"value": "TCP", "count": 100},
            {"value": "UDP", "count": 50}
        ]

    en :

        Counter({
            "TCP": 100,
            "UDP": 50
        })

    Compatible avec les profils actuels d'INPA.
    """

    section = _get_profile_section(
        profile,
        section_name,
    )

    data = section.get(
        field_name,
        [],
    )

    result = Counter()

    if isinstance(data, dict):

        for key, value in data.items():

            result[str(key)] = _safe_int(
                value
            )

        return result

    if not isinstance(data, list):
        return result

    for item in data:

        if isinstance(item, dict):

            value = item.get("value")

            if value is None:
                value = item.get("name")

            if value is None:
                continue

            count = item.get(
                "count",
                1,
            )

            result[str(value)] += _safe_int(
                count,
                default=1,
            )

        elif item is not None:

            result[str(item)] += 1

    return result


def _get_packet_count(profile):
    """
    Nombre total de paquets du profil.
    """
    summary = _get_profile_section(
        profile,
        "summary",
    )

    return _safe_int(
        summary.get(
            "packet_count",
            0,
        )
    )


def _get_duration(profile):
    """
    Durée de la fenêtre d'observation.
    """
    summary = _get_profile_section(
        profile,
        "summary",
    )

    return _safe_float(
        summary.get(
            "duration_seconds",
            0,
        )
    )


def _get_normalized_rate(
    count,
    total_packets,
):
    """
    Retourne la proportion d'un élément
    par rapport au nombre total de paquets.

    Exemple :

        100 / 1000 = 0.10
    """

    count = _safe_int(count)
    total_packets = _safe_int(
        total_packets
    )

    if total_packets <= 0:
        return 0.0

    return count / total_packets


def _get_rate_per_second(
    count,
    duration_seconds,
):
    """
    Retourne une fréquence approximative par seconde.
    """
    count = _safe_int(count)
    duration_seconds = _safe_float(
        duration_seconds
    )

    if duration_seconds <= 0:
        return 0.0

    return count / duration_seconds


def _parse_timestamp(value):
    """Convertit un horodatage ISO en datetime UTC sans fuseau.

    Normaliser les dates évite les erreurs de comparaison entre dates
    avec fuseau horaire et dates sans fuseau horaire.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            from datetime import timezone
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except (TypeError, ValueError, OverflowError):
        return None


def _profile_fingerprint(profile):
    """
    Empreinte stable des principales données du profil.
    Un profil identique ne compte pas comme une nouvelle observation.
    """
    summary = _get_profile_section(profile, "summary")
    payload = {
        "summary": {
            "packet_count": _get_packet_count(profile),
            "first_seen": summary.get("first_seen"),
            "last_seen": summary.get("last_seen"),
            "duration_seconds": round(_get_duration(profile), 3),
        },
        "protocols": sorted(_get_counter(profile, "protocols", "distribution").items()),
        "services": sorted(_get_counter(profile, "services", "distribution").items()),
        "destinations": sorted(_get_counter(profile, "devices", "destinations").items()),
        "destination_ports": sorted(_get_counter(profile, "ports", "destination_ports").items()),
        "communications": _get_profile_section(profile, "communications"),
        "network_discovery": _get_profile_section(profile, "network_discovery"),
    }
    serialized = json.dumps(
        payload, ensure_ascii=False, sort_keys=True,
        default=str, separators=(",", ":"),
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _is_common_service_name(service):
    """Indique si le service est courant et ne doit pas être signalé comme nouveau."""
    return str(service or "").strip().upper() in COMMON_SERVICE_NAMES


def _observation_persistence_key(observation):
    """Clé stable d'une observation, indépendante de ses compteurs."""
    evidence = observation.get("evidence") or {}
    for field in ("service", "protocol", "destination", "destination_port", "field", "port"):
        if evidence.get(field) is not None:
            return str(observation.get("type", "observation")), field, str(evidence[field])
    return str(observation.get("type", "observation")), "title", str(observation.get("title", ""))


# ============================================================
# CONSTRUCTION DES OBSERVATIONS
# ============================================================

def _build_observation(
    observation_type,
    severity,
    title,
    observed_fact,
    interpretation,
    hypothesis,
    evidence=None,
):
    """
    Construit une observation INPA standardisée.

    Chaque observation respecte :

        FAIT OBSERVÉ
        INTERPRÉTATION
        HYPOTHÈSE
    """

    return {
        "type": observation_type,
        "severity": severity,
        "title": title,
        "observed_fact": observed_fact,
        "interpretation": interpretation,
        "hypothesis": hypothesis,
        "evidence": evidence or {},
    }


# ============================================================
# BASELINE MANAGER
# ============================================================

class BaselineManager:
    """
    Gestionnaire de la baseline comportementale d'INPA.

    La baseline est conservée dans un fichier JSON local afin qu'un
    redémarrage de FastAPI ou un rechargement du code ne la supprime pas.

    IMPORTANT :
    Une baseline ne signifie jamais que le réseau est sécurisé.
    Elle sert uniquement de référence pour comparer le trafic observé.
    """

    def __init__(self, storage_path=None):
        self._baseline = None
        self._generation = 0
        # Par défaut, le fichier est créé à côté de ce module.
        self._storage_path = Path(
            storage_path or (Path(__file__).resolve().with_name("baseline_data.json"))
        )
        self._load_from_disk()

    @property
    def generation(self):
        """Version incrémentée à chaque création ou suppression de baseline."""
        return self._generation

    def _load_from_disk(self):
        """Recharge la baseline si un fichier valide existe."""
        try:
            if not self._storage_path.is_file():
                return
            with self._storage_path.open("r", encoding="utf-8") as file:
                saved = json.load(file)
            if not isinstance(saved, dict):
                return
            profile = saved.get("profile")
            if isinstance(profile, dict) and profile:
                self._baseline = self._copy_profile(profile)
                self._generation = _safe_int(saved.get("generation"), 1)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            # Ne pas empêcher INPA de démarrer si le fichier est illisible.
            self._baseline = None
            self._generation = 0

    def _save_to_disk(self):
        """Écrit la baseline de façon atomique pour limiter les fichiers incomplets."""
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self._storage_path.with_suffix(
            self._storage_path.suffix + ".tmp"
        )
        payload = {
            "generation": self._generation,
            "profile": self._baseline,
        }
        with temporary_path.open("w", encoding="utf-8") as file:
            json.dump(payload, file, ensure_ascii=False, indent=2, default=str)
        temporary_path.replace(self._storage_path)

    def set_baseline(self, profile: dict) -> dict:
        """Enregistre la baseline en mémoire et sur disque."""
        if not isinstance(profile, dict) or not profile:
            raise ValueError("Le profil fourni est vide ou invalide.")

        self._baseline = self._copy_profile(profile)
        self._generation += 1
        self._save_to_disk()
        return self.get_baseline()

    def get_baseline(self):
        """Retourne une copie indépendante de la baseline."""
        if self._baseline is None:
            return None
        return self._copy_profile(self._baseline)

    def clear_baseline(self):
        """Supprime la baseline de la mémoire et du disque."""
        self._baseline = None
        self._generation += 1
        try:
            self._storage_path.unlink(missing_ok=True)
        except OSError:
            # La baseline est au moins supprimée de la mémoire.
            pass

    def exists(self):
        """Vérifie si une baseline existe."""
        return self._baseline is not None

    @staticmethod
    def _copy_profile(profile):
        """Copie profonde du profil."""
        return copy.deepcopy(profile)


baseline_manager = BaselineManager()


# ============================================================
# BASELINE COMPARATOR V4
# ============================================================

class BaselineComparator:
    """
    Compare une fenêtre réseau actuelle avec une baseline.

    V4 conserve les comparaisons V3 et ajoute :

    - persistance entre profils distincts ;
    - déduplication des appels sur un profil identique ;
    - progression minimale de 10 secondes entre fenêtres acceptées ;
    - exclusion des services courants des alertes « nouveau service ».

    V3 ajoutait :

    - comparaison par fréquence ;
    - normalisation par nombre de paquets ;
    - comparaison par seconde ;
    - seuils pour les nouvelles destinations ;
    - seuils pour les nouveaux services ;
    - seuils pour les nouveaux protocoles ;
    - exclusion des ports connus ;
    - exclusion des ports éphémères ;
    - comparaison multicast ;
    - comparaison broadcast ;
    - comparaison des communications ;
    - distinction privé / externe.

    Le système ne conclut jamais automatiquement à une attaque.
    """

    def __init__(self):
        self._baseline_generation = None
        self._last_profile_fingerprint = None
        self._last_accepted_timestamp = None
        self._persistence_streaks = {}

    def reset_persistence(self):
        """Réinitialise l'état de persistance."""
        self._last_profile_fingerprint = None
        self._last_accepted_timestamp = None
        self._persistence_streaks = {}
        self._baseline_generation = getattr(baseline_manager, "generation", None)

    def _apply_persistence(self, observations, current, fingerprint):
        """
        Annote les observations avec leur persistance.

        Un profil identique ne compte jamais deux fois. Avec des horodatages,
        last_seen doit avancer d'au moins 10 secondes pour valider une nouvelle
        fenêtre. Les fenêtres du buffer glissant peuvent se chevaucher : ce
        mécanisme mesure des profils successifs, pas des fenêtres disjointes.
        """
        summary = _get_profile_section(current, "summary")
        current_timestamp = _parse_timestamp(summary.get("last_seen"))
        profile_changed = fingerprint != self._last_profile_fingerprint
        accepted_window = False

        if profile_changed:
            # La première fenêtre peut être acceptée sans comparaison temporelle.
            # Ensuite, une fenêtre n'est acceptée que si son horodatage existe
            # et avance d'au moins le délai minimal. Un horodatage manquant ne
            # doit pas permettre de contourner la confirmation temporelle.
            if self._last_profile_fingerprint is None:
                accepted_window = True
            elif current_timestamp is not None and self._last_accepted_timestamp is not None:
                try:
                    advance = (
                        current_timestamp - self._last_accepted_timestamp
                    ).total_seconds()
                    accepted_window = advance >= PERSISTENCE_MIN_ADVANCE_SECONDS
                except TypeError:
                    accepted_window = False
            else:
                accepted_window = False
        current_keys = {_observation_persistence_key(item) for item in observations}

        if accepted_window:
            # N'enregistrer le fingerprint qu'une fois la fenêtre acceptée.
            # Sinon, une fenêtre refusée à t+5s pourrait empêcher le même
            # profil d'être réévalué à t+10s.
            self._last_profile_fingerprint = fingerprint
            new_streaks = {
                key: self._persistence_streaks.get(key, 0) + 1
                for key in current_keys
            }
            # Une observation absente d'une fenêtre acceptée perd sa continuité.
            self._persistence_streaks = new_streaks
            if current_timestamp is not None:
                self._last_accepted_timestamp = current_timestamp
        # Si la fenêtre n'est pas acceptée, les nouvelles observations
        # restent affichables avec un compteur provisoire à 1, mais ne sont
        # pas mémorisées comme une fenêtre confirmée.
        for observation in observations:
            key = _observation_persistence_key(observation)
            windows = self._persistence_streaks.get(key, 1)
            evidence = observation.setdefault("evidence", {})
            evidence["persistence_windows"] = windows
            evidence["persistence_confirmed"] = windows >= 2
            evidence["persistence_window_accepted"] = accepted_window
            evidence["persistence_min_advance_seconds"] = PERSISTENCE_MIN_ADVANCE_SECONDS
            if windows >= 3:
                observation["persistence_assessment"] = (
                    "Comportement observé sur au moins trois fenêtres acceptées."
                )
            elif windows == 2:
                observation["persistence_assessment"] = (
                    "Comportement réobservé sur une deuxième fenêtre acceptée."
                )
            elif not accepted_window:
                observation["persistence_assessment"] = (
                    "Signal observé, mais cette fenêtre n'est pas assez espacée "
                    "pour confirmer sa persistance."
                )
            else:
                observation["persistence_assessment"] = (
                    "Signal observé sur une première fenêtre acceptée."
                )

            # L'importance reste distincte de la sévérité d'origine :
            # elle combine persistance et contexte sans déclarer une attaque.
            destination = evidence.get("destination")
            external_destination = _is_external_ip(destination)
            port_value = evidence.get("destination_port", evidence.get("port"))
            unusual_port = (
                port_value is not None
                and not _is_common_service_port(port_value)
                and not _is_ephemeral_port(port_value)
            )
            severity = str(observation.get("severity", "LOW")).upper()

            if severity == "HIGH":
                importance = "ÉLEVÉE"
            elif severity == "MEDIUM":
                importance = "MOYENNE"
            elif windows >= 3 and (external_destination or unusual_port):
                importance = "MOYENNE"
            elif windows >= 2 and (external_destination or unusual_port):
                importance = "À EXAMINER"
            elif severity == "INFO":
                importance = "INFORMATION"
            else:
                importance = "FAIBLE"

            observation["contextual_importance"] = importance
            evidence["external_destination"] = external_destination
            evidence["nonstandard_destination_port"] = unusual_port

        return accepted_window

    def compare(
        self,
        baseline,
        current,
    ):
        """
        Compare baseline et profil courant.
        """

        if not baseline:
            return {
                "available": False,
                "message": (
                    "Aucune baseline disponible."
                ),
                "observations": [],
            }

        if not current:
            return {
                "available": False,
                "message": (
                    "Aucun profil courant disponible."
                ),
                "observations": [],
            }

        current_generation = getattr(baseline_manager, "generation", None)
        if current_generation != self._baseline_generation:
            self.reset_persistence()
            self._baseline_generation = current_generation

        observations = []

        # ----------------------------------------------------
        # Protocoles
        # ----------------------------------------------------

        observations.extend(
            self._compare_protocols(
                baseline,
                current,
            )
        )

        # ----------------------------------------------------
        # Services
        # ----------------------------------------------------

        observations.extend(
            self._compare_services(
                baseline,
                current,
            )
        )

        # ----------------------------------------------------
        # Destinations
        # ----------------------------------------------------

        observations.extend(
            self._compare_destinations(
                baseline,
                current,
            )
        )

        # ----------------------------------------------------
        # Ports
        # ----------------------------------------------------

        observations.extend(
            self._compare_ports(
                baseline,
                current,
            )
        )

        # ----------------------------------------------------
        # Communications
        # ----------------------------------------------------

        observations.extend(
            self._compare_communications(
                baseline,
                current,
            )
        )

        # ----------------------------------------------------
        # Multicast
        # ----------------------------------------------------

        observations.extend(
            self._compare_multicast(
                baseline,
                current,
            )
        )

        # ----------------------------------------------------
        # Broadcast
        # ----------------------------------------------------

        observations.extend(
            self._compare_broadcast(
                baseline,
                current,
            )
        )

        current_fingerprint = _profile_fingerprint(current)
        window_fingerprint_changed = (
            current_fingerprint != self._last_profile_fingerprint
        )
       
        window_accepted = self._apply_persistence(
            observations,
            current,
            current_fingerprint,
        )

        # Sur un réseau partagé, une nouvelle destination peut être
        # légitime. On attend une deuxième fenêtre acceptée avant
        # de l'afficher comme observation.
        provisional_observation_count = sum(
            1
            for item in observations
            if item.get("type") == "new_destination"
            and not (
                item.get("evidence") or {}
            ).get("persistence_confirmed", False)
        )

        # Garder uniquement les nouvelles destinations confirmées.
        # Le suivi de persistance a déjà été mis à jour ci-dessus.
        observations = [
            item
            for item in observations
            if item.get("type") != "new_destination"
            or (
                item.get("evidence") or {}
            ).get("persistence_confirmed", False)
        ]

        return {
            "available": True,
            "observation_count": len(observations),
            "observations": observations,
            "persistence": {
                "window_fingerprint_changed": window_fingerprint_changed,
                "window_accepted": window_accepted,
                "minimum_advance_seconds": PERSISTENCE_MIN_ADVANCE_SECONDS,
                "provisional_destination_observations_suppressed": (
                    provisional_observation_count
                ),
                "note": (
                    "Les nouvelles destinations sont affichées après "
                    "confirmation sur au moins deux fenêtres acceptées. "
                    "Les profils successifs peuvent se chevaucher car "
                    "le buffer de capture est glissant."
                ),
            },
        }


    # ========================================================
    # PROTOCOLES
    # ========================================================

    def _compare_protocols(
        self,
        baseline,
        current,
    ):
        observations = []

        baseline_counts = _get_counter(
            baseline,
            "protocols",
            "distribution",
        )

        current_counts = _get_counter(
            current,
            "protocols",
            "distribution",
        )

        baseline_packets = _get_packet_count(
            baseline
        )

        current_packets = _get_packet_count(
            current
        )

        for protocol, current_count in current_counts.items():

            # Ignorer les versions IP : ce sont des catégories
            # de couche réseau, pas de nouveaux protocoles applicatifs.
            normalized_protocol = str(protocol or "").strip().upper()
            if normalized_protocol in {
                "IPV4",
                "IPV6",
                "IP",
                "ETHERNET",
                "UNKNOWN",
                "INCONNU",
                "NONE",
                "NULL",
                "",
            }:
                # Les couches IP et les valeurs inconnues ne sont pas
                # des protocoles applicatifs nouveaux à elles seules.
                continue

            baseline_count = baseline_counts.get(
                protocol,
                0,
            )



            current_rate = _get_normalized_rate(
                current_count,
                current_packets,
            )

            baseline_rate = _get_normalized_rate(
                baseline_count,
                baseline_packets,
            )

            # Nouveau protocole réellement présent.
            if (
                baseline_count == 0
                and current_count
                >= MIN_NEW_PROTOCOL_COUNT
            ):

                observations.append(
                    _build_observation(
                        observation_type="new_protocol",
                        severity="LOW",
                        title="Nouveau protocole observé",
                        observed_fact=(
                            f"Le protocole {protocol} "
                            f"a été observé {current_count} fois "
                            "dans la fenêtre courante alors "
                            "qu'il n'était pas présent "
                            "dans la baseline."
                        ),
                        interpretation=(
                            "Le trafic actuel contient un "
                            "protocole qui n'apparaissait "
                            "pas dans la référence."
                        ),
                        hypothesis=(
                            "Cela peut correspondre à une "
                            "nouvelle application, un nouvel "
                            "équipement ou une évolution "
                            "normale du trafic réseau."
                        ),
                        evidence={
                            "protocol": protocol,
                            "current_count": current_count,
                            "baseline_count": baseline_count,
                            "current_rate": round(
                                current_rate,
                                6,
                            ),
                        },
                    )
                )

                continue

            # ------------------------------------------------
            # Variation importante de fréquence.
            # ------------------------------------------------

            if (
                baseline_rate > 0
                and current_rate
                >= baseline_rate
                * SIGNIFICANT_RATIO
                and (
                    current_rate
                    - baseline_rate
                )
                >= MIN_PERCENTAGE_POINT_CHANGE
            ):

                ratio = (
                    current_rate
                    / baseline_rate
                )

                observations.append(
                    _build_observation(
                        observation_type=(
                            "protocol_frequency_increase"
                        ),
                        severity="LOW",
                        title=(
                            "Augmentation de fréquence "
                            "d'un protocole"
                        ),
                        observed_fact=(
                            f"Le protocole {protocol} "
                            f"représente environ "
                            f"{current_rate * 100:.2f}% "
                            "du trafic courant contre "
                            f"{baseline_rate * 100:.2f}% "
                            "dans la baseline."
                        ),
                        interpretation=(
                            "La proportion de ce protocole "
                            "est nettement supérieure à "
                            "celle observée dans la référence."
                        ),
                        hypothesis=(
                            "Cette variation peut correspondre "
                            "à une utilisation plus importante "
                            "d'une application ou à une "
                            "évolution temporaire du trafic."
                        ),
                        evidence={
                            "protocol": protocol,
                            "baseline_count": baseline_count,
                            "current_count": current_count,
                            "baseline_rate": round(
                                baseline_rate,
                                6,
                            ),
                            "current_rate": round(
                                current_rate,
                                6,
                            ),
                            "ratio": round(
                                ratio,
                                2,
                            ),
                        },
                    )
                )

        return observations

    # ========================================================
    # SERVICES
    # ========================================================

    def _compare_services(
        self,
        baseline,
        current,
    ):
        observations = []

        baseline_counts = _get_counter(
            baseline,
            "services",
            "distribution",
        )

        current_counts = _get_counter(
            current,
            "services",
            "distribution",
        )

        baseline_packets = _get_packet_count(
            baseline
        )

        current_packets = _get_packet_count(
            current
        )

        for service, current_count in (
            current_counts.items()
        ):

            # Un service non identifié ne constitue pas un service réseau
            # dont la fréquence peut être comparée à la baseline.
            if str(service or "").strip().upper() in {
                "UNKNOWN", "INCONNU", "NONE", "NULL", ""
            }:
                continue

            baseline_count = baseline_counts.get(
                service,
                0,
            )

            current_rate = _get_normalized_rate(
                current_count,
                current_packets,
            )

            baseline_rate = _get_normalized_rate(
                baseline_count,
                baseline_packets,
            )

            # Nouveau service.
            if (
                baseline_count == 0
                and current_count
                >= MIN_NEW_SERVICE_COUNT
                and not _is_common_service_name(service)
            ):

                observations.append(
                    _build_observation(
                        observation_type="new_service",
                        severity="LOW",
                        title="Nouveau service probable",
                        observed_fact=(
                            f"Le service probable {service} "
                            f"a été observé {current_count} fois "
                            "dans la fenêtre courante alors "
                            "qu'il n'était pas présent "
                            "dans la baseline."
                        ),
                        interpretation=(
                            "Un service réseau différent "
                            "de ceux observés dans la "
                            "référence apparaît de manière "
                            "répétée."
                        ),
                        hypothesis=(
                            "Cela peut correspondre à une "
                            "nouvelle application, un nouveau "
                            "serveur ou une modification "
                            "normale de configuration."
                        ),
                        evidence={
                            "service": service,
                            "baseline_count": baseline_count,
                            "current_count": current_count,
                            "current_rate": round(
                                current_rate,
                                6,
                            ),
                        },
                    )
                )

                continue

            # Augmentation importante.
            if (
                baseline_rate > 0
                and current_rate
                >= baseline_rate
                * SIGNIFICANT_RATIO
                and (
                    current_rate
                    - baseline_rate
                )
                >= MIN_PERCENTAGE_POINT_CHANGE
            ):

                ratio = (
                    current_rate
                    / baseline_rate
                )

                observations.append(
                    _build_observation(
                        observation_type=(
                            "service_frequency_increase"
                        ),
                        severity="LOW",
                        title=(
                            "Augmentation de fréquence "
                            "d'un service"
                        ),
                        observed_fact=(
                            f"Le service {service} "
                            f"représente environ "
                            f"{current_rate * 100:.2f}% "
                            "du trafic courant contre "
                            f"{baseline_rate * 100:.2f}% "
                            "dans la baseline."
                        ),
                        interpretation=(
                            "L'activité associée à ce service "
                            "est nettement supérieure à "
                            "la référence."
                        ),
                        hypothesis=(
                            "Cela peut correspondre à une "
                            "utilisation plus importante "
                            "d'une application ou à une "
                            "activité réseau temporaire."
                        ),
                        evidence={
                            "service": service,
                            "baseline_count": baseline_count,
                            "current_count": current_count,
                            "baseline_rate": round(
                                baseline_rate,
                                6,
                            ),
                            "current_rate": round(
                                current_rate,
                                6,
                            ),
                            "ratio": round(
                                ratio,
                                2,
                            ),
                        },
                    )
                )

        return observations

    # ========================================================
    # DESTINATIONS
    # ========================================================

    def _compare_destinations(
        self,
        baseline,
        current,
    ):
        observations = []

        baseline_counts = _get_counter(
            baseline,
            "devices",
            "destinations",
        )

        current_counts = _get_counter(
            current,
            "devices",
            "destinations",
        )

        current_packets = _get_packet_count(
            current
        )

        for destination, current_count in (
            current_counts.items()
        ):

            if not _is_valid_ip(
                destination
            ):
                continue

            # Le multicast est évalué séparément et ne doit pas créer
            # de fausses alertes de nouvelle destination (ex. ff02::1).
            if _is_multicast_ip(destination):
                continue

            # Les adresses link-local ne sont valables que sur le lien local.
            # Leur apparition seule ne doit pas être traitée comme une nouvelle
            # destination réseau classique.
            if _is_link_local_ip(destination):
                continue

            baseline_count = baseline_counts.get(
                destination,
                0,
            )

            # Une destination nouvelle doit être
            # suffisamment répétée.
            if (
                baseline_count == 0
                and current_count
                < MIN_NEW_DESTINATION_COUNT
            ):
                continue

            # ------------------------------------------------
            # Nouvelle destination.
            # ------------------------------------------------

            if baseline_count == 0:

                current_rate = _get_normalized_rate(
                    current_count,
                    current_packets,
                )

                if _is_private_ip(destination):
                    context = "destination privée"
                    hypothesis = (
                        "Cela peut correspondre à un nouvel équipement, "
                        "un service local, une imprimante, un routeur ou "
                        "une autre activité du réseau privé."
                    )
                elif _is_external_ip(destination):
                    context = "destination externe globalement routable"
                    hypothesis = (
                        "Cela peut correspondre à un nouveau service Internet, "
                        "une navigation, une mise à jour ou une autre activité légitime."
                    )
                elif _is_link_local_ip(destination):
                    context = "destination link-local"
                    hypothesis = (
                        "Cela peut correspondre à une communication locale au lien, "
                        "à la découverte de voisins ou à un service réseau local."
                    )
                else:
                    context = "destination spéciale ou non globalement routable"
                    hypothesis = (
                        "Cette adresse n'est pas globalement routable. Vérifier son "
                        "rôle réseau avant de tirer une conclusion sur cette observation."
                    )

                observations.append(
                    _build_observation(
                        observation_type="new_destination",
                        severity="LOW",
                        title="Nouvelle destination observée",
                        observed_fact=(
                            f"La destination {destination} "
                            f"a été observée {current_count} fois "
                            "dans la fenêtre courante alors "
                            "qu'elle n'était pas présente "
                            "dans la baseline."
                        ),
                        interpretation=(
                            f"Une communication répétée vers "
                            f"une {context} non observée dans "
                            "la référence est présente."
                        ),
                        hypothesis=hypothesis,
                        evidence={
                            "destination": destination,
                            "current_count": current_count,
                            "baseline_count": baseline_count,
                            "current_rate": round(
                                current_rate,
                                6,
                            ),
                            "is_private": (
                                _is_private_ip(
                                    destination
                                )
                            ),
                        },
                    )
                )

                continue

            # ------------------------------------------------
            # Destination connue mais beaucoup plus fréquente.
            # ------------------------------------------------

            baseline_packets = _get_packet_count(
                baseline
            )

            baseline_rate = _get_normalized_rate(
                baseline_count,
                baseline_packets,
            )

            current_rate = _get_normalized_rate(
                current_count,
                current_packets,
            )

            if (
                baseline_rate > 0
                and current_rate
                >= baseline_rate
                * SIGNIFICANT_RATIO
                and (
                    current_rate
                    - baseline_rate
                )
                >= MIN_PERCENTAGE_POINT_CHANGE
            ):

                ratio = (
                    current_rate
                    / baseline_rate
                )

                observations.append(
                    _build_observation(
                        observation_type=(
                            "destination_frequency_increase"
                        ),
                        severity="LOW",
                        title=(
                            "Augmentation d'une destination"
                        ),
                        observed_fact=(
                            f"La destination {destination} "
                            f"représente environ "
                            f"{current_rate * 100:.2f}% "
                            "du trafic courant contre "
                            f"{baseline_rate * 100:.2f}% "
                            "dans la baseline."
                        ),
                        interpretation=(
                            "Cette destination occupe une "
                            "part nettement plus importante "
                            "du trafic que dans la référence."
                        ),
                        hypothesis=(
                            "Cela peut correspondre à une "
                            "augmentation normale d'utilisation "
                            "d'un service ou à une activité "
                            "réseau temporaire."
                        ),
                        evidence={
                            "destination": destination,
                            "baseline_count": baseline_count,
                            "current_count": current_count,
                            "baseline_rate": round(
                                baseline_rate,
                                6,
                            ),
                            "current_rate": round(
                                current_rate,
                                6,
                            ),
                            "ratio": round(
                                ratio,
                                2,
                            ),
                            "is_private": (
                                _is_private_ip(
                                    destination
                                )
                            ),
                        },
                    )
                )

        return observations

    # ========================================================
    # PORTS
    # ========================================================

    def _compare_ports(
        self,
        baseline,
        current,
    ):
        observations = []

        baseline_counts = _get_counter(
            baseline,
            "ports",
            "destination_ports",
        )
        # Normaliser explicitement les clés en chaînes : certains profils
        # peuvent fournir des ports sous forme d'entiers, d'autres en texte.
        baseline_counts = Counter({str(key): value for key, value in baseline_counts.items()})

        current_counts = _get_counter(
            current,
            "ports",
            "destination_ports",
        )
        current_counts = Counter({str(key): value for key, value in current_counts.items()})

        for port, current_count in (
            current_counts.items()
        ):

            port_number = _safe_int(
                port
            )

            # Ports éphémères ignorés.
            if _is_ephemeral_port(
                port_number
            ):
                continue

            # Ports connus ignorés comme "nouveaux".
            if _is_common_service_port(
                port_number
            ):
                continue

            baseline_count = baseline_counts.get(
                str(port),
                0,
            )

            # Nouveau port non standard.
            if (
                baseline_count == 0
                and current_count
                >= MIN_NEW_PORT_COUNT
            ):

                observations.append(
                    _build_observation(
                        observation_type=(
                            "new_destination_port"
                        ),
                        severity="MEDIUM",
                        title="Nouveau port de destination",
                        observed_fact=(
                            f"Le port de destination "
                            f"{port_number} a été observé "
                            f"{current_count} fois dans la "
                            "fenêtre courante alors qu'il "
                            "n'était pas présent dans la baseline."
                        ),
                        interpretation=(
                            "Une communication répétée utilise "
                            "un port non standard qui n'apparaissait "
                            "pas dans la référence."
                        ),
                        hypothesis=(
                            "Cela peut correspondre à un nouveau "
                            "service ou à une application différente. "
                            "Ce résultat ne constitue pas une preuve "
                            "d'activité malveillante."
                        ),
                        evidence={
                            "destination_port": port_number,
                            "current_count": current_count,
                            "baseline_count": baseline_count,
                        },
                    )
                )

        return observations

    # ========================================================
    # COMMUNICATIONS
    # ========================================================

    def _compare_communications(
        self,
        baseline,
        current,
    ):
        observations = []

        baseline_comm = _get_profile_section(
            baseline,
            "communications",
        )

        current_comm = _get_profile_section(
            current,
            "communications",
        )

        fields = (
            (
                "private_to_private",
                "Communications internes",
            ),
            (
                "private_to_external",
                "Communications vers l'extérieur",
            ),
            (
                "external_to_private",
                "Communications externes vers le réseau privé",
            ),
        )

        baseline_packets = _get_packet_count(
            baseline
        )

        current_packets = _get_packet_count(
            current
        )

        for field, label in fields:

            baseline_count = _safe_int(
                baseline_comm.get(
                    field,
                    0,
                )
            )

            current_count = _safe_int(
                current_comm.get(
                    field,
                    0,
                )
            )

            baseline_rate = _get_normalized_rate(
                baseline_count,
                baseline_packets,
            )

            current_rate = _get_normalized_rate(
                current_count,
                current_packets,
            )

            # Nouveau type de communication.
            if (
                baseline_count == 0
                and current_count
                >= MIN_NEW_DESTINATION_COUNT
            ):

                observations.append(
                    _build_observation(
                        observation_type=(
                            "communication_pattern_change"
                        ),
                        severity="LOW",
                        title=(
                            f"Nouveau profil : {label}"
                        ),
                        observed_fact=(
                            f"{label} : "
                            f"{current_count} paquets "
                            "dans la fenêtre courante "
                            "contre 0 dans la baseline."
                        ),
                        interpretation=(
                            "Un type de communication absent "
                            "de la référence apparaît de "
                            "manière répétée."
                        ),
                        hypothesis=(
                            "Cela peut correspondre à une nouvelle "
                            "activité réseau légitime, à un nouvel "
                            "équipement ou à une modification "
                            "de configuration."
                        ),
                        evidence={
                            "field": field,
                            "baseline_count": baseline_count,
                            "current_count": current_count,
                            "current_rate": round(
                                current_rate,
                                6,
                            ),
                        },
                    )
                )

                continue

            # Variation importante.
            if (
                baseline_rate > 0
                and current_rate
                >= baseline_rate
                * SIGNIFICANT_RATIO
                and (
                    current_rate
                    - baseline_rate
                )
                >= MIN_PERCENTAGE_POINT_CHANGE
            ):

                ratio = (
                    current_rate
                    / baseline_rate
                )

                observations.append(
                    _build_observation(
                        observation_type=(
                            "communication_frequency_increase"
                        ),
                        severity="LOW",
                        title=(
                            f"Augmentation : {label}"
                        ),
                        observed_fact=(
                            f"{label} représente environ "
                            f"{current_rate * 100:.2f}% "
                            "du trafic courant contre "
                            f"{baseline_rate * 100:.2f}% "
                            "dans la baseline."
                        ),
                        interpretation=(
                            "La proportion de ce type de "
                            "communication est nettement "
                            "supérieure à la référence."
                        ),
                        hypothesis=(
                            "Cela peut correspondre à une "
                            "augmentation temporaire de "
                            "l'activité réseau ou à une "
                            "évolution normale des usages."
                        ),
                        evidence={
                            "field": field,
                            "baseline_count": baseline_count,
                            "current_count": current_count,
                            "baseline_rate": round(
                                baseline_rate,
                                6,
                            ),
                            "current_rate": round(
                                current_rate,
                                6,
                            ),
                            "ratio": round(
                                ratio,
                                2,
                            ),
                        },
                    )
                )

        return observations

    # ========================================================
    # MULTICAST
    # ========================================================

    def _compare_multicast(
        self,
        baseline,
        current,
    ):
        observations = []

        baseline_network = _get_profile_section(
            baseline,
            "network_discovery",
        )

        current_network = _get_profile_section(
            current,
            "network_discovery",
        )

        baseline_count = _safe_int(
            baseline_network.get(
                "multicast_packets",
                0,
            )
        )

        current_count = _safe_int(
            current_network.get(
                "multicast_packets",
                0,
            )
        )

        baseline_packets = _get_packet_count(
            baseline
        )

        current_packets = _get_packet_count(
            current
        )

        baseline_rate = _get_normalized_rate(
            baseline_count,
            baseline_packets,
        )

        current_rate = _get_normalized_rate(
            current_count,
            current_packets,
        )

        # ----------------------------------------------------
        # Nouvelle activité multicast.
        # ----------------------------------------------------

        if (
            baseline_count == 0
            and current_count >= MIN_NEW_DESTINATION_COUNT
        ):

            observations.append(
                _build_observation(
                    observation_type=(
                        "multicast_activity_change"
                    ),
                    severity="INFO",
                    title="Nouvelle activité multicast",
                    observed_fact=(
                        f"{current_count} paquets multicast "
                        "ont été observés alors qu'aucun "
                        "paquet multicast n'était présent "
                        "dans la baseline."
                    ),
                    interpretation=(
                        "Le trafic multicast actuel "
                        "diffère de la référence."
                    ),
                    hypothesis=(
                        "Cela peut correspondre à mDNS, "
                        "SSDP/UPnP, à la découverte de services, "
                        "à l'apparition d'appareils ou à d'autres "
                        "mécanismes réseau légitimes."
                    ),
                    evidence={
                        "baseline_count": baseline_count,
                        "current_count": current_count,
                        "current_rate": round(
                            current_rate,
                            6,
                        ),
                    },
                )
            )

            return observations

        # ----------------------------------------------------
        # Forte augmentation.
        # ----------------------------------------------------

        if (
            baseline_rate > 0
            and current_rate
            >= baseline_rate
            * SIGNIFICANT_RATIO
            and (
                current_rate
                - baseline_rate
            )
            >= MIN_PERCENTAGE_POINT_CHANGE
        ):

            ratio = (
                current_rate
                / baseline_rate
            )

            observations.append(
                _build_observation(
                    observation_type=(
                        "multicast_activity_increase"
                    ),
                    severity="LOW",
                    title=(
                        "Augmentation de l'activité multicast"
                    ),
                    observed_fact=(
                        f"L'activité multicast représente "
                        f"{current_rate * 100:.2f}% "
                        "du trafic courant contre "
                        f"{baseline_rate * 100:.2f}% "
                        "dans la baseline."
                    ),
                    interpretation=(
                        "La proportion de trafic multicast "
                        "est nettement supérieure à la référence."
                    ),
                    hypothesis=(
                        "Cela peut être lié à une phase de "
                        "découverte de services, à l'apparition "
                        "d'appareils, à mDNS, SSDP/UPnP ou à "
                        "une activité réseau légitime plus importante."
                    ),
                    evidence={
                        "baseline_count": baseline_count,
                        "current_count": current_count,
                        "baseline_rate": round(
                            baseline_rate,
                            6,
                        ),
                        "current_rate": round(
                            current_rate,
                            6,
                        ),
                        "ratio": round(
                            ratio,
                            2,
                        ),
                    },
                )
            )

        return observations

    # ========================================================
    # BROADCAST
    # ========================================================

    def _compare_broadcast(
        self,
        baseline,
        current,
    ):
        observations = []

        baseline_network = _get_profile_section(
            baseline,
            "network_discovery",
        )

        current_network = _get_profile_section(
            current,
            "network_discovery",
        )

        baseline_count = _safe_int(
            baseline_network.get(
                "broadcast_packets",
                0,
            )
        )

        current_count = _safe_int(
            current_network.get(
                "broadcast_packets",
                0,
            )
        )

        baseline_packets = _get_packet_count(
            baseline
        )

        current_packets = _get_packet_count(
            current
        )

        baseline_rate = _get_normalized_rate(
            baseline_count,
            baseline_packets,
        )

        current_rate = _get_normalized_rate(
            current_count,
            current_packets,
        )

        # ----------------------------------------------------
        # Nouvelle activité broadcast.
        # ----------------------------------------------------

        if (
            baseline_count == 0
            and current_count >= MIN_NEW_DESTINATION_COUNT
        ):

            observations.append(
                _build_observation(
                    observation_type=(
                        "broadcast_activity_change"
                    ),
                    severity="INFO",
                    title="Nouvelle activité broadcast",
                    observed_fact=(
                        f"{current_count} paquets broadcast "
                        "ont été observés alors qu'aucun "
                        "paquet broadcast n'était présent "
                        "dans la baseline."
                    ),
                    interpretation=(
                        "Le trafic broadcast actuel "
                        "diffère de la référence."
                    ),
                    hypothesis=(
                        "Cela peut correspondre à ARP, DHCP, "
                        "à la découverte réseau ou à d'autres "
                        "mécanismes normaux du réseau local."
                    ),
                    evidence={
                        "baseline_count": baseline_count,
                        "current_count": current_count,
                        "current_rate": round(
                            current_rate,
                            6,
                        ),
                    },
                )
            )

            return observations

        # ----------------------------------------------------
        # Forte augmentation.
        # ----------------------------------------------------

        if (
            baseline_rate > 0
            and current_rate
            >= baseline_rate
            * SIGNIFICANT_RATIO
            and (
                current_rate
                - baseline_rate
            )
            >= MIN_PERCENTAGE_POINT_CHANGE
        ):

            ratio = (
                current_rate
                / baseline_rate
            )

            observations.append(
                _build_observation(
                    observation_type=(
                        "broadcast_activity_increase"
                    ),
                    severity="LOW",
                    title=(
                        "Augmentation de l'activité broadcast"
                    ),
                    observed_fact=(
                        f"L'activité broadcast représente "
                        f"{current_rate * 100:.2f}% "
                        "du trafic courant contre "
                        f"{baseline_rate * 100:.2f}% "
                        "dans la baseline."
                    ),
                    interpretation=(
                        "La proportion de trafic broadcast "
                        "est nettement supérieure à la référence."
                    ),
                    hypothesis=(
                        "Cela peut être lié à ARP, DHCP, "
                        "à la découverte réseau ou à une "
                        "augmentation temporaire de l'activité "
                        "sur le réseau local."
                    ),
                    evidence={
                        "baseline_count": baseline_count,
                        "current_count": current_count,
                        "baseline_rate": round(
                            baseline_rate,
                            6,
                        ),
                        "current_rate": round(
                            current_rate,
                            6,
                        ),
                        "ratio": round(
                            ratio,
                            2,
                        ),
                    },
                )
            )

        return observations


# ============================================================
# INSTANCE GLOBALE
# ============================================================

baseline_comparator = BaselineComparator()
