"""
Classification réseau INPA.
Distingue les adresses IPv4 privées, IPv6 ULA, IPv6 link-local et multicast.
"""

from ipaddress import ip_address, ip_network

PRIVATE_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
]
IPV6_ULA_NETWORK = ip_network("fc00::/7")
IPV6_LINK_LOCAL_NETWORK = ip_network("fe80::/10")
MULTICAST_NETWORK = ip_network("224.0.0.0/4")
LIMITED_BROADCAST = "255.255.255.255"

SERVICE_RULES = {
    ("TCP", 20): {"service": "FTP-DATA", "confidence": 0.90, "description": "Canal de données FTP probable."},
    ("TCP", 21): {"service": "FTP", "confidence": 0.95, "description": "Service FTP probable."},
    ("TCP", 22): {"service": "SSH", "confidence": 0.95, "description": "Service SSH probable."},
    ("TCP", 23): {"service": "TELNET", "confidence": 0.95, "description": "Service Telnet probable."},
    ("TCP", 25): {"service": "SMTP", "confidence": 0.90, "description": "Service SMTP probable."},
    ("TCP", 53): {"service": "DNS-over-TCP", "confidence": 0.90, "description": "DNS transporté sur TCP probable."},
    ("UDP", 53): {"service": "DNS", "confidence": 0.95, "description": "Service DNS probable."},
    ("TCP", 80): {"service": "HTTP", "confidence": 0.90, "description": "Service HTTP probable."},
    ("TCP", 110): {"service": "POP3", "confidence": 0.90, "description": "Service POP3 probable."},
    ("UDP", 123): {"service": "NTP", "confidence": 0.95, "description": "Service NTP probable."},
    ("TCP", 143): {"service": "IMAP", "confidence": 0.90, "description": "Service IMAP probable."},
    ("TCP", 443): {"service": "HTTPS/TLS", "confidence": 0.85, "description": "Trafic TCP sur le port 443, compatible avec HTTPS/TLS. Le port seul ne confirme pas le protocole applicatif."},
    ("TCP", 445): {"service": "SMB", "confidence": 0.95, "description": "Service SMB probable."},
    ("UDP", 443): {"service": "QUIC/UDP-443", "confidence": 0.80, "description": "Trafic UDP sur le port 443, compatible avec QUIC. Il ne doit pas être classé automatiquement comme HTTPS."},
    ("TCP", 587): {"service": "SMTP-SUBMISSION", "confidence": 0.90, "description": "Soumission SMTP probable."},
    ("TCP", 993): {"service": "IMAPS", "confidence": 0.90, "description": "IMAP sécurisé probable."},
    ("TCP", 995): {"service": "POP3S", "confidence": 0.90, "description": "POP3 sécurisé probable."},
    ("TCP", 1433): {"service": "MSSQL", "confidence": 0.90, "description": "Microsoft SQL Server probable."},
    ("TCP", 3306): {"service": "MYSQL", "confidence": 0.90, "description": "MySQL probable."},
    ("TCP", 3389): {"service": "RDP", "confidence": 0.95, "description": "Remote Desktop Protocol probable."},
    ("TCP", 5432): {"service": "POSTGRESQL", "confidence": 0.90, "description": "PostgreSQL probable."},
    ("TCP", 5900): {"service": "VNC", "confidence": 0.90, "description": "VNC probable."},
    ("UDP", 1900): {"service": "SSDP/UPnP", "confidence": 0.98, "description": "Découverte SSDP/UPnP probable."},
    ("UDP", 5353): {"service": "mDNS", "confidence": 0.98, "description": "Multicast DNS probable."},
    ("TCP", 8009): {"service": "ANDROID-CAST/ALT", "confidence": 0.60, "description": "Port TCP 8009 observé. Un service Android Cast ou un autre service utilisant ce port est possible."},
    ("TCP", 8080): {"service": "HTTP-ALT", "confidence": 0.85, "description": "Service HTTP alternatif probable."},
}


def _is_ipv4(value: str) -> bool:
    """Vérifie si une valeur est une adresse IPv4."""
    try:
        return ip_address(value).version == 4
    except (ValueError, TypeError):
        return False


def _is_ipv6(value: str) -> bool:
    """Vérifie si une valeur est une adresse IPv6."""
    try:
        return ip_address(value).version == 6
    except (ValueError, TypeError):
        return False


def is_private_ip(value: str | None) -> bool:
    """Détecte IPv4 privé et IPv6 ULA (fc00::/7), mais pas link-local."""
    if not value:
        return False
    try:
        address = ip_address(value)
        if address.version == 4:
            return any(address in network for network in PRIVATE_NETWORKS)
        return address.version == 6 and address in IPV6_ULA_NETWORK
    except (ValueError, TypeError):
        return False


def is_link_local_ip(value: str | None) -> bool:
    """Détecte les adresses IPv6 link-local (fe80::/10)."""
    if not value:
        return False
    try:
        address = ip_address(value)
        return address.version == 6 and address in IPV6_LINK_LOCAL_NETWORK
    except (ValueError, TypeError):
        return False


def is_multicast_ip(value: str | None) -> bool:
    """Détermine si une adresse est multicast en IPv4 ou IPv6."""
    if not value:
        return False
    try:
        address = ip_address(value)
        return address in MULTICAST_NETWORK if address.version == 4 else address.is_multicast
    except (ValueError, TypeError):
        return False


def is_broadcast_ip(value: str | None) -> bool:
    """Vérifie l'adresse broadcast IPv4 limitée."""
    return value == LIMITED_BROADCAST


def _valid_port(value) -> int | None:
    """Convertit un port valide en entier."""
    if value is None:
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _get_service_port(packet: dict) -> int | None:
    """Privilégie le port destination, puis le port source."""
    return _valid_port(packet.get("destination_port")) or _valid_port(packet.get("source_port"))


def _get_service_port_and_direction(packet: dict):
    """Retourne le port d'interprétation et sa direction."""
    source_port = _valid_port(packet.get("source_port"))
    destination_port = _valid_port(packet.get("destination_port"))
    protocol = str(packet.get("transport_protocol") or packet.get("protocol") or "UNKNOWN").upper()

    if destination_port is not None and (protocol, destination_port) in SERVICE_RULES:
        return destination_port, "destination"
    if source_port is not None and (protocol, source_port) in SERVICE_RULES:
        return source_port, "source"
    if destination_port is not None:
        return destination_port, "destination"
    if source_port is not None:
        return source_port, "source"
    return None, None


def _infer_service(packet: dict) -> dict:
    """Propose un service probable sans le présenter comme certain."""
    raw_protocol = str(packet.get("transport_protocol") or packet.get("protocol") or "UNKNOWN").upper()
    port, port_direction = _get_service_port_and_direction(packet)

    if raw_protocol == "DNS":
        if port == 5353:
            return {
                "probable_service": "mDNS", "confidence": 0.98,
                "confidence_label": "très élevée",
                "interpretation": "La couche DNS et le port 5353 sont compatibles avec du multicast DNS.",
                "service_port": port, "service_port_direction": port_direction,
            }
        return {
            "probable_service": "DNS", "confidence": 0.98,
            "confidence_label": "très élevée",
            "interpretation": "Une couche DNS a été observée dans le paquet.",
            "service_port": port, "service_port_direction": port_direction,
        }

    rule = SERVICE_RULES.get((raw_protocol, port)) if port is not None else None
    if rule:
        confidence = float(rule["confidence"])
        if confidence >= 0.95:
            label = "très élevée"
        elif confidence >= 0.80:
            label = "élevée"
        elif confidence >= 0.60:
            label = "moyenne"
        else:
            label = "faible"
        return {
            "probable_service": rule["service"], "confidence": confidence,
            "confidence_label": label, "interpretation": rule["description"],
            "service_port": port, "service_port_direction": port_direction,
        }

    return {
        "probable_service": "INCONNU", "confidence": 0.0,
        "confidence_label": "aucune",
        "interpretation": "Aucun service suffisamment identifiable à partir des informations actuellement disponibles.",
        "service_port": port, "service_port_direction": port_direction,
    }


def classify_packet(packet: dict) -> dict:
    """Classe un paquet sans produire de verdict de sécurité."""
    source = packet.get("source")
    destination = packet.get("destination")
    protocol = str(packet.get("transport_protocol") or packet.get("protocol") or "UNKNOWN").upper()
    source_port = packet.get("source_port")
    destination_port = packet.get("destination_port")
    classifications = []

    multicast = is_multicast_ip(destination)
    broadcast = is_broadcast_ip(destination)
    source_private = is_private_ip(source)
    destination_private = is_private_ip(destination)
    source_link_local = is_link_local_ip(source)
    destination_link_local = is_link_local_ip(destination)

    if multicast:
        classifications.append("MULTICAST")
    if broadcast:
        classifications.append("BROADCAST")
    if source_private:
        classifications.append("SOURCE_PRIVATE")
    if destination_private:
        classifications.append("DESTINATION_PRIVATE")
    if source_link_local:
        classifications.append("SOURCE_LINK_LOCAL")
    if destination_link_local:
        classifications.append("DESTINATION_LINK_LOCAL")

    source_local = source_private or source_link_local
    destination_local = destination_private or destination_link_local

    if (
        source and destination and source_private and not destination_local
        and not multicast and not broadcast
    ):
        classifications.append("SORTIE_RESEAU_PRIVE")

    if (
        source and destination and not source_local and destination_private
        and not multicast and not broadcast
    ):
        classifications.append("ENTREE_RESEAU_PRIVE")

    if protocol == "TCP":
        classifications.append("TCP")
    elif protocol == "UDP":
        classifications.append("UDP")
    elif protocol == "DNS":
        classifications.append("DNS")

    service = _infer_service(packet)
    probable_service = service["probable_service"]
    if probable_service != "INCONNU":
        service_tag = probable_service.upper().replace("/", "_").replace("-", "_")
        classifications.append(f"SERVICE_{service_tag}")

    observed = {
        "source": source, "destination": destination, "protocol": protocol,
        "source_port": source_port, "destination_port": destination_port,
    }

    return {
        "observed": observed,
        "observed_protocol": protocol,
        "probable_service": probable_service,
        "confidence": service["confidence"],
        "confidence_label": service["confidence_label"],
        "interpretation": service["interpretation"],
        "service_port": service["service_port"],
        "service_port_direction": service["service_port_direction"],
        "classifications": sorted(set(classifications)),
        "is_private_source": source_private,
        "is_private_destination": destination_private,
        "is_multicast": multicast,
        "is_broadcast": broadcast,
        "is_link_local": source_link_local or destination_link_local,
    }
