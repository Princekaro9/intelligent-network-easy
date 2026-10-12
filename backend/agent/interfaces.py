from scapy.all import conf, get_if_list
import psutil
import re


def _extract_guid(value: str | None) -> str | None:
    """
    Extrait le GUID Windows d'une interface réseau.
    """

    if not value:
        return None

    match = re.search(
        r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}",
        value,
    )

    if match:
        return match.group(0).lower()

    return None


def _find_npcap_device(guid: str | None) -> str | None:
    """
    Recherche le périphérique Npcap correspondant au GUID Windows.
    """

    if not guid:
        return None

    guid = guid.lower()

    for device in get_if_list():

        if guid in device.lower():
            return device

    return None


def _find_scapy_interface(
    windows_name: str | None,
    description: str | None,
    guid: str | None,
):
    """
    Recherche l'interface réellement utilisable par Scapy.

    Dans ton environnement Scapy utilise par exemple :

        Wi-Fi

    tandis que la description matérielle est :

        Intel(R) Wi-Fi 6 AX201 160MHz

    et Npcap utilise :

        \\Device\\NPF_{GUID}
    """

    windows_name = (windows_name or "").strip()
    description = (description or "").strip()
    guid = (guid or "").lower()

    # =========================================================
    # 1. Correspondance exacte avec le nom Windows
    # =========================================================

    if windows_name:

        try:

            interface = conf.ifaces.dev_from_name(
                windows_name
            )

            if interface:
                return interface

        except Exception:
            pass

    # =========================================================
    # 2. Correspondance avec la description
    # =========================================================

    if description:

        try:

            interface = conf.ifaces.dev_from_name(
                description
            )

            if interface:
                return interface

        except Exception:
            pass

    # =========================================================
    # 3. Recherche dans les interfaces Scapy
    # =========================================================

    for interface in conf.ifaces.values():

        name = str(
            getattr(interface, "name", "") or ""
        )

        iface_description = str(
            getattr(interface, "description", "") or ""
        )

        dev = str(
            getattr(interface, "dev", "") or ""
        )

        # Nom Windows
        if windows_name:

            if name.lower() == windows_name.lower():
                return interface

        # Description
        if description:

            if iface_description.lower() == description.lower():
                return interface

            if description.lower() in name.lower():
                return interface

            if description.lower() in iface_description.lower():
                return interface

        # GUID
        if guid:

            if guid in name.lower():
                return interface

            if guid in iface_description.lower():
                return interface

            if guid in dev.lower():
                return interface

    return None


def get_interfaces():
    """
    Retourne les interfaces réseau disponibles.

    Chaque interface contient :

    - nom Windows
    - description
    - GUID
    - type
    - IPv4
    - IPv6
    - MAC
    - état
    - vitesse
    - disponibilité capture
    - périphérique Npcap
    - nom utilisable par Scapy
    """

    interfaces = []

    psutil_interfaces = psutil.net_if_addrs()
    psutil_stats = psutil.net_if_stats()

    # =========================================================
    # Interfaces réseau Windows
    # =========================================================

    for index, (name, addresses) in enumerate(
        psutil_interfaces.items(),
        start=1,
    ):

        stats = psutil_stats.get(name)

        ipv4 = []
        ipv6 = []
        mac = None

        # =====================================================
        # Adresses
        # =====================================================

        for address in addresses:

            family = str(address.family)

            if "AF_INET" in family:

                ipv4.append(
                    address.address
                )

            elif "AF_INET6" in family:

                ipv6.append(
                    address.address
                )

            elif (
                "AF_LINK" in family
                or "AF_PACKET" in family
            ):

                mac = address.address

        # =====================================================
        # GUID Windows
        # =====================================================

        guid = _extract_guid(name)

        # =====================================================
        # Npcap
        # =====================================================

        npcap_device = _find_npcap_device(
            guid
        )

        # =====================================================
        # Interface Scapy
        # =====================================================

        scapy_interface = _find_scapy_interface(
            windows_name=name,
            description=name,
            guid=guid,
        )

        scapy_name = None

        if scapy_interface:

            scapy_name = getattr(
                scapy_interface,
                "name",
                None,
            )

        # =====================================================
        # Fallback : nom Windows
        # =====================================================

        if not scapy_name:

            try:

                candidate = (
                    conf.ifaces.dev_from_name(name)
                )

                if candidate:

                    scapy_name = getattr(
                        candidate,
                        "name",
                        None,
                    )

            except Exception:
                pass

        # =====================================================
        # Détection du type
        # =====================================================

        lower_name = name.lower()

        if (
            "wi-fi" in lower_name
            or "wifi" in lower_name
        ):

            interface_type = "wifi"

        elif "ethernet" in lower_name:

            interface_type = "ethernet"

        elif "vmware" in lower_name:

            interface_type = "virtual"

        elif "loopback" in lower_name:

            interface_type = "loopback"

        else:

            interface_type = "other"

        # =====================================================
        # Capture disponible
        # =====================================================

        capture_available = (
            scapy_name is not None
        )

        # =====================================================
        # Résultat
        # =====================================================

        interfaces.append(
            {
                "id": index,
                "name": name,
                "description": name,
                "guid": guid,
                "type": interface_type,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "mac": mac,
                "status": (
                    "Up"
                    if stats and stats.isup
                    else "Down"
                ),
                "is_up": bool(
                    stats and stats.isup
                ),
                "speed": (
                    f"{stats.speed} Mbps"
                    if stats and stats.speed
                    else "Inconnue"
                ),
                "capture_available": capture_available,

                # Identifiant Npcap
                "npcap_device": npcap_device,

                # Nom réellement utilisé par Scapy
                "scapy_name": scapy_name,
            }
        )

    return interfaces