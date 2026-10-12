from datetime import datetime
from threading import Lock
import ipaddress

from scapy.all import AsyncSniffer

from backend.agent.interfaces import get_interfaces


class CaptureAgent:
    """
    Agent de capture réseau d'INPA.

    Responsabilités :

    - détecter les interfaces réseau disponibles ;
    - résoudre les noms Windows/Npcap vers une interface Scapy ;
    - capturer les paquets ;
    - extraire les informations réseau utiles ;
    - conserver un buffer limité en mémoire.

    L'agent ne décide jamais si un paquet est malveillant.
    Il fournit uniquement des FAITS OBSERVÉS au moteur d'analyse.
    """

    MAX_BUFFER_SIZE = 5000

    def __init__(self):
        self.sniffer = None
        self.running = False
        self.interface = None

        self.packet_buffer = []

        # Nombre total observé pendant la session, y compris au-delà du buffer.
        self.total_packet_count = 0

        self.lock = Lock()

    # =========================================================
    # INTERFACES
    # =========================================================

    def get_interfaces(self):
        """
        Retourne les interfaces réseau disponibles.
        """

        return get_interfaces()

    # =========================================================
    # RESOLUTION INTERFACE
    # =========================================================

    def _resolve_interface(
        self,
        interface_name: str,
    ):
        """
        Résout une interface Windows/Npcap vers le nom
        réellement utilisable par Scapy.

        Plusieurs valeurs peuvent être fournies :

        - nom Windows
        - nom Scapy
        - description
        - GUID
        - périphérique Npcap
        """

        interfaces = get_interfaces()

        requested = (
            str(interface_name)
            .strip()
            .lower()
        )

        # =====================================================
        # RECHERCHE EXACTE
        # =====================================================

        for interface in interfaces:

            candidates = [
                interface.get("name"),
                interface.get("scapy_name"),
                interface.get("description"),
                interface.get("guid"),
                interface.get("npcap_device"),
            ]

            for candidate in candidates:

                if not candidate:
                    continue

                candidate_normalized = (
                    str(candidate)
                    .strip()
                    .lower()
                )

                if candidate_normalized == requested:

                    scapy_name = interface.get(
                        "scapy_name"
                    )

                    if scapy_name:
                        return scapy_name

                    return interface.get(
                        "name"
                    )

        # =====================================================
        # RECHERCHE PARTIELLE
        # =====================================================

        for interface in interfaces:

            candidates = [
                interface.get("name"),
                interface.get("scapy_name"),
                interface.get("description"),
                interface.get("guid"),
                interface.get("npcap_device"),
            ]

            for candidate in candidates:

                if not candidate:
                    continue

                candidate_normalized = (
                    str(candidate)
                    .strip()
                    .lower()
                )

                if requested in candidate_normalized:

                    return (
                        interface.get(
                            "scapy_name"
                        )
                        or interface.get(
                            "name"
                        )
                    )

        # =====================================================
        # INTERFACE INTROUVABLE
        # =====================================================

        available = []

        for interface in interfaces:

            scapy_name = (
                interface.get(
                    "scapy_name"
                )
                or interface.get(
                    "name"
                )
            )

            if scapy_name:
                available.append(
                    scapy_name
                )

        raise ValueError(
            "Interface réseau introuvable dans "
            f"Scapy : {interface_name}. "
            "Interfaces Scapy disponibles : "
            + ", ".join(available)
        )

    # =========================================================
    # OUTILS IP
    # =========================================================

    @staticmethod
    def _is_multicast(address):
        """
        Détermine si une adresse IP est multicast.
        """

        if not address:
            return False

        try:
            return ipaddress.ip_address(
                address
            ).is_multicast

        except ValueError:
            return False

    @staticmethod
    def _is_broadcast(address):
        """
        Détermine si une adresse est un broadcast IPv4.
        """

        if not address:
            return False

        return address == "255.255.255.255"

    @staticmethod
    def _is_link_local(address):
        """
        Détermine si une adresse est link-local.

        IPv4 :
            169.254.0.0/16

        IPv6 :
            fe80::/10
        """

        if not address:
            return False

        try:
            return ipaddress.ip_address(
                address
            ).is_link_local

        except ValueError:
            return False

    @staticmethod
    def _get_ip_version(address):
        """
        Retourne la version IP d'une adresse.
        """

        if not address:
            return None

        try:

            ip = ipaddress.ip_address(
                address
            )

            return ip.version

        except ValueError:

            return None

    # =========================================================
    # CALLBACK PAQUET
    # =========================================================

    def _packet_callback(self, packet):
        """
        Transforme un paquet Scapy en objet JSON exploitable
        par le reste d'INPA.

        Cette fonction ne produit que des informations
        observables.

        Elle ne conclut jamais qu'un trafic est malveillant.
        """

        try:

            timestamp = datetime.now().isoformat()

            source = None
            destination = None

            protocol = "UNKNOWN"

            source_port = None
            destination_port = None

            ip_version = None

            network_layer = None
            transport_protocol = None

            # =================================================
            # INDICATEURS RÉSEAU
            # =================================================

            is_multicast = False
            is_broadcast = False
            is_link_local = False

            # =================================================
            # IPv4
            # =================================================

            if packet.haslayer("IP"):

                ip = packet["IP"]

                source = ip.src
                destination = ip.dst

                ip_version = 4
                network_layer = "IPv4"

                is_multicast = (
                    self._is_multicast(
                        destination
                    )
                )

                is_broadcast = (
                    self._is_broadcast(
                        destination
                    )
                    or destination == "255.255.255.255"
                )

                is_link_local = (
                    self._is_link_local(
                        source
                    )
                    or self._is_link_local(
                        destination
                    )
                )

                # ---------------------------------------------
                # TCP
                # ---------------------------------------------

                if packet.haslayer("TCP"):

                    tcp = packet["TCP"]

                    protocol = "TCP"
                    transport_protocol = "TCP"

                    source_port = int(
                        tcp.sport
                    )

                    destination_port = int(
                        tcp.dport
                    )

                # ---------------------------------------------
                # UDP
                # ---------------------------------------------

                elif packet.haslayer("UDP"):

                    udp = packet["UDP"]

                    protocol = "UDP"
                    transport_protocol = "UDP"

                    source_port = int(
                        udp.sport
                    )

                    destination_port = int(
                        udp.dport
                    )

                # ---------------------------------------------
                # ICMP
                # ---------------------------------------------

                elif packet.haslayer("ICMP"):

                    protocol = "ICMP"
                    transport_protocol = "ICMP"

                # ---------------------------------------------
                # Autre protocole IPv4
                # ---------------------------------------------

                else:

                    protocol = "IPv4"

            # =================================================
            # IPv6
            # =================================================

            elif packet.haslayer("IPv6"):

                ipv6 = packet["IPv6"]

                source = ipv6.src
                destination = ipv6.dst

                ip_version = 6
                network_layer = "IPv6"

                is_multicast = (
                    self._is_multicast(
                        destination
                    )
                )

                is_link_local = (
                    self._is_link_local(
                        source
                    )
                    or self._is_link_local(
                        destination
                    )
                )

                # ---------------------------------------------
                # TCP
                # ---------------------------------------------

                if packet.haslayer("TCP"):

                    tcp = packet["TCP"]

                    protocol = "TCP"
                    transport_protocol = "TCP"

                    source_port = int(
                        tcp.sport
                    )

                    destination_port = int(
                        tcp.dport
                    )

                # ---------------------------------------------
                # UDP
                # ---------------------------------------------

                elif packet.haslayer("UDP"):

                    udp = packet["UDP"]

                    protocol = "UDP"
                    transport_protocol = "UDP"

                    source_port = int(
                        udp.sport
                    )

                    destination_port = int(
                        udp.dport
                    )

                # ---------------------------------------------
                # ICMPv6
                # ---------------------------------------------

                elif packet.haslayer("ICMPv6"):

                    protocol = "ICMPv6"
                    transport_protocol = "ICMPv6"

                # ---------------------------------------------
                # IPv6 sans transport identifié
                # ---------------------------------------------

                else:

                    protocol = "IPv6"

            # =================================================
            # ARP
            # =================================================

            elif packet.haslayer("ARP"):

                arp = packet["ARP"]

                source = arp.psrc
                destination = arp.pdst

                protocol = "ARP"
                network_layer = "ARP"

                ip_version = 4

            # =================================================
            # ETHERNET
            # =================================================

            elif packet.haslayer("Ether"):

                ethernet = packet["Ether"]

                source = ethernet.src
                destination = ethernet.dst

                protocol = "ETHERNET"
                network_layer = "Ethernet"

            # =================================================
            # INDICATEURS CALCULÉS DEPUIS LES ADRESSES
            # =================================================

            # Calculer les indicateurs une seule fois depuis les adresses.
            # Cela évite de conserver un indicateur incohérent défini plus haut.
            is_multicast = self._is_multicast(destination)
            is_broadcast = self._is_broadcast(destination)
            is_link_local = (
                self._is_link_local(source)
                or self._is_link_local(destination)
            )

            # =================================================
            # DONNÉES DU PAQUET
            # =================================================

            packet_data = {

                # -------------------------------------------------
                # Compatibilité avec l'ancien analyseur
                # -------------------------------------------------

                "timestamp": timestamp,

                "source": source,

                "destination": destination,

                "protocol": protocol,

                "source_port": source_port,

                "destination_port": destination_port,

                "size": len(packet),

                # -------------------------------------------------
                # Nouvelles informations réseau
                # -------------------------------------------------

                "ip_version": ip_version,

                "network_layer": network_layer,

                "transport_protocol": (
                    transport_protocol
                ),

                "is_multicast": is_multicast,

                "is_broadcast": is_broadcast,

                "is_link_local": is_link_local,

                # Compatibilité avec les anciennes versions de l'analyseur.
                # Les indicateurs sont conservés au niveau principal et
                # également regroupés dans context pour les anciens lecteurs.
                "context": {
                    "is_multicast": is_multicast,
                    "is_broadcast": is_broadcast,
                    "is_link_local": is_link_local,
                    "ip_version": ip_version,
                    "network_layer": network_layer,
                    "transport_protocol": transport_protocol,
                },
            }

            # =================================================
            # AJOUT AU BUFFER
            # =================================================

            with self.lock:

                self.total_packet_count += 1

                self.packet_buffer.append(
                    packet_data
                )

                # =================================================
                # LIMITE MÉMOIRE
                # =================================================

                if (
                    len(self.packet_buffer)
                    > self.MAX_BUFFER_SIZE
                ):

                    self.packet_buffer = (
                        self.packet_buffer[
                            -self.MAX_BUFFER_SIZE:
                        ]
                    )

        except Exception as error:

            print(
                "[INPA] Erreur traitement paquet : "
                f"{error}"
            )

    # =========================================================
    # DÉMARRER CAPTURE
    # =========================================================

    def start_capture(
        self,
        interface: str,
    ):
        """
        Démarre la capture réseau.
        """

        # =====================================================
        # VÉRIFIER SI UNE CAPTURE EXISTE DÉJÀ
        # =====================================================

        if self.running:

            raise RuntimeError(
                "La capture réseau est déjà en cours."
            )

        # =====================================================
        # RÉSOUDRE INTERFACE
        # =====================================================

        scapy_interface = (
            self._resolve_interface(
                interface
            )
        )

        print(
            "[INPA] Interface demandée : "
            f"{interface}"
        )

        print(
            "[INPA] Interface Scapy utilisée : "
            f"{scapy_interface}"
        )

        # =====================================================
        # NETTOYER BUFFER
        # =====================================================

        with self.lock:

            self.packet_buffer = []
            self.total_packet_count = 0

        # =====================================================
        # CRÉER LE SNIFFER
        # =====================================================

        try:

            self.sniffer = AsyncSniffer(
                iface=scapy_interface,
                prn=self._packet_callback,
                store=False,
            )

            # =================================================
            # DÉMARRAGE
            # =================================================

            self.sniffer.start()

            self.running = True

            # IMPORTANT :
            # On conserve le nom Scapy réel.

            self.interface = scapy_interface

            print(
                "[INPA] Capture démarrée."
            )

            print(
                "[INPA] Interface : "
                f"{self.interface}"
            )

        except Exception as error:

            self.sniffer = None

            self.running = False

            self.interface = None

            raise RuntimeError(
                "Impossible de démarrer la capture : "
                f"{error}"
            )

        return self.get_status()

    # =========================================================
    # ARRÊTER CAPTURE
    # =========================================================

    def stop_capture(self):
        """
        Arrête la capture réseau.
        """

        if self.sniffer:

            try:

                self.sniffer.stop()

            except Exception as error:

                print(
                    "[INPA] Erreur arrêt capture : "
                    f"{error}"
                )

        self.sniffer = None

        self.running = False

        self.interface = None

        return self.get_status()

    # =========================================================
    # STATUT
    # =========================================================

    def get_status(self):
        """
        Retourne le statut actuel de l'agent.
        """

        with self.lock:

            packet_count = len(
                self.packet_buffer
            )
            total_packet_count = self.total_packet_count

        return {

            "running": self.running,

            "interface": self.interface,

            "packet_count": packet_count,

            "total_packet_count": total_packet_count,

        }

    # =========================================================
    # PAQUETS
    # =========================================================

    def get_packets(
        self,
        limit: int = 100,
    ):
        """
        Retourne les derniers paquets capturés.
        """

        # =====================================================
        # SÉCURITÉ
        # =====================================================

        if limit <= 0:

            limit = 100

        # =====================================================
        # LIMITE MAXIMALE
        # =====================================================

        if limit > self.MAX_BUFFER_SIZE:

            limit = self.MAX_BUFFER_SIZE

        # =====================================================
        # COPIE THREAD-SAFE
        # =====================================================

        with self.lock:

            packets = list(
                self.packet_buffer[
                    -limit:
                ]
            )

        return packets


# =============================================================
# INSTANCE GLOBALE
# =============================================================

capture_agent = CaptureAgent()
