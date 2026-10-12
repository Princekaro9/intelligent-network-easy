"""Consultation explicite et limitée de la réputation d'une IP publique via VirusTotal."""
import asyncio
import ipaddress
import os
import time

import httpx


_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
_CACHE_TTL_SECONDS = 900
_CACHE_MAX_ITEMS = 512
_RATE_WINDOW_SECONDS = 60
_RATE_MAX_REQUESTS = 4
_cache = {}
_recent_requests = []
_lock = asyncio.Lock()


class VirusTotalError(Exception):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


async def lookup_public_ip(address: str) -> dict:
    """Retourne un résumé d'un rapport IP sans jamais envoyer une IP non publique."""
    try:
        parsed_ip = ipaddress.ip_address(str(address).strip())
    except ValueError as error:
        raise VirusTotalError(422, "Adresse IP invalide.") from error

    normalized_ip = str(parsed_ip)
    if not parsed_ip.is_global:
        raise VirusTotalError(422, "VirusTotal ne consulte que les adresses IP publiques.")

    api_key = os.getenv("EXTERNAL_API_KEY", "").strip()
    if not api_key:
        raise VirusTotalError(503, "La variable EXTERNAL_API_KEY n'est pas configurée sur le serveur.")

    now = time.monotonic()
    async with _lock:
        cached = _cache.get(normalized_ip)
        if cached and cached[0] > now:
            return {**cached[1], "cached": True}
        if cached:
            _cache.pop(normalized_ip, None)

        while _recent_requests and now - _recent_requests[0] >= _RATE_WINDOW_SECONDS:
            _recent_requests.pop(0)
        if len(_recent_requests) >= _RATE_MAX_REQUESTS:
            raise VirusTotalError(429, "Limite INPA atteinte : réessaie dans une minute.")
        _recent_requests.append(now)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                _API_URL.format(ip=normalized_ip),
                headers={"x-apikey": api_key, "Accept": "application/json"},
            )
    except httpx.TimeoutException as error:
        raise VirusTotalError(502, "VirusTotal n'a pas répondu à temps.") from error
    except httpx.HTTPError as error:
        raise VirusTotalError(502, "Impossible de joindre VirusTotal.") from error

    if response.status_code in (401, 403):
        raise VirusTotalError(502, "VirusTotal a refusé la clé API configurée.")
    if response.status_code == 404:
        raise VirusTotalError(404, "VirusTotal ne possède pas encore de rapport pour cette IP.")
    if response.status_code == 429:
        raise VirusTotalError(429, "Quota VirusTotal atteint ; réessaie plus tard.")
    if response.status_code >= 500:
        raise VirusTotalError(502, "Le service VirusTotal est temporairement indisponible.")
    if response.status_code >= 400:
        raise VirusTotalError(422, "VirusTotal n'a pas accepté cette adresse IP.")

    try:
        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats") or {}
        result = {
            "ip": normalized_ip,
            "reputation": attributes.get("reputation"),
            "malicious": int(stats.get("malicious", 0) or 0),
            "suspicious": int(stats.get("suspicious", 0) or 0),
            "harmless": int(stats.get("harmless", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0),
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
            "network": attributes.get("network"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "url": f"https://www.virustotal.com/gui/ip-address/{normalized_ip}",
            "cached": False,
        }
    except (AttributeError, TypeError, ValueError) as error:
        raise VirusTotalError(502, "Réponse VirusTotal invalide.") from error

    async with _lock:
        if len(_cache) >= _CACHE_MAX_ITEMS:
            _cache.pop(next(iter(_cache)))
        _cache[normalized_ip] = (time.monotonic() + _CACHE_TTL_SECONDS, result)

    return result