import hmac
import ipaddress
import os
import asyncio
from collections import deque
from threading import Lock
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

from backend.agent.capture import capture_agent
from backend.analyzer.analyzer import network_analyzer
from backend.analyzer.baseline import baseline_manager
from backend.analyzer.classifier import classify_packet
from backend.analyzer.profile import network_profile_builder
from backend.database.history import AnalysisHistory, default_history_path, utc_now
from backend.database.accounts import AccountStore
from backend.reports import build_report, serialize_csv, serialize_json


# =========================================================
# CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

FRONTEND_DIR = BASE_DIR / "frontend"
load_dotenv(BASE_DIR / ".env")
history_store = AnalysisHistory(default_history_path(BASE_DIR))
account_store = AccountStore(history_store.database_path)
active_capture_id = None
active_capture_started_at = None
active_capture_interface = None
last_capture_metadata = {}
ACCESS_TOKEN = os.getenv("INPA_ACCESS_TOKEN", "").strip()
AGENT_TOKEN = os.getenv("INPA_AGENT_TOKEN", "").strip()
AGENT_EXECUTABLE = BASE_DIR / "agent" / "INPA-Agent.exe"
REMOTE_AGENT_LOCK = Lock()
REMOTE_PACKET_ID_SET = set()
REMOTE_PACKET_ID_ORDER = deque()
REMOTE_AGENT_STATE = {
    "agent_id": None,
    "name": None,
    "version": None,
    "interfaces": [],
    "running": False,
    "interface": None,
    "last_error": None,
    "dropped_packets": 0,
    "last_seen": None,
    "pending_command": None,
}
remote_capture_active = False
remote_stop_requested = False


class UserRuntime:
    """État isolé d'un utilisateur et de son agent distant."""
    def __init__(self):
        self.capture = capture_agent.__class__()
        self.state = {
            "agent_id": None, "name": None, "version": None, "interfaces": [],
            "running": False, "interface": None, "last_error": None,
            "dropped_packets": 0, "last_seen": None, "pending_command": None,
        }
        self.packet_ids = set()
        self.packet_order = deque()
        self.capture_id = None
        self.started_at = None
        self.interface = None
        self.last_metadata = {}
        self.remote_active = False
        self.stop_requested = False
        self.baseline = None
        self.lock = Lock()


USER_RUNTIMES = {}
USER_RUNTIMES_LOCK = Lock()


def _user_runtime(user_id: str) -> UserRuntime:
    with USER_RUNTIMES_LOCK:
        if user_id not in USER_RUNTIMES:
            USER_RUNTIMES[user_id] = UserRuntime()
        return USER_RUNTIMES[user_id]


def _agent_token_for_user(user_id: str) -> str:
    if not AGENT_TOKEN:
        raise HTTPException(status_code=503, detail="INPA_AGENT_TOKEN n'est pas configuré sur le serveur.")
    signature = hmac.new(AGENT_TOKEN.encode("utf-8"), user_id.encode("ascii"), "sha256").hexdigest()
    return f"{user_id}.{signature}"


# =========================================================
# APPLICATION
# =========================================================

app = FastAPI(
    title="Intelligent Network Packet Analyzer",
    version="0.3.0",
    description="INPA - Intelligent Network Packet Analyzer",
)


@app.on_event("startup")
async def initialize_history():
    history_store.initialize()
    account_store.initialize()
    history_store.mark_interrupted_sessions()


async def require_history_access(request: Request):
    """Retourne l'identifiant du compte distant ou autorise le mode local historique."""
    session_token = request.headers.get("x-inpa-session", "")
    user = account_store.get_session_user(session_token)
    if user:
        return user["id"]

    # Les requêtes distantes ne doivent jamais tomber sur l'état global local.
    client_host = request.client.host if request.client else ""
    try:
        is_local = ipaddress.ip_address(client_host).is_loopback
    except ValueError:
        is_local = False
    if (request.headers.get("x-forwarded-for") or request.headers.get("forwarded")
            or request.headers.get("x-forwarded-proto") or not is_local):
        raise HTTPException(status_code=401, detail="Connecte-toi à ton compte INPA.")

    if ACCESS_TOKEN:
        supplied = request.headers.get("x-inpa-token", "")
        if not hmac.compare_digest(supplied, ACCESS_TOKEN):
            raise HTTPException(status_code=401, detail="Jeton INPA requis ou invalide.")
        return None

    if not is_local:
        raise HTTPException(status_code=401, detail="Connecte-toi à ton compte INPA.")


def require_remote_agent_access(request: Request):
    if not AGENT_TOKEN:
        raise HTTPException(status_code=503, detail="L'agent distant n'est pas configuré. Définis INPA_AGENT_TOKEN sur le serveur.")
    supplied = request.headers.get("x-inpa-agent-token", "")
    if not hmac.compare_digest(supplied, AGENT_TOKEN):
        raise HTTPException(status_code=401, detail="Jeton INPA_AGENT_TOKEN absent ou invalide.")


def _agent_user_id(request: Request) -> str | None:
    supplied = request.headers.get("x-inpa-agent-token", "")
    if not AGENT_TOKEN or "." not in supplied:
        require_remote_agent_access(request)
        return None
    user_id, signature = supplied.split(".", 1)
    expected = hmac.new(AGENT_TOKEN.encode("utf-8"), user_id.encode("ascii", errors="ignore"), "sha256").hexdigest()
    if not hmac.compare_digest(signature, expected) or not account_store.get_user(user_id):
        raise HTTPException(status_code=401, detail="Jeton individuel de l'agent absent ou invalide.")
    return user_id


@app.post("/api/auth/register")
async def register_account(payload: dict):
    try:
        user = account_store.register(payload.get("email", ""), payload.get("password", ""))
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except Exception as error:
        if "UNIQUE constraint failed" in str(error):
            raise HTTPException(status_code=409, detail="Un compte existe déjà pour cette adresse e-mail.") from error
        raise
    token = account_store.create_session(user["id"])
    return {"success": True, "user": user, "session_token": token}


@app.post("/api/auth/login")
async def login_account(payload: dict):
    user = account_store.authenticate(payload.get("email", ""), payload.get("password", ""))
    if not user:
        raise HTTPException(status_code=401, detail="Adresse e-mail ou mot de passe incorrect.")
    return {"success": True, "user": user, "session_token": account_store.create_session(user["id"])}


@app.get("/api/auth/me")
async def current_account(user_id: str = Depends(require_history_access)):
    if not user_id:
        raise HTTPException(status_code=401, detail="Connecte-toi à ton compte INPA.")
    return {"success": True, "user": account_store.get_user(user_id)}


@app.post("/api/auth/logout")
async def logout_account(request: Request):
    account_store.revoke_session(request.headers.get("x-inpa-session", ""))
    return {"success": True}


@app.get("/api/auth/agent-config")
async def user_agent_config(request: Request, user_id: str = Depends(require_history_access)):
    if not user_id:
        raise HTTPException(status_code=401, detail="Connecte-toi à ton compte INPA.")
    return {"success": True, "server_url": str(request.base_url).rstrip("/"), "agent_token": _agent_token_for_user(user_id)}


def _remote_agent_connected() -> bool:
    last_seen = REMOTE_AGENT_STATE.get("last_seen")
    if not last_seen:
        return False
    try:
        moment = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - moment).total_seconds() <= 20
    except (TypeError, ValueError):
        return False


def _remote_agent_status() -> dict:
    connected = _remote_agent_connected()
    stopping = bool(remote_stop_requested and remote_capture_active)
    return {
        "running": bool(remote_capture_active and not stopping),
        "stopping": stopping,
        "connected": connected,
        "remote": True,
        "name": REMOTE_AGENT_STATE.get("name") or "INPA-Agent",
        "version": REMOTE_AGENT_STATE.get("version"),
        "interface": active_capture_interface or REMOTE_AGENT_STATE.get("interface") or "Aucune",
        "packet_count": capture_agent.total_packet_count,
        "total_packet_count": capture_agent.total_packet_count,
        "last_error": REMOTE_AGENT_STATE.get("last_error"),
        "dropped_packets": REMOTE_AGENT_STATE.get("dropped_packets", 0),
        "last_seen": REMOTE_AGENT_STATE.get("last_seen"),
    }


def _user_agent_connected(runtime: UserRuntime) -> bool:
    last_seen = runtime.state.get("last_seen")
    if not last_seen:
        return False
    try:
        moment = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - moment).total_seconds() <= 20
    except (TypeError, ValueError):
        return False


def _user_agent_status(runtime: UserRuntime) -> dict:
    stopping = bool(runtime.stop_requested and runtime.remote_active)
    return {
        "running": bool(runtime.remote_active and not stopping), "stopping": stopping,
        "connected": _user_agent_connected(runtime), "remote": True,
        "name": runtime.state.get("name") or "INPA-Agent", "version": runtime.state.get("version"),
        "interface": runtime.interface or runtime.state.get("interface") or "Aucune",
        "packet_count": runtime.capture.total_packet_count,
        "total_packet_count": runtime.capture.total_packet_count,
        "last_error": runtime.state.get("last_error"),
        "dropped_packets": runtime.state.get("dropped_packets", 0),
        "last_seen": runtime.state.get("last_seen"),
    }


def _finish_user_capture(user_id: str, runtime: UserRuntime):
    analysis_id = runtime.capture_id
    if not analysis_id:
        runtime.remote_active = False
        runtime.stop_requested = False
        return
    packets = runtime.capture.get_packets(runtime.capture.MAX_BUFFER_SIZE)
    ended_at = utc_now()
    metadata = {
        "status": "completed", "interface": runtime.interface,
        "started_at": runtime.started_at, "ended_at": ended_at,
        "duration_seconds": _duration_seconds(runtime.started_at, ended_at),
        "total_packet_count": runtime.capture.total_packet_count,
    }
    runtime.last_metadata = metadata
    try:
        if packets:
            history_store.finish(analysis_id, build_report(network_analyzer.analyze(packets), metadata))
        else:
            history_store.delete(analysis_id)
    except Exception as error:
        history_store.delete(analysis_id)
        runtime.state["last_error"] = f"Capture arrêtée, mais l'analyse a échoué : {error}"
    finally:
        runtime.capture_id = None
        runtime.started_at = None
        runtime.interface = None
        runtime.remote_active = False
        runtime.stop_requested = False


def _finish_remote_capture():
    global active_capture_id, active_capture_started_at, active_capture_interface
    global last_capture_metadata, remote_capture_active, remote_stop_requested
    analysis_id = active_capture_id
    if not analysis_id:
        remote_capture_active = False
        remote_stop_requested = False
        return
    packets = capture_agent.get_packets(capture_agent.MAX_BUFFER_SIZE)
    ended_at = utc_now()
    metadata = {
        "status": "completed",
        "interface": active_capture_interface,
        "started_at": active_capture_started_at,
        "ended_at": ended_at,
        "duration_seconds": _duration_seconds(active_capture_started_at, ended_at),
        "total_packet_count": capture_agent.total_packet_count,
    }
    last_capture_metadata = metadata
    try:
        if packets:
            history_store.finish(analysis_id, build_report(network_analyzer.analyze(packets), metadata))
        else:
            history_store.delete(analysis_id)
    except Exception as error:
        history_store.delete(analysis_id)
        REMOTE_AGENT_STATE["last_error"] = f"Capture arrêtée, mais l'analyse a échoué : {error}"
    finally:
        active_capture_id = None
        active_capture_started_at = None
        active_capture_interface = None
        remote_capture_active = False
        remote_stop_requested = False


# =========================================================
# FICHIERS STATIQUES
# =========================================================

app.mount(
    "/static",
    StaticFiles(
        directory=FRONTEND_DIR
    ),
    name="static",
)


# =========================================================
# PAGE D'ACCUEIL
# =========================================================

@app.get(
    "/",
    include_in_schema=False,
)
async def home():

    return FileResponse(
        FRONTEND_DIR / "index.html"
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.get(
    "/dashboard",
    include_in_schema=False,
)
async def dashboard():

    return FileResponse(
        FRONTEND_DIR / "dashboard.html"
    )


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
async def health():

    return {
        "status": "ok",
        "service": "INPA",
        "version": "0.3.0",
        "agent": (
            "running"
            if capture_agent.running
            else "stopped"
        ),
    }


# =========================================================
# INTERFACES RÉSEAU
# =========================================================

@app.get("/api/agent/interfaces")
async def get_interfaces(
    request: Request,
    _access: str | None = Depends(require_history_access),
):

    if _access:
        runtime = _user_runtime(_access)
        if not _user_agent_connected(runtime):
            raise HTTPException(status_code=503, detail="Ton INPA-Agent n'est pas connecté. Lance l'agent configuré pour ton compte.")
        return {"success": True, "interfaces": runtime.state.get("interfaces", [])}

    if REMOTE_AGENT_STATE.get("agent_id"):
        if not _remote_agent_connected():
            raise HTTPException(status_code=503, detail="INPA-Agent n'est pas connecté. Lance l'agent téléchargé depuis ce tableau de bord.")
        return {"success": True, "interfaces": REMOTE_AGENT_STATE.get("interfaces", [])}

    if request.headers.get("x-forwarded-for") or request.headers.get("forwarded"):
        raise HTTPException(status_code=503, detail="Aucun INPA-Agent distant n'est connecté. Télécharge et lance INPA-Agent.exe.")

    try:

        interfaces = (
            capture_agent.get_interfaces()
        )

        return {
            "success": True,
            "interfaces": interfaces,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


# =========================================================
# STATUT DE L'AGENT
# =========================================================

@app.get("/api/agent/status")
async def get_agent_status(
    request: Request,
    _access: str | None = Depends(require_history_access),
):

    if _access:
        return {"success": True, "agent": _user_agent_status(_user_runtime(_access))}

    if REMOTE_AGENT_STATE.get("agent_id") or request.headers.get("x-forwarded-for") or request.headers.get("forwarded"):
        return {"success": True, "agent": _remote_agent_status()}

    return {
        "success": True,
        "agent": capture_agent.get_status(),
    }


@app.get("/download-agent", include_in_schema=False)
@app.get("/api/agent/download", include_in_schema=False)
async def download_windows_agent():
    if not AGENT_EXECUTABLE.is_file():
        raise HTTPException(status_code=404, detail="INPA-Agent.exe n'est pas encore disponible sur ce serveur.")
    return FileResponse(
        AGENT_EXECUTABLE,
        media_type="application/vnd.microsoft.portable-executable",
        filename="INPA-Agent.exe",
    )


@app.post("/api/remote-agent/heartbeat")
async def remote_agent_heartbeat(payload: dict, request: Request):
    user_id = _agent_user_id(request)
    agent_id = str(payload.get("agent_id") or "").strip()
    if not agent_id or len(agent_id) > 128:
        raise HTTPException(status_code=400, detail="Identifiant d'agent invalide.")

    interfaces = payload.get("interfaces")
    packets = payload.get("packets")
    interfaces = [item for item in interfaces if isinstance(item, dict)][:64] if isinstance(interfaces, list) else []
    packets = [item for item in packets if isinstance(item, dict)][:500] if isinstance(packets, list) else []

    if user_id:
        runtime = _user_runtime(user_id)
        state = runtime.state
        previous_id = state.get("agent_id")
        if previous_id and previous_id != agent_id and (_user_agent_connected(runtime) or runtime.remote_active):
            raise HTTPException(status_code=409, detail="Un autre agent est déjà connecté à ce compte.")
        if previous_id != agent_id:
            with runtime.lock:
                state["pending_command"] = None
            runtime.packet_ids.clear()
            runtime.packet_order.clear()
        if runtime.remote_active and packets:
            with runtime.capture.lock:
                for packet in packets:
                    packet_id = str(packet.get("agent_packet_id") or "")
                    if packet_id and packet_id in runtime.packet_ids:
                        continue
                    if packet_id:
                        runtime.packet_ids.add(packet_id)
                        runtime.packet_order.append(packet_id)
                        while len(runtime.packet_order) > 10000:
                            runtime.packet_ids.discard(runtime.packet_order.popleft())
                    runtime.capture.packet_buffer.append(packet)
                    runtime.capture.total_packet_count += 1
                if len(runtime.capture.packet_buffer) > runtime.capture.MAX_BUFFER_SIZE:
                    runtime.capture.packet_buffer = runtime.capture.packet_buffer[-runtime.capture.MAX_BUFFER_SIZE:]
        with runtime.lock:
            state.update({
                "agent_id": agent_id, "name": str(payload.get("name") or "INPA-Agent")[:128],
                "version": str(payload.get("version") or "")[:32], "interfaces": interfaces,
                "running": bool(payload.get("running")),
                "interface": str(payload.get("interface") or "")[:256] or None,
                "last_error": str(payload.get("last_error") or "")[:1000] or None,
                "dropped_packets": max(0, int(payload.get("dropped_packets") or 0)),
                "last_seen": utc_now(),
            })
            command = state.get("pending_command")
            state["pending_command"] = None
        if bool(payload.get("running")) and not runtime.remote_active and command is None:
            command = {"action": "stop"}
        pending_packets = max(0, int(payload.get("pending_packets") or 0))
        if runtime.remote_active and runtime.stop_requested and not state["running"] and pending_packets <= len(packets):
            _finish_user_capture(user_id, runtime)
        return {"success": True, "command": command, "server_time": utc_now()}

    previous_id = REMOTE_AGENT_STATE.get("agent_id")
    if previous_id and previous_id != agent_id and (_remote_agent_connected() or remote_capture_active):
        raise HTTPException(status_code=409, detail="Un autre INPA-Agent est déjà associé à cette application.")
    if previous_id != agent_id:
        with REMOTE_AGENT_LOCK:
            REMOTE_AGENT_STATE["pending_command"] = None
        REMOTE_PACKET_ID_SET.clear()
        REMOTE_PACKET_ID_ORDER.clear()
    if remote_capture_active and packets:
        with capture_agent.lock:
            for packet in packets:
                packet_id = str(packet.get("agent_packet_id") or "")
                if packet_id and packet_id in REMOTE_PACKET_ID_SET:
                    continue
                if packet_id:
                    REMOTE_PACKET_ID_SET.add(packet_id)
                    REMOTE_PACKET_ID_ORDER.append(packet_id)
                    while len(REMOTE_PACKET_ID_ORDER) > 10000:
                        REMOTE_PACKET_ID_SET.discard(REMOTE_PACKET_ID_ORDER.popleft())
                capture_agent.packet_buffer.append(packet)
                capture_agent.total_packet_count += 1
            if len(capture_agent.packet_buffer) > capture_agent.MAX_BUFFER_SIZE:
                capture_agent.packet_buffer = capture_agent.packet_buffer[-capture_agent.MAX_BUFFER_SIZE:]

    with REMOTE_AGENT_LOCK:
        REMOTE_AGENT_STATE.update({
            "agent_id": agent_id,
            "name": str(payload.get("name") or "INPA-Agent")[:128],
            "version": str(payload.get("version") or "")[:32],
            "interfaces": interfaces,
            "running": bool(payload.get("running")),
            "interface": str(payload.get("interface") or "")[:256] or None,
            "last_error": str(payload.get("last_error") or "")[:1000] or None,
            "dropped_packets": max(0, int(payload.get("dropped_packets") or 0)),
            "last_seen": utc_now(),
        })
        command = REMOTE_AGENT_STATE.get("pending_command")
        REMOTE_AGENT_STATE["pending_command"] = None

    # Après un redémarrage du serveur, ne pas laisser reprendre une capture
    # qui n'a plus de session de tableau de bord correspondante.
    if bool(payload.get("running")) and not remote_capture_active and command is None:
        command = {"action": "stop"}

    pending_packets = max(0, int(payload.get("pending_packets") or 0))
    if (
        remote_capture_active
        and remote_stop_requested
        and not REMOTE_AGENT_STATE["running"]
        and pending_packets <= len(packets)
    ):
        _finish_remote_capture()

    return {"success": True, "command": command, "server_time": utc_now()}


# =========================================================
# DÉMARRER UNE CAPTURE
# =========================================================

@app.post("/api/agent/capture/start")
async def start_capture(
    payload: dict,
    request: Request,
    _access: str | None = Depends(require_history_access),
):

    interface = payload.get("interface")

    if _access:
        if not interface:
            raise HTTPException(status_code=400, detail="Le nom de l'interface réseau est obligatoire.")
        runtime = _user_runtime(_access)
        if not _user_agent_connected(runtime):
            raise HTTPException(status_code=503, detail="Ton INPA-Agent n'est pas connecté.")
        if runtime.remote_active or runtime.capture_id:
            raise HTTPException(status_code=409, detail="Une capture est déjà en cours sur ton compte.")
        interfaces = runtime.state.get("interfaces", [])
        selected = next((item for item in interfaces if item.get("scapy_name") == interface or item.get("name") == interface), None)
        if not selected or not selected.get("capture_available"):
            raise HTTPException(status_code=400, detail="L'interface demandée n'est pas disponible sur ton INPA-Agent.")
        with runtime.capture.lock:
            runtime.capture.packet_buffer.clear()
            runtime.capture.total_packet_count = 0
        runtime.started_at = utc_now()
        runtime.interface = selected.get("description") or selected.get("name") or interface
        runtime.last_metadata = {}
        try:
            runtime.capture_id = history_store.start(runtime.interface, owner_id=_access)
        except Exception as error:
            runtime.started_at = None
            runtime.interface = None
            raise HTTPException(status_code=500, detail=f"Impossible d'enregistrer la capture : {error}") from error
        runtime.remote_active = True
        runtime.stop_requested = False
        with runtime.lock:
            runtime.state["pending_command"] = {"action": "start", "interface": selected.get("scapy_name") or interface}
        return {"success": True, "message": "Ordre de démarrage envoyé à ton INPA-Agent.", "agent": _user_agent_status(runtime)}

    global active_capture_id, active_capture_started_at, active_capture_interface
    global last_capture_metadata, remote_capture_active, remote_stop_requested

    if not interface:

        raise HTTPException(
            status_code=400,
            detail=(
                "Le nom de l'interface réseau "
                "est obligatoire."
            ),
        )

    remote_mode = bool(REMOTE_AGENT_STATE.get("agent_id")) or bool(
        request.headers.get("x-forwarded-for") or request.headers.get("forwarded")
    )
    if remote_mode:
        if not _remote_agent_connected():
            raise HTTPException(status_code=503, detail="INPA-Agent n'est pas connecté. Lance INPA-Agent.exe avant de démarrer une capture.")
        if capture_agent.running or active_capture_id:
            raise HTTPException(status_code=409, detail="Une capture est déjà en cours.")
        interfaces = REMOTE_AGENT_STATE.get("interfaces", [])
        selected = next((item for item in interfaces if item.get("scapy_name") == interface or item.get("name") == interface), None)
        if not selected or not selected.get("capture_available"):
            raise HTTPException(status_code=400, detail="L'interface demandée n'est pas disponible sur INPA-Agent.")
        with capture_agent.lock:
            capture_agent.packet_buffer.clear()
            capture_agent.total_packet_count = 0
        active_capture_started_at = utc_now()
        active_capture_interface = selected.get("description") or selected.get("name") or interface
        last_capture_metadata = {}
        try:
            active_capture_id = history_store.start(active_capture_interface)
        except Exception as error:
            active_capture_started_at = None
            active_capture_interface = None
            raise HTTPException(status_code=500, detail=f"Impossible d'enregistrer la capture : {error}") from error
        remote_capture_active = True
        remote_stop_requested = False
        with REMOTE_AGENT_LOCK:
            REMOTE_AGENT_STATE["pending_command"] = {"action": "start", "interface": selected.get("scapy_name") or interface}
        return {"success": True, "message": "Ordre de démarrage envoyé à INPA-Agent.", "agent": _remote_agent_status()}

    try:

        status = (
            capture_agent.start_capture(
                interface
            )
        )
        active_capture_started_at = utc_now()
        active_capture_interface = status.get("interface") or interface
        last_capture_metadata = {}
        try:
            active_capture_id = history_store.start(active_capture_interface)
        except Exception:
            capture_agent.stop_capture()
            active_capture_started_at = None
            active_capture_interface = None
            raise

        return {
            "success": True,
            "message": (
                "Capture réseau démarrée."
            ),
            "agent": status,
        }

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except RuntimeError as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


# =========================================================
# ARRÊTER UNE CAPTURE
# =========================================================

@app.post("/api/agent/capture/stop")
async def stop_capture(
    _access: str | None = Depends(require_history_access),
):

    if _access:
        runtime = _user_runtime(_access)
        if runtime.remote_active:
            saved_analysis_id = runtime.capture_id
            runtime.stop_requested = True
            with runtime.lock:
                runtime.state["pending_command"] = {"action": "stop"}
            for _ in range(48):
                if not runtime.remote_active:
                    break
                await asyncio.sleep(0.25)
            return {
                "success": True, "message": "Ordre d'arrêt envoyé à ton INPA-Agent.",
                "agent": _user_agent_status(runtime), "analysis_id": saved_analysis_id,
                "pending": runtime.remote_active,
            }
        return {"success": True, "message": "Aucune capture distante n'est en cours.", "agent": _user_agent_status(runtime)}

    global active_capture_id, active_capture_started_at, active_capture_interface
    global last_capture_metadata, remote_capture_active, remote_stop_requested

    if remote_capture_active:
        saved_analysis_id = active_capture_id
        remote_stop_requested = True
        with REMOTE_AGENT_LOCK:
            REMOTE_AGENT_STATE["pending_command"] = {"action": "stop"}
        for _ in range(48):
            if not remote_capture_active:
                break
            await asyncio.sleep(0.25)
        return {
            "success": True,
            "message": "Ordre d'arrêt envoyé à INPA-Agent.",
            "agent": _remote_agent_status(),
            "analysis_id": saved_analysis_id,
            "pending": remote_capture_active,
        }

    try:

        status = (
            capture_agent.stop_capture()
        )

        saved_analysis_id = active_capture_id
        if saved_analysis_id:
            packets = capture_agent.get_packets(capture_agent.MAX_BUFFER_SIZE)
            try:
                ended_at = utc_now()
                started_at = active_capture_started_at or (packets[0].get("timestamp") if packets else None)
                metadata = {
                    "status": "completed",
                    "interface": active_capture_interface,
                    "started_at": started_at,
                    "ended_at": ended_at,
                    "duration_seconds": _duration_seconds(started_at, ended_at),
                    "total_packet_count": status.get("total_packet_count", len(packets)),
                }
                last_capture_metadata = metadata
                if packets:
                    analysis = network_analyzer.analyze(packets)
                    report = build_report(analysis, metadata)
                    history_store.finish(saved_analysis_id, report)
                else:
                    history_store.delete(saved_analysis_id)
            except Exception as error:
                history_store.delete(saved_analysis_id)
                raise RuntimeError(f"Capture arrêtée, mais l'analyse n'a pas pu être enregistrée : {error}") from error
            finally:
                active_capture_id = None
                active_capture_started_at = None
                active_capture_interface = None

        return {
            "success": True,
            "message": (
                "Capture réseau arrêtée."
            ),
            "agent": status,
            "analysis_id": saved_analysis_id,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


# =========================================================
# PAQUETS CAPTURÉS
# =========================================================

@app.get("/api/agent/packets")
async def get_packets(
    limit: int = 100,
    _access: str | None = Depends(require_history_access),
):

    try:

        source = _user_runtime(_access).capture if _access else capture_agent
        packets = source.get_packets(limit)

        return {
            "success": True,
            "count": len(packets),
            "packets": packets,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


# =========================================================
# DONNÉES DASHBOARD
# =========================================================

@app.get("/api/dashboard-data")
async def dashboard_data(
    _access: str | None = Depends(require_history_access),
):

    runtime = _user_runtime(_access) if _access else None
    source = runtime.capture if runtime else capture_agent
    status = _user_agent_status(runtime) if runtime else source.get_status()
    packets = source.get_packets(50)

    return {

        "agent": {

            "status": (
                "connected"
                if status["running"]
                else "ready"
            ),

            "name": "INPA Agent",

            "version": "0.3.0",

            "interface": (
                status["interface"]
                or "Aucune"
            ),
        },

        "capture": {

            "status": (
                "running"
                if status["running"]
                else "stopped"
            ),

            "packets": status[
                "packet_count"
            ],
        },

        "packets": packets,
    }


# =========================================================
# ANALYSE DU RÉSEAU
# =========================================================

@app.get("/api/analyzer")
async def analyze_network(
    _access: str | None = Depends(require_history_access),
):
    """
    Analyse les paquets actuellement en mémoire.
    """

    try:

        source = _user_runtime(_access).capture if _access else capture_agent
        packets = source.get_packets(1000)

        result = (
            network_analyzer.analyze(
                packets
            )
        )

        return {
            "success": True,
            "analysis": result,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Erreur d'analyse : {error}"
            ),
        )


def _duration_seconds(started_at, ended_at):
    if not started_at or not ended_at:
        return None
    try:
        start = datetime.fromisoformat(str(started_at).replace("Z", "+00:00"))
        end = datetime.fromisoformat(str(ended_at).replace("Z", "+00:00"))
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        return max(0.0, (end - start).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


def _download_response(report, output_format, filename_prefix, section=None):
    if output_format == "json":
        content = serialize_json(report)
        media_type = "application/json; charset=utf-8"
    elif output_format == "csv":
        valid_sections = {"capture", "protocols", "communications", "observations"}
        if section is not None and section not in valid_sections:
            raise HTTPException(status_code=400, detail="Section de rapport invalide.")
        content = serialize_csv(report, section=section)
        media_type = "text/csv; charset=utf-8"
    else:
        raise HTTPException(status_code=400, detail="Format demandé invalide. Utilise json ou csv.")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename_prefix}-{stamp}.{output_format}"'},
    )


@app.get("/api/history")
async def list_analysis_history(
    limit: int = 50,
    _access: str | None = Depends(require_history_access),
):
    analyses = history_store.list(limit, owner_id=_access)
    if _access:
        runtime = _user_runtime(_access)
        if runtime.capture_id and runtime.remote_active:
            status = _user_agent_status(runtime)
            duration = _duration_seconds(runtime.started_at, utc_now())
            history_store.update_progress(runtime.capture_id, status.get("total_packet_count", 0), duration)
            for item in analyses:
                if item["id"] == runtime.capture_id:
                    item["packet_count"] = status.get("total_packet_count", 0)
                    item["duration_seconds"] = duration
                    break
        return {"success": True, "analyses": analyses}
    if active_capture_id and capture_agent.running:
        status = capture_agent.get_status()
        duration = _duration_seconds(active_capture_started_at, utc_now())
        history_store.update_progress(
            active_capture_id,
            status.get("total_packet_count", status.get("packet_count", 0)),
            duration,
        )
        for item in analyses:
            if item["id"] == active_capture_id:
                item["packet_count"] = status.get("total_packet_count", status.get("packet_count", 0))
                item["duration_seconds"] = duration
                break
    return {"success": True, "analyses": analyses}


@app.get("/api/history/{analysis_id}")
async def get_historical_analysis(
    analysis_id: str,
    _access: str | None = Depends(require_history_access),
):
    record = history_store.get(analysis_id, owner_id=_access)
    if record is None:
        raise HTTPException(status_code=404, detail="Analyse introuvable dans l'historique.")
    return {"success": True, "analysis": record}


@app.get("/api/history/{analysis_id}/report")
async def download_historical_report(
    analysis_id: str,
    format: str = "json",
    section: str | None = None,
    _access: str | None = Depends(require_history_access),
):
    record = history_store.get(analysis_id, owner_id=_access)
    if record is None:
        raise HTTPException(status_code=404, detail="Analyse introuvable dans l'historique.")
    if record["status"] != "completed" or not record.get("report"):
        raise HTTPException(status_code=409, detail="Le rapport est disponible après la fin d'une capture avec des paquets analysables.")
    return _download_response(record["report"], format.lower(), f"inpa-analyse-{analysis_id[:8]}", section)


@app.get("/api/reports/current")
async def download_current_report(
    format: str = "json",
    section: str | None = None,
    _access: str | None = Depends(require_history_access),
):
    runtime = _user_runtime(_access) if _access else None
    source = runtime.capture if runtime else capture_agent
    packets = source.get_packets(source.MAX_BUFFER_SIZE)
    if not packets:
        raise HTTPException(status_code=404, detail="Aucune donnée à exporter. Démarre une capture et attends des paquets.")
    analysis = network_analyzer.analyze(packets)
    running = (runtime.remote_active if runtime else remote_capture_active) or source.running
    metadata = dict(runtime.last_metadata if runtime else last_capture_metadata) if not running else {}
    started_at = (
        (runtime.started_at if runtime else active_capture_started_at) if running else metadata.get("started_at")
    ) or packets[0].get("timestamp")
    ended_at = None if running else (metadata.get("ended_at") or packets[-1].get("timestamp") or utc_now())
    metadata.update({
        "status": "in_progress" if running else "completed",
        "interface": ((runtime.interface if runtime else active_capture_interface) or source.interface) if running else metadata.get("interface"),
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_seconds": (
            _duration_seconds(started_at, ended_at) if ended_at else _duration_seconds(started_at, utc_now())
        ),
        "total_packet_count": source.total_packet_count,
    })
    report = build_report(analysis, metadata)
    return _download_response(report, format.lower(), "inpa-rapport-actuel", section)


# =========================================================
# CONSULTER LA BASELINE
# =========================================================

@app.get("/api/baseline")
async def get_baseline(_access: str | None = Depends(require_history_access)):
    """
    Retourne l'état actuel de la baseline.
    """

    baseline = _user_runtime(_access).baseline if _access else baseline_manager.get_baseline()

    if baseline is None:

        return {
            "success": True,
            "available": False,
            "message": (
                "Aucune baseline configurée."
            ),
            "baseline": None,
        }

    return {
        "success": True,
        "available": True,
        "baseline": baseline,
    }


# =========================================================
# CRÉER UNE BASELINE
# =========================================================

@app.post("/api/baseline/create")
async def create_baseline(_access: str | None = Depends(require_history_access)):
    """
    Crée une baseline à partir du trafic
    actuellement capturé.

    La baseline représente le comportement
    observé pendant cette fenêtre.
    """

    try:

        source = _user_runtime(_access).capture if _access else capture_agent
        packets = source.get_packets(1000)

        if not packets:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Aucun paquet disponible. "
                    "Démarre d'abord une capture réseau."
                ),
            )

        # -------------------------------------------------
        # CLASSIFICATION
        # -------------------------------------------------

        classified_packets = []

        for packet in packets:

            try:

                classified = (
                    classify_packet(
                        packet
                    )
                )

                classified_packets.append(
                    {
                        **packet,
                        **classified,
                    }
                )

            except Exception:

                # Si un paquet ne peut pas être
                # classifié, on le conserve quand même.
                classified_packets.append(
                    packet
                )

        # -------------------------------------------------
        # CONSTRUCTION DU PROFIL
        # -------------------------------------------------

        profile = (
            network_profile_builder.build(
                classified_packets
            )
        )

        # -------------------------------------------------
        # ENREGISTREMENT DE LA BASELINE
        # -------------------------------------------------

        baseline = baseline_manager.set_baseline(profile) if not _access else profile
        if _access:
            _user_runtime(_access).baseline = baseline

        return {

            "success": True,

            "message": (
                "Baseline réseau créée "
                "avec succès."
            ),

            "baseline": baseline,
        }

    except HTTPException:

        raise

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Erreur lors de la création "
                f"de la baseline : {error}"
            ),
        )


# =========================================================
# SUPPRIMER LA BASELINE
# =========================================================

@app.delete("/api/baseline")
async def delete_baseline(_access: str | None = Depends(require_history_access)):
    """
    Supprime la baseline actuelle.
    """

    if _access:
        _user_runtime(_access).baseline = None
    else:
        baseline_manager.clear_baseline()

    return {
        "success": True,
        "message": "Baseline supprimée.",
    }
