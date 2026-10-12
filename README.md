# INPA — Intelligent Network Packet Analyzer

Analyseur intelligent de trafic réseau avec :

**CAPTURER → ANALYSER → COMPRENDRE → EXPLIQUER**

## Architecture

- `backend/` : API FastAPI et logique serveur
- `agent/` : agent Windows Npcap et binaire `INPA-Agent.exe`
- `frontend/` : interface Web
- `test_reports_history.py` : tests des exports, de l'historique et des routes protégées
- `docs/` : documentation
- `frontend/assets/images/` : identité visuelle INPA

## Démarrage local

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
uvicorn backend.main:app --reload
```

Puis ouvrir :

http://127.0.0.1:8000

## Sécurité

La capture réseau doit être effectuée uniquement sur des systèmes et réseaux pour lesquels vous êtes autorisé à effectuer l'analyse.

L'agent Windows capture uniquement après une commande du tableau de bord et
transmet les paquets au serveur par HTTPS. Pour son installation et la
configuration des jetons, consulte [docs/agent-windows.md](docs/agent-windows.md).

## Historique et rapports

Les captures arrêtées avec des paquets analysables sont conservées dans
`data/inpa_history.sqlite3`. Seuls les résultats agrégés sont enregistrés :
les objets paquets individuels ne sont pas conservés dans l'historique.
Les captures sans paquet sont retirées et les sessions interrompues par un
arrêt du serveur sont signalées comme interrompues.

Le tableau de bord permet de télécharger le rapport actuel et les rapports
historiques en JSON ou CSV. Le PDF n'est pas inclus afin de ne pas ajouter une
dépendance de génération documentaire.

En accès local, l'historique reste accessible depuis le poste local. En ligne,
les utilisateurs créent un compte dans le tableau de bord. Chaque compte garde
un historique, un agent et des données de capture isolés. Configure la clé
serveur de l'agent dans `.env` :

```dotenv
INPA_AGENT_TOKEN=remplace-par-une-cle-longue-aleatoire
```

Pour un déploiement Railway persistant, monte un volume sur `/data` et définis
`INPA_HISTORY_DB=/data/inpa_history.sqlite3`. Une seule réplique backend est
prise en charge, car les captures actives sont conservées en mémoire. Consulte
[docs/agent-windows.md](docs/agent-windows.md) pour le parcours agent et les
limites actuelles de la gestion des comptes.

## Installation et lancement sous Windows

Dans le terminal PowerShell de VS Code, depuis le dossier du projet :

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn backend.main:app --reload
```

Ouvre ensuite `http://127.0.0.1:8000/dashboard`. Pour les interfaces Windows,
Scapy peut nécessiter Npcap ainsi que le lancement de VS Code avec les droits
nécessaires à la capture.

## Vérifications

Lancer les tests automatisés depuis PowerShell :

```powershell
python -m pytest
```

Vérifier manuellement dans le tableau de bord :

1. Démarrer une capture sur une interface disponible, puis attendre quelques
   paquets.
2. Télécharger le rapport actuel en JSON puis CSV et vérifier les compteurs,
   protocoles, communications et observations.
3. Arrêter la capture et vérifier que la session apparaît comme terminée dans
   l'historique avec ses détails et ses téléchargements.
4. Arrêter puis relancer le serveur et vérifier que l'historique est conservé.
5. Tester une capture sans paquet : elle ne doit pas créer d'entrée historique.
6. Pour l'accès distant, créer un compte, télécharger l'agent Windows et
   utiliser le bouton « Configurer mon agent » pour connecter ce poste.

Le PDF n'est pas proposé. Le buffer de capture reste limité à 5 000 paquets :
les rapports indiquent séparément le nombre total capturé et le nombre de
paquets analysés disponibles dans le buffer.
