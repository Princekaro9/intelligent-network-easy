# INPA — Intelligent Network Packet Analyzer

INPA est une application Web d’analyse de trafic réseau : le tableau de bord commande les captures, le backend FastAPI reçoit et analyse les paquets, puis l’interface affiche les communications, alertes et rapports. La capture ne doit être utilisée que sur un appareil et un réseau pour lesquels vous avez une autorisation.

## Sommaire

- [Fonctions](#fonctions)
- [Structure](#structure)
- [Description des fichiers](#description-des-fichiers)
- [Flux de données](#flux-de-données)
- [Installation locale](#installation-locale)
- [Configuration](#configuration)
- [Agent Windows](#agent-windows)
- [Déploiement Railway](#déploiement-railway)
- [Stockage, sécurité et limites](#stockage-sécurité-et-limites)
- [Vérifications](#vérifications)

## Fonctions

- Tableau de bord de capture, compteurs, protocoles, paquets, flux et alertes.
- Capture locale via Scapy, ou distante depuis un PC Windows avec l’agent INPA et Npcap.
- Accès partagé au dashboard et à INPA-Agent par une clé API configurée côté serveur.
- Analyse comportementale et comparaison aux profils de référence.
- Exports CSV et JSON et historique SQLite.
- Enrichissement à la demande d’adresses IP publiques via VirusTotal lorsque sa clé est configurée.

## Structure du dépôt

~~~text
network-packet-analyzer-easy/
├── .env.example
├── .gitignore
├── Dockerfile
├── railway.json
├── README.md
├── requirements.txt
├── test_reports_history.py
├── agent/
│   ├── INPA-Agent.cs
│   ├── INPA-Agent.exe
│   └── main.py
├── backend/
│   ├── config.py
│   ├── main.py
│   ├── reports.py
│   ├── agent/ (__init__.py, capture.py, interfaces.py)
│   ├── ai/ (__init__.py)
│   ├── analyzer/ (__init__.py, analyzer.py, baseline_data.json,
│   │              baseline.py, behavior.py, classifier.py, flows.py, profile.py)
│   ├── capture/ (__init__.py)
│   ├── database/ (__init__.py, accounts.py, history.py)
│   ├── detection/ (__init__.py)
│   ├── enrichment/ (__init__.py, virustotal.py)
│   └── models/ (__init__.py)
├── data/
│   └── inpa_history.sqlite3
├── docs/
│   ├── agent-windows.md
│   └── VISUAL_IDENTITY.md
└── frontend/
    ├── dashboard.html
    ├── index.html
    ├── assets/images/ (inpa-background.png, inpa-logo.png, inpa-splash.png)
    ├── css/ (dashboard.css, style.css)
    └── js/ (app.js, dashboard.js)
~~~

## Description des fichiers

### Fichiers à la racine

| Fichier | Rôle |
|---|---|
| .env.example | Modèle de configuration locale. Les valeurs secrètes doivent y rester vides. Copier vers un fichier privé .env pour le développement. |
| .gitignore | Écarte les environnements virtuels, caches, fichiers .env, sorties de compilation et nouvelles bases SQLite non suivies. |
| Dockerfile | Construit l’image Linux, installe les dépendances et lance Uvicorn sur le port 8000 par défaut. Railway fournit son propre port via PORT. |
| railway.json | Configuration de démarrage Railway. |
| requirements.txt | Dépendances serveur : FastAPI, Uvicorn, Scapy, Pydantic, HTTP/WebSocket et client Supabase. |
| README.md | Présente le projet, ses fichiers, sa configuration et son exploitation. |
| test_reports_history.py | Tests automatisés des rapports, de l’historique et de routes protégées. |
| data/inpa_history.sqlite3 | Base SQLite présente dans le dépôt de travail actuel. C’est une donnée locale, pas du code ; ne pas y stocker des données réelles à publier. |

### Agent Windows

| Fichier | Rôle |
|---|---|
| agent/INPA-Agent.cs | Source C# de l’agent distant Windows : découverte d’interfaces, capture Npcap, commandes du tableau de bord, envoi des paquets et reconnexion. |
| agent/INPA-Agent.exe | Programme Windows x64 distribué par l’application. Après une modification du .cs, il faut reconstruire l’exécutable ; le code source seul ne le met pas à jour. |
| agent/main.py | Ancien prototype local Python. Ce n’est pas l’agent Windows distant actuellement distribué. |

Voir docs/agent-windows.md pour l’installation Windows, Npcap, les jetons et l’utilisation.

### Backend

| Fichier | Rôle |
|---|---|
| backend/main.py | Point d’entrée FastAPI : pages, API, comptes, sessions, captures locales/distantes, commandes agent, réception des paquets, analyse, rapports, baselines et téléchargement de l’agent. |
| backend/config.py | Déclare les paramètres Pydantic de l’application et des intégrations. Une variable déclarée ici n’implique pas que le service correspondant soit opérationnel. |
| backend/reports.py | Prépare les données des rapports et leurs formats CSV/JSON. |
| backend/agent/capture.py | Capture locale Scapy et tampon borné de paquets. |
| backend/agent/interfaces.py | Recherche et normalisation des interfaces visibles par Scapy/Npcap. |
| backend/analyzer/analyzer.py | Orchestre l’analyse et construit les résultats pour l’interface et les rapports. |
| backend/analyzer/behavior.py | Déduit les observations et interprétations comportementales. |
| backend/analyzer/baseline.py | Gère les profils de référence et les comparaisons. |
| backend/analyzer/baseline_data.json | Données de référence livrées avec le projet. |
| backend/analyzer/classifier.py | Classe les protocoles, services et plages d’adresses reconnus. |
| backend/analyzer/flows.py | Regroupe les paquets en communications/flux bidirectionnels. |
| backend/analyzer/profile.py | Calcule un profil synthétique du trafic. |
| backend/database/accounts.py | Comptes historiques et codes individuels hachés pour isoler les espaces dans SQLite. |
| backend/database/history.py | Enregistre et relit les comptes/captures/rapports selon le schéma SQLite ; l’historique des rapports est agrégé et ne conserve pas les objets paquet bruts. |
| backend/enrichment/virustotal.py | Enrichissement à la demande d’IP publiques par VirusTotal avec cache et limites de requêtes du module. |
| Les __init__.py des packages | Marquent les répertoires Python comme packages. Les dossiers ai, capture, detection et models ne contiennent pas d’autre logique active pour le moment. |

### Interface et documentation

| Fichier | Rôle |
|---|---|
| frontend/index.html | Page d’accueil. |
| frontend/js/app.js | Interactions de la page d’accueil et écran de lancement. |
| frontend/css/style.css | Mise en forme de la page d’accueil. |
| frontend/dashboard.html | Structure HTML du tableau de bord, formulaires, indicateurs, tableaux et commandes. |
| frontend/js/dashboard.js | Appels API, authentification, capture, rendu des paquets/alertes, configuration agent et exports. |
| frontend/css/dashboard.css | Styles du tableau de bord, formulaires, alertes et panneaux d’enrichissement. |
| frontend/assets/images/inpa-background.png | Illustration d’arrière-plan. |
| frontend/assets/images/inpa-logo.png | Logo INPA. |
| frontend/assets/images/inpa-splash.png | Illustration de lancement/transition. |
| docs/agent-windows.md | Guide d’installation et de connexion de l’agent Windows. |
| docs/VISUAL_IDENTITY.md | Notes sur les ressources et l’identité visuelle. |

## Flux de données

1. Le navigateur charge la page d’accueil ou le tableau de bord.
2. backend/main.py sert l’interface et les routes /api.
3. Une capture locale passe par backend/agent/capture.py ; une capture distante passe par INPA-Agent.exe et les routes d’agent distant.
4. backend/analyzer/ traite les paquets pour fournir statistiques, protocoles, flux et observations au tableau de bord.
5. Les rapports peuvent être exportés en CSV ou JSON ; l’historique est conservé en SQLite si son chemin est persistant.
6. Tester la clé, le téléchargement du programme, le heartbeat, une capture et les exports.

## Installation locale

Prérequis : Python 3.11 ou ultérieur recommandé. Pour une capture locale, il faut une interface accessible et les privilèges adéquats. Sur Windows, Scapy peut nécessiter Npcap.

Dans PowerShell, depuis la racine du projet :

~~~powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn backend.main:app --reload
~~~

Ouvrir http://127.0.0.1:8000 ou http://127.0.0.1:8000/dashboard.

## Configuration

Créer un fichier privé .env en local, ou définir les variables dans les paramètres du service de déploiement. Ne jamais publier des clés dans Git.

| Variable | Description et état |
|---|---|
| APP_NAME | Nom de l’application. |
| APP_ENV | Environnement de fonctionnement. |
| APP_SECRET | Secret privé d’application ; mettre une valeur aléatoire en production. |
| INPA_AGENT_TOKEN | Clé maître historique pour signer les jetons des anciens comptes. |
| INPA_PUBLIC_URL | URL HTTPS publique facultative ; Railway peut fournir son domaine automatiquement. |
| INPA_HISTORY_DB | Chemin SQLite. Sur Railway avec volume, utiliser /data/inpa_history.sqlite3. |
| EXTERNAL_API_KEY | Clé VirusTotal facultative pour les recherches d’IP publiques. |
| SUPABASE_URL, SUPABASE_KEY | Paramètres déclarés ; les comptes et historiques actuels utilisent SQLite. |
| AI_API_KEY | Paramètre prévu ; aucune fonction IA active ne doit être présumée à partir de sa seule présence. |
| WEBSOCKET_SECRET | Paramètre déclaré ; vérifier le code avant de considérer un service WebSocket actif. |

## Accès par clé et agent Windows

Aucun compte ni e-mail. Au premier accès, le serveur crée un code individuel lié au navigateur. Le bouton « Mon code INPA » affiche ce code à copier dans INPA-Agent.exe.

Chaque code possède son propre agent, état de capture, paquets, rapports, baseline et historique. Le bouton de renouvellement invalide le code précédent sans supprimer son espace. Chaque profil de navigateur possède son propre code.
## Déploiement Railway

1. Créer un service Railway depuis le dépôt GitHub.
2. Configurer le démarrage pour écouter la variable PORT fournie par Railway.
3. Définir APP_SECRET comme variable privée Railway et supprimer INPA_SHARED_API_KEY de Railway si elle existe. Aucun code individuel ne doit être ajouté dans Railway.
4. Générer le domaine public HTTPS et vérifier qu’il répond.
5. Monter un volume sur /data puis définir INPA_HISTORY_DB=/data/inpa_history.sqlite3.
6. Tester la clé, le téléchargement du programme, le heartbeat, une capture et les exports.
7. Garder une seule réplique tant que l’état des agents et captures actives reste en mémoire du processus.

## Stockage, sécurité et limites

- Le stockage local SQLite peut être éphémère en conteneur. Un volume persistant est nécessaire pour préserver les comptes et rapports après redémarrage.
- Les paquets et l’état des captures actives résident en mémoire et sont perdus au redémarrage ; l’historique des rapports est agrégé.
- L’architecture actuelle prévoit une seule réplique backend sans coordination distribuée.
- La récupération de mot de passe et la validation d’adresse e-mail ne sont pas disponibles dans le parcours décrit.
- VirusTotal est un service externe. Comprendre ses conditions et conséquences de partage avant de lui soumettre un indicateur sensible.
- Le projet doit être utilisé uniquement sur les réseaux autorisés.
- Si une clé a été publiée dans Git, la supprimer du fichier courant ne l’efface pas de l’historique : la révoquer chez le fournisseur et la remplacer sur le service déployé.

## Vérifications

Les tests se trouvent dans test_reports_history.py. Depuis un environnement Python local, on peut les lancer ainsi :

~~~powershell
python -m pytest
~~~

Vérification manuelle conseillée : clé valide et clé invalide, téléchargement du binaire, connexion du programme, capture et téléchargements CSV/JSON.
