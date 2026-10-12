# INPA-Agent pour Windows

INPA-Agent est un exécutable Windows 64 bits qui capture les paquets sur le PC
où il tourne. Il ne commence aucune capture tant qu'un utilisateur ne l'a pas
demandée dans le tableau de bord. Il envoie les paquets au backend par HTTPS.

## Configuration du serveur

Configure `INPA_AGENT_TOKEN` dans les variables du serveur avec une valeur
longue et aléatoire. Cette clé reste secrète sur le serveur : elle permet de
produire un jeton distinct par compte. `INPA_ACCESS_TOKEN` reste réservé à
l'ancien accès local ; l'accès distant utilise maintenant des comptes INPA.

Pour générer la clé du serveur sous PowerShell :

```powershell
$inpaBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($inpaBytes)
[Convert]::ToBase64String($inpaBytes)
```

En déploiement Railway, ajoute cette variable dans les variables du service et
redéploie. Le domaine public doit être disponible en HTTPS. Le tableau de bord
permet de créer un compte avec une adresse e-mail et un mot de passe de 12
caractères minimum. Le mot de passe est protégé par PBKDF2 ; chaque compte
possède sa propre session et son propre jeton d'agent.

## Installation sur le PC à capturer

1. Télécharge `INPA-Agent.exe` depuis le bouton du tableau de bord.
2. Installe Npcap en suivant le [guide officiel](https://npcap.com/guide/npcap-users-guide.html)
   avec les options par défaut. L'agent utilise l'API `wpcap.dll` ; garde le
   mode compatible WinPcap activé s'il est proposé.
3. Lance `INPA-Agent.exe` en tant qu'administrateur pour autoriser Npcap à
   ouvrir l'interface réseau.
4. Dans le tableau de bord, clique « Configurer mon agent » et saisis l'adresse
   HTTPS et le jeton individuel affichés. Le jeton n'est pas enregistré par
   l'agent.
5. Laisse la fenêtre de l'agent ouverte. Le tableau de bord doit afficher
   l'agent connecté ; choisis ensuite une interface et démarre la capture.
6. Arrête la capture depuis le tableau de bord. Les paquets en attente sont
   synchronisés avant la finalisation du rapport.

L'agent tente automatiquement de se reconnecter après une perte de réseau,
avec un délai progressif. Sa file d'attente est limitée à 5 000 paquets ; si
elle déborde pendant une longue interruption, les paquets écartés sont
signalés au backend. L'agent ne conserve pas le jeton localement. Il mémorise
seulement un identifiant aléatoire non secret dans `%LOCALAPPDATA%\INPA`.

## Liaison entre l'agent et le compte

Les routes existantes `/api/agent/*` pilotaient le moteur de capture installé
sur le serveur et ne recevaient pas les paquets d'un agent distant. L'agent
utilise maintenant `POST /api/remote-agent/heartbeat` avec authentification
`X-INPA-Agent-Token`. Cette route identifie le compte propriétaire et enregistre
l'état, les interfaces et les paquets dans son espace isolé. Le tableau de bord
utilise des sessions de compte pour ses routes protégées.

La capture est limitée aux interfaces visibles par Npcap sur le PC où l'agent
est installé. Utilise-la uniquement sur un appareil et un réseau que tu es
autorisé à analyser.

Chaque compte possède son agent, sa capture, ses paquets en mémoire, son
historique et sa baseline. Des comptes distincts peuvent capturer en même
temps ; un compte ne peut associer qu'un agent actif à la fois. Les captures
en mémoire s'arrêtent au redémarrage du service. Sur Railway, configure un
volume monté sur `/data`, puis `INPA_HISTORY_DB=/data/inpa_history.sqlite3`
pour conserver les comptes et rapports. Garde une seule réplique du backend,
car l'état de capture des agents est conservé en mémoire.

L'inscription est ouverte. La vérification d'adresse e-mail et la récupération
de mot de passe ne sont pas encore disponibles ; prévois-les avant une
ouverture publique à grande échelle.
