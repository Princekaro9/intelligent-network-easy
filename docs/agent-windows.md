# INPA-Agent pour Windows

INPA-Agent est un exécutable Windows 64 bits qui capture les paquets sur le PC où il tourne. Il ne commence aucune capture tant qu’un utilisateur ne l’a pas demandée dans le dashboard. Il transmet les paquets au backend en HTTPS.

## Configuration Railway

Aucune clé commune ne doit être configurée sur Railway. Chaque navigateur reçoit automatiquement un code individuel, conservé dans son stockage local. Le domaine Railway doit être public et HTTPS.


## Accès au dashboard

Aucun compte ni adresse e-mail. Au premier accès, INPA crée un code unique pour ce navigateur. Le bouton « Mon code INPA » permet affichage et copie du code dans INPA-Agent.exe. Le code identifie un espace privé. Le bouton « Renouveler mon code » invalide le code précédent et conserve le même espace ainsi que son historique.

Les paquets, rapports, état de capture, agent et historique sont associés au code individuel. Un code perdu dans ce navigateur ne peut pas être récupéré par le serveur ; un autre navigateur créera un nouvel espace.

## Installation sur le PC à capturer

1. Télécharge INPA-Agent.exe depuis le dashboard.
2. Installe Npcap avec ses options par défaut selon le [guide officiel](https://npcap.com/guide/npcap-users-guide.html). Garde le mode compatible WinPcap activé s’il est proposé.
3. Lance INPA-Agent.exe avec les autorisations nécessaires à l’accès Npcap.
4. Dans le dashboard, ouvre « Mon code INPA » et saisis le code dans INPA-Agent.exe. URL HTTPS déjà intégrée au programme ; le code ne reste pas enregistré localement.
5. Laisse la fenêtre de l’agent ouverte. Lorsque le dashboard indique qu’il est connecté, choisis une interface et démarre la capture.
6. Arrête la capture depuis le dashboard. Les paquets en attente sont synchronisés avant la finalisation du rapport.

L’agent tente automatiquement de se reconnecter après une perte de réseau. Sa file d’attente est limitée à 5 000 paquets ; les paquets écartés en cas de débordement sont signalés au backend.

## Liaison agent/backend

Le programme transmet le code individuel dans X-INPA-Agent-Token. Le backend associe chaque heartbeat, commande et paquet au même espace. Les routes du dashboard utilisent le code via X-INPA-Token.

L’état d’une capture active est gardé en mémoire et disparaît au redémarrage du service. Monte un volume sur /data et configure INPA_HISTORY_DB=/data/inpa_history.sqlite3 pour conserver l’historique. Garde une seule réplique tant que l’état de l’agent n’est pas externalisé dans un stockage partagé.

Utilise l’agent uniquement sur un appareil et un réseau que tu es autorisé à analyser.