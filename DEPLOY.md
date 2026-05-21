# Déploiement VulnTrack sur EC2

## Prérequis

- Un compte GitHub avec un repo créé (public ou privé)
- Une instance EC2 sous **Ubuntu 22.04** ou **Amazon Linux 2023**
- Le port **8000** ouvert dans le Security Group de la VM (inbound TCP 8000)
- Accès SSH à la VM

---

## Étape 1 — Créer le repo GitHub et pusher le code (Mac, une seule fois)

```bash
# Dans le dossier du projet
cd "Desktop/dev wcomply"

# Initialiser git (déjà fait si vous avez suivi le setup)
git init
git add .
git commit -m "Initial commit"

# Créer le repo sur GitHub puis ajouter le remote
git remote add origin https://github.com/TON_USERNAME/wcomply.git
git branch -M main
git push -u origin main
```

---

## Étape 2 — Installer l'app sur la VM (SSH, une seule fois)

### 2a. Se connecter à la VM

```bash
ssh -i votre-cle.pem ubuntu@VOTRE_IP_EC2
```

### 2b. Éditer `install.sh` pour mettre votre URL GitHub

Avant de lancer `install.sh`, modifiez la variable `REPO_URL` en haut du script :

```bash
REPO_URL="https://github.com/TON_USERNAME/wcomply.git"
```

### 2c. Lancer l'installation

```bash
# Télécharger le script depuis votre repo GitHub
curl -O https://raw.githubusercontent.com/TON_USERNAME/wcomply/main/install.sh

# Lancer (nécessite sudo)
sudo bash install.sh
```

L'installation :
- Installe Python3, pip, git
- Clone le repo dans `/opt/vulntrack`
- Crée le virtualenv et installe les dépendances
- Configure et démarre le service systemd `vulntrack`
- L'app redémarre automatiquement si la VM reboot

### 2d. Vérifier que ça tourne

```bash
systemctl status vulntrack         # état du service
journalctl -u vulntrack -f         # logs en direct
curl http://localhost:8000         # test local
```

L'app est accessible sur : `http://VOTRE_IP_EC2:8000`

---

## Étape 3 — Mettre à jour l'app (workflow quotidien)

### Depuis le Mac — pusher les modifications

```bash
cd "Desktop/dev wcomply"
git add .
git commit -m "Description de la modification"
git push
```

### Sur la VM — récupérer et redémarrer

```bash
ssh -i votre-cle.pem ubuntu@VOTRE_IP_EC2
bash /opt/vulntrack/update.sh
```

Le script `update.sh` fait en une commande :
1. `git pull` — récupère le nouveau code
2. `docker compose build app` — reconstruit l'image si besoin
3. `docker compose up -d` — redémarre les conteneurs

---

## Commandes utiles sur la VM

```bash
# Voir l'état du service
systemctl status vulntrack

# Logs en direct
journalctl -u vulntrack -f

# Arrêter / démarrer / redémarrer
sudo systemctl stop vulntrack
sudo systemctl start vulntrack
sudo systemctl restart vulntrack

# Localisation des fichiers
/opt/vulntrack/          # code de l'app
/opt/vulntrack/venv/     # virtualenv (mode sans Docker)

# Voir le service systemd
cat /etc/systemd/system/vulntrack.service
```

---

## Notes importantes

**Base de données** — MongoDB tourne dans un conteneur Docker avec un volume
persistant (`mongo_data`). Les données survivent aux redémarrages et mises à jour.
Ne jamais exécuter `docker compose down -v` (supprime les volumes).

**Port** — L'app écoute sur le port 8000. Pour un usage en production,
il est recommandé de mettre Nginx en reverse proxy sur le port 80/443 :

```nginx
server {
    listen 80;
    server_name VOTRE_DOMAINE_OU_IP;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**Repo privé** — Si votre repo GitHub est privé, remplacez l'URL HTTPS
par SSH dans `install.sh` et configurez une clé SSH sur la VM :

```bash
# Sur la VM, générer une clé SSH
ssh-keygen -t ed25519 -C "ec2-vulntrack"
cat ~/.ssh/id_ed25519.pub
# Ajouter cette clé dans GitHub → Settings → SSH Keys

# Dans install.sh, utiliser :
REPO_URL="git@github.com:TON_USERNAME/wcomply.git"
```
