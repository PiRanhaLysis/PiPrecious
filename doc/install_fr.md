# Environnement de développement
## Étape 1 - Dépendances système
```
sudo apt install -y git virtualenv postgresql-9.6 python3 python3-dev dexdump gcc
```

## Étape 2 - Cloner le projet
```
git clone https://github.com/PiRanhaLysis/PiPrecious.git
```

## Étape 3 - Créer la base de données et l'utilisateur associé
```
sudo su - postgres
psql
CREATE USER piprecious WITH PASSWORD 'piprecious';
CREATE DATABASE piprecious WITH OWNER piprecious;
```

## Étape 4 - Créer l'environnement Python et installer les dépendances
```
cd PiPrecious
virtualenv ./venv -p python3
source venv/bin/activate
pip3 install -r requirements.txt
```

## Étape 5 - Créer le schéma de la base de données
```
cd piprecious
python manage.py migrate --settings=piprecious.settings.dev
```

## Étape 6 - Créer un utilisateur administrateur
Il est nécessaire d'activer l'environnement Python et de se placer dans le même dossier que le fichier `manage.py`.
```
python manage.py createsuperuser --settings=piprecious.settings.dev
```

## Étape 7 - Installer le serveur Minio
Minio est en charge de stocker les fichiers APK, icônes, fichiers de capture réseau, _etc_.
```
wget https://dl.minio.io/server/minio/release/linux-amd64/minio -O $HOME/minio
chmod +x $HOME/minio
```
## Étape 8 - Configurer Minio
```
mkdir -p $HOME/.minio
cat > $HOME/.minio/config.json << EOL
{
        "version": "20",
        "credential": {
                "accessKey": "pipreciouspiprecious",
                "secretKey": "pipreciouspiprecious"
        },
        "region": "",
        "browser": "on",
        "logger": {
                "console": {
                        "enable": true
                },
                "file": {
                        "enable": false,
                        "filename": ""
                }
        },
        "notify": {}
}
EOL
```

## Étape 8 - Créer le dossier de stockage pour Minio
```
mkdir -p $HOME/piprecious-storage
```

## Étape 9 - Démarrer Minio
```
$HOME/minio server $HOME/piprecious-storage
```
Minio écoute désormais sur le port `9000` et son interface Web est accessible à l'adresse 
[http://127.0.0.1:9000](http://127.0.0.1:9000). Les login et mot de passe sont `pipreciouspiprecious`.

## Étape 10 - Démarrer le serveur PiPrecious
Il est nécessaire d'activer l'environnement Python et de se placer dans le même dossier que le fichier `manage.py`.
```
python manage.py runserver --settings=piprecious.settings.dev
```
Rendez-vous sur [http://127.0.0.1:8000](http://127.0.0.1:8000).