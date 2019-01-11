# Development environment
This guide has been tested on:
* Ubuntu 18.04 `x86_64`
* Debian 9 `x86_64`

## Step 1 - System dependencies
```
sudo apt install -y git virtualenv postgresql-9.6 python3 python3-dev dexdump gcc protobuf-compiler
```

## Step 2 - Clone the project
```
git clone https://github.com/PiRanhaLysis/PiPrecious.git
```

## Step 3 - Create database and user
```
sudo su - postgres
psql
CREATE USER piprecious WITH PASSWORD 'piprecious';
CREATE DATABASE piprecious WITH OWNER piprecious;
```

## Step 4 - Set Python virtual environment and install dependencies
```
cd PiPrecious
virtualenv ./venv -p python3
source venv/bin/activate
pip3 install -r requirements.txt
```

## Step 5 - Create the DB schema
```
cd piprecious
python manage.py migrate --settings=piprecious.settings.dev
```

## Step 6 - Create admin user
You have to activate the virtual venv and `cd` into the same directory as `manage.py` file.
```
python manage.py createsuperuser --settings=piprecious.settings.dev
```

## Step 7 - Install Minio server
Minio is in charge to store files like APK, icons, flow and pcap files.
```
wget https://dl.minio.io/server/minio/release/linux-amd64/minio -O $HOME/minio
chmod +x $HOME/minio
```
## Step 8 - Configure Minio
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

## Step 9 - Create Minio storage location
```
mkdir -p $HOME/piprecious-storage
```

## Step 10 - Start Minio
```
$HOME/minio server $HOME/piprecious-storage
```
Minio is now listening on `9000` port and the browser interface is available
at [http://127.0.0.1:9000](http://127.0.0.1:9000). Use `pipreciouspiprecious` as both login
and password.

## Step 11 - Start PiPrecious server
```
python manage.py runserver --settings=piprecious.settings.dev
```
Now browse [http://127.0.0.1:8000](http://127.0.0.1:8000).

**NB**: both Minio server and PiPrecious have to be running.
