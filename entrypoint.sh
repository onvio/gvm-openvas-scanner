#!/bin/bash

if  [ -d /data/database ]; then
    su -c "/usr/lib/postgresql/12/bin/pg_resetwal -f /data/database" postgres
fi

/start.sh

config_exists=""
while [ -z "$config_exists" ]; do
    echo "Waiting for scan configs to be imported. If this is the first run, this may take 10 minutes."
    configs=$(su -c "gvm-cli --gmp-username=admin --gmp-password=admin tls --xml '<get_configs />'" gvm)
    config_exists=$(echo "$configs" | grep "d21f6c81-2b88-4ac1-b7b4-a2a9f2ad4663")
	sleep 10
done

echo "Scan configs are imported, running scanscript"

chown gvm:gvm -R /var/reports/

args="$@"
su -c "python3 /usr/local/share/gvm/scan.py $args" gvm