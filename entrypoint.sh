#!/bin/bash

if  [ -d /data/database ]; then
    su -c "/usr/lib/postgresql/12/bin/pg_resetwal -f /data/database" postgres
fi

/start.sh

chown gvm:gvm -R /var/reports/

args="$@"
su -c "python3 /usr/local/share/gvm/scan.py $args" gvm