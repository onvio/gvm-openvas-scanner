#!/bin/bash

# Try to fix the database if corrupted
if  [ -d /data/database ]; then
    su -c "/usr/lib/postgresql/12/bin/pg_resetwal -f /data/database" postgres
fi

# Force the start script to create a user on each run
rm -rf /data/created_gvm_user

/start.sh

chown gvm:gvm -R /var/reports/

args="$@"
su -c "python3 /usr/local/share/gvm/scan.py $args" gvm