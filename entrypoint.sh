#!/bin/bash

export PASSWORD="admin"

/start.sh

chown gvm:gvm -R /var/reports/

args="$@"
su -c "python3 /usr/local/share/gvm/scan.py $args" gvm