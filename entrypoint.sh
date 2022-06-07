#!/bin/bash

echo "Starting entrypoint"

chown gvm:gvm -R /var/reports/

args="$@"

echo "su -c \"python3 /scan.py $args\" gvm" >> /opt/setup/scripts/start.sh

/opt/setup/scripts/entrypoint.sh /usr/bin/supervisord -n -c /etc/supervisord.conf
