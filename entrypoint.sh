#!/bin/bash

/start.sh

uuid=$(su -c "gvmd --get-users --verbose" gvm | sed 's/^.* //')

su -c "gvmd --modify-setting 78eceaec-3385-11ea-b237-28d24461215b --value $uuid" gvm

chown gvm:gvm -R /var/reports/

args="$@"
su -c "python3 /usr/local/share/gvm/scan.py $args" gvm