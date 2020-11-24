# gvm-openvas-scanner
An automated OpenVAS scanner in Docker

Thanks to [Secure-Compliance](https://github.com/Secure-Compliance-Solutions-LLC/GVM-Docker/) for the base GVM Docker image this script relies on.

# Usage
Run:

```docker run --rm -v gvm-data:/data -v /var/gvm-reports:/var/reports onvio/gvm-openvas-scanner www.mydomain.com,api.mydomain.com myreport```

Two report formats will be generated in /var/gvm-reports:
* myreport.xml
* myreport.pdf

Help:
```
Usage: scan.py [options]

Options:
  -h, --help            show this help message and exit
  -n, --no-ping         Consider all hosts as alive
  --ssh-username=SSH_USERNAME
                        SSH Username
  --ssh-password=SSH_PASSWORD
                        SSH Password
  --ssh-private-key=SSH_PRIVATE_KEY
                        SSH Private Key
  --ssh-key-phrase=SSH_PRIVATE_KEY_PHRASE
                        SSH Private Key Phrase
  --ssh-port=SSH_PORT   SSH Port
  -s SCAN_CONFIG, --scan_config=SCAN_CONFIG
                        Scan Configuration, Base or Full and fast
  -l LOGLEVEL, --loglevel=LOGLEVEL
                        Set loglevel
```

To access the webinterface run, for example to debug the scans:

```docker run --rm -p 9392:9392 -p 9390:9390 -p 5432:5432 --entrypoint /start.sh -v gvm-data:/data -v /var/gvm-reports:/var/reports onvio/gvm-openvas-scanner```
* 9392 = Web interface
* 9390 = GMP Protocol for scanscript
* 5432 = Postgres database

*Warning* the user created is admin/admin so beware when you expose ports. The database uses default credentials as well.