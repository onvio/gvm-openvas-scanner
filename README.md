# gvm-openvas-scanner
An automated OpenVAS scanner in Docker

Thanks to [Secure-Compliance](https://github.com/Secure-Compliance-Solutions-LLC/GVM-Docker/) for the base GVM Docker image this script relies on.

# Usage
Run:
```docker run --rm -v /var/gvm-data:/data -v /opt/gvm-reports:/var/reports onvio/gvm-openvas-scanner www.mydomain.com report```

Help:
```docker run --rm -v /var/gvm-data:/data -v /opt/gvm-reports:/var/reports onvio/gvm-openvas-scanner -h```

To access the webinterface run, for example to debug the scans:
```docker run --rm -p 9392:9392 -v /var/gvm-data:/data -v /opt/gvm-reports:/var/reports onvio/gvm-openvas-scanner www.mydomain.com report```
*Warning* the user created is admin/admin so beware when you expose the webinterface.

You can find the PDF and XML report on your machine in `/opt/gvm-reports`