FROM securecompliance/gvm:latest

# Remove last line so start.sh doesn't hang on tail -F
# https://github.com/Secure-Compliance-Solutions-LLC/GVM-Docker/blob/master/scripts/start.sh
RUN sed -i '$ d' /start.sh

RUN mkdir /var/reports/

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ADD scan.py /usr/local/share/gvm/scan.py

VOLUME /var/reports/

ENTRYPOINT ["/entrypoint.sh"]