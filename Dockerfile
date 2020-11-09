FROM securecompliance/gvm:20.08-v2

# Remove the last line of start.sh so it doesn't hang on tail -F
# https://github.com/Secure-Compliance-Solutions-LLC/GVM-Docker/blob/master/scripts/start.sh
#RUN sed -i '$ d' /start.sh

ADD start.sh /start.sh

RUN mkdir /var/reports/
RUN python3 -m pip install python-gvm

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ADD scan.py /usr/local/share/gvm/scan.py

ENV TZ="Europe/Amsterdam"

VOLUME /var/reports/

ENTRYPOINT ["/entrypoint.sh"]