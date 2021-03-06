FROM securecompliance/gvm:master

ENV TZ="Europe/Amsterdam"

# Remove the last line of start.sh so it doesn't hang on tail -F
# https://github.com/Secure-Compliance-Solutions-LLC/GVM-Docker/blob/master/scripts/start.sh
RUN sed -i '$ d' /start.sh

ADD . /
RUN python3 -m pip install python-gvm\
    && mkdir /var/reports/ \
    && chmod +x /entrypoint.sh

VOLUME /var/reports/

ENTRYPOINT ["/entrypoint.sh"]