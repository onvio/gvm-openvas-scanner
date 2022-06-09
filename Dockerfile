FROM securecompliance/gvm:debian-master-data-full

ENV TZ="Europe/Amsterdam"

RUN sed -i '39 d' /opt/setup/scripts/entrypoint.sh

ADD . /
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py \
    && python3 get-pip.py \
    && python3 -m pip install python-gvm gvm-tools\
    && mkdir /var/reports/ \
    && chmod +x /entrypoint.sh

VOLUME /var/reports/

ENTRYPOINT ["/entrypoint.sh"]
