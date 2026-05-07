FROM postgres:16

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv curl gettext-base \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/patroni \
 && /opt/patroni/bin/pip install --no-cache-dir \
    "patroni[etcd3]==3.3.2" psycopg2-binary

ENV PATH="/opt/patroni/bin:${PATH}"

COPY ha/patroni.yml   /etc/patroni.yml.tmpl
COPY ha/post_init.sh  /ha/post_init.sh
COPY ha/entrypoint.sh /ha-entrypoint.sh

RUN chmod +x /ha-entrypoint.sh /ha/post_init.sh

ENTRYPOINT ["/ha-entrypoint.sh"]
