FROM postgres:16-alpine

COPY seeds/       /seeds/
COPY scripts/run_seeds.sh /scripts/run_seeds.sh

RUN chmod +x /scripts/run_seeds.sh

ENTRYPOINT ["/scripts/run_seeds.sh"]
