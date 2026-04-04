FROM postgres:16-alpine

COPY seeds/ /seeds/

RUN chmod +x /seeds/run_seeds.sh

ENTRYPOINT ["/seeds/run_seeds.sh"]
