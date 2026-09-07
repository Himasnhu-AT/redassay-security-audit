# VULN pack: exposure
FROM postgres:16
# VULN: expose.dockerfile-datastore-port
EXPOSE 5432
RUN adduser --system --no-create-home app
USER app
