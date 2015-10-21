FROM postgres:9.5

RUN mkdir -p /docker-entrypoint-initdb.d
COPY schema.sql /docker-entrypoint-initdb.d/
