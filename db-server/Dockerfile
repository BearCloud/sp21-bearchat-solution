# What image are we pulling? What version do we want?
FROM mysql:latest

COPY initdb.sql /docker-entrypoint-initdb.d/

# What is the default MySQL port?
EXPOSE 3306
