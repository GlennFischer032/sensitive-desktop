FROM guacamole/guacamole:latest

USER root
RUN apt-get update \
  && apt-get install -y mysql-client \
  && rm -rf /var/lib/apt/lists/*
USER 1000
