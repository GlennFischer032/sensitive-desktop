FROM guacamole/guacamole:latest

USER root
RUN mkdir -p /opt/guac-data \
    && chown -R 1000:1000 /opt/guac-data \
    && chmod -R 755 /opt/guac-data \
    && mkdir -p /home/guac \
    && chown -R 1000:1000 /home/guac
USER 1000

ENV HOME=/home/guac
ENV GUACAMOLE_HOME=/opt/guac-data
