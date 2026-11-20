# OutpostGate Pro installer: one command on a clean Ubuntu/Debian server with Docker.
#   docker run --pull=always --rm -it --privileged --pid=host ghcr.io/fedor-afrin/outpost-gate-pro-installer:latest
# The container copies install.sh and the compose file to /opt/outpost-gate-pro on the host and runs
# install.sh there (nsenter into the host): kernel modules, netplan, Docker settings and the router
# container are set up on the host itself. The router image is downloaded from GHCR, not built.
FROM alpine:3.20

RUN apk add --no-cache bash util-linux tar

COPY install.sh /payload/install.sh
COPY deploy/host/docker-compose.yml deploy/host/daemon.json.example deploy/host/README.md /payload/deploy/host/
COPY installer/entrypoint.sh /entrypoint.sh
RUN chmod +x /payload/install.sh /entrypoint.sh

ENV OG_NAME=outpost-gate-pro
ENTRYPOINT ["/entrypoint.sh"]
