#!/bin/sh
# Runs inside the installer container: copy the installer to the host, then run it on the host.
# Arguments are passed to install.sh: --update, --status, --uninstall, -y --wan ... (see --help).
set -e
NAME=${OG_NAME:?}
DEST=${OG_DIR:-/opt/$NAME}
IMAGE=${OG_IMAGE:-ghcr.io/fedor-afrin/$NAME:latest}

die() { echo "ERROR: $*" >&2; exit 1; }
on_host() { nsenter -t 1 -m -u -i -n -p -- "$@"; }

[ "$(readlink /proc/1/ns/mnt)" != "$(readlink /proc/self/ns/mnt)" ] \
    || die "start the installer with --privileged --pid=host:
  docker run --pull=always --rm -it --privileged --pid=host ghcr.io/fedor-afrin/$NAME-installer:latest"
on_host true 2>/dev/null || die "cannot enter the host (is --privileged set?)"
on_host sh -c 'command -v docker >/dev/null' || die "Docker is not installed on the host"

case "${1:-}" in
    -h|--help) exec bash /payload/install.sh --help ;;
esac

echo ">>> Copying the installer to $DEST on the host"
on_host mkdir -p "$DEST"
tar -C /payload -cf - . | on_host tar -C "$DEST" --no-same-owner -xf -

exec nsenter -t 1 -m -u -i -n -p -- env OG_IMAGE="$IMAGE" OG_INSTALLER=container TERM="${TERM:-xterm}" \
    bash "$DEST/install.sh" "$@"
