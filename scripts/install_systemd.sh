#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"

usage() {
	echo "Usage: $0 install <client|server>"
}

if [[ $# -ne 2 || "$1" != "install" ]]; then
	usage
	exit 1
fi

TARGET="$2"

install_server() {
	echo "[vpnodns] building server binary..."
	go build -o "${BIN_DIR}/vpnodns-server" "${ROOT_DIR}/server"

	echo "[vpnodns] installing server unit file..."
	install -m 0644 "${ROOT_DIR}/systemd/vpnodns-server.service" "${SYSTEMD_DIR}/vpnodns-server.service"

	if [[ ! -f /etc/default/vpnodns-server ]]; then
		cat >/etc/default/vpnodns-server <<'EOF'
# Example:
# VPNODNS_SERVER_ARGS="-listen :53535 -domain vpn.internal -iface dns0 -iface-cidr 10.44.0.1/30 -nat-iface eth0 -username demo -password demo"
VPNODNS_SERVER_ARGS="-listen :53535 -domain vpn.internal -username demo -password demo"
EOF
	fi
}

install_client() {
	echo "[vpnodns] building client binary..."
	go build -o "${BIN_DIR}/vpnodns-client" "${ROOT_DIR}/client"

	echo "[vpnodns] installing client unit file..."
	install -m 0644 "${ROOT_DIR}/systemd/vpnodns-client.service" "${SYSTEMD_DIR}/vpnodns-client.service"

	if [[ ! -f /etc/default/vpnodns-client ]]; then
		cat >/etc/default/vpnodns-client <<'EOF'
# Example:
# VPNODNS_CLIENT_ARGS="-server 1.2.3.4:53535 -domain vpn.internal -iface dns1 -iface-cidr 10.44.0.2/30 -route 0.0.0.0/1 -route 128.0.0.0/1 -username demo -password demo"
VPNODNS_CLIENT_ARGS="-server 127.0.0.1:53535 -domain vpn.internal -username demo -password demo"
EOF
	fi
}

case "${TARGET}" in
client)
	install_client
	ENABLED_SERVICE="vpnodns-client"
	;;
server)
	install_server
	ENABLED_SERVICE="vpnodns-server"
	;;
*)
	usage
	exit 1
	;;
esac

echo "[vpnodns] reloading systemd..."
systemctl daemon-reload

echo "[vpnodns] installed."
echo "Enable service when ready:"
echo "  sudo systemctl enable --now ${ENABLED_SERVICE}"
