#!/bin/sh
# Setup a dedicated, locked-down SSH user for redirtor on the relay server.
#
# Usage (run on the relay as root):
#   ./setup-relay-user.sh "$(cat redirtor_relay.pub)"
#
# This creates the user `redirtor`, disables login/shell access, and only
# permits the client to open a reverse tunnel to the specified local port.

set -eu

USER_NAME="${USER_NAME:-redirtor}"
LISTEN_ADDR="${LISTEN_ADDR:-127.0.0.1}"
LISTEN_PORT="${LISTEN_PORT:-4022}"

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
    echo "Usage: $0 '<ssh-public-key>'" >&2
    echo "Example: $0 \"\$(cat ~/.ssh/redirtor_relay.pub)\"" >&2
    exit 1
fi

PUB_KEY="$1"

# Pick a non-login shell.
if [ -x /usr/sbin/nologin ]; then
    SHELL=/usr/sbin/nologin
elif [ -x /bin/false ]; then
    SHELL=/bin/false
else
    SHELL=/bin/true
fi

if id "$USER_NAME" >/dev/null 2>&1; then
    echo "User $USER_NAME already exists."
else
    echo "Creating user $USER_NAME ..."
    useradd --system \
        --create-home \
        --home-dir "/home/$USER_NAME" \
        --shell "$SHELL" \
        --comment "redirtor reverse tunnel" \
        "$USER_NAME"
fi

HOME_DIR="/home/$USER_NAME"
SSH_DIR="$HOME_DIR/.ssh"
AUTH_KEYS="$SSH_DIR/authorized_keys"

mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

# Restrictions:
#   restrict          enable all restrictions
#   permitlisten=...  re-allow remote (-R) forwarding only to this address/port
#   command=...       reject any interactive/session request
{
    printf 'restrict,permitlisten="%s:%s",command="/bin/false" %s\n' \
        "$LISTEN_ADDR" "$LISTEN_PORT" "$PUB_KEY"
} > "$AUTH_KEYS"

chmod 600 "$AUTH_KEYS"
chown -R "$USER_NAME:$USER_NAME" "$HOME_DIR"

echo "Authorized key written to $AUTH_KEYS"
echo ""
echo "Recommended sshd_config snippet (place BEFORE any global Match block):"
echo ""
cat <<EOF
Match User $USER_NAME
    AllowTcpForwarding remote
    GatewayPorts no
    ForceCommand /bin/false
    X11Forwarding no
    AllowAgentForwarding no
    PermitTTY no
EOF
echo ""
echo "Then reload sshd:"
echo "  sudo systemctl reload sshd      # systemd (Debian/Ubuntu/RHEL/Fedora)"
echo "  sudo service ssh reload         # OpenRC / older systems"
