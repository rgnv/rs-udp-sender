#!/bin/bash
set -e

# Set CAP_NET_RAW capability on the binary
setcap cap_net_raw+ep /usr/bin/rs-udp-sender 2>/dev/null || true

# Create udp-senders group
getent group udp-senders >/dev/null || groupadd -r udp-senders

# Set group ownership
chgrp udp-senders /usr/bin/rs-udp-sender
chmod 750 /usr/bin/rs-udp-sender

echo "rs-udp-sender installed. Add users to 'udp-senders' group: sudo usermod -aG udp-senders \$USER"
