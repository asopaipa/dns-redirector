#!/bin/sh

# Set default values if environment variables are not provided
DEFAULT_TARGET_IP=${DEFAULT_TARGET_IP:-199.34.228.49}
WORKERS=${WORKERS:-4}
IP_BLOCKS_FILE=${IP_BLOCKS_FILE:-/app/ip_blocks.txt}
LISTEN_ADDR=${LISTEN_ADDR:-:53}
RELOAD_INTERVAL=${RELOAD_INTERVAL:-30s}
CONFIG_FILE=${CONFIG_FILE:-/app/config.txt}
DOT_CERT=${DOT_CERT:-/etc/letsencrypt/live/digi-dns.duckdns.org/fullchain.pem}
DOT_KEY=${DOT_KEY:-/etc/letsencrypt/live/digi-dns.duckdns.org/privkey.pem}

# Update config.txt with the environment variable value if provided
if [ -n "$DEFAULT_TARGET_IP" ]; then
  echo "# Configuración para DNS Redirector" > $CONFIG_FILE
  echo "# Última actualización: $(date)" >> $CONFIG_FILE
  echo "DEFAULT_TARGET_IP=$DEFAULT_TARGET_IP" >> $CONFIG_FILE
  echo "Config file updated with DEFAULT_TARGET_IP=$DEFAULT_TARGET_IP"
fi

echo "Starting DNS Redirector with the following configuration:"
echo "IP Blocks File: $IP_BLOCKS_FILE"
echo "Config File: $CONFIG_FILE"
echo "Initial Default Target IP: $DEFAULT_TARGET_IP"
echo "Listen Address: $LISTEN_ADDR"
echo "Worker Threads: $WORKERS"
echo "Reload Interval: $RELOAD_INTERVAL"

echo "DoT Cert: $DOT_CERT"
echo "DoT Key: $DOT_KEY"


# Execute the DNS redirector with the configured parameters
exec /app/dns-redirector \
  -ip-blocks="${IP_BLOCKS_FILE}" \
  -default-target-ip="${DEFAULT_TARGET_IP}" \
  -listen="${LISTEN_ADDR}" \
  -workers="${WORKERS}" \
  -reload-interval="${RELOAD_INTERVAL}" \

  -enable-dot \
  -dot-cert="${DOT_CERT}" \
  -dot-key="${DOT_KEY}" \
  -dot-listen ":853" \
  -upstream-dot "1.1.1.1:853"

  -config="${CONFIG_FILE}"

