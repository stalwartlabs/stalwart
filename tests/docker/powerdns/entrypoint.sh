#!/bin/bash
set -e

# Wait for PowerDNS to be ready (started by default entrypoint)
echo "Waiting for PowerDNS to start..."
for i in $(seq 1 30); do
  if pdnsutil list-all-zones 2>/dev/null; then
    break
  fi
  sleep 1
done

# Run zone initialization
bash /etc/powerdns/init-zone.sh
