#!/bin/bash
set -eu

for i in $(seq 1 30); do
    if fdbcli --exec 'status minimal' --timeout 5 2>&1 | grep -q "The database is available"; then
        echo "FoundationDB already configured."
        exit 0
    fi
    if fdbcli --exec 'configure new single memory' --timeout 5 2>&1 | grep -q "Database created"; then
        echo "FoundationDB configured."
        exit 0
    fi
    echo "Waiting for FoundationDB to be ready (attempt $i)..."
    sleep 2
done

echo "ERROR: Failed to configure FoundationDB after retries" >&2
exit 1
