#!/bin/bash
set -e

CERT_DIR=/certs

if [ ! -f "$CERT_DIR/cert.pem" ]; then
  echo "Generating self-signed certificate..."
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert.pem" \
    -days 365 \
    -subj "/CN=localhost/O=Stalwart Test/C=US" \
    -addext "subjectAltName=DNS:localhost,DNS:keycloak,DNS:openldap,DNS:pebble,DNS:*.stalwart.test,IP:127.0.0.1"
  
  # Create combined PEM for services that need it
  cat "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem" > "$CERT_DIR/combined.pem"
  
  # Create PKCS12 for Keycloak
  openssl pkcs12 -export -in "$CERT_DIR/cert.pem" -inkey "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/keystore.p12" -name localhost -password pass:changeit
  
  chmod 644 "$CERT_DIR"/*
  echo "Certificates generated."
else
  echo "Certificates already exist."
fi
