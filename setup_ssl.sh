#!/bin/bash
# Generate self-signed SSL certificate for development/internal use.
# For internet-facing production, replace with Let's Encrypt or your CA.

set -e

SSL_DIR="./ssl"
CERT_FILE="$SSL_DIR/cert.pem"
KEY_FILE="$SSL_DIR/key.pem"
DAYS=825  # max accepted by modern browsers

mkdir -p "$SSL_DIR"

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "[SSL] Certificates already exist at $SSL_DIR/. Skipping generation."
    echo "      Delete $SSL_DIR/ and re-run to regenerate."
    exit 0
fi

if ! command -v openssl &>/dev/null; then
    echo "[ERROR] openssl not found. Install it first: sudo apt install openssl"
    exit 1
fi

echo "[SSL] Generating 4096-bit RSA self-signed certificate (valid $DAYS days)..."

openssl req -x509 -nodes -days "$DAYS" \
    -newkey rsa:4096 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/C=US/ST=State/L=City/O=SecureWatch SIEM/OU=Security/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:siem.local,IP:127.0.0.1"

chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

echo ""
echo "[SSL] Done."
echo "  Certificate : $CERT_FILE"
echo "  Private key : $KEY_FILE"
echo ""
echo "  NOTE: This is a self-signed certificate."
echo "  Browsers will show a warning — accept it or add the cert to your trust store."
echo ""
echo "  For production with a real domain:"
echo "    certbot certonly --standalone -d yourdomain.com"
echo "    cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ssl/cert.pem"
echo "    cp /etc/letsencrypt/live/yourdomain.com/privkey.pem   ssl/key.pem"
