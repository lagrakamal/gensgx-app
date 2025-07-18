#!/bin/bash
set -e

# 1. Starte die SGX-App im Hintergrund, damit /csr erreichbar ist
node /app/src/app.js &
APP_PID=$!

# 2. Warte, bis /csr erreichbar ist
until curl -sf http://localhost:9000/csr > /app/sgx-app.csr; do
  echo "Warte auf SGX-App /csr-Endpoint..."
  sleep 1
done

# 3. Hole Zertifikat von CA, falls noch nicht vorhanden
if [ ! -f /app/sgx-server.crt ]; then
  echo "Fordere Zertifikat von CA an..."
  CSR=$(cat /app/sgx-app.csr)
  CERT=$(curl -s -X POST http://ca-service:9100/sign-csr -H "Content-Type: application/json" --data "{\"csr\":\"$CSR\"}")
  echo "$CERT" > /app/sgx-server.crt
fi

# 4. Beende die temporäre App-Instanz
kill $APP_PID
sleep 1

# 5. Starte die SGX-App als mTLS-Server (blockierend)
exec node /app/src/app.js 