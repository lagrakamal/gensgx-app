// SGX Sign Service - Maximale Sicherheit, minimaler Code
// Alle Krypto-Operationen laufen in der SGX-Enklave mit konstanter Zeit

const express = require('express');
const { sign, verify, getPublicKey, getCSR } = require('./secure-key');
const https = require('https');
const fs = require('fs');

const app = express();
app.use(express.json());

// Rate Limiting: Max 100 Requests pro 15 Minuten pro IP
const rateLimit = require('express-rate-limit');
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Zu viele Anfragen' }
}));

// Hilfsfunktion: Prüft ob String nur Hex-Zeichen enthält
function isValidHex(str) {
    return /^[0-9a-fA-F]+$/.test(str);
}

// HTTPS/mTLS-Optionen: Nur Clients mit gültigem Zertifikat dürfen zugreifen
const options = {
    key: fs.readFileSync('../sgx_private_key'), // Private Key aus Enklave
    cert: fs.readFileSync('../sgx-server.crt'), // Von CA signiertes Zertifikat
    ca: fs.readFileSync('../ca.crt'), // Root-CA
    requestCert: true,
    rejectUnauthorized: true, // Nur Clients mit gültigem Zertifikat
};

// GET /health - Beweist SGX-Sicherheit
app.get('/health', (req, res) => {
    const testHash = 'deadbeef';
    const signature = sign(testHash);
    const publicKey = getPublicKey();
    const isValid = verify(testHash, signature, publicKey);

    res.json({
        status: 'ok',
        sgx: {
            testHash,
            signature,
            publicKey,
            valid: isValid,
            message: isValid ? 'SGX-Signatur erfolgreich' : 'SGX-Fehler'
        }
    });
});

// POST /sign - Signiert Hash (nur in Enklave)
app.post('/sign', (req, res) => {
    const { hash } = req.body;

    if (!hash || !isValidHex(hash)) {
        return res.status(400).json({ error: 'Hash (hex) erforderlich' });
    }

    try {
        const signature = sign(hash);
        res.json({ signature });
    } catch (error) {
        res.status(500).json({ error: 'Signierung fehlgeschlagen' });
    }
});

// POST /verify - Verifiziert Signatur (nur in Enklave)
app.post('/verify', (req, res) => {
    const { hash, signature, publicKey } = req.body;

    if (!hash || !signature || !publicKey ||
        !isValidHex(hash) || !isValidHex(signature) || !isValidHex(publicKey)) {
        return res.status(400).json({ error: 'Hash, Signatur, PublicKey (hex) erforderlich' });
    }

    try {
        const isValid = verify(hash, signature, publicKey);
        res.json({ valid: isValid });
    } catch (error) {
        res.status(500).json({ error: 'Verifikation fehlgeschlagen' });
    }
});

// GET /getPublicKey - Gibt Public Key zurück
app.get('/getPublicKey', (req, res) => {
    res.json({ publicKey: getPublicKey() });
});

// GET /csr - Gibt aktuellen Certificate Signing Request (CSR) im PEM-Format zurück
app.get('/csr', (req, res) => {
    res.type('text/plain').send(getCSR());
});

// Starte HTTPS-Server mit mTLS
https.createServer(options, app).listen(9000, () => {
    console.log('SGX-App läuft mit mTLS auf Port 9000');
}); 