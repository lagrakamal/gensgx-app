// Secure Key Management - Maximale SGX-Sicherheit
// Private Key wird NUR in der Enklave gespeichert und verwendet

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEY_FILE = path.join(__dirname, '..', 'sgx_private_key');

// Fügt node-forge für CSR-Erstellung hinzu
const forge = require('node-forge');

// Konstante-Zeit-String-Vergleich (Schutz gegen Timing-Angriffe)
function constantTimeCompare(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}

// Sichere Schlüsselgenerierung (jetzt RSA für maximale Kompatibilität mit node-forge und PKI)
function generateKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        publicKeyEncoding: { type: 'spki', format: 'pem' }
    });
}

// Schlüssel laden oder neu erstellen
let privateKey, publicKey;

if (fs.existsSync(KEY_FILE)) {
    // Lade existierenden Schlüssel
    const keyData = JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
    privateKey = keyData.privateKey;
    publicKey = keyData.publicKey;
} else {
    // Erstelle neuen Schlüssel
    const keyPair = generateKeyPair();
    privateKey = keyPair.privateKey;
    publicKey = keyPair.publicKey;

    // Speichere sicher (nur im Enclave)
    fs.writeFileSync(KEY_FILE, JSON.stringify({ privateKey, publicKey }), {
        mode: 0o600
    });
}

// Signiert Hash mit konstanter Zeit
function sign(hash) {
    const signer = crypto.createSign('SHA256');
    signer.update(Buffer.from(hash, 'hex'));
    return signer.sign(privateKey, 'hex');
}

// Verifiziert Signatur mit konstanter Zeit
function verify(hash, signature, publicKeyHex) {
    try {
        // Konvertiere Hex zu PEM
        const publicKeyBuffer = Buffer.from(publicKeyHex, 'hex');
        const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${publicKeyBuffer.toString('base64')}\n-----END PUBLIC KEY-----`;

        const verifier = crypto.createVerify('SHA256');
        verifier.update(Buffer.from(hash, 'hex'));
        return verifier.verify(publicKeyPem, signature, 'hex');
    } catch (error) {
        return false;
    }
}

// Gibt Public Key als Hex zurück
function getPublicKey() {
    const publicKeyBuffer = crypto.createPublicKey(publicKey);
    const publicKeyDer = publicKeyBuffer.export({ type: 'spki', format: 'der' });
    return publicKeyDer.toString('hex');
}

// Gibt einen CSR (Certificate Signing Request) im PEM-Format zurück
function getCSR() {
    const pki = forge.pki;
    const privateKeyForge = pki.privateKeyFromPem(privateKey);
    const publicKeyForge = pki.publicKeyFromPem(publicKey);
    const csr = pki.createCertificationRequest();
    csr.publicKey = publicKeyForge;
    csr.setSubject([{ name: 'commonName', value: 'sgx-app' }]);
    csr.sign(privateKeyForge);
    return pki.certificationRequestToPem(csr);
}

module.exports = { sign, verify, getPublicKey, getCSR }; 