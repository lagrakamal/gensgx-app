const express = require('express');
const fs = require('fs');
const { execSync } = require('child_process');
const app = express();
app.use(express.json());

const CA_KEY = 'ca.key';
const CA_CERT = 'ca.crt';

// CA-Key und -Zertifikat generieren, falls nicht vorhanden
if (!fs.existsSync(CA_KEY) || !fs.existsSync(CA_CERT)) {
    execSync(`openssl genrsa -out ${CA_KEY} 4096`);
    execSync(`openssl req -x509 -new -nodes -key ${CA_KEY} -sha256 -days 3650 -out ${CA_CERT} -subj "/CN=GenChainCA"`);
}

// POST /sign-csr - nimmt PEM-CSR entgegen, gibt PEM-Zertifikat zurück
app.post('/sign-csr', (req, res) => {
    const { csr } = req.body;
    if (!csr) return res.status(400).json({ error: 'CSR erforderlich' });

    // Schreibe CSR temporär
    fs.writeFileSync('tmp.csr', csr);
    // Signiere mit OpenSSL
    execSync(`openssl x509 -req -in tmp.csr -CA ${CA_CERT} -CAkey ${CA_KEY} -CAcreateserial -out tmp.crt -days 3650 -sha256`);
    const cert = fs.readFileSync('tmp.crt', 'utf8');
    fs.unlinkSync('tmp.csr');
    fs.unlinkSync('tmp.crt');
    res.type('text/plain').send(cert);
});

app.listen(9100, () => {
    console.log('CA-Service läuft auf Port 9100');
}); 