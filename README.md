# SGX Node.js App with Gramine – Minimal & Production-ready

## Overview

This project demonstrates how to securely run a Node.js app inside an Intel SGX enclave using Gramine and Docker. The app provides an API for signing, verifying, and retrieving a public key – the private key always stays inside the enclave.

**Features:**
- **Maximum Security**: Private keys remain in SGX enclave
- **Constant Time**: Protection against side-channel attacks
- **Minimal Code**: Easy to understand and maintain
- **Production Ready**: Rate limiting and error handling

---

## 1. Prerequisites

- **Hardware:** Intel CPU with SGX support (6th gen or newer)
- **Software:** Ubuntu 22.04, Docker, SGX driver installed
- **SGX Devices:** `/dev/sgx_enclave` and `/dev/sgx_provision` must exist on the host

**Check:**
```bash
ls /dev/sgx*
```

---

## 2. Running on Azure (Tested Setup)

This project was tested on Microsoft Azure:
- **VM Size:** Standard DC1s v3 (1 vCPU, 8 GiB RAM, Intel SGX)
- **OS Image:** Ubuntu 22.04 LTS
- **SGX Devices:** `/dev/sgx_enclave` and `/dev/sgx_provision` available by default
- **Port 3000** was opened in the Azure Network Security Group

**Tip:** If SGX devices are missing, check that you selected a DC-series VM and SGX is enabled.

---

## 3. Build & Run

```bash
# Build the image
$ docker build -t sgx-app .

# Run the container (SGX/Gramine mode)
$ docker run --rm -it -p 3000:3000 \
  --device=/dev/sgx_enclave \
  --device=/dev/sgx_provision \
  sgx-app:latest

# Test the API
$ curl http://localhost:3000/health
$ curl http://localhost:3000/getPublicKey
$ curl -X POST http://localhost:3000/sign -H "Content-Type: application/json" -d '{"hash":"deadbeef"}'
# Use the signature from above:
$ curl -X POST http://localhost:3000/verify -H "Content-Type: application/json" -d '{"hash":"deadbeef","signature":"...","publicKey":"..."}'
```

---

## 4. Key Files and App Structure

- **src/app.js** – Main Express API (sign, verify, getPublicKey, health) - minimal and secure
- **src/secure-key.js** – Secure key management with constant-time cryptography
- **sgx_private_key** – The private key file, created on first start, only accessible inside the enclave (never leaves /app)
- **node.manifest.template** – Gramine manifest (chroot, mounts, entrypoint)
- **Dockerfile** – Minimal, only copies Node.js and required libraries into chroot

**Key Security:**
- The private key is generated on first start and saved as `/app/sgx_private_key` inside the enclave (chroot).
- On subsequent starts, the key is loaded only from this file.
- The key is never imported, exported, or set via environment variable.
- No `.env` file or `PRIVATE_KEY` variable is needed.
- The key never leaves the enclave, ensuring maximum SGX security.

---

## 5. Example: node.manifest.template (annotated)
```toml
# Gramine manifest for Node.js SGX app
loader.env.LD_LIBRARY_PATH = "/lib:/lib/x86_64-linux-gnu:/usr/lib:/usr/lib/x86_64-linux-gnu"
loader.env.PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
loader.env.NODE_ENV = "production"

# Root filesystem is chrooted to /app
fs.root.type = "chroot"
fs.root.uri = "file:/app"

# Mount only what is needed for Node.js
fs.mounts = [
    { type = "chroot", uri = "file:/lib", path = "/lib" },
    { type = "chroot", uri = "file:/lib/x86_64-linux-gnu", path = "/lib/x86_64-linux-gnu" },
    { type = "chroot", uri = "file:/usr/lib", path = "/usr/lib" },
    { type = "chroot", uri = "file:/usr/lib/x86_64-linux-gnu", path = "/usr/lib/x86_64-linux-gnu" },
    { type = "chroot", uri = "file:/dev/null", path = "/dev/null" },
    { type = "chroot", uri = "file:/dev/urandom", path = "/dev/urandom" },
    { type = "chroot", uri = "file:/dev/zero", path = "/dev/zero" },
    { type = "chroot", uri = "file:/lib64", path = "/lib64" },
    { type = "chroot", uri = "file:/usr/bin", path = "/usr/bin" }
]

# Entrypoint: Node.js runs your app
loader.argv = [
    "/usr/bin/node",
    "/src/app.js"
]

sgx.enclave_size = "2G"

[libos]
entrypoint = "/usr/bin/node"
```

---

## 6. Example: Dockerfile (annotated)
```dockerfile
# Ubuntu 22.04 base image
FROM ubuntu:22.04

# Install dependencies and SGX drivers
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wget gnupg2 ca-certificates curl lsb-release \
        git build-essential cmake python3 python3-pip \
        libssl-dev libcurl4-openssl-dev \
        libprotobuf-dev protobuf-compiler \
        libsgx-enclave-common libsgx-urts pkg-config

# Install Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs

# Build and install Gramine
# ... (see full Dockerfile for details)

# Copy app code
WORKDIR /app
COPY . /app

# Copy Node.js binary and libraries for chroot
RUN cp -r --parents /usr/bin/node /app \
    && ldd /usr/bin/node | awk '{print $3}' | grep -v '^$' | xargs -I '{}' cp -v --parents '{}' /app || true

# Install Node.js dependencies
RUN npm ci --omit=dev

# Expose API port
EXPOSE 3000

# No ENTRYPOINT: run Gramine/Node.js manually or via manifest
WORKDIR /app
```

---

## 7. Security Provided by SGX/Gramine

- **Private keys and sensitive data never leave the enclave.**
- **Signing and verification happen in protected memory.**
- **Even root or an attacker with host access cannot read the enclave's memory.**
- **Constant-time cryptography** protects against side-channel attacks.
- **Remote Attestation (optional):** Allows third parties to verify your app is really running in an enclave (see Gramine docs).

---

## 8. Debugging & Tips

- **Test inside the container (recommended):**
  ```bash
  docker run --rm -it -p 3000:3000 \
    --device=/dev/sgx_enclave \
    --device=/dev/sgx_provision \
    sgx-app:latest
  chroot /app /usr/bin/node /src/app.js
  ```

- **Alternative: Debug mode without SGX devices:**
  ```bash
  docker run --rm -it --entrypoint /bin/bash sgx-app:latest
  chroot /app /usr/bin/node /src/app.js
  ```

- **Logs & errors:**
  - Gramine errors are usually manifest or chroot issues.
  - Debug Node.js as usual.
- **Healthcheck:**
  - `/health` returns a real signature, public key, and verification result – proof that SGX security is active.

---

**With this setup, you can run any Node.js app securely inside an SGX enclave and benefit from maximum protection for keys and sensitive data.** 

## References & Further Reading

- [Intel SGX Documentation](https://software.intel.com/sgx)
- [Gramine Project](https://gramineproject.io/)
- [Node.js Crypto API](https://nodejs.org/api/crypto.html)