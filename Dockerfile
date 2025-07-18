FROM ubuntu:22.04
ENV PATH="/usr/local/bin:${PATH}"

# 1. Basis-Tools und SGX-Repo
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wget gnupg2 ca-certificates curl lsb-release && \
    echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main" > /etc/apt/sources.list.d/intel-sgx.list && \
    wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -

# 2. SGX-Laufzeit und Build-Tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git build-essential cmake python3 python3-pip \
        libssl-dev libcurl4-openssl-dev \
        libprotobuf-dev protobuf-compiler \
        libsgx-enclave-common libsgx-urts \
        pkg-config

# 3. Node.js installieren (hier v18, anpassbar)
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs

# Entferne alle alten Gramine- und graminelibos-Pakete und -Verzeichnisse
RUN apt-get purge -y gramine* || true
RUN rm -rf /usr/lib/python3/dist-packages/graminelibos*
RUN rm -rf /usr/local/lib/python3.10/dist-packages/graminelibos*

# 4. Gramine aus dem Source bauen (mit Meson, ab v1.9)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git build-essential python3 python3-pip \
        cmake libprotobuf-c-dev protobuf-c-compiler \
        protobuf-compiler python3-cryptography python3-protobuf \
        libunwind8 musl-tools python3-pytest libgmp-dev libmpfr-dev libmpc-dev libisl-dev \
        meson ninja-build pkg-config nasm \
        gawk bison flex texinfo libtool autoconf automake m4 && \
    git clone https://github.com/gramineproject/gramine.git /opt/gramine && \
    cd /opt/gramine && \
    git checkout v1.9 && \
    git submodule update --init --recursive && \
    meson setup build/ --buildtype=release -Ddirect=enabled -Dsgx=enabled && \
    meson compile -C build/ -j 2 && \
    meson install -C build/ && \
    cd / && rm -rf /opt/gramine
RUN pip3 install --no-cache-dir jinja2 click pyyaml voluptuous markupsafe toml tomli tomli_w pyelftools
ENV PYTHONPATH="/usr/local/lib/python3.10/dist-packages"

# 4.1 Python-Abhängigkeiten für gramine-manifest
RUN pip3 install click jinja2 pyyaml voluptuous markupsafe toml tomli tomli_w pyelftools

# 5. App-Code und Manifest kopieren
WORKDIR /app
COPY . /app

# Kopiere nur Node.js und seine Libraries für Gramine-chroot
RUN cp -r --parents /usr/bin/node /app \
    && ldd /usr/bin/node | awk '{print $3}' | grep -v '^$' | xargs -I '{}' cp -v --parents '{}' /app || true

# --- Elegante chroot-Vorbereitung für Gramine ---
RUN mkdir -p /app/bin /app/lib \
    && cp -r --parents /bin/sh /bin/dash /app \
    && ldd /bin/sh | awk '{print $3}' | grep -v '^$' | xargs -I '{}' cp -v --parents '{}' /app || true \
    && cp -r --parents /lib64/ld-linux-x86-64.so.2 /app || true \
    && cp -r --parents /lib/x86_64-linux-gnu/libc.so.6 /app || true \
    && cp -r --parents /bin/ls /app \
    && cp -r --parents /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /app \
    && ldd /bin/dash | awk '{print $3}' | grep -v '^$' | xargs -I '{}' cp -v --parents '{}' /app || true

# 6. Node-Dependencies installieren (falls nötig)
RUN npm ci --omit=dev

# 7. Demo-Key generieren (für Produktion eigenen Key verwenden!)
RUN openssl genrsa -3 -out /app/enclave-key.pem 3072

# 8. Gramine-Version prüfen (korrekt)
RUN which gramine-manifest && gramine-manifest --help | head -n 1

# 9. Gramine-Manifest generieren und signieren (entfernt, wird jetzt im Startscript gemacht)

# 9. Exponierte Ports (anpassen)
#EXPOSE 3000

# 10. Startbefehl (Gramine im SGX-Modus)
WORKDIR /app
# Füge das Startscript für den automatisierten CA-Workflow hinzu
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Setze das Startscript als ENTRYPOINT
ENTRYPOINT ["/app/entrypoint.sh"]