# ---- stage 1: build the React UI -----------------------------------------
FROM node:22-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# ---- stage 2: runtime -----------------------------------------------------
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BRUP_DATA_DIR=/data

WORKDIR /app

# VPN clients so proxy traffic can be routed through OpenVPN or WireGuard.
# wireguard-go is the userspace fallback for when the host's kernel module is
# not reachable from inside the container.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        openvpn wireguard-tools wireguard-go iproute2 iptables procps \
 && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# See the script's own comment: lets wg-quick run under Docker's read-only
# /proc/sys. Placed on PATH only for the VPN subprocesses, not globally.
COPY backend/container/sysctl-shim /usr/local/libexec/brup/sysctl
RUN chmod +x /usr/local/libexec/brup/sysctl

COPY backend/brup ./brup
COPY --from=ui /ui/dist ./static

RUN mkdir -p /data
VOLUME ["/data"]

# 9080 UI + API, 9081 proxy listener, 9444 invisible-HTTPS listener
EXPOSE 9080 9081 9444

CMD ["uvicorn", "brup.main:app", "--host", "0.0.0.0", "--port", "9080", \
     "--no-access-log", "--ws-max-size", "33554432"]
