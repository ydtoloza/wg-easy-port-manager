FROM docker.io/library/node:krypton-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS build_node_modules

# Copy Web UI
COPY src /app
WORKDIR /app
RUN npm ci &&\
    npm run check:www-template &&\
    npm prune --omit=dev &&\
    mv node_modules /node_modules

# Copy build result to a new image.
# This saves a lot of disk space.
FROM docker.io/library/node:krypton-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43
HEALTHCHECK CMD /usr/bin/timeout 5s /bin/sh -c "/usr/bin/wg show wg0 >/dev/null && /usr/bin/wget -q -O /dev/null http://127.0.0.1:${PORT:-51821}/api/session" --interval=1m --timeout=5s --retries=3
COPY --from=build_node_modules /app /app

# Move node_modules one directory up, so during development
# we don't have to mount it in a volume.
# This results in much faster reloading!
#
# Also, some node_modules might be native, and
# the architecture & OS of your development machine might differ
# than what runs inside of docker.
COPY --from=build_node_modules /node_modules /node_modules

# Copy the needed wg-password scripts
COPY --from=build_node_modules /app/wgpw.sh /bin/wgpw
RUN chmod +x /bin/wgpw

# Install Linux packages
RUN apk add --no-cache \
    bash \
    dpkg \
    dumb-init \
    iptables \
    nftables \
    wireguard-tools \
    iproute2 \
    procps \
    conntrack-tools

# Set Environment
# Debug logging is opt-in (docker run -e DEBUG=Server,WireGuard ...). It is
# deliberately not baked into production images: debug output is not audited
# as secret-free, and future settings (e.g. webhook secrets) must never risk
# being logged by default.
ENV DEBUG=

# Run Web UI
WORKDIR /app
CMD ["/usr/bin/dumb-init", "node", "server.js"]
