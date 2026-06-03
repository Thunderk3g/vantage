# Vantage console — static assets served by nginx.
# Build context is ./frontend. The .jsx files are compiled in-browser by
# Babel-standalone (loaded via CDN in index.html), so nginx just serves files;
# script[type=text/babel] reads the response body regardless of content-type.
#
# Hardened image: nginxinc/nginx-unprivileged runs as uid 101 (non-root) and
# listens on 8080 by default, serving /usr/share/nginx/html. Pinned by digest
# for reproducibility (tag: nginxinc/nginx-unprivileged:alpine).
FROM nginxinc/nginx-unprivileged@sha256:02c985e54bee40c14c6de677226f394d96c661944185d407e77ca73602f15e1b

COPY . /usr/share/nginx/html

# Non-default, non-privileged port — the container listens on 8080.
EXPOSE 8080

# Liveness: index.html is served at /, so a 200 there is a good signal.
# busybox wget ships with the alpine base.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://localhost:8080/ || exit 1
