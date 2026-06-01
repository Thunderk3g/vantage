# Vantage console — static assets served by nginx.
# Build context is ./frontend. The .jsx files are compiled in-browser by
# Babel-standalone (loaded via CDN in index.html), so nginx just serves files;
# script[type=text/babel] reads the response body regardless of content-type.
FROM nginx:alpine

COPY . /usr/share/nginx/html

EXPOSE 80
