FROM scratch
COPY script/ca-certificates.crt /etc/ssl/certs/
COPY dist/traefik_linux-arm /traefik
EXPOSE 80
VOLUME ["/tmp"]
ENTRYPOINT ["/traefik"]
