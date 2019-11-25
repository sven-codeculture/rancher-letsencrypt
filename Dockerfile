FROM golang:1.12.13-alpine3.10 as build

RUN apk --no-cache add make git && mkdir /build

COPY ./ /build

WORKDIR /build

RUN make build

FROM alpine:3.10

RUN apk add --no-cache ca-certificates openssl bash && update-ca-certificates

ENV LETSENCRYPT_RELEASE v2.0.0
ENV SSL_SCRIPT_COMMIT 08278ace626ada71384fc949bd637f4c15b03b53

RUN wget -O /usr/bin/update-rancher-ssl https://raw.githubusercontent.com/rancher/rancher/${SSL_SCRIPT_COMMIT}/server/bin/update-rancher-ssl && \
    chmod +x /usr/bin/update-rancher-ssl

COPY --from=build /build/package/rancher-entrypoint.sh /usr/bin/
COPY --from=build /build/build/rancher-letsencrypt-linux-amd64 /usr/bin/rancher-letsencrypt

RUN chmod +x /usr/bin/rancher-letsencrypt

EXPOSE 80
ENTRYPOINT ["/usr/bin/rancher-entrypoint.sh"]
