# Build the plugin on Alpine/musl
FROM alpine:3.19 AS build

RUN apk add --no-cache build-base openssl-dev mosquitto-dev

WORKDIR /src
COPY auth_derive.c .

# Disable fortify just in case, and build as a shared object
RUN gcc -fPIC -shared -O2 -D_FORTIFY_SOURCE=0 -o auth_derive.so auth_derive.c -lcrypto

# Runtime: your existing mosquitto image (musl/alpine)
FROM eclipse-mosquitto:latest

COPY --from=build /src/auth_derive.so /mosquitto/plugins/auth_derive.so
