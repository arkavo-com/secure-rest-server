FROM golang:1.13-alpine as builder
WORKDIR /build
RUN apk add --update alpine-sdk
COPY . .
ENTRYPOINT ["go", "build"]
CMD ["-v", "-a", "-o", ".", "./..."]
# "-race",  fails x86_64-alpine-linux-musl/8.3.0/