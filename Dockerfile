ARG GO_VERSION=latest

FROM golang:$GO_VERSION as builder
WORKDIR /build/
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -v -a -installsuffix cgo -o . ./...

FROM golang:$GO_VERSION as tester
WORKDIR /test/
COPY . .
RUN go test ./...
RUN CGO_ENABLED=1 GOOS=linux go build -v -a -race -installsuffix cgo -o . ./...

FROM scratch as runner
EXPOSE 1337
ENTRYPOINT ["/arkavo-server"]
COPY --from=builder /build/arkavo-server /