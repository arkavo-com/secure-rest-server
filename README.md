# secure-rest-server
REST server focusing on security with minimal dependencies

### Build
`protoc -I proto --go_out=security proto/*.proto`

`prototag -dir=security`

`pb-go-tag-bson -dir=security`

#### Certificate
`openssl genrsa -out server.key 2048`

`openssl req -new -x509 -sha256 -key server.key -out server.pem -days 365`
