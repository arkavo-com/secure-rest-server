# secure-rest-server
REST server focusing on security with minimal dependencies

## Security Features

### Secure Transmission
* Transport Layer Security (TLS) enabled and required
* CORS HTTP headers

### Authentication
* Account name and password authentication method
* Encrypted hash storage of password

### Session Management
* Secure-only, HTTP-only cookie
* Cross-Site Request Forgery (CSRF)

### Authorization
* Permission-based access control

### Input validation
* OpenAPI Specification (Swagger) generated from code used for input validation 

###### [OWASP reference](https://www.owasp.org/index.php/Web_Application_Security_Testing_Cheat_Sheet)

---

## Build

#### Dependency

`glide install`

#### Protocol Buffers
`protoc -I proto --go_out=security proto/*.proto`

`prototag -dir=security`

`pb-go-tag-bson -dir=security`

#### Certificate
`openssl genrsa -out server.key 2048`

`openssl req -new -x509 -sha256 -key server.key -out server.pem -days 365`
