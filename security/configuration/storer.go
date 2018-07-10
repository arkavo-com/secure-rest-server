package configuration

import (
	"bytes"
	"log"
	"net/http"
	"secure-rest-server/security"
)

func init() {
	httpClient := &http.Client{}
	// store
	buf := new(bytes.Buffer)
	r, err := httpClient.Get("http://127.0.0.1:8500/v1/kv/pbac/store?raw")
	if err != nil {
		log.Println("consul unreachable, using defaults")
		log.Println(err)
		buf.WriteString("memdb://")
	}
	if err == nil && r.StatusCode == http.StatusOK {
		buf.ReadFrom(r.Body)
	} else {
		log.Println("curl --request PUT --data \"mongodb://localhost:27107\" http://127.0.0.1:8500/v1/kv/pbac/store")
	}
	Account = security.Configuration_Account{
		Store: &security.Configuration_Store{
			Url: buf.String(),
		},
	}
	Permission = security.Configuration_Permission{
		Store: &security.Configuration_Store{
			Url: buf.String(),
		},
	}
	Policy = security.Configuration_Policy{
		Store: &security.Configuration_Store{
			Url: buf.String(),
		},
	}
	Role = security.Configuration_Role{
		Store: &security.Configuration_Store{
			Url: buf.String(),
		},
	}
	Session = security.Configuration_Session{
		Store: &security.Configuration_Store{
			Url: buf.String(),
		},
	}
	// redis
	buf = new(bytes.Buffer)
	r, err = httpClient.Get("http://127.0.0.1:8500/v1/kv/pbac/store/session?raw")
	if err == nil && r.StatusCode == http.StatusOK {
		buf.ReadFrom(r.Body)
		Session.Store.Redis.Network = "tcp"
		Session.Store.Redis.Address = buf.String()
	} else {
		log.Println("curl --request PUT --data \"redis://localhost:6379\" http://127.0.0.1:8500/v1/kv/pbac/store/session")
	}
	// server
	Server.Address = ":1337" // default
	r, err = httpClient.Get("http://127.0.0.1:8500/v1/kv/pbac/server/address?raw")
	if err == nil && r.StatusCode == http.StatusOK {
		buf = new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		Server.Address = buf.String()
	} else {
		log.Println("curl --request PUT --data \":https\" http://127.0.0.1:8500/v1/kv/pbac/server/address")
	}
	Server.Certificate = "server.pem" //default
	r, err = httpClient.Get("http://127.0.0.1:8500/v1/kv/pbac/server/certificate?raw")
	if err == nil && r.StatusCode == http.StatusOK {
		buf = new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		Server.Certificate = buf.String()
	} else {
		log.Println("curl --request PUT --data \"server.pem\" http://127.0.0.1:8500/v1/kv/pbac/server/certificate")
	}
	Server.Key = "server.key" // default
	r, err = httpClient.Get("http://127.0.0.1:8500/v1/kv/pbac/server/key?raw")
	if err == nil && r.StatusCode == http.StatusOK {
		buf = new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		Server.Key = buf.String()
	} else {
		log.Println("curl --request PUT --data \"server.key\" http://127.0.0.1:8500/v1/kv/pbac/server/key")
	}
	Server.Origin = "https://localhost:3000" //default
	r, err = httpClient.Get("http://127.0.0.1:8500/v1/kv/pbac/server/origin?raw")
	if err == nil && r.StatusCode == http.StatusOK {
		buf = new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		Server.Origin = buf.String()
	} else {
		log.Println("curl --request PUT --data \"https://localhost:3000\" http://127.0.0.1:8500/v1/kv/pbac/server/origin")
	}
}

var (
	Account    security.Configuration_Account
	Permission security.Configuration_Permission
	Policy     security.Configuration_Policy
	Role       security.Configuration_Role
	Session    security.Configuration_Session
	Server     security.Configuration_Server
)
