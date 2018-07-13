package configuration

import (
	"log"
	"net/http"
	"secure-rest-server/security"
	"protobuf/jsonpb"
)

var (
	Account    security.Configuration_Account
	Permission security.Configuration_Permission
	Policy     security.Configuration_Policy
	Role       security.Configuration_Role
	Session    security.Configuration_Session
	Server     security.Configuration_Server
)

type httpGetter interface {
	Get(url string) (resp *http.Response, err error)
}

func init() {
	getSet(&http.Client{})
}

func getSet(httpClient httpGetter) {
	// default
	Account = security.Configuration_Account{
		Store: &security.Configuration_Store{
			Url: "memdb://",
		},
	}
	Permission = security.Configuration_Permission{
		Store: &security.Configuration_Store{
			Url: "memdb://",
		},
	}
	Policy = security.Configuration_Policy{
		Store: &security.Configuration_Store{
			Url: "memdb://",
		},
	}
	Role = security.Configuration_Role{
		Store: &security.Configuration_Store{
			Url: "memdb://",
		},
	}
	Session = security.Configuration_Session{
		Store: &security.Configuration_Store{
			Url:   "memdb://",
			Redis: &security.Configuration_Store_Redis{},
		},
	}
	Server = security.Configuration_Server{
		Address: ":1337",
		Origin: "https://localhost:3000",
		Key: "server.key",
		Certificate: "server.pem",
	}
	// get
	r, err := httpClient.Get("http://127.0.0.1:8500/v1/kv/arkavo/configuration?raw")
	if err != nil {
		log.Println("consul unreachable", err)
		// TODO log defaults
		return
	}
	if r.StatusCode != http.StatusOK {
		log.Println("bad response code", r.StatusCode, r.Request.URL)
		// TODO log defaults
		return
	}
	var config security.Configuration
	// TODO add validation
	err = jsonpb.Unmarshal(r.Body, &config)
	if err != nil {
		log.Println("bad JSON", err)
		return
	}
	// set
	Account = *config.Account
	Permission = *config.Permission
	Policy = *config.Policy
	Role = *config.Role
	Session = *config.Session
	Server = *config.Server
	httpClient = nil
}
