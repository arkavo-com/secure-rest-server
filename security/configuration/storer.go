package configuration

import (
	"log"
	"net/http"

	"github.com/arkavo-com/secure-rest-server/security"
	"github.com/golang/protobuf/jsonpb"
)

var (
	// Account configuration
	Account security.Configuration_Account
	// Permission configuration
	Permission security.Configuration_Permission
	// Policy configuration
	Policy security.Configuration_Policy
	// Role configuration
	Role security.Configuration_Role
	// Session configuration
	Session security.Configuration_Session
	// Server configuration
	Server security.Configuration_Server
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
		Address:     ":1337",
		Origin:      "https://localhost:3000",
		Key:         "server.key",
		Certificate: "server.pem",
		Host:        "localhost:1337",
	}
	// get
	r, err := httpClient.Get("http://127.0.0.1:8500/v1/kv/arkavo/configuration?raw")
	if err != nil {
		log.Println("consul unreachable", err)
		logConfiguration()
		return
	}
	if r.StatusCode != http.StatusOK {
		log.Println("bad response code", r.StatusCode, r.Request.URL)
		logConfiguration()
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

func logConfiguration() {
	m := jsonpb.Marshaler{
		EmitDefaults: true,
		Indent:       "  ",
	}
	s, _ := m.MarshalToString(&security.Configuration{
		Account:    &Account,
		Permission: &Permission,
		Policy:     &Policy,
		Role:       &Role,
		Session:    &Session,
		Server:     &Server,
	})
	log.Println("configuration: \n", s)
}
