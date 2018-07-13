package configuration

import (
	"encoding/json"
	"secure-rest-server/security"
	"testing"
	"net/http"
	"io/ioutil"
	"bytes"
	"github.com/stretchr/testify/assert"
	"os"
	"io"
	"strings"
	"net/url"
)

func TestMain(m *testing.M) {
	c = security.Configuration{
		Account: &security.Configuration_Account{
			Store: &security.Configuration_Store{
				Url: "",
			},
		},
		Permission: &security.Configuration_Permission{
			Store: &security.Configuration_Store{
				Url: "",
			},
		},
		Policy: &security.Configuration_Policy{
			Store: &security.Configuration_Store{
				Url: "",
			},
		},
		Role: &security.Configuration_Role{
			Store: &security.Configuration_Store{
				Url: "",
			},
		},
		Session: &security.Configuration_Session{
			Store: &security.Configuration_Store{
				Url:   "",
				Redis: &security.Configuration_Store_Redis{},
			},
		},
		Server: &security.Configuration_Server{
		},
	}
	c.Account.Store.Url = "mongodb://"
	c.Permission.Store.Url = c.Account.Store.Url
	c.Policy.Store.Url = c.Account.Store.Url
	c.Role.Store.Url = c.Account.Store.Url
	c.Session.Store.Url = c.Account.Store.Url
	c.Server.Address = ":https"
	b, _ = json.Marshal(&c)
	os.Exit(m.Run())
}

var (
	c security.Configuration
	b []byte
)

type mockClient struct {
	http.Client
	statusCode int
	readCloser io.ReadCloser
}

func (c *mockClient) Get(u string) (*http.Response, error) {
	header := http.Header{}
	ru, _ := url.Parse(u)
	resp := http.Response{
		StatusCode: c.statusCode,
		Header:     header,
		Body:       c.readCloser,
		Request:    &http.Request{
			URL: ru,
		},
	}
	return &resp, nil
}

func TestJson(t *testing.T) {
	getSet(&mockClient{
		statusCode: 200,
		readCloser: ioutil.NopCloser(bytes.NewReader(b)),
	})
	assert.Equal(t, c.Account.Store.Url, Account.Store.Url)
	assert.Equal(t, c.Permission.Store.Url, Permission.Store.Url)
	assert.Equal(t, c.Policy.Store.Url, Policy.Store.Url)
	assert.Equal(t, c.Role.Store.Url, Role.Store.Url)
	assert.Equal(t, c.Session.Store.Url, Session.Store.Url)
	assert.Equal(t, c.Server.Address, Server.Address)
}

func TestConnectionBad(t *testing.T) {
	getSet(&mockClient{
		statusCode: 500,
		readCloser: ioutil.NopCloser(strings.NewReader("")),
	})
	assert.NotEqual(t, c.Account.Store.Url, Account.Store.Url)
	assert.NotEqual(t, c.Permission.Store.Url, Permission.Store.Url)
	assert.NotEqual(t, c.Policy.Store.Url, Policy.Store.Url)
	assert.NotEqual(t, c.Role.Store.Url, Role.Store.Url)
	assert.NotEqual(t, c.Session.Store.Url, Session.Store.Url)
	assert.NotEqual(t, c.Server.Address, Server.Address)
}

func TestConnectionMissing(t *testing.T) {
	getSet(&mockClient{
		statusCode: 404,
		readCloser: ioutil.NopCloser(strings.NewReader("")),
	})
	assert.NotEqual(t, c.Account.Store.Url, Account.Store.Url)
	assert.NotEqual(t, c.Permission.Store.Url, Permission.Store.Url)
	assert.NotEqual(t, c.Policy.Store.Url, Policy.Store.Url)
	assert.NotEqual(t, c.Role.Store.Url, Role.Store.Url)
	assert.NotEqual(t, c.Session.Store.Url, Session.Store.Url)
	assert.NotEqual(t, c.Server.Address, Server.Address)
}

func TestJsonBad(t *testing.T) {
	getSet(&mockClient{
		statusCode: 200,
		readCloser: ioutil.NopCloser(strings.NewReader("{\"bad\":true}")),
	})
	assert.NotEqual(t, c.Account.Store.Url, Account.Store.Url)
	assert.NotEqual(t, c.Permission.Store.Url, Permission.Store.Url)
	assert.NotEqual(t, c.Policy.Store.Url, Policy.Store.Url)
	assert.NotEqual(t, c.Role.Store.Url, Role.Store.Url)
	assert.NotEqual(t, c.Session.Store.Url, Session.Store.Url)
	assert.NotEqual(t, c.Server.Address, Server.Address)
}

func TestJsonInvalid(t *testing.T) {
	getSet(&mockClient{
		statusCode: 200,
		readCloser: ioutil.NopCloser(strings.NewReader("bad")),
	})
	assert.NotEqual(t, c.Account.Store.Url, Account.Store.Url)
	assert.NotEqual(t, c.Permission.Store.Url, Permission.Store.Url)
	assert.NotEqual(t, c.Policy.Store.Url, Policy.Store.Url)
	assert.NotEqual(t, c.Role.Store.Url, Role.Store.Url)
	assert.NotEqual(t, c.Session.Store.Url, Session.Store.Url)
	assert.NotEqual(t, c.Server.Address, Server.Address)
}
