package configuration

import (
	"encoding/json"
	"secure-rest-server/security"
	"testing"
)

func TestJson(t *testing.T) {
	c := security.Configuration{
		Account:              &Account,
		Permission:           &Permission,
		Policy:               &Policy,
		Role:                 &Role,
		Session:              &Session,
		Server:               &Server,
	}
	b, err := json.Marshal(&c)
	if err != nil {
		t.Error(err)
	}
	t.Log(string(b))
}
