package session

import (
	"strings"

	"github.com/arkavo-com/secure-rest-server/security"
	"github.com/arkavo-com/secure-rest-server/security/policy"
)

// enforceAuthenticateInitial checks initial login. returns roles
func enforceAuthenticateInitial(state security.Account_State) (bool, []string) {
	if security.Account_Initialized == state {
		roleString := policy.Password.AuthenticateInitialConsequence
		if "" != roleString {
			return true, strings.Split(roleString, ",")
		}
	}
	return false, nil
}

// enforceCsrf
func enforceCsrf() bool {
	return policy.Session.Csrf
}
