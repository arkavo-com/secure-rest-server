package session

import (
	"secure-rest-server/security"
	"strings"
)

// enforceAuthenticateInitial checks initial login. returns roles
func enforceAuthenticateInitial(pr security.PolicyReader, state security.Account_State) (bool, []string) {
	if security.Account_Initialized == state {
		roleString := pr.ReadPolicy().Password.AuthenticateInitialConsequence
		if "" != roleString {
			return true, strings.Split(roleString, ",")
		}
	}
	return false, nil
}

// enforceCsrf
func enforceCsrf(pr security.PolicyReader) bool {
	return pr.ReadPolicy().Session.Csrf
}
