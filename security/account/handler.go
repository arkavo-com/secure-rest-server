package account

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"net/http"
	"secure-rest-server/security"
	"secure-rest-server/security/authorization"
	"secure-rest-server/security/rest"
	"secure-rest-server/security/session"
	"time"

	"github.com/go-openapi/spec"
	"github.com/golang/protobuf/proto"
)

var (
	accountCREATE         = spec.NewOperation("accountCreate")
	accountREAD           = spec.NewOperation("accountRead")
	accountREADAll        = spec.NewOperation("accountReadAll")
	accountReadAllHead    = spec.NewOperation("accountReadAllHead")
	accountUPDATEPASSWORD = spec.NewOperation("accountUpdatePassword")
	accountDELETE         = spec.NewOperation("accountDelete")
	// parameters
	accountParameterName     spec.Parameter
	accountParameterPassword spec.Parameter
)

func RegisterHttpHandler(paths spec.Paths, ar security.AccountReader) {
	p := "/account"
	http.HandleFunc(p, session.HandlerFunc(serveHTTP))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Get:  accountREADAll,
			Post: accountCREATE,
			Head: accountReadAllHead,
		},
	}
	accountCREATE.Parameters = append(accountCREATE.Parameters, rest.BodyParameter(spec.Schema{
		SchemaProps: spec.SchemaProps{
			Required:   []string{"name", "roles"},
			Properties: map[string]spec.Schema{},
		},
	}))
	accountCREATE.Consumes = []string{"application/json"}
	accountCREATE.Produces = []string{"application/json"}
	p = "/account/{name}"
	rest.PathHandlerFunc(p, session.HandlerFunc(serveHTTPparameter))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Get:    accountREAD,
			Delete: accountDELETE,
		},
	}
	accountParameterName = spec.Parameter{
		ParamProps: spec.ParamProps{
			Name:     "name",
			In:       "path",
			Required: true,
			Schema: &spec.Schema{
				SchemaProps: spec.SchemaProps{
					MinLength: &[]int64{2}[0],
					MaxLength: &[]int64{256}[0],
					Pattern:   "[0-9a-fA-F]",
				},
			},
		},
	}
	accountREAD.Parameters = append(accountREAD.Parameters, accountParameterName)
	p = "/account/password/{name}"
	rest.PathHandlerFunc(p, rest.PasswordHandlerFunc(ar, session.HandlerFunc(serveHTTPpassword)))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Put: accountUPDATEPASSWORD,
		},
	}
	accountUPDATEPASSWORD.Consumes = []string{"application/x-www-form-urlencoded"}
	accountUPDATEPASSWORD.Parameters = append(accountUPDATEPASSWORD.Parameters, accountParameterName)
	accountParameterPassword = spec.Parameter{
		ParamProps: spec.ParamProps{
			Name:     "p",
			In:       "formData",
			Required: true,
			Schema: &spec.Schema{
				SchemaProps: spec.SchemaProps{
					MinLength: &[]int64{2}[0],
					MaxLength: &[]int64{1024}[0],
					Pattern:   "[0-9a-fA-F]",
				},
			},
		},
	}
	accountUPDATEPASSWORD.Parameters = append(accountUPDATEPASSWORD.Parameters, accountParameterPassword)
}

func serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "HEAD":
		modifiedTime := time.Now()
		w.Header().Set("last-modified", modifiedTime.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	case "GET":
		err := authorize(r.Context(), security.Account_READ)
		if rest.Errored(w, err) {
			return
		}
		accounts, err := s.readAccounts()
		if rest.Errored(w, err) {
			return
		}
		pbs := make([]proto.Message, len(accounts), len(accounts))
		for i := 0; i < len(accounts); i++ {
			pbs[i] = accounts[i]
		}
		rest.WriteProtos(w, pbs)
	case "POST":
		err := authorize(r.Context(), security.Account_CREATE)
		if rest.Errored(w, err) {
			return
		}
		a := security.Account{}
		err = rest.Validate(r, accountCREATE, &a)
		if rest.Errored(w, err) {
			return
		}
		// state
		a.State = transition(a.State, security.Account_CREATE)
		// salt
		token := make([]byte, 32)
		rand.Read(token)
		a.Salt = base32.StdEncoding.EncodeToString(token)
		err = s.createAccount(&a)
		if err == ErrDuplicate {
			err = rest.ValidationErrors{
				rest.ValidationError{
					Property: "name",
					Rule:     "Unique",
				},
			}
		}
		if rest.Errored(w, err) {
			return
		}
		rest.WriteProto(w, &a)
	}
}

func serveHTTPparameter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		err := authorize(r.Context(), security.Account_READ)
		if rest.Errored(w, err) {
			return
		}
		n, err := rest.ValidateParameter(*r, accountParameterName)
		if rest.Errored(w, err) {
			return
		}
		a, err := s.ReadAccount(n)
		if rest.Errored(w, err) {
			return
		}
		rest.WriteProto(w, a)
	case "PUT":
		err := authorize(r.Context(), security.Account_UPDATE_PASSWORD)
		if rest.Errored(w, err) {
			return
		}
		// account
		n, err := rest.ValidateParameter(*r, accountParameterName)
		if rest.Errored(w, err) {
			return
		}
		a, err := s.ReadAccount(n)
		if rest.Errored(w, err) {
			return
		}
		na := security.Account{}
		err = rest.Validate(r, accountCREATE, &na)
		if rest.Errored(w, err) {
			return
		}
		// TODO merge, consider readonly and hidden
		err = s.updateAccount(a)
		if rest.Errored(w, err) {
			return
		}
		rest.WriteProto(w, a)
	case "DELETE":
		err := authorize(r.Context(), security.Account_DEACTIVATE)
		if rest.Errored(w, err) {
			return
		}
		// account
		n, err := rest.ValidateParameter(*r, accountParameterName)
		if rest.Errored(w, err) {
			return
		}
		a, err := s.ReadAccount(n)
		if rest.Errored(w, err) {
			return
		}
		// state
		a.State = transition(a.State, security.Account_DEACTIVATE)
		err = s.updateAccount(a)
		if rest.Errored(w, err) {
			return
		}
		rest.WriteProto(w, a)
	}
}

func serveHTTPpassword(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "PUT":
		err := authorize(r.Context(), security.Account_UPDATE_PASSWORD)
		if rest.Errored(w, err) {
			return
		}
		// account
		n, err := rest.ValidateParameter(*r, accountParameterName)
		if rest.Errored(w, err) {
			return
		}
		a, err := s.ReadAccount(n)
		if rest.Errored(w, err) {
			return
		}
		// hash
		h, err := rest.ValidateParameter(*r, accountParameterPassword)
		a.Hash = h
		// state
		a.State = transition(a.State, security.Account_UPDATE_PASSWORD)
		err = s.updateAccount(a)
		if rest.Errored(w, err) {
			return
		}
		rest.WriteProto(w, a)
	}
}

func authorize(ctx context.Context, a security.Account_Action) error {
	return authorization.Authorize(ctx, security.AccountPermission.Class, security.AccountPermission.Actions[a])
}

// transition provides a guard to protect from invalid transitions
func transition(state security.Account_State, trigger security.Account_Action) security.Account_State {
	switch state {
	case security.Account_nonstate:
		switch trigger {
		case security.Account_CREATE:
			return security.Account_Initialized
		}
	case security.Account_Initialized:
		switch trigger {
		case security.Account_ACTIVATE, security.Account_UPDATE_PASSWORD:
			return security.Account_Activated
		}
	case security.Account_Activated:
		switch trigger {
		case security.Account_LOCK:
			return security.Account_Locked
		case security.Account_DEACTIVATE:
			return security.Account_Deactivated
		}
	case security.Account_Locked:
		switch trigger {
		case security.Account_DEACTIVATE:
			return security.Account_Deactivated
		case security.Account_INITIALIZE:
			return security.Account_Initialized
		}
	}
	return state
}