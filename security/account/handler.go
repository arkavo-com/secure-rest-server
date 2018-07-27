package account

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"net/http"

	"secure-rest-server/security"
	"secure-rest-server/security/authorization"
	"secure-rest-server/security/policy"
	"secure-rest-server/security/rest"
	"secure-rest-server/security/session"

	"github.com/go-openapi/spec"
	"github.com/golang/protobuf/proto"
)

var (
	// operation
	operationCreate = &spec.Operation{
		OperationProps: spec.OperationProps{
			ID:          "accountCreate",
			Description: "",
			Consumes:    []string{"application/json"},
			Produces:    []string{"application/json"},
			Parameters: []spec.Parameter{
				rest.BodyParameter(spec.Schema{
					SchemaProps: spec.SchemaProps{
						Required:   []string{"name", "roles"},
						Properties: map[string]spec.Schema{},
					},
				}),
			},
		},
	}
	operationRead = &spec.Operation{
		OperationProps: spec.OperationProps{
			ID:       "accountRead",
			Consumes: []string{"application/json"},
			Produces: []string{"application/json"},
			Parameters: []spec.Parameter{
				parameterName,
			},
		},
	}
	operationReadAll = &spec.Operation{
		OperationProps: spec.OperationProps{
			ID:       "accountReadAll",
			Produces: []string{"application/json"},
		},
	}
	operationUpdatePassword = &spec.Operation{
		OperationProps: spec.OperationProps{
			ID:       "accountUpdatePassword",
			Consumes: []string{"application/x-www-form-urlencoded"},
			Produces: []string{"application/json"},
			Parameters: []spec.Parameter{
				parameterName,
				parameterPassword,
			},
		},
	}
	operationDelete = &spec.Operation{
		OperationProps: spec.OperationProps{
			ID: "accountDelete",
			Parameters: []spec.Parameter{
				parameterName,
			},
		},
	}
	// parameter
	parameterName = spec.Parameter{
		ParamProps: spec.ParamProps{
			Name:     "name",
			In:       "path",
			Required: true,
			Schema: &spec.Schema{
				SchemaProps: spec.SchemaProps{
					MinLength: &[]int64{int64(policy.Password.LengthMinimum)}[0],
					MaxLength: &[]int64{int64(policy.Password.LengthMaximum)}[0],
					Pattern:   policy.Password.Pattern,
				},
			},
		},
	}
	parameterPassword = spec.Parameter{
		ParamProps: spec.ParamProps{
			Name:     "p",
			In:       "formData",
			Required: true,
			Schema: &spec.Schema{
				SchemaProps: spec.SchemaProps{
					MinLength: &[]int64{int64(policy.Password.LengthMinimum)}[0],
					MaxLength: &[]int64{int64(policy.Password.LengthMaximum)}[0],
					Pattern:   policy.Password.Pattern,
				},
			},
		},
	}
)
// HandlePath registers http.HandleFunc and spec.Operation for paths
func HandlePath(paths spec.Paths, ar security.AccountReader) {
	p := "/account"
	http.HandleFunc(p, session.HandlerFunc(serveHTTP))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Get:  operationReadAll,
			Post: operationCreate,
		},
	}
	p = "/account/{name}"
	rest.PathHandlerFunc(p, session.HandlerFunc(serveHTTPparameter))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Get:    operationRead,
			Delete: operationDelete,
		},
	}
	p = "/account/password/{name}"
	rest.PathHandlerFunc(p, rest.PasswordHandlerFunc(ar, session.HandlerFunc(serveHTTPpassword)))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Put: operationUpdatePassword,
		},
	}
}

func serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
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
		err = rest.Validate(r, operationCreate, &a)
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
		n, err := rest.ValidateParameter(*r, parameterName)
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
		n, err := rest.ValidateParameter(*r, parameterName)
		if rest.Errored(w, err) {
			return
		}
		a, err := s.ReadAccount(n)
		if rest.Errored(w, err) {
			return
		}
		na := security.Account{}
		err = rest.Validate(r, operationCreate, &na)
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
		n, err := rest.ValidateParameter(*r, parameterName)
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
		w.WriteHeader(http.StatusNoContent)
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
		n, err := rest.ValidateParameter(*r, parameterName)
		if rest.Errored(w, err) {
			return
		}
		a, err := s.ReadAccount(n)
		if rest.Errored(w, err) {
			return
		}
		// hash
		h, err := rest.ValidateParameter(*r, parameterPassword)
		if rest.Errored(w, err) {
			return
		}
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
	return authorization.Authorize(ctx, security.AccountPermission.Class, security.Account_Action_name[int32(a)])
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
