package session

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"log"
	"net/http"

	"github.com/arkavo-com/secure-rest-server/security"
	"github.com/arkavo-com/secure-rest-server/security/authorization"
	"github.com/arkavo-com/secure-rest-server/security/policy"
	"github.com/arkavo-com/secure-rest-server/security/rest"
	"github.com/go-openapi/spec"
)

var (
	// operation
	operationCreate = &spec.Operation{
		OperationProps: spec.OperationProps{
			ID:       "sessionCreate",
			Consumes: []string{"application/x-www-form-urlencoded"},
			Produces: []string{"application/json"},
			Parameters: []spec.Parameter{
				parameterAccountName,
				parameterAccountPassword,
			},
			Responses: rest.CreateResponses(),
		},
	}
	operationRead = &spec.Operation{
		OperationProps: spec.OperationProps{
			ID:        "sessionRead",
			Produces:  []string{"application/json"},
			Responses: rest.ReadResponses(),
		},
	}
	operationTerminate = &spec.Operation{
		OperationProps: spec.OperationProps{
			ID:        "sessionTerminate",
			Produces:  []string{"application/json"},
			Responses: rest.DeleteResponses(),
		},
	}
	// parameter
	parameterAccountName = spec.Parameter{
		SimpleSchema: spec.SimpleSchema{
			Type: "string",
		},
		ParamProps: spec.ParamProps{
			Name:     "name",
			In:       "path",
			Required: true,
			Schema: &spec.Schema{
				SchemaProps: spec.SchemaProps{
					MinLength: &[]int64{int64(policy.Account.LengthMinimum)}[0],
					MaxLength: &[]int64{int64(policy.Account.LengthMaximum)}[0],
					Pattern:   policy.Account.Pattern,
				},
			},
		},
	}
	parameterAccountPassword = spec.Parameter{
		SimpleSchema: spec.SimpleSchema{
			Type: "string",
		},
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
	// reader
	accountReader security.AccountReader
	roleReader    security.RoleReader
)

// HandlerFunc checks session cookie and CSRF header
func HandlerFunc(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("c")
		if err != nil {
			w.Header().Set("content-type", "text/plain")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
			log.Println("session missing")
			return
		}
		si := c.Value
		ss, err := s.readSession(si)
		if err != nil {
			w.Header().Set("content-type", "text/plain")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
			log.Println("session not found")
			return
		}
		if enforceCsrf() && ss.Csrf != r.Header.Get("x-csrf-token") {
			w.Header().Set("content-type", "text/plain")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
			log.Println("csrf error", ss.Account)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), "session.context", ss))
		f(w, r)
	}
}

// HandlePath registers http.HandleFunc and spec.Operation for paths
func HandlePath(paths spec.Paths, ar security.AccountReader, rr security.RoleReader) {
	accountReader = ar
	roleReader = rr
	p := "/session"
	http.HandleFunc(p, HandlerFunc(serveHTTP))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Get:    operationRead,
			Delete: operationTerminate,
		},
	}
	p = "/session/{name}"
	rest.PathHandlerFunc(p, rest.PasswordHandlerFunc(ar, serveHTTPparameter))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Post: operationCreate,
		},
	}
}

func serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		v := r.Context().Value("session.context")
		ss, ok := v.(*security.Session)
		if !ok && rest.Errored(w, rest.ErrUnauthorized) {
			return
		}
		// remove CSRF, once per session
		ss.Csrf = ""
		rest.WriteProto(w, ss)
	case "DELETE":
		err := authorize(r.Context(), security.Session_TERMINATE)
		if rest.Errored(w, err) {
			return
		}
		v := r.Context().Value("session.context")
		ss, ok := v.(*security.Session)
		if !ok {
			return
		}
		ss.State = transition(ss.State, security.Session_TERMINATE)
		s.deleteSession(ss.Id)
		w.WriteHeader(http.StatusNoContent)
	}
}

func serveHTTPparameter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		n, err := rest.ValidateParameter(*r, parameterAccountName)
		if rest.Errored(w, err) {
			return
		}
		ac, err := accountReader.ReadAccount(n)
		if err != nil {
			err = rest.ValidationErrors{
				rest.ValidationError{
					Property: "name",
					Rule:     "Exist",
				},
			}
		}
		if rest.Errored(w, err) {
			return
		}
		// check password hash
		if ac.Hash != r.Form.Get("p") {
			err = rest.ValidationErrors{
				rest.ValidationError{
					Property: "p",
					Rule:     "Equal",
				},
			}
		}
		if rest.Errored(w, err) {
			return
		}
		enforce, roles := enforceAuthenticateInitial(ac.State)
		if enforce {
			ac.Roles = roles
		}
		var permissions []*security.Permission
		for _, role := range ac.Roles {
			// TODO review database calls in loop
			ro, err := roleReader.ReadRole(role)
			if rest.Errored(w, err) {
				return
			}
			permissions = append(permissions, ro.Permissions...)
		}
		token := make([]byte, 32)
		rand.Read(token)
		csrf := make([]byte, 32)
		rand.Read(csrf)
		ss := security.Session{
			Id:          base32.StdEncoding.EncodeToString(token),
			Csrf:        base32.StdEncoding.EncodeToString(csrf),
			Account:     ac.Name,
			Permissions: permissions,
		}
		ss.State = transition(ss.State, security.Session_CREATE)
		err = s.createSession(ss)
		if rest.Errored(w, err) {
			return
		}
		if enforce {
			ss.State = transition(ss.State, security.Session_REDUCE)
		}
		c := http.Cookie{
			Name:     "c",
			Value:    ss.Id,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			// TODO Expires:
			// TODO MaxAge:
		}
		http.SetCookie(w, &c)
		ss.Id = "" // do not expose
		rest.WriteProtoCreated(w, &ss, "/session")
	}
}

func authorize(ctx context.Context, a security.Session_Action) error {
	return authorization.Authorize(ctx, security.SessionPermission.Class, security.Session_Action_name[int32(a)])
}

// transition provides a guard to protect from invalid transitions
func transition(state security.Session_State, trigger security.Session_Action) security.Session_State {
	switch state {
	case security.Session_initial:
		switch trigger {
		case security.Session_CREATE:
			return security.Session_Activated
		}
	case security.Session_Activated:
		switch trigger {
		case security.Session_IDLE, security.Session_REDUCE:
			return security.Session_Reduced
		case security.Session_EXPIRE, security.Session_TERMINATE:
			return security.Session_Deactivated
		}
	case security.Session_Reduced:
		switch trigger {
		case security.Session_EXPIRE, security.Session_TERMINATE:
			return security.Session_Deactivated
		}
	}
	return state
}
