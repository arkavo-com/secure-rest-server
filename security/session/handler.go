package session

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"log"
	"net/http"

	"secure-rest-server/security"
	"secure-rest-server/security/authorization"
	"secure-rest-server/security/rest"

	"github.com/go-openapi/spec"
)

var (
	sessionCREATE            = spec.NewOperation("sessionCreate")
	sessionREAD              = spec.NewOperation("sessionRead")
	sessionTERMINATE         = spec.NewOperation("sessionTerminate")
	accountParameterName     spec.Parameter
	accountParameterPassword spec.Parameter
	accountReader            security.AccountReader
	roleReader               security.RoleReader
	policyReader             security.PolicyReader
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
		if enforceCsrf(policyReader) && ss.Csrf != r.Header.Get("x-csrf-token") {
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

func RegisterHttpHandler(paths spec.Paths, ar security.AccountReader, rr security.RoleReader, pr security.PolicyReader) {
	accountReader = ar
	roleReader = rr
	policyReader = pr
	p := "/session"
	http.HandleFunc(p, HandlerFunc(serveHTTP))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Get:    sessionREAD,
			Delete: sessionTERMINATE,
		},
	}
	p = "/session/{name}"
	rest.PathHandlerFunc(p, rest.PasswordHandlerFunc(ar, serveHTTP))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Post: sessionCREATE,
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
	sessionCREATE.Parameters = append(sessionCREATE.Parameters, accountParameterName)
	sessionCREATE.Consumes = []string{"application/x-www-form-urlencoded"}
	sessionCREATE.Parameters = append(sessionCREATE.Parameters, accountParameterPassword)
}

func serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
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
	case "GET":
		v := r.Context().Value("session.context")
		ss, ok := v.(*security.Session)
		if !ok && rest.Errored(w, rest.ErrUnauthorized) {
			return
		}
		// remove CSRF, once per session
		ss.Csrf = ""
		rest.WriteProto(w, ss)
	case "POST":
		n, err := rest.ValidateParameter(*r, accountParameterName)
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
		enforce, roles := enforceAuthenticateInitial(policyReader, ac.State)
		if enforce {
			ac.Roles = roles
		}
		var permissions []*security.Permission
		for _, role := range ac.Roles {
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
		rest.WriteProto(w, &ss)
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
