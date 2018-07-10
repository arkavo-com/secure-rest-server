package policy

import (
	"context"
	"net/http"
	"secure-rest-server/security"
	"secure-rest-server/security/authorization"
	"secure-rest-server/security/rest"
	"secure-rest-server/security/session"

	"github.com/go-openapi/spec"
)

var (
	policyREAD   = spec.NewOperation("policyRead")
	policyUPDATE = spec.NewOperation("policyUpdate")
)

func RegisterHttpHandler(paths spec.Paths) {
	p := "/policy"
	http.HandleFunc(p, session.HandlerFunc(serveHTTP))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Get: policyREAD,
			Put: policyUPDATE,
		},
	}
	policyUPDATE.Parameters = append(policyUPDATE.Parameters, rest.BodyParameter(spec.Schema{
		SchemaProps: spec.SchemaProps{
			Required:   []string{"account", "password", "session"},
			Properties: map[string]spec.Schema{},
		},
	}))
}

func serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		err := authorize(r.Context(), security.Policy_READ)
		if rest.Errored(w, err) {
			return
		}
		p := s.ReadPolicy()
		rest.WriteProto(w, p)
		return
	case "PUT":
		err := authorize(r.Context(), security.Policy_UPDATE)
		if rest.Errored(w, err) {
			return
		}
		policy := security.Policy{}
		err = rest.Validate(r, policyUPDATE, &policy)
		if rest.Errored(w, err) {
			return
		}
		err = s.updatePolicy(&policy)
		if rest.Errored(w, err) {
			return
		}
		rest.WriteProto(w, &policy)
		return
	}
}

func authorize(ctx context.Context, a security.Policy_Action) error {
	return authorization.Authorize(ctx, security.PolicyPermission.Class, security.PolicyPermission.Actions[a])
}
