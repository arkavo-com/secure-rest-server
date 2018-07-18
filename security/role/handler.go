package role

import (
	"context"
	"net/http"

	"secure-rest-server/security"
	"secure-rest-server/security/authorization"
	"secure-rest-server/security/rest"
	"secure-rest-server/security/session"

	"github.com/go-openapi/spec"
	"github.com/golang/protobuf/proto"
)

var (
	roleCREATE     = spec.NewOperation("roleCreate")
	roleREAD       = spec.NewOperation("roleRead")
	roleREADAll    = spec.NewOperation("roleReadAll")
	roleUPDATE     = spec.NewOperation("roleUpdate")
	roleDELETE     = spec.NewOperation("roleDelete")
	roleACTIVATE   = spec.NewOperation("roleActivate")
	roleDEACTIVATE = spec.NewOperation("roleDeactivate")
	// parameters
	roleParameterName   spec.Parameter
	roleParameterUpdate spec.Parameter
)

func RegisterHttpHandler(paths spec.Paths) {
	p := "/role"
	http.HandleFunc(p, session.HandlerFunc(serveHTTP))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Get:  roleREADAll,
			Post: roleCREATE,
		},
	}
	roleCREATE.Parameters = append(roleCREATE.Parameters, rest.BodyParameter(spec.Schema{
		SchemaProps: spec.SchemaProps{
			Required:   []string{"name", "permissions"},
			Properties: map[string]spec.Schema{},
		},
	}))
	roleCREATE.Consumes = []string{"application/json"}
	roleCREATE.Produces = []string{"application/json"}
	p = "/role/{name}"
	rest.PathHandlerFunc(p, session.HandlerFunc(serveHTTPparameter))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Get:    roleREAD,
			Put:    roleUPDATE,
			Delete: roleDELETE,
		},
	}
	roleUPDATE.Parameters = append(roleUPDATE.Parameters, roleParameterName)
	roleUPDATE.Parameters = append(roleUPDATE.Parameters, roleParameterUpdate)
	roleParameterUpdate = rest.BodyParameter(spec.Schema{
		SchemaProps: spec.SchemaProps{
			Required:   []string{"name", "permissions", "state"},
			Properties: map[string]spec.Schema{},
		},
	})
	p = "/role/{name}/ACTIVATE"
	// FIXME
	//rest.PathHandlerFunc(p, session.HandlerFunc(serveHTTP))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Put: roleACTIVATE,
		},
	}
	p = "/role/{name}/DEACTIVATE"
	// FIXME
	//rest.PathHandlerFunc(p, session.HandlerFunc(serveHTTP))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Put: roleDEACTIVATE,
		},
	}
	roleParameterName = spec.Parameter{
		ParamProps: spec.ParamProps{
			Name: "name",
			In:   "path",
			Schema: &spec.Schema{
				SchemaProps: spec.SchemaProps{
					MinLength: &[]int64{2}[0],
					MaxLength: &[]int64{256}[0],
					Pattern:   "[0-9a-fA-F]",
				},
			},
		},
	}
}

func serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		err := authorize(r.Context(), security.Role_CREATE)
		if rest.Errored(w, err) {
			return
		}
		var role security.Role
		err = rest.Validate(r, roleCREATE, &role)
		if rest.Errored(w, err) {
			return
		}
		// state
		role.State = transition(role.State, security.Role_CREATE)
		err = s.createRole(&role)
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
		rest.WriteProto(w, &role)
	case "GET":
		err := authorize(r.Context(), security.Role_READ)
		if rest.Errored(w, err) {
			return
		}
		// return all
		roles, err := s.readRoles()
		if rest.Errored(w, err) {
			return
		}
		pbs := make([]proto.Message, len(roles), len(roles))
		for i := 0; i < len(roles); i++ {
			pbs[i] = roles[i]
		}
		rest.WriteProtos(w, pbs)
	}
}

func serveHTTPparameter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		err := authorize(r.Context(), security.Role_READ)
		if rest.Errored(w, err) {
			return
		}
		n, err := rest.ValidateParameter(*r, roleParameterName)
		if rest.Errored(w, err) {
			return
		}
		role, err := s.ReadRole(n)
		if rest.Errored(w, err) {
			return
		}
		rest.WriteProto(w, role)
	case "PUT":
		err := authorize(r.Context(), security.Role_UPDATE)
		if rest.Errored(w, err) {
			return
		}
		_, err = rest.ValidateParameter(*r, roleParameterName)
		if rest.Errored(w, err) {
			return
		}
		role := security.Role{}
		err = rest.Validate(r, roleCREATE, &role)
		if rest.Errored(w, err) {
			return
		}
		err = s.updateRole(&role)
		if rest.Errored(w, err) {
			return
		}
		rest.WriteProto(w, &role)
	case "DELETE":
		err := authorize(r.Context(), security.Role_UPDATE)
		if rest.Errored(w, err) {
			return
		}
		n, err := rest.ValidateParameter(*r, roleParameterName)
		if rest.Errored(w, err) {
			return
		}
		err = s.deleteRole(n)
		if rest.Errored(w, err) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func authorize(ctx context.Context, a security.Role_Action) error {
	return authorization.Authorize(ctx, security.RolePermission.Class, security.RolePermission.Actions[a])
}

// transition provides a guard to protect from invalid transitions
func transition(state security.Role_State, trigger security.Role_Action) security.Role_State {
	switch state {
	case security.Role_nonstate:
		switch trigger {
		case security.Role_CREATE:
			return security.Role_Initialized
		}
	case security.Role_Initialized:
		switch trigger {
		case security.Role_ACTIVATE:
			return security.Role_Activated
		}
	case security.Role_Activated:
		switch trigger {
		case security.Role_DEACTIVATE:
			return security.Role_Deactivated
		}
	}
	return state
}
