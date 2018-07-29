package permission

import (
	"context"
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
			ID:          "permissionCreate",
			Description: "",
			Consumes:    []string{"application/json"},
			Produces:    []string{"application/json"},
			Parameters: []spec.Parameter{
				rest.BodyParameter(spec.Schema{
					SchemaProps: spec.SchemaProps{
						Required: []string{"class", "actions"},
						Properties: map[string]spec.Schema{
							"class":   {},
							"actions": {},
						},
					},
				}),
			},
			Responses: rest.CreateResponses(),
		},
	}
	operationRead = &spec.Operation{
		OperationProps: spec.OperationProps{
			ID:       "permissionRead",
			Produces: []string{"application/json"},
			Parameters: []spec.Parameter{
				parameterClass,
			},
			Responses: rest.ReadResponses(),
		},
	}
	operationReadAll = &spec.Operation{
		OperationProps: spec.OperationProps{
			ID:        "permissionReadAll",
			Produces:  []string{"application/json"},
			Responses: rest.ReadResponses(),
		},
	}
	// parameter
	parameterClass = spec.Parameter{
		SimpleSchema: spec.SimpleSchema{
			Type: "string",
		},
		ParamProps: spec.ParamProps{
			Name:     "class",
			In:       "path",
			Required: true,
			Schema: &spec.Schema{
				SchemaProps: spec.SchemaProps{
					MinLength: &[]int64{4}[0],
					MaxLength: &[]int64{256}[0],
					Pattern:   policy.Password.Pattern,
				},
			},
		},
	}
	// TODO move to storer
	// permission standard
	standard = []security.Permission{
		security.AccountPermission,
		security.PermissionPermission,
		security.RolePermission,
		security.SessionPermission,
		security.PolicyPermission,
	}
)

// HandlePath registers http.HandleFunc and spec.Operation for paths
func HandlePath(paths spec.Paths) {
	p := "/permission"
	http.HandleFunc(p, session.HandlerFunc(serveHTTP))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Get:  operationReadAll,
			Post: operationCreate,
		},
	}
	p = "/permission/{class}"
	rest.PathHandlerFunc(p, session.HandlerFunc(serveHTTPparameter))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Get: operationRead,
		},
	}
}

func serveHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	switch r.Method {
	case "GET":
		err = authorize(r.Context(), security.Permission_READ)
		if rest.Errored(w, err) {
			return
		}
		var pbs []proto.Message
		for i := 0; i < len(standard); i++ {
			pbs = append(pbs, &standard[i])
		}
		var permissions []*security.Permission
		permissions, err = s.readPermissions()
		if rest.Errored(w, err) {
			return
		}
		for _, p := range permissions {
			pbs = append(pbs, p)
		}
		rest.WriteProtos(w, pbs)
	case "POST":
		err = authorize(r.Context(), security.Permission_CREATE)
		if rest.Errored(w, err) {
			return
		}
		permission := security.Permission{}
		err = rest.Validate(r, operationCreate, &permission)
		if rest.Errored(w, err) {
			return
		}
		err = s.createPermission(&permission)
		if err == rest.ErrDuplicate {
			err = rest.ValidationErrors{
				rest.ValidationError{
					Property: "class",
					Rule:     "Unique",
				},
			}
		}
		if rest.Errored(w, err) {
			return
		}
		rest.WriteProtoCreated(w, &permission, r.RequestURI+"/"+permission.Class)
	}
}

func serveHTTPparameter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		err := authorize(r.Context(), security.Permission_READ)
		if rest.Errored(w, err) {
			return
		}
		c, err := rest.ValidateParameter(*r, parameterClass)
		if rest.Errored(w, err) {
			return
		}
		var p *security.Permission
		for i := 0; i < len(standard); i++ {
			if c == standard[i].Class {
				p = &standard[i]
			}
		}
		if p == nil {
			p, err = s.readPermission(c)
			if rest.Errored(w, err) {
				return
			}
		}
		rest.WriteProto(w, p)
	}
}

func authorize(ctx context.Context, a security.Permission_Action) error {
	return authorization.Authorize(ctx, security.PermissionPermission.Class, security.Permission_Action_name[int32(a)])
}
