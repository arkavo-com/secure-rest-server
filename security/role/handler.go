package role

import (
	"context"
	"net/http"

	"github.com/arkavo-com/secure-rest-server/security"
	"github.com/arkavo-com/secure-rest-server/security/authorization"
	"github.com/arkavo-com/secure-rest-server/security/rest"
	"github.com/arkavo-com/secure-rest-server/security/session"
	"github.com/go-openapi/spec"
	"google.golang.org/protobuf/proto"
)

var (
	// operation
	operationCreate = &spec.Operation{
		OperationProps: spec.OperationProps{
			ID:          "roleCreate",
			Description: "",
			Consumes:    []string{"application/json"},
			Produces:    []string{"application/json"},
			Parameters: []spec.Parameter{
				rest.BodyParameter(spec.Schema{
					SchemaProps: spec.SchemaProps{
						Required: []string{"name", "permissions"},
						Properties: map[string]spec.Schema{
							"name":        {},
							"permissions": {},
						},
					},
				}),
			},
			Responses: rest.CreateResponses(),
		},
	}
	operationRead = &spec.Operation{
		OperationProps: spec.OperationProps{
			ID:       "roleRead",
			Produces: []string{"application/json"},
			Parameters: []spec.Parameter{
				parameterName,
			},
			Responses: rest.ReadResponses(),
		},
	}
	operationReadAll = &spec.Operation{
		OperationProps: spec.OperationProps{
			ID:        "roleReadAll",
			Produces:  []string{"application/json"},
			Responses: rest.ReadResponses(),
		},
	}
	operationUpdate = &spec.Operation{
		OperationProps: spec.OperationProps{
			ID:       "roleUpdate",
			Consumes: []string{"application/json"},
			Produces: []string{"application/json"},
			Parameters: []spec.Parameter{
				parameterName,
				parameterActivate,
				parameterDeactivate,
				{
					ParamProps: spec.ParamProps{
						Name: "body",
						In:   "body",
						Schema: &spec.Schema{
							SchemaProps: spec.SchemaProps{
								Required: []string{"permissions"},
								Properties: map[string]spec.Schema{
									"name": {
										SwaggerSchemaProps: spec.SwaggerSchemaProps{
											ReadOnly: true,
										},
									},
									"permissions": {},
									"state": {
										SwaggerSchemaProps: spec.SwaggerSchemaProps{
											ReadOnly: true,
										},
									},
								},
							},
						},
					},
				},
			},
			Responses: rest.UpdateResponses(),
		},
	}
	operationDelete = &spec.Operation{
		OperationProps: spec.OperationProps{
			ID: "roleDelete",
			Parameters: []spec.Parameter{
				parameterName,
			},
			Responses: rest.DeleteResponses(),
		},
	}
	// parameter
	parameterName = spec.Parameter{
		SimpleSchema: spec.SimpleSchema{
			Type: "string",
		},
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
	parameterActivate = spec.Parameter{
		SimpleSchema: spec.SimpleSchema{
			Type: "string",
		},
		ParamProps: spec.ParamProps{
			Name:            security.Role_ACTIVATE.String(),
			In:              "query",
			AllowEmptyValue: true,
			Required:        false,
		},
	}
	parameterDeactivate = spec.Parameter{
		SimpleSchema: spec.SimpleSchema{
			Type: "string",
		},
		ParamProps: spec.ParamProps{
			Name:            security.Role_DEACTIVATE.String(),
			In:              "query",
			AllowEmptyValue: true,
			Required:        false,
		},
	}
)

// HandlePath registers http.HandleFunc and spec.Operation for paths
func HandlePath(paths spec.Paths) {
	p := "/role"
	http.HandleFunc(p, session.HandlerFunc(serveHTTP))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Get:  operationReadAll,
			Post: operationCreate,
		},
	}
	p = "/role/{name}"
	rest.PathHandlerFunc(p, session.HandlerFunc(serveHTTPparameter))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Get:    operationRead,
			Put:    operationUpdate,
			Delete: operationDelete,
		},
	}
}

func serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
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
		var pbs []proto.Message
		for i := 0; i < len(roles); i++ {
			pbs = append(pbs, roles[i])
		}
		rest.WriteProtos(w, pbs)
	case "POST":
		err := authorize(r.Context(), security.Role_CREATE)
		if rest.Errored(w, err) {
			return
		}
		var role security.Role
		err = rest.Validate(r, operationCreate, &role)
		if rest.Errored(w, err) {
			return
		}
		// state
		role.State = transition(role.State, security.Role_CREATE)
		err = s.createRole(&role)
		if err == rest.ErrDuplicate {
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
		rest.WriteProtoCreated(w, &role, r.RequestURI+"/"+role.Name)
	}
}

func serveHTTPparameter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		err := authorize(r.Context(), security.Role_READ)
		if rest.Errored(w, err) {
			return
		}
		n, err := rest.ValidateParameter(*r, parameterName)
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
		n, err := rest.ValidateParameter(*r, parameterName)
		if rest.Errored(w, err) {
			return
		}
		role, err := s.ReadRole(n)
		if rest.Errored(w, err) {
			return
		}
		// action
		action := rest.ValidateParameterQueryAction(*r, parameterActivate, parameterDeactivate)
		if action != "" {
			ns := transition(role.State, security.Role_Action(security.Role_Action_value[action]))
			// if previous state then 304
			if role.State == ns {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			role.State = ns
		} else {
			nr := security.Role{}
			err = rest.Validate(r, operationUpdate, &nr)
			if rest.Errored(w, err) {
				return
			}
			role.Permissions = nr.Permissions
		}
		err = s.updateRole(role)
		if rest.Errored(w, err) {
			return
		}
		rest.WriteProto(w, role)
	case "DELETE":
		err := authorize(r.Context(), security.Role_DELETE)
		if rest.Errored(w, err) {
			return
		}
		n, err := rest.ValidateParameter(*r, parameterName)
		if rest.Errored(w, err) {
			return
		}
		role, err := s.ReadRole(n)
		if rest.Errored(w, err) {
			return
		}
		// only delete Deactivated
		if role.State != security.Role_Deactivated {
			w.WriteHeader(http.StatusNotModified)
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
	return authorization.Authorize(ctx, security.RolePermission.Class, security.Role_Action_name[int32(a)])
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
