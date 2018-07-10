package permission

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
	permissionCREATE  = spec.NewOperation("permissionCreate")
	permissionREAD    = spec.NewOperation("permissionRead")
	permissionREADAll = spec.NewOperation("permissionReadAll")
)

func RegisterHttpHandler(paths spec.Paths) {
	p := "/permission"
	http.HandleFunc(p, session.HandlerFunc(serveHTTP))
	paths.Paths[p] = spec.PathItem{
		PathItemProps: spec.PathItemProps{
			Get:  permissionREADAll,
			Post: permissionCREATE,
		},
	}
	permissionCREATE.Parameters = append(permissionCREATE.Parameters, rest.BodyParameter(spec.Schema{
		SchemaProps: spec.SchemaProps{
			Required:   []string{"class", "actions"},
			Properties: map[string]spec.Schema{},
		},
	}))
}

func serveHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	switch r.Method {
	case "POST":
		err = authorize(r.Context(), security.Permission_CREATE)
		if rest.Errored(w, err) {
			return
		}
		permission := security.Permission{}
		err = rest.Validate(r, permissionCREATE, &permission)
		if rest.Errored(w, err) {
			return
		}
		err = s.createPermission(&permission)
		if rest.Errored(w, err) {
			return
		}
		rest.WriteProto(w, &permission)
	case "GET":
		err = authorize(r.Context(), security.Permission_READ)
		if rest.Errored(w, err) {
			return
		}
		var pbs []proto.Message
		pbs = append(pbs, &security.AccountPermission)
		pbs = append(pbs, &security.PermissionPermission)
		pbs = append(pbs, &security.RolePermission)
		pbs = append(pbs, &security.SessionPermission)
		pbs = append(pbs, &security.PolicyPermission)
		permissions, err := s.readPermissions()
		if rest.Errored(w, err) {
			return
		}
		for _, p := range permissions {
			pbs = append(pbs, p)
		}
		rest.WriteProtos(w, pbs)
	}
}

func authorize(ctx context.Context, a security.Permission_Action) error {
	return authorization.Authorize(ctx, security.PermissionPermission.Class, security.PermissionPermission.Actions[a])
}
