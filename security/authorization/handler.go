package authorization

import (
	"context"

	"github.com/arkavo-com/secure-rest-server/security"
	"github.com/arkavo-com/secure-rest-server/security/rest"
)

// Authorize checks context for allowed actions
func Authorize(ctx context.Context, c, a string) error {
	v := ctx.Value("session.context")
	ss, ok := v.(*security.Session)
	if ok {
		for _, p := range ss.Permissions {
			if c == p.Class {
				for _, pa := range p.Actions {
					if pa == a {
						return nil
					}
				}
				break
			}
		}
	}
	return rest.ErrUnauthorized
}
