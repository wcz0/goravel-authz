package facades

import (
	"github.com/casbin/casbin/v2"
	authz "github.com/wcz0/goravel-authz"
)

// Enforcer returns the shared enforcer of the given model name. Without a
// name the model configured as casbin.default is used.
//
// It panics when the casbin configuration cannot be resolved, which only
// happens for configuration errors that should be fixed at boot time.
func Enforcer(guard ...string) *casbin.SyncedEnforcer {
	name := ""
	if len(guard) > 0 {
		name = guard[0]
	}

	instance, err := authz.NewEnforcer(name)
	if err != nil {
		panic(err)
	}

	return instance
}
