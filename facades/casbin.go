package facades

import (
	"log"

	"github.com/casbin/casbin/v2"
	authz "github.com/wcz0/goravel-authz"
)

func Enforcer(guard ...string) *casbin.Enforcer  {
	g := ""
	if len(guard) > 0 {
		g = guard[0]
	}
	instance, err := authz.App.MakeWith(authz.Binding, map[string]any{"guard": g})
	if err != nil {
		log.Fatalln(err)
		return nil
	}

	return instance.(*casbin.Enforcer)
}