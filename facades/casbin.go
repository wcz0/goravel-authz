package facades

import (
	"log"
	"github.com/casbin/casbin/v2"

	gauthz "github.com/wcz0/goravel-authz"
)

func Enforcer() *casbin.Enforcer  {
	instance, err := gauthz.App.Make(gauthz.Binding)
	if err != nil {
		log.Fatalln(err)
		return nil
	}

	return instance.(*casbin.Enforcer)
}