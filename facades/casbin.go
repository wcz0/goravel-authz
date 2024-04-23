package facades

import (
	"log"

	gauthz "github.com/wcz0/goravel-authz"
)

func Enforcer() *gauthz.EnforcerManager  {
	instance, err := gauthz.App.Make(gauthz.Binding)
	if err != nil {
		log.Fatalln(err)
		return nil
	}

	return instance.(*gauthz.EnforcerManager)
}