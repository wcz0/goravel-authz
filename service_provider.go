package authz

import "github.com/goravel/framework/contracts/foundation"

const Binding = "casbin"

var App foundation.Application

type ServiceProvider struct {
}

// Register the service provider.
func (receiver *ServiceProvider) Register(app foundation.Application) {
	App = app

	app.BindWith(Binding, func(app foundation.Application, parameters map[string]any) (any, error) {
		guard, _ := parameters["guard"].(string)

		return NewEnforcer(guard)
	})
}

func (receiver *ServiceProvider) Boot(app foundation.Application) {
}
