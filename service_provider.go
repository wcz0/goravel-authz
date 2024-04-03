package goravelcasbin

import "github.com/goravel/framework/contracts/foundation"

const Binding = "goravelcasbin"

var App foundation.Application

type ServiceProvider struct {
}

// Register the service provider.
func (receiver *ServiceProvider) Register(app foundation.Application) {
	App = app

	app.Bind(Binding, func(app foundation.Application) (any, error) {
		return nil, nil
	})
}

func (receiver *ServiceProvider) Boot(app foundation.Application) {
	app.Publishes("github.com/wcz0/goravel-casbin", map[string]string{
		"config/casbin.go": app.ConfigPath("casbin.go"),
	})
}
