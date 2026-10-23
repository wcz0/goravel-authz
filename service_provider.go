package authz

import (
	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/foundation"
	"github.com/goravel/framework/facades"

	"github.com/wcz0/goravel-authz/commands"
)

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
	app.MakeArtisan().Register([]console.Command{
		commands.NewPolicyAddCommand(NewEnforcer),
		commands.NewPolicyRemoveCommand(NewEnforcer),
		commands.NewPolicyListCommand(NewEnforcer),
		commands.NewGroupAddCommand(NewEnforcer),
		commands.NewGroupRemoveCommand(NewEnforcer),
		commands.NewEnforceCommand(NewEnforcer),
	})

	if config := facades.Config(); config != nil && config.GetBool("casbin.gate.enabled", true) {
		RegisterGate(facades.Gate())
	}
}
