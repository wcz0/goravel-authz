package commands

import (
	"fmt"

	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/console/command"
)

// EnforceCommand checks a request against a casbin model without a HTTP
// request, which is useful to verify policies after editing them.
type EnforceCommand struct {
	open OpenFunc
}

func NewEnforceCommand(open OpenFunc) *EnforceCommand {
	return &EnforceCommand{open: open}
}

func (receiver *EnforceCommand) Signature() string {
	return "authz:enforce"
}

func (receiver *EnforceCommand) Description() string {
	return "Check whether a subject is allowed to perform an action"
}

func (receiver *EnforceCommand) Extend() command.Extend {
	return valuesExtend("Request values, e.g. alice /admin/users GET")
}

func (receiver *EnforceCommand) Handle(ctx console.Context) error {
	values, err := requireValues(ctx, 2)
	if err != nil {
		return err
	}

	enforcer, err := receiver.open(ctx.Option("guard"))
	if err != nil {
		return err
	}
	if err := checkSize(enforcer, "r", "r", values); err != nil {
		return err
	}

	allowed, err := enforcer.Enforce(params(values)...)
	if err != nil {
		return fmt.Errorf("authz: enforce: %w", err)
	}

	if allowed {
		ctx.Success(fmt.Sprintf("Allowed: %s", describe(values)))
		return nil
	}

	ctx.Warning(fmt.Sprintf("Denied: %s", describe(values)))

	return nil
}
