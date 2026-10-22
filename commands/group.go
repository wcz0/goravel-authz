package commands

import (
	"fmt"

	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/console/command"
)

// GroupAddCommand adds a g rule, binding a subject to a role or group.
type GroupAddCommand struct {
	open OpenFunc
}

func NewGroupAddCommand(open OpenFunc) *GroupAddCommand {
	return &GroupAddCommand{open: open}
}

func (receiver *GroupAddCommand) Signature() string {
	return "authz:group:add"
}

func (receiver *GroupAddCommand) Description() string {
	return "Bind a subject to a role or group in a casbin model"
}

func (receiver *GroupAddCommand) Extend() command.Extend {
	return valuesExtend("Grouping values, e.g. alice admin")
}

func (receiver *GroupAddCommand) Handle(ctx console.Context) error {
	values, err := requireValues(ctx, 2)
	if err != nil {
		return err
	}

	enforcer, err := receiver.open(ctx.Option("guard"))
	if err != nil {
		return err
	}
	if err := checkSize(enforcer, "g", "g", values); err != nil {
		return err
	}

	added, err := enforcer.AddGroupingPolicy(params(values)...)
	if err != nil {
		return fmt.Errorf("authz: add grouping: %w", err)
	}
	if !added {
		ctx.Warning(fmt.Sprintf("Grouping already exists: %s", describe(values)))
		return nil
	}

	ctx.Success(fmt.Sprintf("Grouping added: %s", describe(values)))

	return nil
}

// GroupRemoveCommand removes a g rule.
type GroupRemoveCommand struct {
	open OpenFunc
}

func NewGroupRemoveCommand(open OpenFunc) *GroupRemoveCommand {
	return &GroupRemoveCommand{open: open}
}

func (receiver *GroupRemoveCommand) Signature() string {
	return "authz:group:remove"
}

func (receiver *GroupRemoveCommand) Description() string {
	return "Remove a role or group binding from a casbin model"
}

func (receiver *GroupRemoveCommand) Extend() command.Extend {
	return valuesExtend("Grouping values, e.g. alice admin")
}

func (receiver *GroupRemoveCommand) Handle(ctx console.Context) error {
	values, err := requireValues(ctx, 2)
	if err != nil {
		return err
	}

	enforcer, err := receiver.open(ctx.Option("guard"))
	if err != nil {
		return err
	}
	if err := checkSize(enforcer, "g", "g", values); err != nil {
		return err
	}

	removed, err := enforcer.RemoveGroupingPolicy(params(values)...)
	if err != nil {
		return fmt.Errorf("authz: remove grouping: %w", err)
	}
	if !removed {
		ctx.Warning(fmt.Sprintf("Grouping not found: %s", describe(values)))
		return nil
	}

	ctx.Success(fmt.Sprintf("Grouping removed: %s", describe(values)))

	return nil
}
