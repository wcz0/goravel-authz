package commands

import (
	"fmt"
	"slices"

	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/console/command"
)

// PolicyAddCommand adds a p rule to a casbin model.
type PolicyAddCommand struct {
	open OpenFunc
}

func NewPolicyAddCommand(open OpenFunc) *PolicyAddCommand {
	return &PolicyAddCommand{open: open}
}

func (receiver *PolicyAddCommand) Signature() string {
	return "authz:policy:add"
}

func (receiver *PolicyAddCommand) Description() string {
	return "Add a policy rule to a casbin model"
}

func (receiver *PolicyAddCommand) Extend() command.Extend {
	return valuesExtend("Policy values, e.g. admin /admin/users GET")
}

func (receiver *PolicyAddCommand) Handle(ctx console.Context) error {
	values, err := requireValues(ctx, 2)
	if err != nil {
		return err
	}

	enforcer, err := receiver.open(ctx.Option("guard"))
	if err != nil {
		return err
	}
	if err := checkSize(enforcer, "p", "p", values); err != nil {
		return err
	}

	added, err := enforcer.AddPolicy(params(values)...)
	if err != nil {
		return fmt.Errorf("authz: add policy: %w", err)
	}
	if !added {
		ctx.Warning(fmt.Sprintf("Policy already exists: %s", describe(values)))
		return nil
	}

	ctx.Success(fmt.Sprintf("Policy added: %s", describe(values)))

	return nil
}

// PolicyRemoveCommand removes a p rule from a casbin model.
type PolicyRemoveCommand struct {
	open OpenFunc
}

func NewPolicyRemoveCommand(open OpenFunc) *PolicyRemoveCommand {
	return &PolicyRemoveCommand{open: open}
}

func (receiver *PolicyRemoveCommand) Signature() string {
	return "authz:policy:remove"
}

func (receiver *PolicyRemoveCommand) Description() string {
	return "Remove a policy rule from a casbin model"
}

func (receiver *PolicyRemoveCommand) Extend() command.Extend {
	return valuesExtend("Policy values, e.g. admin /admin/users GET")
}

func (receiver *PolicyRemoveCommand) Handle(ctx console.Context) error {
	values, err := requireValues(ctx, 2)
	if err != nil {
		return err
	}

	enforcer, err := receiver.open(ctx.Option("guard"))
	if err != nil {
		return err
	}
	if err := checkSize(enforcer, "p", "p", values); err != nil {
		return err
	}

	removed, err := enforcer.RemovePolicy(params(values)...)
	if err != nil {
		return fmt.Errorf("authz: remove policy: %w", err)
	}
	if !removed {
		ctx.Warning(fmt.Sprintf("Policy not found: %s", describe(values)))
		return nil
	}

	ctx.Success(fmt.Sprintf("Policy removed: %s", describe(values)))

	return nil
}

// PolicyListCommand prints the p and g rules of a casbin model.
type PolicyListCommand struct {
	open OpenFunc
}

func NewPolicyListCommand(open OpenFunc) *PolicyListCommand {
	return &PolicyListCommand{open: open}
}

func (receiver *PolicyListCommand) Signature() string {
	return "authz:policy:list"
}

func (receiver *PolicyListCommand) Description() string {
	return "List policies and role bindings of a casbin model"
}

func (receiver *PolicyListCommand) Extend() command.Extend {
	return command.Extend{
		Category: category,
		Flags:    []command.Flag{guardFlag()},
	}
}

func (receiver *PolicyListCommand) Handle(ctx console.Context) error {
	enforcer, err := receiver.open(ctx.Option("guard"))
	if err != nil {
		return err
	}

	var (
		rows    [][]string
		columns int
	)
	appendRows := func(ptype string, policies [][]string) {
		policies = slices.Clone(policies)
		slices.SortFunc(policies, slices.Compare)

		for _, values := range policies {
			row := make([]string, 0, len(values)+1)
			row = append(row, ptype)
			row = append(row, values...)
			rows = append(rows, row)

			if len(values) > columns {
				columns = len(values)
			}
		}
	}
	appendRows("p", enforcer.GetPolicy())
	appendRows("g", enforcer.GetGroupingPolicy())

	if columns == 0 {
		ctx.Info("No policies found.")
		return nil
	}

	headers := make([]string, 0, columns+1)
	headers = append(headers, "Ptype")
	for index := 0; index < columns; index++ {
		headers = append(headers, fmt.Sprintf("V%d", index))
	}
	ctx.Table(headers, rows)

	return nil
}
