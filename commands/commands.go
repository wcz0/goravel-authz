package commands

import (
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/console/command"
)

// OpenFunc opens the enforcer of a casbin model. An empty guard means the
// model configured as casbin.default.
type OpenFunc func(guard string) (*casbin.SyncedEnforcer, error)

const category = "authz"

func guardFlag() command.Flag {
	return &command.StringFlag{
		Name:    "guard",
		Aliases: []string{"g"},
		Usage:   "The casbin model to use, defaults to casbin.default",
	}
}

func valuesExtend(usage string) command.Extend {
	return command.Extend{
		Category:  category,
		ArgsUsage: usage,
		Flags:     []command.Flag{guardFlag()},
	}
}

func requireValues(ctx console.Context, count int) ([]string, error) {
	values := ctx.Arguments()
	if len(values) < count {
		return nil, fmt.Errorf("authz: expected at least %d values, got %d", count, len(values))
	}

	return values, nil
}

// checkSize validates the value count against the model tokens. Casbin accepts
// shorter rules silently, which would store policies that can never match.
func checkSize(enforcer *casbin.SyncedEnforcer, section, ptype string, values []string) error {
	assertion, ok := enforcer.GetModel()[section][ptype]
	if !ok || len(assertion.Tokens) == 0 {
		return nil
	}

	if len(values) != len(assertion.Tokens) {
		return fmt.Errorf("authz: %s rule expects %d values, got %d", ptype, len(assertion.Tokens), len(values))
	}

	return nil
}

func params(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}

	return result
}

func describe(values []string) string {
	return strings.Join(values, " ")
}
