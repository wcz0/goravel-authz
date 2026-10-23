package authz

import (
	"context"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/goravel/framework/auth/access"
	contractsaccess "github.com/goravel/framework/contracts/auth/access"
	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/wcz0/goravel-authz/internal/logging"
)

// RegisterGate connects the Goravel Gate to the Casbin policies.
//
// Abilities that contain a comma are treated as Casbin requests:
//
//	Gate.Allows("articles,read", map[string]any{"guard": "admin"})
//
// is evaluated as Enforce(subject, "articles", "read") against the "admin"
// model. The subject comes from middleware.SetSubject or, when that is empty,
// from the ID of the authenticated Goravel Auth user.
//
// Abilities without a comma are left untouched, so ordinary Gate abilities
// keep working. The callback is registered before every other Gate check; a
// comma inside a regular ability name therefore takes precedence.
//
// RegisterGate is called automatically when the service provider boots and
// casbin.gate.enabled is not false.
func RegisterGate(gate contractsaccess.Gate) {
	registerGate(gate, NewEnforcer)
}

func registerGate(gate contractsaccess.Gate, open func(string) (*casbin.SyncedEnforcer, error)) {
	if gate == nil {
		return
	}

	gate.Before(func(ctx context.Context, ability string, arguments map[string]any) contractsaccess.Response {
		return gatePolicy(ctx, ability, arguments, open)
	})
}

// gateSubjectFromAuth is replaced in tests.
var gateSubjectFromAuth = SubjectFromAuth

// gatePolicy returns nil for abilities that are not Casbin requests, so the
// Gate continues with its normal ability resolution.
func gatePolicy(ctx context.Context, ability string, arguments map[string]any, open func(string) (*casbin.SyncedEnforcer, error)) contractsaccess.Response {
	tokens, ok := abilityTokens(ability)
	if !ok {
		return nil
	}

	guard := gateGuard(arguments)

	subject := SubjectFromContext(ctx)
	if subject == "" {
		if httpCtx, ok := ctx.(contractshttp.Context); ok {
			var err error
			subject, err = gateSubjectFromAuth(httpCtx)
			if err != nil {
				logGateFailure(guard, ability, err)
				return access.NewDenyResponse(DefaultUnavailableMessage)
			}
		}
	}
	if subject == "" {
		return access.NewDenyResponse(DefaultDeniedMessage)
	}

	enforcer, err := open(guard)
	if err != nil {
		logGateFailure(guard, ability, err)
		return access.NewDenyResponse(DefaultUnavailableMessage)
	}

	request := make([]any, 0, len(tokens)+1)
	request = append(request, subject)
	for _, token := range tokens {
		request = append(request, token)
	}

	allowed, err := enforcer.Enforce(request...)
	if err != nil {
		logGateFailure(guard, ability, err)
		return access.NewDenyResponse(DefaultUnavailableMessage)
	}
	if !allowed {
		return access.NewDenyResponse(DefaultDeniedMessage)
	}

	return access.NewAllowResponse()
}

// abilityTokens splits "articles,read" into its Casbin tokens. Abilities
// without a comma or with fewer than two non-empty tokens are not Casbin
// requests and return false.
func abilityTokens(ability string) ([]string, bool) {
	if !strings.Contains(ability, ",") {
		return nil, false
	}

	parts := strings.Split(ability, ",")
	tokens := make([]string, 0, len(parts))
	for _, part := range parts {
		if token := strings.TrimSpace(part); token != "" {
			tokens = append(tokens, token)
		}
	}
	if len(tokens) < 2 {
		return nil, false
	}

	return tokens, true
}

func gateGuard(arguments map[string]any) string {
	if arguments == nil {
		return ""
	}

	guard, _ := arguments["guard"].(string)

	return guard
}

func logGateFailure(guard, ability string, err error) {
	logger := logging.Load().Logger()
	if logger == nil {
		return
	}

	fields := map[string]any{
		"ability": ability,
		"error":   err,
	}
	if guard != "" {
		fields["guard"] = guard
	}

	logger.With(fields).Error("authz: gate check failed")
}
