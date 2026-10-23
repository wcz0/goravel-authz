package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/goravel/framework/auth/access"
	contractsaccess "github.com/goravel/framework/contracts/auth/access"
	contractshttp "github.com/goravel/framework/contracts/http"
	goravelhttp "github.com/goravel/framework/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gateTestModel = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act`

func gateEnforcer(t *testing.T, rules ...[]string) *casbin.SyncedEnforcer {
	t.Helper()

	m, err := model.NewModelFromString(gateTestModel)
	require.NoError(t, err)

	e, err := casbin.NewSyncedEnforcer(m)
	require.NoError(t, err)

	for _, rule := range rules {
		_, err := e.AddPolicy(rule)
		require.NoError(t, err)
	}

	return e
}

func TestGateAllowsCommaAbilities(t *testing.T) {
	gate := access.NewGate(context.Background())
	opened := ""
	registerGate(gate, func(name string) (*casbin.SyncedEnforcer, error) {
		opened = name
		return gateEnforcer(t, []string{"alice", "articles", "read"}), nil
	})

	ctx := context.WithValue(context.Background(), SubjectKey, "alice")
	gated := gate.WithContext(ctx)

	assert.True(t, gated.Allows("articles,read", nil))
	assert.False(t, gated.Allows("articles,write", nil))
	assert.Equal(t, "", opened, "an empty guard resolves casbin.default")
}

func TestGateUsesGuardArgument(t *testing.T) {
	gate := access.NewGate(context.Background())
	opened := ""
	registerGate(gate, func(name string) (*casbin.SyncedEnforcer, error) {
		opened = name
		return gateEnforcer(t, []string{"alice", "articles", "read"}), nil
	})

	ctx := context.WithValue(context.Background(), SubjectKey, "alice")
	allowed := gate.WithContext(ctx).Allows("articles,read", map[string]any{"guard": "admin"})

	assert.True(t, allowed)
	assert.Equal(t, "admin", opened)
}

func TestGateLeavesNormalAbilitiesAlone(t *testing.T) {
	gate := access.NewGate(context.Background())
	gate.Define("view-dashboard", func(context.Context, map[string]any) contractsaccess.Response {
		return access.NewAllowResponse()
	})
	registerGate(gate, func(string) (*casbin.SyncedEnforcer, error) {
		t.Fatal("the enforcer must not be opened for a normal ability")
		return nil, nil
	})

	ctx := context.WithValue(context.Background(), SubjectKey, "alice")
	gated := gate.WithContext(ctx)

	assert.True(t, gated.Allows("view-dashboard", nil))
	assert.False(t, gated.Allows("unknown-ability", nil))
}

func TestGateDeniesMissingSubject(t *testing.T) {
	gate := access.NewGate(context.Background())
	registerGate(gate, func(string) (*casbin.SyncedEnforcer, error) {
		t.Fatal("the enforcer must not be opened without a subject")
		return nil, nil
	})

	response := gate.WithContext(context.Background()).Inspect("articles,read", nil)

	assert.False(t, response.Allowed())
	assert.Equal(t, DefaultDeniedMessage, response.Message())
}

func TestGateDeniesUnavailableEnforcer(t *testing.T) {
	gate := access.NewGate(context.Background())
	registerGate(gate, func(string) (*casbin.SyncedEnforcer, error) {
		return nil, errors.New("model is broken")
	})

	ctx := context.WithValue(context.Background(), SubjectKey, "alice")
	response := gate.WithContext(ctx).Inspect("articles,read", nil)

	assert.False(t, response.Allowed())
	assert.Equal(t, DefaultUnavailableMessage, response.Message())
}

func TestGateDeniesEnforceError(t *testing.T) {
	gate := access.NewGate(context.Background())
	registerGate(gate, func(string) (*casbin.SyncedEnforcer, error) {
		return gateEnforcer(t), nil
	})

	ctx := context.WithValue(context.Background(), SubjectKey, "alice")
	response := gate.WithContext(ctx).Inspect("articles,read,extra", nil)

	assert.False(t, response.Allowed())
	assert.Equal(t, DefaultUnavailableMessage, response.Message())
}

func TestGateUsesAuthenticatedUser(t *testing.T) {
	previous := gateSubjectFromAuth
	gateSubjectFromAuth = func(contractshttp.Context) (string, error) {
		return "alice", nil
	}
	t.Cleanup(func() { gateSubjectFromAuth = previous })

	gate := access.NewGate(context.Background())
	registerGate(gate, func(string) (*casbin.SyncedEnforcer, error) {
		return gateEnforcer(t, []string{"alice", "articles", "read"}), nil
	})

	assert.True(t, gate.WithContext(goravelhttp.NewContext()).Allows("articles,read", nil))
}

func TestGateDeniesWhenAuthResolutionFails(t *testing.T) {
	previous := gateSubjectFromAuth
	gateSubjectFromAuth = func(contractshttp.Context) (string, error) {
		return "", errors.New("auth is misconfigured")
	}
	t.Cleanup(func() { gateSubjectFromAuth = previous })

	gate := access.NewGate(context.Background())
	registerGate(gate, func(string) (*casbin.SyncedEnforcer, error) {
		t.Fatal("the enforcer must not be opened when the auth resolver fails")
		return nil, nil
	})

	response := gate.WithContext(goravelhttp.NewContext()).Inspect("articles,read", nil)
	assert.False(t, response.Allowed())
	assert.Equal(t, DefaultUnavailableMessage, response.Message())
}

func TestRegisterGateToleratesMissingGate(t *testing.T) {
	assert.NotPanics(t, func() { RegisterGate(nil) })
}

func TestAbilityTokens(t *testing.T) {
	tokens, ok := abilityTokens("articles, read")
	assert.True(t, ok)
	assert.Equal(t, []string{"articles", "read"}, tokens)

	tokens, ok = abilityTokens("articles,read,tenant-a")
	assert.True(t, ok)
	assert.Equal(t, []string{"articles", "read", "tenant-a"}, tokens)

	_, ok = abilityTokens("view-dashboard")
	assert.False(t, ok)

	_, ok = abilityTokens("articles,")
	assert.False(t, ok, "an ability with fewer than two tokens is not a casbin request")
}

func TestAbilityTokensTrimEmptyParts(t *testing.T) {
	tokens, ok := abilityTokens(" articles , , read ")
	assert.True(t, ok)
	assert.Equal(t, []string{"articles", "read"}, tokens)
}
