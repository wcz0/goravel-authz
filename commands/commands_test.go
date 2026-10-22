package commands

import (
	"errors"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/console/command"
	mocksconsole "github.com/goravel/framework/mocks/console"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

func newTestEnforcer(t *testing.T) *casbin.SyncedEnforcer {
	t.Helper()

	m, err := model.NewModelFromString(testModel)
	require.NoError(t, err)

	enforcer, err := casbin.NewSyncedEnforcer(m)
	require.NoError(t, err)

	return enforcer
}

func newTestEnforcerWithAdapter(t *testing.T, adapter persist.Adapter) *casbin.SyncedEnforcer {
	t.Helper()

	m, err := model.NewModelFromString(testModel)
	require.NoError(t, err)

	enforcer, err := casbin.NewSyncedEnforcer(m, adapter)
	require.NoError(t, err)

	return enforcer
}

// failingAdapter fails every write, which exercises command error paths.
type failingAdapter struct{}

func (failingAdapter) LoadPolicy(model.Model) error { return nil }

func (failingAdapter) SavePolicy(model.Model) error { return nil }

func (failingAdapter) AddPolicy(string, string, []string) error {
	return errors.New("adapter write failed")
}

func (failingAdapter) RemovePolicy(string, string, []string) error {
	return errors.New("adapter write failed")
}

func (failingAdapter) RemoveFilteredPolicy(string, string, int, ...string) error {
	return errors.New("adapter write failed")
}

func testOpen(enforcer *casbin.SyncedEnforcer) OpenFunc {
	return func(string) (*casbin.SyncedEnforcer, error) {
		return enforcer, nil
	}
}

func failingOpen() OpenFunc {
	return func(string) (*casbin.SyncedEnforcer, error) {
		return nil, errors.New("enforcer is unavailable")
	}
}

func TestPolicyAddCommand(t *testing.T) {
	t.Run("adds a policy", func(t *testing.T) {
		enforcer := newTestEnforcer(t)
		command := NewPolicyAddCommand(testOpen(enforcer))

		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"admin", "/admin/users", "GET"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()
		ctx.EXPECT().Success("Policy added: admin /admin/users GET").Once()

		require.NoError(t, command.Handle(ctx))
		assert.Equal(t, [][]string{{"admin", "/admin/users", "GET"}}, enforcer.GetPolicy())
	})

	t.Run("reports an existing policy", func(t *testing.T) {
		enforcer := newTestEnforcer(t)
		_, err := enforcer.AddPolicy("admin", "/admin/users", "GET")
		require.NoError(t, err)

		command := NewPolicyAddCommand(testOpen(enforcer))
		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"admin", "/admin/users", "GET"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()
		ctx.EXPECT().Warning("Policy already exists: admin /admin/users GET").Once()

		require.NoError(t, command.Handle(ctx))
	})

	t.Run("rejects too few values", func(t *testing.T) {
		command := NewPolicyAddCommand(failingOpen())
		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"admin"}).Once()

		err := command.Handle(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least 2 values")
	})

	t.Run("validates the rule size", func(t *testing.T) {
		enforcer := newTestEnforcer(t)
		command := NewPolicyAddCommand(testOpen(enforcer))

		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"admin", "/admin/users"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()

		err := command.Handle(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "p rule expects 3 values")
		assert.Empty(t, enforcer.GetPolicy())
	})

	t.Run("wraps adapter errors", func(t *testing.T) {
		enforcer := newTestEnforcerWithAdapter(t, failingAdapter{})
		command := NewPolicyAddCommand(testOpen(enforcer))

		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"admin", "/admin/users", "GET"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()

		err := command.Handle(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authz: add policy")
		assert.Contains(t, err.Error(), "adapter write failed")
	})

	t.Run("returns open errors", func(t *testing.T) {
		command := NewPolicyAddCommand(failingOpen())
		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"admin", "/admin/users", "GET"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()

		err := command.Handle(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "enforcer is unavailable")
	})
}

func TestCommandMetadata(t *testing.T) {
	open := failingOpen()
	instances := []console.Command{
		NewPolicyAddCommand(open),
		NewPolicyRemoveCommand(open),
		NewPolicyListCommand(open),
		NewGroupAddCommand(open),
		NewGroupRemoveCommand(open),
		NewEnforceCommand(open),
	}
	signatures := []string{
		"authz:policy:add",
		"authz:policy:remove",
		"authz:policy:list",
		"authz:group:add",
		"authz:group:remove",
		"authz:enforce",
	}

	for index, instance := range instances {
		assert.Equal(t, signatures[index], instance.Signature())
		assert.NotEmpty(t, instance.Description())

		extend := instance.Extend()
		assert.Equal(t, "authz", extend.Category)
		require.Len(t, extend.Flags, 1)

		guard, ok := extend.Flags[0].(*command.StringFlag)
		require.True(t, ok)
		assert.Equal(t, "guard", guard.Name)
		assert.Equal(t, []string{"g"}, guard.Aliases)
	}
}

func TestPolicyRemoveCommand(t *testing.T) {
	t.Run("removes a policy", func(t *testing.T) {
		enforcer := newTestEnforcer(t)
		_, err := enforcer.AddPolicy("admin", "/admin/users", "GET")
		require.NoError(t, err)

		command := NewPolicyRemoveCommand(testOpen(enforcer))
		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"admin", "/admin/users", "GET"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()
		ctx.EXPECT().Success("Policy removed: admin /admin/users GET").Once()

		require.NoError(t, command.Handle(ctx))
		assert.Empty(t, enforcer.GetPolicy())
	})

	t.Run("reports a missing policy", func(t *testing.T) {
		enforcer := newTestEnforcer(t)
		command := NewPolicyRemoveCommand(testOpen(enforcer))

		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"admin", "/admin/users", "GET"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()
		ctx.EXPECT().Warning("Policy not found: admin /admin/users GET").Once()

		require.NoError(t, command.Handle(ctx))
	})

	t.Run("rejects too few values", func(t *testing.T) {
		command := NewPolicyRemoveCommand(failingOpen())
		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"admin"}).Once()

		err := command.Handle(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least 2 values")
	})

	t.Run("wraps adapter errors", func(t *testing.T) {
		enforcer := newTestEnforcerWithAdapter(t, failingAdapter{})
		enforcer.GetModel().AddPolicy("p", "p", []string{"admin", "/admin/users", "GET"})
		command := NewPolicyRemoveCommand(testOpen(enforcer))

		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"admin", "/admin/users", "GET"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()

		err := command.Handle(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authz: remove policy")
		assert.Contains(t, err.Error(), "adapter write failed")
	})
}

func TestPolicyListCommand(t *testing.T) {
	t.Run("lists policies and groupings", func(t *testing.T) {
		enforcer := newTestEnforcer(t)
		_, err := enforcer.AddPolicy("editor", "/admin/posts", "POST")
		require.NoError(t, err)
		_, err = enforcer.AddPolicy("admin", "/admin/users", "GET")
		require.NoError(t, err)
		_, err = enforcer.AddGroupingPolicy("bob", "editor")
		require.NoError(t, err)
		_, err = enforcer.AddGroupingPolicy("alice", "admin")
		require.NoError(t, err)

		command := NewPolicyListCommand(testOpen(enforcer))
		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().Option("guard").Return("").Once()
		ctx.EXPECT().Table(
			[]string{"Ptype", "V0", "V1", "V2"},
			[][]string{
				{"p", "admin", "/admin/users", "GET"},
				{"p", "editor", "/admin/posts", "POST"},
				{"g", "alice", "admin"},
				{"g", "bob", "editor"},
			},
		).Once()

		require.NoError(t, command.Handle(ctx))
	})

	t.Run("prints a message when empty", func(t *testing.T) {
		command := NewPolicyListCommand(testOpen(newTestEnforcer(t)))
		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().Option("guard").Return("").Once()
		ctx.EXPECT().Info("No policies found.").Once()

		require.NoError(t, command.Handle(ctx))
	})

	t.Run("passes the guard to the opener", func(t *testing.T) {
		enforcer := newTestEnforcer(t)
		var guard string
		command := NewPolicyListCommand(func(name string) (*casbin.SyncedEnforcer, error) {
			guard = name
			return enforcer, nil
		})

		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().Option("guard").Return("admin").Once()
		ctx.EXPECT().Info("No policies found.").Once()

		require.NoError(t, command.Handle(ctx))
		assert.Equal(t, "admin", guard)
	})

	t.Run("returns open errors", func(t *testing.T) {
		command := NewPolicyListCommand(failingOpen())
		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().Option("guard").Return("").Once()

		err := command.Handle(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "enforcer is unavailable")
	})
}

func TestGroupCommands(t *testing.T) {
	t.Run("adds a grouping", func(t *testing.T) {
		enforcer := newTestEnforcer(t)
		command := NewGroupAddCommand(testOpen(enforcer))

		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"alice", "admin"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()
		ctx.EXPECT().Success("Grouping added: alice admin").Once()

		require.NoError(t, command.Handle(ctx))
		assert.Equal(t, [][]string{{"alice", "admin"}}, enforcer.GetGroupingPolicy())
	})

	t.Run("reports an existing grouping", func(t *testing.T) {
		enforcer := newTestEnforcer(t)
		_, err := enforcer.AddGroupingPolicy("alice", "admin")
		require.NoError(t, err)

		command := NewGroupAddCommand(testOpen(enforcer))
		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"alice", "admin"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()
		ctx.EXPECT().Warning("Grouping already exists: alice admin").Once()

		require.NoError(t, command.Handle(ctx))
	})

	t.Run("validates the grouping size", func(t *testing.T) {
		enforcer := newTestEnforcer(t)
		command := NewGroupAddCommand(testOpen(enforcer))

		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"alice", "admin", "tenant"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()

		err := command.Handle(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "g rule expects 2 values")
	})

	t.Run("wraps adapter errors", func(t *testing.T) {
		enforcer := newTestEnforcerWithAdapter(t, failingAdapter{})
		command := NewGroupAddCommand(testOpen(enforcer))

		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"alice", "admin"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()

		err := command.Handle(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authz: add grouping")
		assert.Contains(t, err.Error(), "adapter write failed")
	})

	t.Run("removes a grouping", func(t *testing.T) {
		enforcer := newTestEnforcer(t)
		_, err := enforcer.AddGroupingPolicy("alice", "admin")
		require.NoError(t, err)

		command := NewGroupRemoveCommand(testOpen(enforcer))
		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"alice", "admin"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()
		ctx.EXPECT().Success("Grouping removed: alice admin").Once()

		require.NoError(t, command.Handle(ctx))
		assert.Empty(t, enforcer.GetGroupingPolicy())
	})

	t.Run("reports a missing grouping", func(t *testing.T) {
		command := NewGroupRemoveCommand(testOpen(newTestEnforcer(t)))
		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"alice", "admin"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()
		ctx.EXPECT().Warning("Grouping not found: alice admin").Once()

		require.NoError(t, command.Handle(ctx))
	})

	t.Run("wraps adapter errors", func(t *testing.T) {
		enforcer := newTestEnforcerWithAdapter(t, failingAdapter{})
		enforcer.GetModel().AddPolicy("g", "g", []string{"alice", "admin"})
		command := NewGroupRemoveCommand(testOpen(enforcer))

		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"alice", "admin"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()

		err := command.Handle(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authz: remove grouping")
		assert.Contains(t, err.Error(), "adapter write failed")
	})
}

func TestEnforceCommand(t *testing.T) {
	newEnforcerWithAlice := func(t *testing.T) *casbin.SyncedEnforcer {
		enforcer := newTestEnforcer(t)
		_, err := enforcer.AddPolicy("admin", "/admin/users", "GET")
		require.NoError(t, err)
		_, err = enforcer.AddGroupingPolicy("alice", "admin")
		require.NoError(t, err)

		return enforcer
	}

	t.Run("allows an inherited role", func(t *testing.T) {
		command := NewEnforceCommand(testOpen(newEnforcerWithAlice(t)))
		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"alice", "/admin/users", "GET"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()
		ctx.EXPECT().Success("Allowed: alice /admin/users GET").Once()

		require.NoError(t, command.Handle(ctx))
	})

	t.Run("denies an unknown subject", func(t *testing.T) {
		command := NewEnforceCommand(testOpen(newEnforcerWithAlice(t)))
		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"bob", "/admin/users", "GET"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()
		ctx.EXPECT().Warning("Denied: bob /admin/users GET").Once()

		require.NoError(t, command.Handle(ctx))
	})

	t.Run("validates the request size", func(t *testing.T) {
		command := NewEnforceCommand(testOpen(newTestEnforcer(t)))
		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"alice", "/admin/users"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()

		err := command.Handle(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "r rule expects 3 values")
	})

	t.Run("returns open errors", func(t *testing.T) {
		command := NewEnforceCommand(failingOpen())
		ctx := mocksconsole.NewContext(t)
		ctx.EXPECT().ArgumentStringSlice("values").Return([]string{"alice", "/admin/users", "GET"}).Once()
		ctx.EXPECT().Option("guard").Return("").Once()

		err := command.Handle(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "enforcer is unavailable")
	})
}
