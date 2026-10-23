package authz

import (
	"sync"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wcz0/goravel-authz/adapters"
	"github.com/wcz0/goravel-authz/models"
)

// withConfig replaces the casbin configuration for the duration of the test,
// so the lifecycle can be exercised without booting a Goravel application.
func withConfig(t *testing.T, values map[string]any) {
	t.Helper()

	previousString, previousEntry := configString, configEntry
	configString = func(key string) string {
		value, _ := values[key].(string)

		return value
	}
	configEntry = func(key string) any {
		return values[key]
	}

	t.Cleanup(func() {
		configString, configEntry = previousString, previousEntry
	})
}

func basicConfig(rule adapters.Rule) map[string]any {
	return map[string]any{
		"casbin.default":      "basic",
		"casbin.models.basic": rule,
	}
}

func TestNewEnforcerResolvesDefaultModel(t *testing.T) {
	withStore(t, &memoryStore{rows: []adapters.PolicyRow{
		{Ptype: "p", Values: []string{"admin", "data1", "read"}},
		{Ptype: "g", Values: []string{"alice", "admin"}},
	}})
	withConfig(t, basicConfig(&textRule{Rule: models.NewRule(), rule: rbacModel}))

	instance, err := NewEnforcer("")
	require.NoError(t, err)

	allowed, err := instance.Enforce("alice", "data1", "read")
	require.NoError(t, err)
	assert.True(t, allowed)

	named, err := NewEnforcer("basic")
	require.NoError(t, err)
	assert.Same(t, instance, named, "an empty name must resolve to casbin.default")
}

func TestNewEnforcerWithoutDefaultModel(t *testing.T) {
	withConfig(t, map[string]any{})

	instance, err := NewEnforcer("")

	assert.Nil(t, instance)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no default model is configured")
}

func TestNewEnforcerUnknownModel(t *testing.T) {
	withConfig(t, map[string]any{"casbin.default": "basic"})

	instance, err := NewEnforcer("")

	assert.Nil(t, instance)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `model "basic" is not defined`)
}

func TestNewEnforcerRejectsModelThatIsNotARule(t *testing.T) {
	withConfig(t, map[string]any{
		"casbin.default":      "basic",
		"casbin.models.basic": "not a rule",
	})

	instance, err := NewEnforcer("")

	assert.Nil(t, instance)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must implement adapters.Rule")
}

func TestNewEnforcerRejectsUnsupportedModelKind(t *testing.T) {
	withStore(t, &memoryStore{})
	rule := &textRule{Rule: models.NewRule()}
	rule.rule = rbacModel
	withConfig(t, basicConfig(&unsupportedRule{textRule: rule}))

	instance, err := NewEnforcer("basic")

	assert.Nil(t, instance)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported Model() type")
}

func TestReloadCreatesMissingEnforcer(t *testing.T) {
	withStore(t, &memoryStore{rows: []adapters.PolicyRow{
		{Ptype: "p", Values: []string{"admin", "data1", "read"}},
	}})
	withConfig(t, basicConfig(&textRule{Rule: models.NewRule(), rule: rbacModel}))

	require.NoError(t, Reload("basic"))

	instance, err := NewEnforcer("basic")
	require.NoError(t, err)

	allowed, err := instance.Enforce("admin", "data1", "read")
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestReloadPicksUpStoredPolicies(t *testing.T) {
	store := &memoryStore{rows: []adapters.PolicyRow{
		{Ptype: "p", Values: []string{"admin", "data1", "read"}},
	}}
	withStore(t, store)
	withConfig(t, basicConfig(&textRule{Rule: models.NewRule(), rule: rbacModel}))

	instance, err := NewEnforcer("basic")
	require.NoError(t, err)

	allowed, err := instance.Enforce("bob", "data1", "read")
	require.NoError(t, err)
	assert.False(t, allowed, "bob has no policy yet")

	store.rows = append(store.rows, adapters.PolicyRow{Ptype: "p", Values: []string{"bob", "data1", "read"}})

	require.NoError(t, Reload("basic"))

	allowed, err = instance.Enforce("bob", "data1", "read")
	require.NoError(t, err)
	assert.True(t, allowed, "reload must load the policies written by another process")
}

func TestReloadWithoutDefaultModel(t *testing.T) {
	withConfig(t, map[string]any{})

	err := Reload("")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no default model is configured")
}

func TestResetDropsCachedEnforcers(t *testing.T) {
	withStore(t, &memoryStore{})
	withConfig(t, basicConfig(&textRule{Rule: models.NewRule(), rule: rbacModel}))

	first, err := NewEnforcer("basic")
	require.NoError(t, err)

	Reset()

	second, err := NewEnforcer("basic")
	require.NoError(t, err)
	assert.NotSame(t, first, second)
}

// TestConcurrentNewEnforcerSharesInstance makes sure a burst of first requests
// builds the model once. It is meant to run with -race.
func TestConcurrentNewEnforcerSharesInstance(t *testing.T) {
	withStore(t, &memoryStore{rows: []adapters.PolicyRow{
		{Ptype: "p", Values: []string{"admin", "data1", "read"}},
	}})
	withConfig(t, basicConfig(&textRule{Rule: models.NewRule(), rule: rbacModel}))

	const goroutines = 16

	instances := make([]*casbin.SyncedEnforcer, goroutines)
	failures := make(chan error, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(index int) {
			defer wg.Done()

			instance, err := NewEnforcer("basic")
			if err != nil {
				failures <- err
				return
			}
			instances[index] = instance
		}(i)
	}
	wg.Wait()
	close(failures)

	for err := range failures {
		require.NoError(t, err)
	}

	require.NotNil(t, instances[0])
	for _, instance := range instances[1:] {
		assert.Same(t, instances[0], instance)
	}
}

// unsupportedRule reports a model type this package does not know.
type unsupportedRule struct {
	*textRule
}

func (r *unsupportedRule) Model() (string, string) {
	return "inline", r.textRule.rule
}
