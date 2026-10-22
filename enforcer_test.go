package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wcz0/goravel-authz/adapters"
	"github.com/wcz0/goravel-authz/models"
)

const rbacModel = `
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

// textRule is a models.Rule configured with an inline casbin model and a fake
// store, so the manager can be tested without booting a Goravel application.
type textRule struct {
	*models.Rule
	rule string
}

func (r *textRule) Model() (string, string) {
	return "text", r.rule
}

func (r *textRule) Cache() (bool, string, string) {
	return false, "", ""
}

type memoryStore struct {
	rows []adapters.PolicyRow
}

func (s *memoryStore) Load() ([]adapters.PolicyRow, error) { return s.rows, nil }
func (s *memoryStore) Insert(row adapters.PolicyRow) error {
	s.rows = append(s.rows, row)
	return nil
}
func (s *memoryStore) DeleteExact(string, []string) error { return nil }
func (s *memoryStore) DeleteFiltered(string, int, []string) error {
	return nil
}
func (s *memoryStore) DeleteAll() error { return nil }

func withStore(t *testing.T, store adapters.Store) {
	t.Helper()

	previous := adapterFactory
	adapterFactory = func(rule adapters.Rule) *adapters.Adapter {
		return adapters.NewAdapter(rule).SetStore(store).SetCache(nil)
	}
	t.Cleanup(func() {
		adapterFactory = previous
		Reset()
	})
}

func TestNewEnforcerCachesInstances(t *testing.T) {
	store := &memoryStore{rows: []adapters.PolicyRow{
		{Ptype: "p", Values: []string{"admin", "data1", "read"}},
		{Ptype: "g", Values: []string{"alice", "admin"}},
	}}
	withStore(t, store)

	rule := &textRule{Rule: models.NewRule(), rule: rbacModel}

	first, err := enforcerFor("basic", rule)
	require.NoError(t, err)

	allowed, err := first.Enforce("alice", "data1", "read")
	require.NoError(t, err)
	assert.True(t, allowed)

	second, err := enforcerFor("basic", rule)
	require.NoError(t, err)
	assert.Same(t, first, second, "the enforcer must be shared per model name")
}

func TestNewEnforcerKeepsModelsSeparate(t *testing.T) {
	store := &memoryStore{rows: []adapters.PolicyRow{
		{Ptype: "p", Values: []string{"admin", "data1", "read"}},
	}}
	withStore(t, store)

	rule := &textRule{Rule: models.NewRule(), rule: rbacModel}

	first, err := enforcerFor("first", rule)
	require.NoError(t, err)

	second, err := enforcerFor("second", rule)
	require.NoError(t, err)

	assert.NotSame(t, first, second)

	Reset()
	assert.NotNil(t, enforcers)
}
