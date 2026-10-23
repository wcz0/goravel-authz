package adapters

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/goravel/framework/cache"
	"github.com/goravel/framework/config"
	contractsdriver "github.com/goravel/framework/contracts/database/driver"
	contractsorm "github.com/goravel/framework/contracts/database/orm"
	databasedriver "github.com/goravel/framework/database/driver"
	databaseorm "github.com/goravel/framework/database/orm"
	frameworkjson "github.com/goravel/framework/foundation/json"
	frameworklog "github.com/goravel/framework/log"
	"github.com/goravel/sqlite"
	"github.com/wcz0/goravel-authz/models"
)

const createTableSQL = `CREATE TABLE casbin_rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ptype TEXT,
	v0 TEXT,
	v1 TEXT,
	v2 TEXT,
	v3 TEXT,
	v4 TEXT,
	v5 TEXT,
	UNIQUE (ptype, v0, v1, v2, v3, v4, v5)
)`

// newSQLiteStore boots a real Goravel ORM on top of a temporary SQLite
// database, so the persistence layer is exercised end to end.
func newSQLiteStore(t *testing.T) (*ormStore, *models.Rule) {
	t.Helper()

	cfg := config.NewApplication("")
	logger, err := frameworklog.NewApplication(cfg, frameworkjson.New())
	require.NoError(t, err)

	dbPath := filepath.Join(t.TempDir(), "authz.db")
	// Goravel caches one pool per connection name, so a fresh database per
	// test needs the previous pool dropped before building a new one.
	databasedriver.ResetConnections()

	cfg.Add("database", map[string]any{
		"default": "sqlite",
		"connections": map[string]any{
			"sqlite": map[string]any{
				"driver":   "sqlite",
				"database": dbPath,
				"via": func() (contractsdriver.Driver, error) {
					return sqlite.NewSqlite(cfg, logger, "sqlite"), nil
				},
			},
		},
	})

	orm, err := databaseorm.BuildOrm(context.Background(), cfg, "sqlite", logger, func(key ...any) {})
	require.NoError(t, err)
	// Close the pool so the SQLite file is unlocked before the temporary
	// directory is removed, and drop the cached pool for the next test.
	t.Cleanup(func() {
		if db, err := orm.DB(); err == nil {
			_ = db.Close()
		}
		databasedriver.ResetConnections()
	})

	_, err = orm.Query().Exec(createTableSQL)
	require.NoError(t, err)

	rule := models.NewRule()

	return newORMStore(rule, func() contractsorm.Orm { return orm }), rule
}

func TestSQLiteEnforceRoundTrip(t *testing.T) {
	store, rule := newSQLiteStore(t)
	adapter := NewAdapter(rule).SetStore(store).SetCache(nil)

	// SavePolicy must insert several rows in a row without a primary key
	// collision on the reused model instance.
	m := testModel(t)
	m["p"]["p"].Policy = [][]string{
		{"admin", "data1", "read"},
		{"user", "data1", "read"},
	}
	m["g"]["g"].Policy = [][]string{{"alice", "admin"}}
	require.NoError(t, adapter.SavePolicy(m))

	e, err := casbin.NewEnforcer(testModel(t), adapter)
	require.NoError(t, err)

	allowed, err := e.Enforce("alice", "data1", "read")
	require.NoError(t, err)
	assert.True(t, allowed, "alice inherits read access from admin")

	allowed, err = e.Enforce("bob", "data1", "read")
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestSQLiteAddAndRemovePolicy(t *testing.T) {
	store, rule := newSQLiteStore(t)
	adapter := NewAdapter(rule).SetStore(store).SetCache(nil)

	require.NoError(t, adapter.AddPolicy("p", "p", []string{"admin", "data1", "read"}))
	require.NoError(t, adapter.AddPolicy("p", "p", []string{"admin", "data2", "write"}))
	require.NoError(t, adapter.AddPolicy("p", "p", []string{"editor", "data3", "read"}))

	rows, err := store.Load()
	require.NoError(t, err)
	assert.Len(t, rows, 3)

	require.NoError(t, adapter.RemovePolicy("p", "p", []string{"admin", "data1", "read"}))

	rows, err = store.Load()
	require.NoError(t, err)
	assert.Equal(t, []PolicyRow{
		{Ptype: "p", Values: []string{"admin", "data2", "write"}},
		{Ptype: "p", Values: []string{"editor", "data3", "read"}},
	}, rows)
}

func TestSQLiteRemoveFilteredPolicy(t *testing.T) {
	store, rule := newSQLiteStore(t)
	adapter := NewAdapter(rule).SetStore(store).SetCache(nil)

	for _, values := range [][]string{
		{"admin", "data1", "read"},
		{"admin", "data2", "read"},
		{"editor", "data2", "write"},
	} {
		require.NoError(t, adapter.AddPolicy("p", "p", values))
	}

	require.NoError(t, adapter.RemoveFilteredPolicy("p", "p", 1, "data1"))

	rows, err := store.Load()
	require.NoError(t, err)
	assert.Equal(t, []PolicyRow{
		{Ptype: "p", Values: []string{"admin", "data2", "read"}},
		{Ptype: "p", Values: []string{"editor", "data2", "write"}},
	}, rows)
}

func TestSQLitePolicyCacheRoundTrip(t *testing.T) {
	store, rule := newSQLiteStore(t)

	memory, err := cache.NewMemory(config.NewApplication(""))
	require.NoError(t, err)

	adapter := NewAdapter(rule).SetStore(store).SetCache(func(string) policyCache { return memory })

	require.NoError(t, adapter.AddPolicy("p", "p", []string{"admin", "data1", "read"}))

	m := testModel(t)
	require.NoError(t, adapter.LoadPolicy(m))
	assert.Equal(t, [][]string{{"admin", "data1", "read"}}, m["p"]["p"].Policy)

	// Bypass the adapter: the cached result must hide this row until the
	// cache is flushed, which is what an out-of-band write looks like.
	require.NoError(t, store.Insert(PolicyRow{Ptype: "p", Values: []string{"editor", "data2", "write"}}))

	cached := testModel(t)
	require.NoError(t, adapter.LoadPolicy(cached))
	assert.Len(t, cached["p"]["p"].Policy, 1, "the second load must be served from the cache")

	require.NoError(t, adapter.RefreshCache())

	fresh := testModel(t)
	require.NoError(t, adapter.LoadPolicy(fresh))
	assert.Len(t, fresh["p"]["p"].Policy, 2, "a flushed cache must read both rows")
}

func TestSQLiteSavePolicyReplacesRows(t *testing.T) {
	store, rule := newSQLiteStore(t)
	adapter := NewAdapter(rule).SetStore(store).SetCache(nil)

	require.NoError(t, adapter.AddPolicy("p", "p", []string{"stale", "data0", "read"}))

	m := testModel(t)
	m["p"]["p"].Policy = [][]string{{"admin", "data1", "read"}}
	require.NoError(t, adapter.SavePolicy(m))

	rows, err := store.Load()
	require.NoError(t, err)
	assert.Equal(t, []PolicyRow{{Ptype: "p", Values: []string{"admin", "data1", "read"}}}, rows)
}

func TestSQLiteBatchPoliciesThroughEnforcer(t *testing.T) {
	store, rule := newSQLiteStore(t)
	adapter := NewAdapter(rule).SetStore(store).SetCache(nil)

	e, err := casbin.NewEnforcer(testModel(t), adapter)
	require.NoError(t, err)

	added, err := e.AddPolicies([][]string{
		{"admin", "data1", "read"},
		{"editor", "data2", "write"},
	})
	require.NoError(t, err)
	assert.True(t, added)

	rows, err := store.Load()
	require.NoError(t, err)
	assert.Len(t, rows, 2)

	removed, err := e.RemovePolicies([][]string{{"admin", "data1", "read"}})
	require.NoError(t, err)
	assert.True(t, removed)

	rows, err = store.Load()
	require.NoError(t, err)
	assert.Equal(t, []PolicyRow{
		{Ptype: "p", Values: []string{"editor", "data2", "write"}},
	}, rows)
}

func TestSQLiteUpdatePoliciesThroughEnforcer(t *testing.T) {
	store, rule := newSQLiteStore(t)
	adapter := NewAdapter(rule).SetStore(store).SetCache(nil)

	e, err := casbin.NewEnforcer(testModel(t), adapter)
	require.NoError(t, err)

	_, err = e.AddPolicies([][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
	})
	require.NoError(t, err)

	updated, err := e.UpdatePolicies([][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
	}, [][]string{
		{"bob", "data2", "write"},
		{"alice", "data1", "read"},
	})
	require.NoError(t, err)
	assert.True(t, updated)

	rows, err := store.Load()
	require.NoError(t, err)
	assert.ElementsMatch(t, []PolicyRow{
		{Ptype: "p", Values: []string{"alice", "data1", "read"}},
		{Ptype: "p", Values: []string{"bob", "data2", "write"}},
	}, rows)

	updated, err = e.UpdatePolicy(
		[]string{"alice", "data1", "read"},
		[]string{"alice", "data1", "write"},
	)
	require.NoError(t, err)
	assert.True(t, updated)

	rows, err = store.Load()
	require.NoError(t, err)
	assert.ElementsMatch(t, []PolicyRow{
		{Ptype: "p", Values: []string{"alice", "data1", "write"}},
		{Ptype: "p", Values: []string{"bob", "data2", "write"}},
	}, rows)
}

func TestSQLiteUpdateFilteredPoliciesThroughEnforcer(t *testing.T) {
	store, rule := newSQLiteStore(t)
	adapter := NewAdapter(rule).SetStore(store).SetCache(nil)

	e, err := casbin.NewEnforcer(testModel(t), adapter)
	require.NoError(t, err)

	_, err = e.AddPolicies([][]string{
		{"admin", "data1", "read"},
		{"admin", "data2", "read"},
		{"editor", "data1", "write"},
	})
	require.NoError(t, err)

	updated, err := e.UpdateFilteredPolicies(
		[][]string{{"admin", "data1", "write"}},
		1,
		"data1",
	)
	require.NoError(t, err)
	assert.True(t, updated)

	rows, err := store.Load()
	require.NoError(t, err)
	assert.ElementsMatch(t, []PolicyRow{
		{Ptype: "p", Values: []string{"admin", "data1", "write"}},
		{Ptype: "p", Values: []string{"admin", "data2", "read"}},
	}, rows, "both rules with data1 match the filter and are replaced")

	allowed, err := e.Enforce("admin", "data1", "write")
	require.NoError(t, err)
	assert.True(t, allowed, "the enforcer model must contain the updated rule")
}

func TestSQLiteLoadFilteredPolicyThroughEnforcer(t *testing.T) {
	store, rule := newSQLiteStore(t)
	adapter := NewAdapter(rule).SetStore(store).SetCache(nil)

	require.NoError(t, adapter.AddPolicy("p", "p", []string{"admin", "data1", "read"}))
	require.NoError(t, adapter.AddPolicy("p", "p", []string{"editor", "data2", "write"}))
	require.NoError(t, adapter.AddPolicy("g", "g", []string{"alice", "admin"}))

	e, err := casbin.NewEnforcer(testModel(t), adapter)
	require.NoError(t, err)

	require.NoError(t, e.LoadFilteredPolicy(Filter{P: []string{"admin"}}))
	assert.True(t, e.IsFiltered())

	policies, err := e.GetPolicy()
	require.NoError(t, err)
	assert.Equal(t, [][]string{{"admin", "data1", "read"}}, policies)

	grouping, err := e.GetGroupingPolicy()
	require.NoError(t, err)
	assert.Equal(t, [][]string{{"alice", "admin"}}, grouping,
		"a filter without a G entry loads all grouping policies")

	// Casbin refuses to save a filtered policy as well; both guards are in
	// place because SavePolicy would delete the rows that were not loaded.
	assert.Error(t, e.SavePolicy())

	require.NoError(t, e.LoadPolicy())
	assert.False(t, e.IsFiltered())
}

func TestSQLiteBatchRollsBackOnConstraintError(t *testing.T) {
	store, rule := newSQLiteStore(t)
	adapter := NewAdapter(rule).SetStore(store).SetCache(nil)

	require.NoError(t, adapter.AddPolicy("p", "p", []string{"admin", "data1", "read"}))

	err := adapter.AddPolicies("p", "p", [][]string{
		{"editor", "data2", "read"},
		{"admin", "data1", "read"},
	})

	require.Error(t, err)
	rows, loadErr := store.Load()
	require.NoError(t, loadErr)
	assert.Equal(t, []PolicyRow{
		{Ptype: "p", Values: []string{"admin", "data1", "read"}},
	}, rows, "the first insert must be rolled back when the second one violates the unique index")
}
