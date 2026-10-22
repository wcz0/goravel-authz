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
	"github.com/goravel/framework/support"
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

	support.DontVerifyAppKey = true
	cfg := config.NewApplication("")
	logger, err := frameworklog.NewApplication(context.Background(), nil, cfg, frameworkjson.New(), nil)
	require.NoError(t, err)

	dbPath := filepath.Join(t.TempDir(), "authz.db")
	// The framework caches pools per connection name, so a fresh database
	// per test needs the previous pool dropped before building a new one.
	t.Cleanup(databasedriver.CloseConnections)
	databasedriver.CloseConnections()

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

	orm, err := databaseorm.BuildOrm(context.Background(), cfg, "sqlite", logger, func(key ...any) {}, nil)
	require.NoError(t, err)

	_, err = orm.Query().Exec(createTableSQL)
	require.NoError(t, err)

	rule := models.NewRule()

	return &ormStore{rule: rule, open: func() contractsorm.Orm { return orm }}, rule
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
