package adapters

import (
	"encoding/json"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/casbin/casbin/v2/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubRule struct {
	ptype string
	v0    string
	v1    string
	v2    string
	v3    string
	v4    string
	v5    string

	cacheEnabled bool
	cacheStore   string
	cacheKey     string
	cacheTTL     time.Duration
	refreshed    int
}

func (r *stubRule) SetPtype(value string) { r.ptype = value }
func (r *stubRule) GetPtype() string      { return r.ptype }
func (r *stubRule) SetV0(value string)    { r.v0 = value }
func (r *stubRule) GetV0() string         { return r.v0 }
func (r *stubRule) SetV1(value string)    { r.v1 = value }
func (r *stubRule) GetV1() string         { return r.v1 }
func (r *stubRule) SetV2(value string)    { r.v2 = value }
func (r *stubRule) GetV2() string         { return r.v2 }
func (r *stubRule) SetV3(value string)    { r.v3 = value }
func (r *stubRule) GetV3() string         { return r.v3 }
func (r *stubRule) SetV4(value string)    { r.v4 = value }
func (r *stubRule) GetV4() string         { return r.v4 }
func (r *stubRule) SetV5(value string)    { r.v5 = value }
func (r *stubRule) GetV5() string         { return r.v5 }
func (r *stubRule) Model() (string, string) {
	return "text", ""
}
func (r *stubRule) Cache() (bool, string, string) {
	return r.cacheEnabled, r.cacheStore, r.cacheKey
}
func (r *stubRule) RefreshCache() { r.refreshed++ }
func (r *stubRule) CacheTTL() time.Duration {
	return r.cacheTTL
}

type fakeStore struct {
	rows []PolicyRow

	loadCalls    int
	inserted     []PolicyRow
	deleteAll    int
	exactCalls   []deleteCall
	filterCalls  []filteredCall
	loadErr      error
	insertErr    error
	deleteAllErr error
}

type deleteCall struct {
	ptype  string
	values []string
}

type filteredCall struct {
	ptype      string
	fieldIndex int
	values     []string
}

func (s *fakeStore) Load() ([]PolicyRow, error) {
	s.loadCalls++
	return s.rows, s.loadErr
}

func (s *fakeStore) Insert(row PolicyRow) error {
	s.inserted = append(s.inserted, row)
	return s.insertErr
}

func (s *fakeStore) DeleteExact(ptype string, values []string) error {
	s.exactCalls = append(s.exactCalls, deleteCall{ptype: ptype, values: values})
	return nil
}

func (s *fakeStore) DeleteFiltered(ptype string, fieldIndex int, values []string) error {
	s.filterCalls = append(s.filterCalls, filteredCall{ptype: ptype, fieldIndex: fieldIndex, values: values})
	return nil
}

func (s *fakeStore) DeleteAll() error {
	s.deleteAll++
	return s.deleteAllErr
}

type fakeCache struct {
	values    map[string]string
	forgotten []string
	ttl       time.Duration
}

func newFakeCache() *fakeCache {
	return &fakeCache{values: map[string]string{}}
}

func (c *fakeCache) Remember(key string, ttl time.Duration, callback func() (any, error)) (any, error) {
	c.ttl = ttl
	if value, ok := c.values[key]; ok {
		return value, nil
	}

	value, err := callback()
	if err != nil {
		return nil, err
	}

	encoded, ok := value.(string)
	if !ok {
		return nil, ErrUnexpectedCachedValue
	}
	c.values[key] = encoded

	return encoded, nil
}

func (c *fakeCache) Forget(key string) bool {
	c.forgotten = append(c.forgotten, key)
	_, ok := c.values[key]
	delete(c.values, key)

	return ok
}

func testModel(t *testing.T) model.Model {
	t.Helper()

	m, err := model.NewModelFromString(`
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
`)
	require.NoError(t, err)

	return m
}

func newTestAdapter(rule Rule, store Store, cache *fakeCache) *Adapter {
	adapter := NewAdapter(rule).SetStore(store)
	if cache != nil {
		adapter.SetCache(func(string) policyCache { return cache })
	} else {
		adapter.SetCache(nil)
	}

	return adapter
}

func TestNewPolicyRow(t *testing.T) {
	row, err := NewPolicyRow("p", []string{"alice", "data1", "", ""})
	require.NoError(t, err)
	assert.Equal(t, PolicyRow{Ptype: "p", Values: []string{"alice", "data1"}}, row)
	assert.Equal(t, []string{"p", "alice", "data1"}, row.Line())

	_, err = NewPolicyRow("p", []string{"1", "2", "3", "4", "5", "6", "7"})
	assert.ErrorIs(t, err, errTooManyFields)
}

func TestPolicyColumn(t *testing.T) {
	column, ok := policyColumn(0)
	assert.True(t, ok)
	assert.Equal(t, "v0", column)

	column, ok = policyColumn(5)
	assert.True(t, ok)
	assert.Equal(t, "v5", column)

	_, ok = policyColumn(6)
	assert.False(t, ok)

	_, ok = policyColumn(-1)
	assert.False(t, ok)
}

func TestAdapterLoadPolicyWithoutCache(t *testing.T) {
	store := &fakeStore{rows: []PolicyRow{
		{Ptype: "p", Values: []string{"alice", "data1", "read"}},
		{Ptype: "g", Values: []string{"alice", "admin"}},
	}}
	adapter := newTestAdapter(&stubRule{}, store, nil)

	m := testModel(t)
	require.NoError(t, adapter.LoadPolicy(m))

	assert.Equal(t, 1, store.loadCalls)
	assert.Equal(t, [][]string{{"alice", "data1", "read"}}, m["p"]["p"].Policy)
	assert.Equal(t, [][]string{{"alice", "admin"}}, m["g"]["g"].Policy)
}

func TestAdapterLoadPolicyWithCache(t *testing.T) {
	store := &fakeStore{rows: []PolicyRow{
		{Ptype: "p", Values: []string{"alice", "data1", "read"}},
	}}
	cache := newFakeCache()
	rule := &stubRule{cacheEnabled: true, cacheStore: "memory", cacheKey: "casbin-test"}
	adapter := newTestAdapter(rule, store, cache)

	for i := 0; i < 2; i++ {
		m := testModel(t)
		require.NoError(t, adapter.LoadPolicy(m))
		assert.Equal(t, [][]string{{"alice", "data1", "read"}}, m["p"]["p"].Policy)
	}

	assert.Equal(t, 1, store.loadCalls, "second load must be served from the cache")
	assert.Equal(t, DefaultCacheTTL, cache.ttl)

	require.NoError(t, adapter.RefreshCache())
	assert.Equal(t, []string{"casbin-test"}, cache.forgotten)

	m := testModel(t)
	require.NoError(t, adapter.LoadPolicy(m))
	assert.Equal(t, 2, store.loadCalls, "a flushed cache must hit the store again")
}

func TestAdapterCacheTTLOverride(t *testing.T) {
	store := &fakeStore{rows: []PolicyRow{}}
	cache := newFakeCache()
	rule := &stubRule{cacheEnabled: true, cacheStore: "memory", cacheKey: "k", cacheTTL: time.Minute}
	adapter := newTestAdapter(rule, store, cache)

	require.NoError(t, adapter.LoadPolicy(testModel(t)))
	assert.Equal(t, time.Minute, cache.ttl)
}

func TestAdapterCacheRequiresKey(t *testing.T) {
	adapter := newTestAdapter(&stubRule{cacheEnabled: true, cacheStore: "memory"}, &fakeStore{}, newFakeCache())

	err := adapter.LoadPolicy(testModel(t))
	assert.ErrorIs(t, err, ErrEmptyCacheKey)
}

func TestAdapterInsertClearsStaleValues(t *testing.T) {
	rule := &stubRule{v0: "old", v1: "old", v2: "old", v3: "old"}
	store := NewORMStore(rule).(*ormStore)

	store.applyRow(PolicyRow{Ptype: "p", Values: []string{"alice"}})

	assert.Equal(t, "p", rule.ptype)
	assert.Equal(t, "alice", rule.v0)
	assert.Empty(t, rule.v1)
	assert.Empty(t, rule.v2)
	assert.Empty(t, rule.v3)
}

func TestAdapterSavePolicy(t *testing.T) {
	store := &fakeStore{}
	cache := newFakeCache()
	rule := &stubRule{cacheEnabled: true, cacheStore: "memory", cacheKey: "k"}
	adapter := newTestAdapter(rule, store, cache)

	m := testModel(t)
	m["p"]["p"].Policy = [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write", "extra"},
	}
	m["g"]["g"].Policy = [][]string{{"alice", "admin"}}

	require.NoError(t, adapter.SavePolicy(m))

	assert.Equal(t, 1, store.deleteAll, "SavePolicy must replace the stored policies")
	assert.Len(t, store.inserted, 3)

	rows := store.inserted
	sort.Slice(rows, func(i, j int) bool { return rows[i].Ptype < rows[j].Ptype })
	assert.Equal(t, PolicyRow{Ptype: "g", Values: []string{"alice", "admin"}}, rows[0])
	assert.Equal(t, PolicyRow{Ptype: "p", Values: []string{"alice", "data1", "read"}}, rows[1])
	assert.Equal(t, PolicyRow{Ptype: "p", Values: []string{"bob", "data2", "write", "extra"}}, rows[2])
	assert.Equal(t, []string{"k"}, cache.forgotten)
}

func TestAdapterSavePolicyPropagatesDeleteError(t *testing.T) {
	store := &fakeStore{deleteAllErr: assert.AnError}
	adapter := newTestAdapter(&stubRule{}, store, nil)

	err := adapter.SavePolicy(testModel(t))
	assert.ErrorIs(t, err, assert.AnError)
	assert.Empty(t, store.inserted)
}

func TestAdapterAddPolicy(t *testing.T) {
	store := &fakeStore{}
	cache := newFakeCache()
	rule := &stubRule{cacheEnabled: true, cacheStore: "memory", cacheKey: "k"}
	adapter := newTestAdapter(rule, store, cache)

	require.NoError(t, adapter.AddPolicy("p", "p", []string{"alice", "data1", "read"}))

	assert.Equal(t, []PolicyRow{{Ptype: "p", Values: []string{"alice", "data1", "read"}}}, store.inserted)
	assert.Equal(t, []string{"k"}, cache.forgotten)
}

func TestAdapterRemovePolicy(t *testing.T) {
	store := &fakeStore{}
	adapter := newTestAdapter(&stubRule{}, store, nil)

	require.NoError(t, adapter.RemovePolicy("p", "p", []string{"alice", "data1", "read"}))

	require.Len(t, store.exactCalls, 1)
	assert.Equal(t, "p", store.exactCalls[0].ptype)
	assert.Equal(t, []string{"alice", "data1", "read"}, store.exactCalls[0].values)
}

func TestAdapterRemoveFilteredPolicy(t *testing.T) {
	store := &fakeStore{}
	adapter := newTestAdapter(&stubRule{}, store, nil)

	require.NoError(t, adapter.RemoveFilteredPolicy("p", "p", 1, "data1"))

	require.Len(t, store.filterCalls, 1)
	assert.Equal(t, filteredCall{ptype: "p", fieldIndex: 1, values: []string{"data1"}}, store.filterCalls[0])
}

func TestAdapterLoadPolicyError(t *testing.T) {
	adapter := newTestAdapter(&stubRule{}, &fakeStore{loadErr: assert.AnError}, nil)

	assert.ErrorIs(t, adapter.LoadPolicy(testModel(t)), assert.AnError)
}

func TestDecodeRows(t *testing.T) {
	rows := []PolicyRow{{Ptype: "p", Values: []string{"alice"}}}

	encoded, err := json.Marshal(rows)
	require.NoError(t, err)

	decoded, err := decodeRows(string(encoded))
	require.NoError(t, err)
	assert.Equal(t, rows, decoded)

	decoded, err = decodeRows(encoded)
	require.NoError(t, err)
	assert.Equal(t, rows, decoded)

	decoded, err = decodeRows(rows)
	require.NoError(t, err)
	assert.Equal(t, rows, decoded)

	_, err = decodeRows(42)
	assert.True(t, errors.Is(err, ErrUnexpectedCachedValue))
}
