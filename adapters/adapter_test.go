package adapters

import (
	"encoding/json"
	"errors"
	"slices"
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
	table        string
	refreshed    int
}

func (r *stubRule) TableName() string { return r.table }

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

func TestAdapterAutoCacheKey(t *testing.T) {
	store := &fakeStore{rows: []PolicyRow{}}
	cache := newFakeCache()
	rule := &stubRule{cacheEnabled: true, cacheStore: "memory", table: "casbin_rules"}
	adapter := newTestAdapter(rule, store, cache)

	require.NoError(t, adapter.LoadPolicy(testModel(t)))

	_, cached := cache.values["goravel-authz:casbin_rules"]
	assert.True(t, cached, "the cache key must be derived from the table name")

	require.NoError(t, adapter.RefreshCache())
	assert.Equal(t, []string{"goravel-authz:casbin_rules"}, cache.forgotten)
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

func TestAdapterLoadFilteredPolicy(t *testing.T) {
	store := &fakeStore{rows: []PolicyRow{
		{Ptype: "p", Values: []string{"alice", "data1", "read"}},
		{Ptype: "p", Values: []string{"bob", "data1", "write"}},
		{Ptype: "g", Values: []string{"alice", "admin"}},
	}}
	adapter := newTestAdapter(&stubRule{}, store, nil)

	m := testModel(t)
	require.NoError(t, adapter.LoadFilteredPolicy(m, Filter{
		P: []string{"alice", "", "read"},
		G: []string{},
	}))

	assert.True(t, adapter.IsFiltered())
	assert.Equal(t, [][]string{{"alice", "data1", "read"}}, m["p"]["p"].Policy)
	assert.Equal(t, [][]string{{"alice", "admin"}}, m["g"]["g"].Policy)

	// The enforcer checks IsFiltered before saving; the adapter protects
	// direct callers as well.
	assert.ErrorIs(t, adapter.SavePolicy(m), ErrFilteredPolicy)
	assert.Zero(t, store.deleteAll)
}

func TestAdapterLoadFilteredPolicyFunc(t *testing.T) {
	store := &fakeStore{rows: []PolicyRow{
		{Ptype: "p", Values: []string{"alice", "data1", "read"}},
		{Ptype: "p", Values: []string{"bob", "data2", "write"}},
	}}
	adapter := newTestAdapter(&stubRule{}, store, nil)

	m := testModel(t)
	require.NoError(t, adapter.LoadFilteredPolicy(m, FilterFunc(func(row PolicyRow) bool {
		return row.Values[0] == "bob"
	})))

	assert.True(t, adapter.IsFiltered())
	assert.Equal(t, [][]string{{"bob", "data2", "write"}}, m["p"]["p"].Policy)
}

func TestAdapterLoadFilteredPolicyRejectsUnknownFilter(t *testing.T) {
	adapter := newTestAdapter(&stubRule{}, &fakeStore{}, nil)

	err := adapter.LoadFilteredPolicy(testModel(t), "alice")
	assert.ErrorIs(t, err, ErrUnsupportedFilter)
	assert.False(t, adapter.IsFiltered())
}

func TestAdapterLoadPolicyResetsFilteredState(t *testing.T) {
	store := &fakeStore{rows: []PolicyRow{
		{Ptype: "p", Values: []string{"alice", "data1", "read"}},
	}}
	adapter := newTestAdapter(&stubRule{}, store, nil)

	require.NoError(t, adapter.LoadFilteredPolicy(testModel(t), Filter{P: []string{"alice"}}))
	assert.True(t, adapter.IsFiltered())

	require.NoError(t, adapter.LoadPolicy(testModel(t)))
	assert.False(t, adapter.IsFiltered())
}

func TestAdapterAddPolicies(t *testing.T) {
	store := &fakeStore{}
	cache := newFakeCache()
	rule := &stubRule{cacheEnabled: true, cacheStore: "memory", cacheKey: "k"}
	adapter := newTestAdapter(rule, store, cache)

	require.NoError(t, adapter.AddPolicies("p", "p", [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
	}))

	assert.Equal(t, []PolicyRow{
		{Ptype: "p", Values: []string{"alice", "data1", "read"}},
		{Ptype: "p", Values: []string{"bob", "data2", "write"}},
	}, store.inserted)
	assert.Equal(t, []string{"k"}, cache.forgotten)
}

func TestAdapterAddPoliciesValidatesBeforeWriting(t *testing.T) {
	store := &fakeStore{}
	adapter := newTestAdapter(&stubRule{}, store, nil)

	err := adapter.AddPolicies("p", "p", [][]string{
		{"alice", "data1", "read"},
		{"bob", "1", "2", "3", "4", "5", "6"},
	})

	assert.ErrorIs(t, err, errTooManyFields)
	assert.Empty(t, store.inserted, "no row may be written when a later rule is invalid")
}

func TestAdapterRemovePolicies(t *testing.T) {
	store := &fakeStore{}
	adapter := newTestAdapter(&stubRule{}, store, nil)

	require.NoError(t, adapter.RemovePolicies("p", "p", [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
	}))

	assert.Equal(t, []deleteCall{
		{ptype: "p", values: []string{"alice", "data1", "read"}},
		{ptype: "p", values: []string{"bob", "data2", "write"}},
	}, store.exactCalls)
}

func TestAdapterUpdatePolicy(t *testing.T) {
	store := &fakeStore{}
	adapter := newTestAdapter(&stubRule{}, store, nil)

	require.NoError(t, adapter.UpdatePolicy("p", "p",
		[]string{"alice", "data1", "read"},
		[]string{"alice", "data1", "write"},
	))

	assert.Equal(t, []deleteCall{{
		ptype:  "p",
		values: []string{"alice", "data1", "read"},
	}}, store.exactCalls)
	assert.Equal(t, []PolicyRow{{
		Ptype:  "p",
		Values: []string{"alice", "data1", "write"},
	}}, store.inserted)
}

func TestAdapterUpdatePolicies(t *testing.T) {
	store := &fakeStore{}
	adapter := newTestAdapter(&stubRule{}, store, nil)

	// Swapping two rules is only safe when every old row is deleted before
	// the new rows are inserted.
	require.NoError(t, adapter.UpdatePolicies("p", "p", [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
	}, [][]string{
		{"bob", "data2", "write"},
		{"alice", "data1", "read"},
	}))

	assert.Equal(t, []deleteCall{
		{ptype: "p", values: []string{"alice", "data1", "read"}},
		{ptype: "p", values: []string{"bob", "data2", "write"}},
	}, store.exactCalls)
	assert.Len(t, store.inserted, 2)
}

func TestAdapterUpdatePoliciesRequiresMatchingCounts(t *testing.T) {
	store := &fakeStore{}
	adapter := newTestAdapter(&stubRule{}, store, nil)

	err := adapter.UpdatePolicies("p", "p", [][]string{{"alice"}}, [][]string{{"bob"}, {"carol"}})

	assert.ErrorIs(t, err, ErrRuleCountMismatch)
	assert.Empty(t, store.exactCalls)
	assert.Empty(t, store.inserted)
}

func TestAdapterUpdateFilteredPolicies(t *testing.T) {
	store := &fakeStore{rows: []PolicyRow{
		{Ptype: "p", Values: []string{"admin", "data1", "read"}},
		{Ptype: "p", Values: []string{"admin", "data2", "read"}},
		{Ptype: "p", Values: []string{"editor", "data1", "write"}},
		{Ptype: "g", Values: []string{"alice", "admin"}},
	}}
	cache := newFakeCache()
	rule := &stubRule{cacheEnabled: true, cacheStore: "memory", cacheKey: "k"}
	adapter := newTestAdapter(rule, store, cache)

	oldRules, err := adapter.UpdateFilteredPolicies("p", "p", [][]string{
		{"admin", "data1", "write"},
	}, 1, "data1")

	require.NoError(t, err)
	assert.Equal(t, [][]string{
		{"admin", "data1", "read"},
		{"editor", "data1", "write"},
	}, oldRules, "every p row matching the filter is returned, without the ptype")
	require.Len(t, store.filterCalls, 1)
	assert.Equal(t, filteredCall{ptype: "p", fieldIndex: 1, values: []string{"data1"}}, store.filterCalls[0])
	assert.Equal(t, []PolicyRow{{Ptype: "p", Values: []string{"admin", "data1", "write"}}}, store.inserted)
	assert.Equal(t, []string{"k"}, cache.forgotten)
}

func TestMatchRowFilter(t *testing.T) {
	row := PolicyRow{Ptype: "p", Values: []string{"alice", "data1", "read"}}

	assert.True(t, matchRowFilter(row, 1, []string{"data1"}))
	assert.True(t, matchRowFilter(row, 1, []string{"data1", ""}))
	assert.False(t, matchRowFilter(row, 1, []string{"data2"}))
	assert.False(t, matchRowFilter(row, 2, []string{"data1"}))
	assert.False(t, matchRowFilter(row, 5, []string{"read"}))
	assert.True(t, matchRowFilter(row, 0, nil), "an empty filter matches every row")
	assert.False(t, matchRowFilter(row, -1, nil))
}

func TestFilterMatches(t *testing.T) {
	row := PolicyRow{Ptype: "p", Values: []string{"alice", "data1", "read"}}

	assert.True(t, matchFilterValues(row, &Filter{P: []string{"alice", "", "read"}}))
	assert.True(t, matchFilterValues(row, &Filter{P: []string{"", "", ""}}))
	assert.False(t, matchFilterValues(row, &Filter{P: []string{"bob"}}))
	assert.False(t, matchFilterValues(row, &Filter{P: []string{"", "", "", "extra"}}),
		"a filter longer than the row cannot match")
	assert.True(t, matchFilterValues(row, &Filter{G: []string{"nobody"}}),
		"policy types without a filter entry are loaded completely")
}

// memoryStore is a transactional in-memory Store. It rejects duplicate rows,
// like the unique index of the default table, and only applies a transaction
// when its callback succeeds.
type memoryStore struct {
	rows         []PolicyRow
	transactions int
}

func (s *memoryStore) Load() ([]PolicyRow, error) {
	return append([]PolicyRow(nil), s.rows...), nil
}

func (s *memoryStore) Insert(row PolicyRow) error {
	for _, existing := range s.rows {
		if existing.Ptype == row.Ptype && slices.Equal(existing.Values, row.Values) {
			return errors.New("duplicate policy")
		}
	}

	s.rows = append(s.rows, row)
	return nil
}

func (s *memoryStore) DeleteExact(ptype string, values []string) error {
	kept := s.rows[:0]
	for _, row := range s.rows {
		if row.Ptype == ptype && slices.Equal(row.Values, values) {
			continue
		}
		kept = append(kept, row)
	}
	s.rows = kept

	return nil
}

func (s *memoryStore) DeleteFiltered(ptype string, fieldIndex int, values []string) error {
	kept := s.rows[:0]
	for _, row := range s.rows {
		if row.Ptype == ptype && matchRowFilter(row, fieldIndex, values) {
			continue
		}
		kept = append(kept, row)
	}
	s.rows = kept

	return nil
}

func (s *memoryStore) DeleteAll() error {
	s.rows = nil
	return nil
}

func (s *memoryStore) Transaction(fn func(Store) error) error {
	s.transactions++

	child := &memoryStore{rows: append([]PolicyRow(nil), s.rows...)}
	if err := fn(child); err != nil {
		return err
	}

	s.rows = child.rows
	return nil
}

func TestAdapterRollsBackFailedBatchOnTransactionalStore(t *testing.T) {
	initial := PolicyRow{Ptype: "p", Values: []string{"admin", "data1", "read"}}
	store := &memoryStore{rows: []PolicyRow{initial}}
	adapter := newTestAdapter(&stubRule{}, store, nil)

	// The second rule duplicates an existing row and fails on the unique
	// constraint; the first insert must be rolled back with it.
	err := adapter.AddPolicies("p", "p", [][]string{
		{"editor", "data2", "read"},
		{"admin", "data1", "read"},
	})

	require.Error(t, err)
	assert.Equal(t, 1, store.transactions)
	assert.Equal(t, []PolicyRow{initial}, store.rows)
}
