package adapters

import (
	"errors"
	"fmt"
	"reflect"
	"sync"

	contractsorm "github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/facades"
)

// MaxPolicyFields is the number of casbin value columns (v0-v5) supported by
// the default table schema.
const MaxPolicyFields = 6

// policyColumns is the column order used when reading and writing policies.
var policyColumns = []string{"ptype", "v0", "v1", "v2", "v3", "v4", "v5"}

var errTooManyFields = errors.New("goravel-authz: policy rule exceeds the supported 6 values (v0-v5)")

// PolicyRow is a storage independent representation of a single policy line.
// Values are trimmed of trailing empty entries.
type PolicyRow struct {
	Ptype  string   `json:"ptype"`
	Values []string `json:"values"`
}

// NewPolicyRow builds a PolicyRow from a casbin ptype and its values.
func NewPolicyRow(ptype string, values []string) (PolicyRow, error) {
	if len(values) > MaxPolicyFields {
		return PolicyRow{}, errTooManyFields
	}

	trimmed := make([]string, len(values))
	copy(trimmed, values)
	for len(trimmed) > 0 && trimmed[len(trimmed)-1] == "" {
		trimmed = trimmed[:len(trimmed)-1]
	}

	return PolicyRow{Ptype: ptype, Values: trimmed}, nil
}

// Line returns the row in the format expected by casbin.
func (r PolicyRow) Line() []string {
	line := make([]string, 0, len(r.Values)+1)
	line = append(line, r.Ptype)
	return append(line, r.Values...)
}

// Store persists policy rows. The default implementation uses the Goravel
// ORM; a custom implementation can be supplied through Adapter.SetStore.
type Store interface {
	// Load returns every policy row.
	Load() ([]PolicyRow, error)
	// Insert adds a single policy row.
	Insert(row PolicyRow) error
	// DeleteExact removes rows matching every given value, including empty ones.
	DeleteExact(ptype string, values []string) error
	// DeleteFiltered removes rows matching the non-empty values starting at
	// fieldIndex, following casbin's RemoveFilteredPolicy semantics.
	DeleteFiltered(ptype string, fieldIndex int, values []string) error
	// DeleteAll removes every row.
	DeleteAll() error
}

// TransactionalStore is an optional Store capability. When implemented, every
// update that touches more than one row (SavePolicy, AddPolicies, UpdatePolicy
// and friends) runs inside a single transaction and is rolled back when any
// statement fails.
type TransactionalStore interface {
	Store
	// Transaction runs fn against a store whose writes are part of one
	// transaction. Returning an error rolls the transaction back.
	Transaction(fn func(Store) error) error
}

type policyRecord struct {
	Ptype string `gorm:"column:ptype"`
	V0    string `gorm:"column:v0"`
	V1    string `gorm:"column:v1"`
	V2    string `gorm:"column:v2"`
	V3    string `gorm:"column:v3"`
	V4    string `gorm:"column:v4"`
	V5    string `gorm:"column:v5"`
}

func (r policyRecord) row() PolicyRow {
	row, _ := NewPolicyRow(r.Ptype, []string{r.V0, r.V1, r.V2, r.V3, r.V4, r.V5})
	return row
}

type ormStore struct {
	rule    Rule
	mu      *sync.Mutex
	open    func() contractsorm.Orm
	queryFn func() contractsorm.Query
}

// NewORMStore returns the default Store backed by the Goravel ORM.
func NewORMStore(rule Rule) Store {
	return newORMStore(rule, func() contractsorm.Orm { return facades.Orm() })
}

func newORMStore(rule Rule, open func() contractsorm.Orm) *ormStore {
	return &ormStore{
		rule: rule,
		mu:   &sync.Mutex{},
		open: open,
	}
}

// orm returns the ORM instance of the connection declared by the rule.
func (s *ormStore) orm() contractsorm.Orm {
	orm := s.open()
	if connector, ok := s.rule.(interface{ Connection() string }); ok && orm != nil {
		return orm.Connection(connector.Connection())
	}

	return orm
}

func (s *ormStore) query() contractsorm.Query {
	if s.queryFn != nil {
		return s.queryFn()
	}

	return s.orm().Query()
}

// Transaction runs fn inside a database transaction, routing every statement
// through the connection of the rule. Nested calls reuse the current
// transaction.
func (s *ormStore) Transaction(fn func(Store) error) error {
	if s.queryFn != nil {
		return fn(s)
	}

	return s.orm().Transaction(func(tx contractsorm.Query) error {
		return fn(&ormStore{
			rule:    s.rule,
			mu:      s.mu,
			open:    s.open,
			queryFn: func() contractsorm.Query { return tx },
		})
	})
}

func (s *ormStore) Load() ([]PolicyRow, error) {
	var records []policyRecord
	if err := s.query().Model(s.rule).Select(policyColumns...).Get(&records); err != nil {
		return nil, err
	}

	rows := make([]PolicyRow, 0, len(records))
	for _, record := range records {
		rows = append(rows, record.row())
	}

	return rows, nil
}

func (s *ormStore) Insert(row PolicyRow) error {
	if s.mu != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
	}

	s.applyRow(row)

	// The model instance is reused for every insert, so its primary key is
	// omitted and left to the database after the first save filled it in.
	if err := s.query().Omit("Id").Create(s.rule); err != nil {
		return err
	}

	// GORM writes the generated key back into the model. Keeping it would
	// turn the next Delete into "WHERE id = <previous row>", silently
	// deleting nothing, so the key is cleared again.
	s.resetPrimaryKey()

	return nil
}

func (s *ormStore) resetPrimaryKey() {
	value := reflect.ValueOf(s.rule)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return
	}

	value = value.Elem()
	for _, name := range []string{"Id", "ID"} {
		if field := value.FieldByName(name); field.IsValid() && field.CanSet() {
			field.SetZero()
			return
		}
	}
}

// applyRow copies the row onto the rule instance. Every column is reset first
// so a shorter rule never inherits trailing values from a rule saved
// previously through the same model instance.
func (s *ormStore) applyRow(row PolicyRow) {
	setters := []func(string){
		s.rule.SetV0, s.rule.SetV1, s.rule.SetV2, s.rule.SetV3, s.rule.SetV4, s.rule.SetV5,
	}
	for _, setter := range setters {
		setter("")
	}

	s.rule.SetPtype(row.Ptype)
	for i, setter := range setters {
		if i < len(row.Values) {
			setter(row.Values[i])
		}
	}
}

func (s *ormStore) DeleteExact(ptype string, values []string) error {
	query := s.query().Model(s.rule).Where("ptype", ptype)
	for i, value := range values {
		column, ok := policyColumn(i)
		if !ok {
			return errTooManyFields
		}
		query = query.Where(column, value)
	}
	_, err := query.Delete(s.rule)
	return err
}

func (s *ormStore) DeleteFiltered(ptype string, fieldIndex int, values []string) error {
	query := s.query().Model(s.rule).Where("ptype", ptype)
	for i, value := range values {
		if value == "" {
			continue
		}
		column, ok := policyColumn(fieldIndex + i)
		if !ok {
			return errTooManyFields
		}
		query = query.Where(column, value)
	}
	_, err := query.Delete(s.rule)
	return err
}

func (s *ormStore) DeleteAll() error {
	// "1 = 1" keeps GORM's global delete protection satisfied.
	_, err := s.query().Model(s.rule).Where("1 = 1").Delete(s.rule)
	return err
}

// policyColumn maps a value index (0-based) to its column name.
func policyColumn(index int) (string, bool) {
	if index < 0 || index >= MaxPolicyFields {
		return "", false
	}
	return fmt.Sprintf("v%d", index), true
}
