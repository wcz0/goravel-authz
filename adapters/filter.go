package adapters

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnsupportedFilter is returned by LoadFilteredPolicy when the filter type
// is not one of Filter, *Filter, FilterFunc or func(PolicyRow) bool.
var ErrUnsupportedFilter = errors.New("goravel-authz: unsupported policy filter")

// Filter mirrors the filter of casbin's file adapter. Values are positional:
// a non-empty value must equal the policy value at the same position. Empty
// values match anything. Policy types without an entry (for example p2 or
// g10) are loaded completely.
type Filter struct {
	P  []string
	G  []string
	G1 []string
	G2 []string
	G3 []string
	G4 []string
	G5 []string
}

// FilterFunc decides whether a policy row is loaded. Returning true keeps the
// row, unlike casbin's internal file adapter where a true predicate means
// "skip".
type FilterFunc func(PolicyRow) bool

// filterRows applies any supported filter to the loaded rows.
func filterRows(rows []PolicyRow, filter any) ([]PolicyRow, error) {
	switch value := filter.(type) {
	case nil:
		return rows, nil
	case Filter:
		return filterByValue(rows, &value), nil
	case *Filter:
		if value == nil {
			return rows, nil
		}

		return filterByValue(rows, value), nil
	case FilterFunc:
		if value == nil {
			return rows, nil
		}

		return filterByFunc(rows, value), nil
	case func(PolicyRow) bool:
		if value == nil {
			return rows, nil
		}

		return filterByFunc(rows, value), nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedFilter, filter)
	}
}

func filterByValue(rows []PolicyRow, filter *Filter) []PolicyRow {
	result := make([]PolicyRow, 0, len(rows))
	for _, row := range rows {
		if matchFilterValues(row, filter) {
			result = append(result, row)
		}
	}

	return result
}

func filterByFunc(rows []PolicyRow, filter FilterFunc) []PolicyRow {
	result := make([]PolicyRow, 0, len(rows))
	for _, row := range rows {
		if filter(row) {
			result = append(result, row)
		}
	}

	return result
}

func matchFilterValues(row PolicyRow, filter *Filter) bool {
	if filter == nil {
		return true
	}

	var expected []string
	switch row.Ptype {
	case "p":
		expected = filter.P
	case "g":
		expected = filter.G
	case "g1":
		expected = filter.G1
	case "g2":
		expected = filter.G2
	case "g3":
		expected = filter.G3
	case "g4":
		expected = filter.G4
	case "g5":
		expected = filter.G5
	default:
		// Casbin's file adapter has no entry for other policy types and
		// therefore loads them without filtering.
		return true
	}

	expected = trimTrailingEmpty(expected)
	if len(row.Values) < len(expected) {
		return false
	}
	for i, value := range expected {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if strings.TrimSpace(value) != strings.TrimSpace(row.Values[i]) {
			return false
		}
	}

	return true
}

func trimTrailingEmpty(values []string) []string {
	for len(values) > 0 && strings.TrimSpace(values[len(values)-1]) == "" {
		values = values[:len(values)-1]
	}

	return values
}

// matchRowFilter reports whether a policy row matches the filter used by
// RemoveFilteredPolicy and UpdateFilteredPolicies. fieldIndex is relative to
// the policy values (v0 is index 0) and empty field values are ignored.
func matchRowFilter(row PolicyRow, fieldIndex int, fieldValues []string) bool {
	if fieldIndex < 0 {
		return false
	}

	for i, value := range fieldValues {
		if value == "" {
			continue
		}

		index := fieldIndex + i
		if index >= len(row.Values) || row.Values[index] != value {
			return false
		}
	}

	return true
}
