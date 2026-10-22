package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRuleAccessors(t *testing.T) {
	rule := NewRule()

	rule.SetPtype("p")
	rule.SetV0("alice")
	rule.SetV1("data1")
	rule.SetV2("read")
	rule.SetV3("domain1")
	rule.SetV4("extra4")
	rule.SetV5("extra5")

	assert.Equal(t, "p", rule.GetPtype())
	assert.Equal(t, "alice", rule.GetV0())
	assert.Equal(t, "data1", rule.GetV1())
	assert.Equal(t, "read", rule.GetV2())
	assert.Equal(t, "domain1", rule.GetV3())
	assert.Equal(t, "extra4", rule.GetV4())
	assert.Equal(t, "extra5", rule.GetV5())
}

func TestRuleDefaults(t *testing.T) {
	rule := NewRule()

	assert.Equal(t, "casbin_rules", rule.TableName())
	assert.Empty(t, rule.Connection(), "the default connection must not be hardcoded")

	modelType, modelValue := rule.Model()
	assert.Equal(t, "file", modelType)
	assert.Equal(t, "casbin-rbac-model.conf", modelValue)

	enabled, store, key := rule.Cache()
	assert.True(t, enabled)
	assert.Equal(t, "memory", store)
	assert.Equal(t, "goravel-authz:casbin_rules", key)
}
