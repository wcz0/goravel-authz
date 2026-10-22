package logging

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type fakeConfig struct {
	values map[string]any
}

func (f fakeConfig) GetString(path string, defaultValue ...string) string {
	value, ok := f.values[path]
	if !ok {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}

		return ""
	}

	return value.(string)
}

func (f fakeConfig) GetBool(path string, defaultValue ...bool) bool {
	value, ok := f.values[path]
	if !ok {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}

		return false
	}

	return value.(bool)
}

func TestReadUsesDefaults(t *testing.T) {
	settings := read(fakeConfig{values: map[string]any{}})

	assert.Equal(t, Settings{
		Enabled: true,
		Channel: "",
		Allowed: false,
		Denied:  true,
		Casbin:  false,
	}, settings)
}

func TestReadUsesConfiguredValues(t *testing.T) {
	settings := read(fakeConfig{values: map[string]any{
		"casbin.log.enabled": false,
		"casbin.log.channel": "audit",
		"casbin.log.allowed": true,
		"casbin.log.denied":  false,
		"casbin.log.casbin":  true,
	}})

	assert.Equal(t, Settings{
		Enabled: false,
		Channel: "audit",
		Allowed: true,
		Denied:  false,
		Casbin:  true,
	}, settings)
}

func TestLoggerIsNilWithoutApplication(t *testing.T) {
	assert.Nil(t, Settings{Enabled: true}.Logger())
	assert.Nil(t, Settings{Enabled: false}.Logger())
}
