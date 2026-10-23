package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// The framework hands the stubs bare import paths: the quotes are part of
	// the stub templates.
	testFacadesImport  = "example.com/app/facades"
	testFacadesPackage = "facades"
	testMigrationPkg   = "migrations"
)

func TestConfigStubIsValidGo(t *testing.T) {
	content := Stubs{}.Config(testFacadesImport, testFacadesPackage)

	file, err := parser.ParseFile(token.NewFileSet(), "config/casbin.go", content, parser.AllErrors)
	require.NoError(t, err, "the generated config must be valid Go")
	assert.Equal(t, "config", file.Name.Name)

	assert.NotContains(t, content, "Dummy", "every placeholder must be substituted")
	assert.Contains(t, content, `"default": "basic"`)
	assert.Contains(t, content, `"basic": models.NewRule()`)
	assert.Contains(t, content, `"log": map[string]any{`)
	assert.Contains(t, content, `"gate": map[string]any{`)
	assert.Contains(t, content, testFacadesImport)
	assert.Contains(t, content, testFacadesPackage+".Config()")
}

// TestCasbinModelStubParsesAsCasbinModel makes sure the model written by
// package:install is accepted by casbin, so a fresh install enforces with the
// documented RBAC model.
func TestCasbinModelStubParsesAsCasbinModel(t *testing.T) {
	parsed, err := model.NewModelFromString(Stubs{}.CasbinModel())
	require.NoError(t, err)

	assert.Contains(t, parsed["r"], "r")
	assert.Contains(t, parsed["p"], "p")
	assert.Contains(t, parsed["g"], "g")

	// casbin prefixes the tokens of a definition with its key, so r yields
	// r_sub and p yields p_sub.
	requestTokens := parsed["r"]["r"].Tokens
	require.Len(t, requestTokens, 3)
	for index, want := range []string{"sub", "obj", "act"} {
		assert.Equal(t, want, strings.TrimPrefix(requestTokens[index], "r_"))
	}

	policyTokens := parsed["p"]["p"].Tokens
	require.Len(t, policyTokens, 3)
	for index, want := range []string{"sub", "obj", "act"} {
		assert.Equal(t, want, strings.TrimPrefix(policyTokens[index], "p_"))
	}

	// The g tokens are parsed from "g = _, _", so casbin keeps the spaces.
	tokens := parsed["g"]["g"].Tokens
	require.Len(t, tokens, 2)
	for _, token := range tokens {
		assert.Equal(t, "_", strings.TrimSpace(token))
	}
}

func TestMigrationStubIsValidGo(t *testing.T) {
	fileName, structName, content := Stubs{}.Migration(testMigrationPkg, testFacadesImport, testFacadesPackage)

	assert.Equal(t, "20240327160147_create_casbin_rules_table.go", fileName)

	file, err := parser.ParseFile(token.NewFileSet(), fileName, content, parser.AllErrors)
	require.NoError(t, err, "the generated migration must be valid Go")
	assert.Equal(t, testMigrationPkg, file.Name.Name, "the migration must be written into the migrations package")

	assert.NotContains(t, content, "Dummy", "every placeholder must be substituted")
	assert.Contains(t, content, "type "+structName+" struct{}")
	assert.Contains(t, content, `return "20240327160147_create_casbin_rules_table"`)
	assert.Contains(t, content, `Schema().Create("casbin_rules"`)
	assert.Contains(t, content, `table.Unique("ptype", "v0", "v1", "v2", "v3", "v4", "v5")`)
}

// TestMigrationStubDeclaresSignature guards the migration registration: the
// framework resolves migrations by the Signature method, which must stay in
// sync with the file name.
func TestMigrationStubDeclaresSignature(t *testing.T) {
	fileName, structName, _ := Stubs{}.Migration(testMigrationPkg, testFacadesImport, testFacadesPackage)

	assert.Equal(t, strings.TrimSuffix(fileName, ".go"), "20240327160147_create_casbin_rules_table")
	assert.NotEmpty(t, structName)
}

// TestConfigStubKeepsModelContract checks that the generated config only uses
// the constructors and nested keys the code reads at runtime.
func TestConfigStubKeepsModelContract(t *testing.T) {
	content := Stubs{}.Config(testFacadesImport, testFacadesPackage)

	file, err := parser.ParseFile(token.NewFileSet(), "config/casbin.go", content, parser.AllErrors)
	require.NoError(t, err)

	imported := false
	ast.Inspect(file, func(node ast.Node) bool {
		spec, ok := node.(*ast.ImportSpec)
		if ok && strings.Contains(spec.Path.Value, "goravel-authz/models") {
			imported = true
		}

		return true
	})
	assert.True(t, imported, "the stub must import models.NewRule")
}
