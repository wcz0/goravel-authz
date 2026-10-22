package main

import "strings"

type Stubs struct{}

func (s Stubs) Config(facadesImport, facadesPackage string) string {
	content := `package config

import (
	"github.com/wcz0/goravel-authz/models"

	"DummyFacadesImport"
)

func init() {
	config := DummyFacadesPackage.Config()
	config.Add("casbin", map[string]any{
		// Default model used by facades.Enforcer() and middleware.Authz().
		"default": "basic",

		// Every entry is an independent enforcer with its own table, connection,
		// casbin model and cache.
		"models": map[string]any{
			"basic": models.NewRule(),
		},
	})
}
`

	content = strings.ReplaceAll(content, "DummyFacadesImport", facadesImport)
	content = strings.ReplaceAll(content, "DummyFacadesPackage", facadesPackage)

	return content
}

func (s Stubs) CasbinModel() string {
	return `[request_definition]
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
}

func (s Stubs) Migration(pkg, facadesImport, facadesPackage string) (fileName, structName, content string) {
	fileName = "20240327160147_create_casbin_rules_table.go"
	structName = "M20240327160147CreateCasbinRulesTable"
	content = `package DummyPackage

import (
	"fmt"

	"github.com/goravel/framework/contracts/database/schema"

	"DummyFacadesImport"
)

type DummyStruct struct{}

// Signature The unique signature for the migration.
func (r *DummyStruct) Signature() string {
	return "20240327160147_create_casbin_rules_table"
}

// Up Run the migrations.
func (r *DummyStruct) Up() error {
	if DummyFacadesPackage.Schema().HasTable("casbin_rules") {
		return nil
	}

	return DummyFacadesPackage.Schema().Create("casbin_rules", func(table schema.Blueprint) {
		table.ID()
		table.String("ptype", 100).Nullable()
		for i := 0; i < 6; i++ {
			table.String(fmt.Sprintf("v%d", i), 100).Nullable()
		}
		table.Unique("ptype", "v0", "v1", "v2", "v3", "v4", "v5")
	})
}

// Down Reverse the migrations.
func (r *DummyStruct) Down() error {
	return DummyFacadesPackage.Schema().DropIfExists("casbin_rules")
}
`

	content = strings.ReplaceAll(content, "DummyPackage", pkg)
	content = strings.ReplaceAll(content, "DummyFacadesImport", facadesImport)
	content = strings.ReplaceAll(content, "DummyFacadesPackage", facadesPackage)
	content = strings.ReplaceAll(content, "DummyStruct", structName)

	return fileName, structName, content
}
