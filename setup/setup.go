package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/goravel/framework/packages"
	"github.com/goravel/framework/packages/match"
	"github.com/goravel/framework/packages/modify"
	"github.com/goravel/framework/support/path"
)

// Goravel 1.16 registers providers in config/app.go and migrations in
// database/kernel.go, and it writes files through modify.File. The
// bootstrap/providers.go based installer only exists from 1.17 on.
func main() {
	setup := packages.Setup(os.Args)
	stubs := Stubs{}

	moduleImport := packages.GetModulePath()
	facadesImport := appModulePath() + "/app/facades"
	facadesPackage := "facades"

	// Outside an application directory the module of the app is unknown, so
	// the generated config falls back to the framework facades, which expose
	// the same API.
	if facadesImport == "/app/facades" {
		facadesImport = "github.com/goravel/framework/facades"
	}

	migrationPackage := "migrations"
	migrationImport := moduleImport + "/database/migrations"
	migrationFileName, migrationStruct, migrationContent := stubs.Migration(migrationPackage, facadesImport, facadesPackage)
	migrationPath := path.Database("migrations", migrationFileName)
	migrationStructWithPackage := fmt.Sprintf("&%s.%s{}", migrationPackage, migrationStruct)

	provider := "&authz.ServiceProvider{}"
	configPath := path.Config("casbin.go")
	modelPath := path.Config("casbin-rbac-model.conf")

	setup.Install(
		// Register the service provider in the providers list of config/app.go.
		modify.GoFile(path.Config("app.go")).
			Find(match.Imports()).Modify(modify.AddImport(moduleImport)).
			Find(match.Providers()).Modify(modify.Register(provider)),

		// Write the configuration, the default RBAC model and the migration.
		modify.File(configPath).Overwrite(stubs.Config(facadesImport, facadesPackage)),
		modify.File(modelPath).Overwrite(stubs.CasbinModel()),
		modify.File(migrationPath).Overwrite(migrationContent),

		// Register the migration in the migrations list of database/kernel.go.
		modify.GoFile(path.Database("kernel.go")).
			Find(match.Imports()).Modify(modify.AddImport(migrationImport)).
			Find(match.Migrations()).Modify(modify.Register(migrationStructWithPackage)),
	).Uninstall(
		modify.GoFile(path.Database("kernel.go")).
			Find(match.Migrations()).Modify(modify.Unregister(migrationStructWithPackage)).
			Find(match.Imports()).Modify(modify.RemoveImport(migrationImport)),
		modify.File(migrationPath).Remove(),
		modify.File(modelPath).Remove(),
		modify.File(configPath).Remove(),
		modify.GoFile(path.Config("app.go")).
			Find(match.Providers()).Modify(modify.Unregister(provider)).
			Find(match.Imports()).Modify(modify.RemoveImport(moduleImport)),
	).Execute()
}

// appModulePath reads the module path of the application the installer runs
// in. Goravel 1.16 does not expose it, but the generated config has to import
// the facades package of the application, not the one of this package.
func appModulePath() string {
	content, err := os.ReadFile("go.mod")
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "module "); ok {
			return strings.TrimSpace(after)
		}
	}

	return ""
}
