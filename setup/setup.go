package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/goravel/framework/packages"
	"github.com/goravel/framework/packages/modify"
	"github.com/goravel/framework/support/path"
)

func main() {
	setup := packages.Setup(os.Args)
	stubs := Stubs{}
	moduleImport := setup.Paths().Module().Import()
	facadesPackage := setup.Paths().Facades().Package()
	migrationPackage := setup.Paths().Migrations().Package()

	// The config and the migration are written into the application, so their
	// imports have to point at the application module, not at this package.
	appModule := appModulePath()
	facadesImport := appModule + "/app/facades"
	migrationImport := appModule + "/database/migrations"
	// Outside an application directory the module is unknown; the framework
	// facades expose the same API, so the generated config still compiles.
	if appModule == "" {
		facadesImport = "github.com/goravel/framework/facades"
	}
	migrationFileName, migrationStruct, migrationContent := stubs.Migration(migrationPackage, facadesImport, facadesPackage)
	migrationPath := path.Migration(migrationFileName)
	migrationStructWithPackage := fmt.Sprintf("&%s.%s{}", migrationPackage, migrationStruct)
	configPath := path.Config("casbin.go")
	modelPath := path.Config("casbin-rbac-model.conf")

	setup.Install(
		// Register the service provider in bootstrap/providers.go.
		modify.RegisterProvider(moduleImport, "&authz.ServiceProvider{}"),

		// Write the configuration and the default RBAC model.
		modify.File(configPath).Overwrite(stubs.Config(facadesImport, facadesPackage)),
		modify.File(modelPath).Overwrite(stubs.CasbinModel()),

		// Create and register the casbin_rules migration.
		modify.File(migrationPath).Overwrite(migrationContent),
		modify.RegisterMigration(migrationImport, migrationStructWithPackage),
	).Uninstall(
		modify.UnregisterMigration(migrationImport, migrationStructWithPackage),
		modify.File(migrationPath).Remove(),
		modify.File(modelPath).Remove(),
		modify.File(configPath).Remove(),
		modify.UnregisterProvider(moduleImport, "&authz.ServiceProvider{}"),
	).Execute()
}

// appModulePath reads the module path of the application the installer runs
// in. The package paths of the framework are relative to this package, which
// would make the generated imports point at files that do not exist.
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
