package main

import (
	"fmt"
	"os"

	"github.com/goravel/framework/packages"
	"github.com/goravel/framework/packages/modify"
	"github.com/goravel/framework/support/path"
)

func main() {
	setup := packages.Setup(os.Args)
	stubs := Stubs{}
	moduleImport := setup.Paths().Module().Import()
	facadesImport := setup.Paths().Facades().Import()
	facadesPackage := setup.Paths().Facades().Package()
	migrationPackage := setup.Paths().Migrations().Package()
	migrationImport := setup.Paths().Migrations().Import()
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
