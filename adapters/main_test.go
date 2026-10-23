package adapters

import (
	"os"
	"testing"
)

// TestMain provides the APP_KEY that Goravel 1.16 requires when it builds its
// configuration. The SQLite fixtures create a config application, which would
// otherwise exit the test binary.
func TestMain(m *testing.M) {
	if os.Getenv("APP_KEY") == "" {
		_ = os.Setenv("APP_KEY", "00000000000000000000000000000000")
	}

	os.Exit(m.Run())
}
