package middleware

import (
	"os"
	"testing"
)

// TestMain provides the APP_KEY that Goravel 1.16 requires when it builds its
// configuration on the first facades.Config() call, which the middleware does
// when it reads the casbin.log settings.
func TestMain(m *testing.M) {
	if os.Getenv("APP_KEY") == "" {
		_ = os.Setenv("APP_KEY", "00000000000000000000000000000000")
	}

	os.Exit(m.Run())
}
