// Package logging routes the diagnostics of goravel-authz to the Goravel
// logger. It is internal on purpose: applications configure it through the
// casbin.log configuration block and never touch it directly.
package logging

import (
	"github.com/goravel/framework/contracts/log"
	"github.com/goravel/framework/facades"
	"github.com/goravel/framework/foundation"
)

// Settings is the casbin.log configuration.
type Settings struct {
	// Enabled turns all package logging on or off.
	Enabled bool
	// Channel is a Goravel log channel. Empty uses logging.default.
	Channel string
	// Allowed logs authorized requests at info level.
	Allowed bool
	// Denied logs rejected requests at warning level.
	Denied bool
	// Casbin routes Casbin's own diagnostics to the Goravel logger at debug
	// level.
	Casbin bool
}

type configReader interface {
	GetString(path string, defaultValue ...string) string
	GetBool(path string, defaultValue ...bool) bool
}

// Load reads casbin.log from the current Goravel application. Outside a booted
// application every switch stays off, so the package remains silent in unit
// tests and standalone tools.
func Load() Settings {
	if foundation.App == nil {
		return Settings{}
	}

	return read(facades.Config())
}

func read(config configReader) Settings {
	return Settings{
		Enabled: config.GetBool("casbin.log.enabled", true),
		Channel: config.GetString("casbin.log.channel"),
		Allowed: config.GetBool("casbin.log.allowed", false),
		Denied:  config.GetBool("casbin.log.denied", true),
		Casbin:  config.GetBool("casbin.log.casbin", false),
	}
}

// Logger returns the Goravel logger bound to the configured channel. It
// returns nil when logging is disabled, which lets callers skip the work.
//
// Goravel 1.16 returns a Writer from Channel, so the whole package logs
// through Writer: it carries every method used here, including With.
func (s Settings) Logger() log.Writer {
	if !s.Enabled || foundation.App == nil {
		return nil
	}

	logger := facades.Log()
	if s.Channel != "" {
		return logger.Channel(s.Channel)
	}

	return logger
}
