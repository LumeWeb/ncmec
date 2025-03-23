// Package build provides build-time information about the package
package build

import (
	"fmt"
	"runtime"
)

var (
	// Version is the version of the library
	Version = "dev"

	// GitCommit is the git commit hash from which this was built
	GitCommit = "unknown"

	// GitTag is the git tag from which this was built
	GitTag = "unknown"

	// BuildDate is the date on which this was built
	BuildDate = "unknown"
)

// UserAgent returns a string suitable for use as a User-Agent header
func UserAgent() string {
	return fmt.Sprintf("LumeWeb-NCMEC/%s (%s; %s) GitCommit/%s",
		Version,
		runtime.GOOS,
		runtime.GOARCH,
		GitCommit)
}

// Info returns a map of version information
func Info() map[string]string {
	return map[string]string{
		"version":   Version,
		"gitCommit": GitCommit,
		"gitTag":    GitTag,
		"buildDate": BuildDate,
		"goVersion": runtime.Version(),
		"platform":  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// String returns a string representation of the version information
func String() string {
	return fmt.Sprintf("LumeWeb-NCMEC %s (Git: %s, Tag: %s, Built: %s, %s, %s/%s)",
		Version,
		GitCommit,
		GitTag,
		BuildDate,
		runtime.Version(),
		runtime.GOOS,
		runtime.GOARCH)
}
