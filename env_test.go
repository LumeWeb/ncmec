package ncmec_test

import (
	"os"
	"testing"
)

// TestLoadEnvFiles tests that our environment loading works properly
func TestLoadEnvFiles(t *testing.T) {
	username := os.Getenv("NCMEC_USERNAME")
	password := os.Getenv("NCMEC_PASSWORD")

	// Just log the values for verification
	if username != "" {
		t.Logf("NCMEC_USERNAME is set to a non-empty value")
	} else {
		t.Logf("NCMEC_USERNAME is not set")
	}

	if password != "" {
		t.Logf("NCMEC_PASSWORD is set to a non-empty value")
	} else {
		t.Logf("NCMEC_PASSWORD is not set")
	}
}
