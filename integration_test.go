//go:build integration
// +build integration

package ncmec_test

import (
	"context"
	"crypto/md5"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lumeweb.com/ncmec"
)

// Integration tests that can be run against the NCMEC test environment
// These tests require valid credentials to be set in environment variables:
// - NCMEC_USERNAME: The username provided by NCMEC
// - NCMEC_PASSWORD: The password provided by NCMEC
//
// Credentials can be provided in three ways:
// 1. Environment variables set before running tests
// 2. A .env file in the project root or parent directories
// 3. A .env.test file in the project root or parent directories (takes precedence over .env)
//
// To run the integration tests:
// go test -tags=integration ./...

func init() {
	// Load .env and .env.test files for integration tests
	// This allows for easier local testing without modifying environment variables
	loadEnvFiles()
}

// loadEnvFiles loads environment variables from .env and .env.test files
// It searches for these files in the current directory and parent directories
// .env.test takes precedence over .env
func loadEnvFiles() {
	// Find all potential .env and .env.test files
	var envFiles []string
	var testEnvFiles []string

	// Try to find the .env and .env.test files in current directory or parent directories
	dir, err := os.Getwd()
	if err != nil {
		log.Printf("Warning: Could not determine current directory: %v", err)
		return
	}

	// Walk up directory tree looking for .env files
	for {
		// Check for .env file
		envFile := filepath.Join(dir, ".env")
		if _, err := os.Stat(envFile); err == nil {
			envFiles = append(envFiles, envFile)
		}

		// Check for .env.test file
		testEnvFile := filepath.Join(dir, ".env.test")
		if _, err := os.Stat(testEnvFile); err == nil {
			testEnvFiles = append(testEnvFiles, testEnvFile)
		}

		// If we've reached the filesystem root, stop searching
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	// Reverse the order so we load from root to project directory
	// This way, the project directory's .env files take precedence
	reverseSlice(envFiles)
	reverseSlice(testEnvFiles)

	// Load regular .env files first
	for _, file := range envFiles {
		if err := godotenv.Load(file); err != nil {
			log.Printf("Warning: Error loading .env file at %s: %v", file, err)
		} else {
			log.Printf("Loaded .env file from %s", file)
		}
	}

	// Then load .env.test files to override
	for _, file := range testEnvFiles {
		if err := godotenv.Overload(file); err != nil {
			log.Printf("Warning: Error loading .env.test file at %s: %v", file, err)
		} else {
			log.Printf("Loaded .env.test file from %s", file)
		}
	}
}

// reverseSlice reverses the order of a string slice in place
func reverseSlice(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func TestIntegrationAuthentication(t *testing.T) {
	// Skip if not running integration tests
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Get credentials from environment
	username := os.Getenv("NCMEC_USERNAME")
	password := os.Getenv("NCMEC_PASSWORD")
	if username == "" || password == "" {
		t.Skip("Skipping integration test because NCMEC_USERNAME or NCMEC_PASSWORD is not set")
	}

	// Create client
	client, err := ncmec.NewClient(
		ncmec.WithCredentials(username, password),
		ncmec.WithEnvironment(ncmec.Testing),
	)
	require.NoError(t, err)

	// Verify credentials
	ctx := context.Background()
	err = client.VerifyCredentials(ctx)
	assert.NoError(t, err)
}

func TestIntegrationCompleteReportWorkflow(t *testing.T) {
	// Skip if not running integration tests
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Get credentials from environment
	username := os.Getenv("NCMEC_USERNAME")
	password := os.Getenv("NCMEC_PASSWORD")
	if username == "" || password == "" {
		t.Skip("Skipping integration test because NCMEC_USERNAME or NCMEC_PASSWORD is not set")
	}

	// Create client
	client, err := ncmec.NewClient(
		ncmec.WithCredentials(username, password),
		ncmec.WithEnvironment(ncmec.Testing),
	)
	require.NoError(t, err)

	// Create a test file
	fileContent := "test file content"

	// Create report with all the details
	reportBuilder := client.NewReport().
		WithIncidentType(ncmec.ChildPornography).
		WithIncidentTime(time.Now()).
		WithWebIncident("http://example.com/badcontent").
		WithReporter("Integration", "Test", "integration.test@example.com")

	// Add a file
	fileDetails := &ncmec.FileDetails{
		OriginalFileName: "original.txt",
		IPCapture: &ncmec.IPCaptureEvent{
			IPAddress: "192.168.1.1",
			EventName: "Upload",
			DateTime:  time.Now(),
		},
		AdditionalInfo: "Integration test file",
	}
	reportBuilder.AddFileContent(strings.NewReader(fileContent), "test.txt", fileDetails)

	// Submit the report
	ctx := context.Background()
	result, err := reportBuilder.Submit(ctx)
	require.NoError(t, err)

	// Verify the result
	assert.NotEmpty(t, result.ReportID)
	assert.Len(t, result.FileIDs, 1)
}

func TestIntegrationReportCancellation(t *testing.T) {
	// Skip if not running integration tests
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Get credentials from environment
	username := os.Getenv("NCMEC_USERNAME")
	password := os.Getenv("NCMEC_PASSWORD")
	if username == "" || password == "" {
		t.Skip("Skipping integration test because NCMEC_USERNAME or NCMEC_PASSWORD is not set")
	}

	// Create client
	client, err := ncmec.NewClient(
		ncmec.WithCredentials(username, password),
		ncmec.WithEnvironment(ncmec.Testing),
	)
	require.NoError(t, err)

	// Create minimal report
	ctx := context.Background()
	reportBuilder := client.NewReport().
		WithIncidentType(ncmec.ChildPornography).
		WithIncidentTime(time.Now()).
		WithWebIncident("http://example.com/badcontent").
		WithReporter("Cancellation", "Test", "cancellation.test@example.com")

	// Submit the report as a draft using CreateReport
	updater, err := reportBuilder.CreateReport(ctx)
	require.NoError(t, err)
	reportID := updater.ReportID
	require.NotEmpty(t, reportID, "Report ID should be set")

	// Cancel the report
	err = client.CancelReport(ctx, reportID)
	assert.NoError(t, err)
}

func TestIntegrationReportUpdateWorkflow(t *testing.T) {
	// Skip if not running integration tests
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Get credentials from environment
	username := os.Getenv("NCMEC_USERNAME")
	password := os.Getenv("NCMEC_PASSWORD")
	if username == "" || password == "" {
		t.Skip("Skipping integration test because NCMEC_USERNAME or NCMEC_PASSWORD is not set")
	}

	// Create client
	client, err := ncmec.NewClient(
		ncmec.WithCredentials(username, password),
		ncmec.WithEnvironment(ncmec.Testing),
	)
	require.NoError(t, err)

	// Create context
	ctx := context.Background()

	// Step 1: Create initial report with no files
	reportBuilder := client.NewReport().
		WithIncidentType(ncmec.ChildPornography).
		WithIncidentTime(time.Now()).
		WithWebIncident("http://example.com/badcontent").
		WithReporter("Integration", "Test", "update.test@example.com")

	// Submit the initial report as a draft
	updater, err := reportBuilder.CreateReport(ctx)
	require.NoError(t, err)
	reportID := updater.ReportID
	require.NotEmpty(t, reportID, "Report ID should be set")

	// Add first file with details
	fileContent1 := "first file content"
	fileDetails1 := &ncmec.FileDetails{
		OriginalFileName: "first.txt",
		IPCapture: &ncmec.IPCaptureEvent{
			IPAddress: "192.168.1.1",
			EventName: "Upload",
			DateTime:  time.Now(),
		},
		AdditionalInfo: "First test file",
	}
	updater.AddFileContent(strings.NewReader(fileContent1), "first.txt", fileDetails1)

	// Update report without finishing
	updateResult, err := updater.Update(ctx)
	require.NoError(t, err)
	require.Equal(t, reportID, updateResult.ReportID)
	require.Len(t, updateResult.FileIDs, 1)

	// Step 3: Update again with a content-addressed file
	fileContent2 := "content addressed file"

	// Calculate an MD5 hash first
	hasher := ncmec.NewFileHasher()
	hash := hasher.HashBytes([]byte(fileContent2))

	// Also test with raw MD5 hash bytes
	md5Sum := md5.Sum([]byte(fileContent2))
	hashBytes := md5Sum[:]

	// Create a ContentAddressedFile
	caFile := ncmec.ContentAddressedFile{
		ContentID: "content://12345", // Example content ID
		FileName:  "distributed.txt",
		Size:      int64(len(fileContent2)),
		MimeType:  "text/plain",
		Hash:      hash,
		HashBytes: hashBytes, // Include hash bytes as an alternative
	}

	// Update the report again
	updater.AddContentAddressedFile(
		strings.NewReader(fileContent2),
		caFile,
		nil, // Let AddContentAddressedFile create the details
	)

	// Finish the report
	result, err := updater.Finish(ctx)
	require.NoError(t, err)
	require.Equal(t, reportID, result.ReportID)
	// Final check - should have 2 files in result
	require.Len(t, result.FileIDs, 2)
}
