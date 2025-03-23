package ncmec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lumeweb.com/ncmec"
)

// TestClientInitialization verifies client creation with various configurations.
// Covers valid/invalid credentials, environment selection, and HTTP client customization.
func TestClientInitialization(t *testing.T) {
	tests := []struct {
		name        string
		options     []ncmec.ClientOption
		expectError bool
	}{
		{
			name: "valid credentials and environment",
			options: []ncmec.ClientOption{
				ncmec.WithCredentials("username", "password"),
				ncmec.WithEnvironment(ncmec.Testing),
			},
			expectError: false,
		},
		{
			name:        "missing credentials",
			options:     []ncmec.ClientOption{ncmec.WithEnvironment(ncmec.Testing)},
			expectError: true,
		},
		{
			name: "invalid environment",
			options: []ncmec.ClientOption{
				ncmec.WithCredentials("username", "password"),
				ncmec.WithEnvironment("invalid"),
			},
			expectError: true,
		},
		{
			name: "custom http client",
			options: []ncmec.ClientOption{
				ncmec.WithCredentials("username", "password"),
				ncmec.WithEnvironment(ncmec.Testing),
				ncmec.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := ncmec.NewClient(tt.options...)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

// TestVerifyCredentials validates authentication against the NCMEC API.
// Tests both successful and failed authentication scenarios.
func TestVerifyCredentials(t *testing.T) {
	// Setup mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "validuser" || pass != "validpass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.URL.Path != "/status" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	tests := []struct {
		name     string
		user     string
		pass     string
		expected bool
	}{
		{"valid credentials", "validuser", "validpass", true},
		{"invalid username", "invaliduser", "validpass", false},
		{"invalid password", "validuser", "invalidpass", false},
		{"empty credentials", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip credential validation for empty credentials
			if tt.name == "empty credentials" {
				// This should fail at client creation
				_, err := ncmec.NewClient(
					ncmec.WithCredentials(tt.user, tt.pass),
					ncmec.WithBaseURL(mockServer.URL),
				)
				assert.Error(t, err)
				return
			}

			// For other tests, client creation should succeed
			client, err := ncmec.NewClient(
				ncmec.WithCredentials(tt.user, tt.pass),
				ncmec.WithBaseURL(mockServer.URL),
			)
			require.NoError(t, err)

			ctx := context.Background()
			err = client.VerifyCredentials(ctx)
			if tt.expected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestNewReportBuilder verifies report builder initialization and fluent interface.
// Ensures all chained methods properly populate the report structure.
func TestNewReportBuilder(t *testing.T) {
	client, err := ncmec.NewClient(
		ncmec.WithCredentials("username", "password"),
		ncmec.WithEnvironment(ncmec.Testing),
	)
	require.NoError(t, err)

	reportBuilder := client.NewReport()
	assert.NotNil(t, reportBuilder)

	// Test fluent interface
	sampleTime := time.Now()
	reportBuilder = reportBuilder.
		WithIncidentType(ncmec.ChildPornography).
		WithIncidentTime(sampleTime).
		WithWebIncident("http://example.com/badcontent").
		WithReporter("John", "Smith", "jsmith@example.com")

	// Verify the report has been properly populated
	report := reportBuilder.Build()
	assert.Equal(t, ncmec.ChildPornography, report.IncidentSummary.IncidentType)
	assert.Equal(t, sampleTime, report.IncidentSummary.IncidentDateTime)
	assert.Equal(t, "http://example.com/badcontent", report.InternetDetails.WebPageIncident.URL)
	assert.Equal(t, "John", report.Reporter.ReportingPerson.FirstName)
	assert.Equal(t, "Smith", report.Reporter.ReportingPerson.LastName)
	assert.Equal(t, "jsmith@example.com", report.Reporter.ReportingPerson.Email)
}
