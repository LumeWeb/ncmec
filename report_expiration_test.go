package ncmec_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go.lumeweb.com/ncmec"
)

func TestReportExpiration(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name            string
		creationTime    time.Time
		lastModified    time.Time
		expectedStatus  ncmec.ReportExpirationStatus
		messageContains string
	}{
		{
			name:            "new report",
			creationTime:    now,
			lastModified:    now,
			expectedStatus:  ncmec.ReportStatusOk,
			messageContains: "not in danger",
		},
		{
			name:            "report with 80% of creation time elapsed",
			creationTime:    now.Add(-19 * time.Hour), // 19 hours out of 24 = ~80%
			lastModified:    now.Add(-19 * time.Hour),
			expectedStatus:  ncmec.ReportStatusExpired,
			messageContains: "expired",
		},
		{
			name:            "report with 95% of creation time elapsed",
			creationTime:    now.Add(-23 * time.Hour), // 23 hours out of 24 = ~95%
			lastModified:    now.Add(-23 * time.Hour),
			expectedStatus:  ncmec.ReportStatusExpired,
			messageContains: "expired",
		},
		{
			name:            "recently modified older report",
			creationTime:    now.Add(-23 * time.Hour),   // 23 hours out of 24 = ~95%
			lastModified:    now.Add(-30 * time.Minute), // 30 minutes out of 60 = 50%
			expectedStatus:  ncmec.ReportStatusCritical, // Modified time < 90% but Creation time > 90%
			messageContains: "about to expire",
		},
		{
			name:            "report with 80% of modification time elapsed",
			creationTime:    now.Add(-23 * time.Hour),
			lastModified:    now.Add(-48 * time.Minute), // 48 minutes out of 60 = 80%
			expectedStatus:  ncmec.ReportStatusCritical, // Modified time < 90% but Creation time > 90%
			messageContains: "about to expire",
		},
		{
			name:            "report with 95% of modification time elapsed",
			creationTime:    now.Add(-23 * time.Hour),
			lastModified:    now.Add(-57 * time.Minute), // 57 minutes out of 60 = 95%
			expectedStatus:  ncmec.ReportStatusCritical,
			messageContains: "about to expire",
		},
		{
			name:            "expired report (creation)",
			creationTime:    now.Add(-25 * time.Hour), // More than 24 hours ago
			lastModified:    now.Add(-25 * time.Hour),
			expectedStatus:  ncmec.ReportStatusExpired,
			messageContains: "expired",
		},
		{
			name:            "expired report (modification)",
			creationTime:    now.Add(-23 * time.Hour),
			lastModified:    now.Add(-65 * time.Minute), // More than 60 minutes ago
			expectedStatus:  ncmec.ReportStatusExpired,
			messageContains: "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := ncmec.CheckReportExpiration(tt.creationTime, tt.lastModified)

			assert.Equal(t, tt.expectedStatus, status.Status)
			assert.Contains(t, status.Message, tt.messageContains)

			// Additional check for the convenience function
			isExpired := ncmec.IsReportExpired(tt.creationTime, tt.lastModified)
			expectedIsExpired := status.Status == ncmec.ReportStatusExpired || status.Status == ncmec.ReportStatusCritical
			assert.Equal(t, expectedIsExpired, isExpired)
		})
	}
}

func TestReportBuilderExpiration(t *testing.T) {
	// Create a client for testing
	client, err := ncmec.NewClient(
		ncmec.WithCredentials("testuser", "testpass"),
		ncmec.WithEnvironment(ncmec.Testing),
	)
	assert.NoError(t, err)

	// Create a report with expiration checking
	report := client.NewReport().AddExpirationChecking()

	// Check status of a new report
	status := report.CheckExpiration()
	assert.Equal(t, ncmec.ReportStatusOk, status.Status)

	// Simulate time passing by setting internal fields (not normally accessible)
	// In a real scenario, time would actually pass between operations
	// For testing, we use reflection to access unexported fields

	// For now, we'll just test the public API
	report.UpdateLastModified() // This should update the last modified time

	// Verify expiration status again (should still be OK since we just updated it)
	status = report.CheckExpiration()
	assert.Equal(t, ncmec.ReportStatusOk, status.Status)
}
