package ncmec_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lumeweb.com/ncmec"
)

func TestReportSubmission(t *testing.T) {
	// Sample report response XML
	submitResponseXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>4564654</reportId>
</reportResponse>`

	// Setup mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")

		// Check auth
		user, pass, ok := r.BasicAuth()
		if !ok || user != "testuser" || pass != "testpass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch r.URL.Path {
		case "/submit":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}

			// Check content type
			contentType := r.Header.Get("Content-Type")
			if !strings.Contains(contentType, "text/xml") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Simple XML validation (in a real test we'd do more comprehensive validation)
			if !strings.Contains(r.Header.Get("Content-Type"), "utf-8") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(submitResponseXML))

		case "/finish":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}

			// Check content type
			contentType := r.Header.Get("Content-Type")
			if !strings.Contains(contentType, "application/x-www-form-urlencoded") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Parse form data
			if err := r.ParseForm(); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			id := r.FormValue("id")
			if id != "4564654" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Return success response
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportDoneResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>4564654</reportId>
    <files>
        <fileId>file123</fileId>
    </files>
</reportDoneResponse>`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	// Create client
	client, err := ncmec.NewClient(
		ncmec.WithCredentials("testuser", "testpass"),
		ncmec.WithBaseURL(mockServer.URL),
	)
	require.NoError(t, err)

	// Create and submit a minimal report
	ctx := context.Background()
	reportBuilder := client.NewReport().
		WithIncidentType(ncmec.ChildPornography).
		WithIncidentTime(time.Now()).
		WithWebIncident("http://example.com/badcontent").
		WithReporter("John", "Smith", "jsmith@example.com")

	result, err := reportBuilder.Submit(ctx)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "4564654", result.ReportID)
}

func TestReportWithInvalidData(t *testing.T) {
	// Setup mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")

		// Check auth
		user, pass, ok := r.BasicAuth()
		if !ok || user != "testuser" || pass != "testpass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.URL.Path == "/submit" && r.Method == http.MethodPost {
			// Return an error response
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>1</responseCode>
    <responseDescription>Invalid report data: missing incident type</responseDescription>
</reportResponse>`))
		}
	}))
	defer mockServer.Close()

	// Create client
	client, err := ncmec.NewClient(
		ncmec.WithCredentials("testuser", "testpass"),
		ncmec.WithBaseURL(mockServer.URL),
	)
	require.NoError(t, err)

	// Create an incomplete report
	ctx := context.Background()
	reportBuilder := client.NewReport().
		// Intentionally omit required fields
		WithReporter("John", "Smith", "jsmith@example.com")

	// Submit report and expect an error
	result, err := reportBuilder.Submit(ctx)
	assert.Error(t, err)
	assert.Nil(t, result)

	// Check error details
	ncmecErr, ok := err.(*ncmec.Error)
	assert.True(t, ok, "Expected error to be of type *ncmec.Error")
	assert.Equal(t, 1, ncmecErr.Code)
	assert.Contains(t, ncmecErr.Description, "missing incident type")
}

func TestReportUpdaterFileManagement(t *testing.T) {
	// Setup mock server with upload counter
	var uploadCount int32
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")

		// Check auth
		user, pass, ok := r.BasicAuth()
		if !ok || user != "testuser" || pass != "testpass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch r.URL.Path {
		case "/submit":
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>12345</reportId>
</reportResponse>`))
		case "/upload":
			atomic.AddInt32(&uploadCount, 1)
			w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>12345</reportId>
    <fileId>FILE-%d</fileId>
</reportResponse>`, atomic.LoadInt32(&uploadCount))))
		case "/finish":
			w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportDoneResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>12345</reportId>
    <files>
        <fileId>FILE-%d</fileId>
        <fileId>FILE-%d</fileId>
    </files>
</reportDoneResponse>`, atomic.LoadInt32(&uploadCount)-1, atomic.LoadInt32(&uploadCount))))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	// Create client
	client, err := ncmec.NewClient(
		ncmec.WithCredentials("testuser", "testpass"),
		ncmec.WithBaseURL(mockServer.URL),
	)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("Initial report creation clears files", func(t *testing.T) {
		reportBuilder := client.NewReport().
			WithIncidentType(ncmec.ChildPornography).
			WithIncidentTime(time.Now()).
			WithWebIncident("http://example.com/badcontent").
			WithReporter("John", "Smith", "jsmith@example.com").
			AddFileContent(strings.NewReader("test"), "test.txt", nil)

		updater, err := reportBuilder.CreateReport(ctx)
		require.NoError(t, err)
		
		// Verify files are cleared after creation
		assert.Empty(t, updater.Files(), "Files should be cleared after report creation")
		// Should have current time (allow 1 second window for test execution)
		assert.WithinDuration(t, time.Now(), updater.LastUpdated, time.Second, "Last updated time should be set")
	})

	t.Run("Multiple updates don't cause duplicates", func(t *testing.T) {
		// Reset upload counter for this subtest
		atomic.StoreInt32(&uploadCount, 0)
		updater := client.UpdateReport("12345")
		initialTime := updater.LastUpdated

		// First update
		updater.AddFileContent(strings.NewReader("test1"), "test1.txt", nil)
		updateResult, err := updater.Update(ctx)
		require.NoError(t, err)
		assert.Len(t, updateResult.FileIDs, 1, "First update should have 1 file")
		assert.Empty(t, updater.Files(), "Files should be cleared after Update()")
		assert.True(t, updater.LastUpdated.After(initialTime), "Last updated time should be updated")

		// Second update
		updater.AddFileContent(strings.NewReader("test2"), "test2.txt", nil)
		updateResult, err = updater.Update(ctx)
		require.NoError(t, err)
		assert.Len(t, updateResult.FileIDs, 1, "Second update should have 1 file")
		assert.Empty(t, updater.Files(), "Files should be cleared after Update()")

		// Verify total upload count
		assert.Equal(t, int32(2), atomic.LoadInt32(&uploadCount), "Should have 2 total uploads")
	})

	t.Run("Finish processes only current files", func(t *testing.T) {
		// Reset upload counter for this subtest
		atomic.StoreInt32(&uploadCount, 0)
		updater := client.UpdateReport("12345")
		
		// Add file but don't call Update()
		updater.AddFileContent(strings.NewReader("test"), "test.txt", nil)
		
		result, err := updater.Finish(ctx)
		require.NoError(t, err)
		
		// Should have 1 file from upload + 2 from mock finish response
		assert.Len(t, result.FileIDs, 2, "Finish should return files from finish response")
		assert.Empty(t, updater.Files(), "Files should be cleared after Finish()")
	})
}

func TestCompleteReportWorkflow(t *testing.T) {
	// Setup mock server with handlers for all steps of the report workflow
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")

		// Check auth for all requests
		user, pass, ok := r.BasicAuth()
		if !ok || user != "testuser" || pass != "testpass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch r.URL.Path {
		case "/submit":
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>12345</reportId>
</reportResponse>`))

		case "/upload":
			// Check for the report ID
			if err := r.ParseMultipartForm(10 << 20); err != nil { // 10 MB limit
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			id := r.FormValue("id")
			if id != "12345" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Check that a file was uploaded
			if _, _, err := r.FormFile("file"); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>12345</reportId>
    <fileId>abcdef123456</fileId>
    <hash>fafa5efeaf3cbe3b23b2748d13e629a1</hash>
</reportResponse>`))

		case "/fileinfo":
			// Here we would validate the fileDetails XML
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>12345</reportId>
</reportResponse>`))

		case "/finish":
			// Extract the report ID
			if err := r.ParseForm(); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			id := r.FormValue("id")
			if id != "12345" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportDoneResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>12345</reportId>
    <files>
        <fileId>abcdef123456</fileId>
    </files>
</reportDoneResponse>`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	// Create client
	client, err := ncmec.NewClient(
		ncmec.WithCredentials("testuser", "testpass"),
		ncmec.WithBaseURL(mockServer.URL),
	)
	require.NoError(t, err)

	ctx := context.Background()

	// Create a complete report with file
	fileContent := "test file content"
	fileDetails := &ncmec.FileDetails{
		OriginalFileName: "test.jpg",
		IPCapture: &ncmec.IPCaptureEvent{
			IPAddress: "192.168.1.1",
			EventName: "Upload",
			DateTime:  time.Now(),
		},
		AdditionalInfo: "Test file",
	}

	reportBuilder := client.NewReport().
		WithIncidentType(ncmec.ChildPornography).
		WithIncidentTime(time.Now()).
		WithWebIncident("http://example.com/badcontent").
		WithReporter("John", "Smith", "jsmith@example.com").
		AddFileContent(strings.NewReader(fileContent), "test.jpg", fileDetails)

	// Submit the complete report
	result, err := reportBuilder.Submit(ctx)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "12345", result.ReportID)
	assert.Len(t, result.FileIDs, 1)
	assert.Equal(t, "abcdef123456", result.FileIDs[0])
}
