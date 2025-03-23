package ncmec_test

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"go.lumeweb.com/ncmec"
)

func Example() {
	// Create a mock server to simulate the NCMEC API
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")

		// Check auth - using test credentials
		user, pass, ok := r.BasicAuth()
		if !ok || user != "testuser" || pass != "testpass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch r.URL.Path {
		case "/status":
			// Verify credentials response
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
</reportResponse>`))

		case "/submit":
			// Report submission response
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>12345</reportId>
</reportResponse>`))

		case "/upload":
			// File upload response
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>12345</reportId>
    <fileId>file123</fileId>
    <hash>abcdef123456</hash>
</reportResponse>`))

		case "/fileinfo":
			// File info response
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
</reportResponse>`))

		case "/finish":
			// Finish response
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportDoneResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>12345</reportId>
    <files>
        <fileId>file123</fileId>
    </files>
</reportDoneResponse>`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	// Create a client with test credentials
	client, err := ncmec.NewClient(
		ncmec.WithCredentials("testuser", "testpass"),
		ncmec.WithBaseURL(mockServer.URL), // Use mock server URL
	)
	if err != nil {
		fmt.Printf("Failed to create client: %v\n", err)
		return
	}

	// Verify credentials
	ctx := context.Background()
	if err := client.VerifyCredentials(ctx); err != nil {
		fmt.Printf("Failed to verify credentials: %v\n", err)
		return
	}
	fmt.Println("Credentials verified successfully")

	// Create a report
	reportBuilder := client.NewReport().
		WithIncidentType(ncmec.ChildPornography).
		WithIncidentTime(time.Now()).
		WithWebIncident("http://example.com/badcontent").
		WithReporter("John", "Smith", "jsmith@example.com")

	// Add a file from a string (for example purposes)
	fileContent := "test file content"
	fileDetails := &ncmec.FileDetails{
		OriginalFileName: "test.txt",
		IPCapture: &ncmec.IPCaptureEvent{
			IPAddress: "192.168.1.1",
			EventName: "Upload",
			DateTime:  time.Now(),
		},
		AdditionalInfo: "Test file for example",
	}
	reportBuilder.AddFileContent(strings.NewReader(fileContent), "test.txt", fileDetails)

	// Submit the report
	result, err := reportBuilder.Submit(ctx)
	if err != nil {
		fmt.Printf("Failed to submit report: %v\n", err)
		return
	}

	fmt.Printf("Report submitted successfully, ID: %s\n", result.ReportID)
	fmt.Printf("Uploaded %d files\n", len(result.FileIDs))

	// Output:
	// Credentials verified successfully
	// Report submitted successfully, ID: 12345
	// Uploaded 1 files
}

func ExampleClient_NewReport() {
	// Create a client
	client, err := ncmec.NewClient(
		ncmec.WithCredentials("username", "password"),
		ncmec.WithEnvironment(ncmec.Testing),
	)
	if err != nil {
		fmt.Printf("Failed to create client: %v\n", err)
		return
	}

	// Create a report builder
	reportBuilder := client.NewReport()

	// Build a report with the fluent interface
	reportBuilder.
		WithIncidentType(ncmec.ChildPornography).
		WithIncidentTime(time.Now()).
		WithWebIncident("http://example.com/badcontent").
		WithReporter("John", "Smith", "jsmith@example.com")

	// Get the report without submitting it
	report := reportBuilder.Build()

	fmt.Printf("Report incident type: %s\n", report.IncidentSummary.IncidentType)
	fmt.Printf("Report URL: %s\n", report.InternetDetails.WebPageIncident.URL)
	fmt.Printf("Reporter: %s %s\n", report.Reporter.ReportingPerson.FirstName, report.Reporter.ReportingPerson.LastName)

	// Output:
	// Report incident type: Child Pornography (possession, manufacture, and distribution)
	// Report URL: http://example.com/badcontent
	// Reporter: John Smith
}

func ExampleClient_CancelReport() {
	// Create a mock server to simulate the NCMEC API
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")

		// Check auth - using test credentials
		user, pass, ok := r.BasicAuth()
		if !ok || user != "testuser" || pass != "testpass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch r.URL.Path {
		case "/submit":
			// Report submission response
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>12345</reportId>
</reportResponse>`))

		case "/retract":
			// Parse form data to ensure ID is provided
			if err := r.ParseForm(); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			id := r.FormValue("id")
			if id != "12345" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Cancel report response
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Report successfully canceled</responseDescription>
</reportResponse>`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	// Create a client with test credentials
	client, err := ncmec.NewClient(
		ncmec.WithCredentials("testuser", "testpass"),
		ncmec.WithBaseURL(mockServer.URL), // Use mock server URL
	)
	if err != nil {
		fmt.Printf("Failed to create client: %v\n", err)
		return
	}

	ctx := context.Background()

	// Create a minimal report
	reportBuilder := client.NewReport().
		WithIncidentType(ncmec.ChildPornography).
		WithIncidentTime(time.Now()).
		WithReporter("John", "Smith", "jsmith@example.com")

	// Build and marshal the report to XML
	report := reportBuilder.Build()
	reportXML, err := report.MarshalToXML()
	if err != nil {
		fmt.Printf("Failed to marshal report: %v\n", err)
		return
	}

	// Submit the report to open it
	headers := map[string]string{
		"Content-Type": "text/xml; charset=utf-8",
	}

	resp, err := client.DoRequest(
		ctx,
		http.MethodPost,
		"/submit",
		bytes.NewReader(reportXML),
		headers,
	)
	if err != nil {
		fmt.Printf("Failed to submit report: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Parse the response
	var response ncmec.ReportResponse
	if err := xml.NewDecoder(resp.Body).Decode(&response); err != nil {
		fmt.Printf("Failed to decode response: %v\n", err)
		return
	}

	// Check for success
	if response.ResponseCode != 0 {
		fmt.Printf("Failed to submit report: %s\n", response.ResponseDescription)
		return
	}

	// Get the report ID
	reportID := response.ReportID
	fmt.Printf("Report opened with ID: %s\n", reportID)

	// Now cancel the report
	err = client.CancelReport(ctx, reportID)
	if err != nil {
		fmt.Printf("Failed to cancel report: %v\n", err)
		return
	}

	fmt.Println("Report cancelled successfully")

	// Output:
	// Report opened with ID: 12345
	// Report cancelled successfully
}
