# NCMEC CyberTipline Reporting Client

A Go client library for submitting reports to the National Center for Missing & Exploited Children (NCMEC) CyberTipline API.

## Installation

```bash
go get go.lumeweb.com/ncmec
```

## Usage

### Basic Report Submission

```go
package main

import (
	"context"
	"log"
	"os"
	"time"

	"go.lumeweb.com/ncmec"
)

func main() {
	// Create a client
	client, err := ncmec.NewClient(
		ncmec.WithCredentials(os.Getenv("NCMEC_USERNAME"), os.Getenv("NCMEC_PASSWORD")),
		ncmec.WithEnvironment(ncmec.Testing), // Use Testing for test environment, Production for production
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Verify credentials
	ctx := context.Background()
	if err := client.VerifyCredentials(ctx); err != nil {
		log.Fatalf("Failed to verify credentials: %v", err)
	}

	// Create and submit a report
	result, err := client.NewReport().
		WithIncidentType(ncmec.ChildPornography).
		WithIncidentTime(time.Now()).
		WithWebIncident("http://example.com/badcontent").
		WithReporter("John", "Smith", "jsmith@example.com").
		Submit(ctx)

	if err != nil {
		log.Fatalf("Failed to submit report: %v", err)
	}

	log.Printf("Report submitted successfully, ID: %s", result.ReportID)
	if len(result.FileIDs) > 0 {
		log.Printf("Uploaded %d files", len(result.FileIDs))
	}
}
```

### Report with File Uploads and Expiration Tracking

```go
// Create a report with expiration checking
reportBuilder := client.NewReport().
    WithIncidentType(ncmec.ChildPornography).
    WithIncidentTime(time.Now()).
    WithWebIncident("http://example.com/badcontent").
    WithReporter("John", "Smith", "jsmith@example.com").
    AddExpirationChecking()  // Enable time tracking

// Add file with details and precomputed hash
fileHash := "5eb63bbbe01eeed093cb22bb8f5acdc3"
reportBuilder.AddFileWithPrecomputedHash(
    "/path/to/file.jpg",
    fileHash,
    &ncmec.FileDetails{
        OriginalFileName: "original.jpg",
        IPCapture: &ncmec.IPCaptureEvent{
            IPAddress: "192.168.1.1",
            EventName: "Upload",
            DateTime:  time.Now(),
        },
        AdditionalInfo: "File verified via external system",
    },
)

// Check expiration before submission
if status := reportBuilder.CheckExpiration(); status.Status == ncmec.ReportStatusExpired {
    log.Fatal("Cannot submit expired report")
}

// Submit the report
result, err := reportBuilder.Submit(ctx)
if err != nil {
	log.Fatalf("Failed to submit report: %v", err)
}
```

### Updating an Existing Report

You can update an existing report with additional files before finalizing it:

```go
// Create an initial report
reportBuilder := client.NewReport().
    WithIncidentType(ncmec.ChildPornography).
    WithIncidentTime(time.Now()).
    WithReporter("John", "Smith", "jsmith@example.com")

// Submit initial report to get a report ID
report := reportBuilder.Build()
reportXML, err := report.MarshalToXML()
if err != nil {
    log.Fatalf("Failed to marshal report: %v", err)
}

resp, err := client.DoRequest(
    ctx,
    http.MethodPost,
    "/submit",
    bytes.NewReader(reportXML),
    map[string]string{"Content-Type": "text/xml; charset=utf-8"},
)
if err != nil {
    log.Fatalf("Failed to submit initial report: %v", err)
}

var response ncmec.ReportResponse
err = xml.NewDecoder(resp.Body).Decode(&response)
if err != nil {
    log.Fatalf("Failed to decode response: %v", err)
}
resp.Body.Close()

reportID := response.ReportID

// Update the report with new files
updater := client.UpdateReport(reportID)

// Add a new file
updater.AddFile("/path/to/file.jpg", &ncmec.FileDetails{
    OriginalFileName: "evidence.jpg",
    IPCapture: &ncmec.IPCaptureEvent{
        IPAddress: "192.168.1.1",
        EventName: "Upload",
        DateTime:  time.Now(),
    },
})

// Update without finalizing
updateResult, err := updater.Update(ctx)
if err != nil {
    log.Fatalf("Failed to update report: %v", err)
}

// Later, finalize the report
finishResult, err := client.FinishReport(ctx, reportID)
if err != nil {
    log.Fatalf("Failed to finish report: %v", err)
}
```

### Working with Content Addressed Storage (IPFS)

The library provides support for content-addressed storage systems like IPFS:

```go
// Create a report
reportBuilder := client.NewReport().
    WithIncidentType(ncmec.ChildPornography).
    WithIncidentTime(time.Now()).
    WithReporter("John", "Smith", "jsmith@example.com")

// Create a content-addressed file reference
caFile := ncmec.ContentAddressedFile{
    ContentID: "ipfs://QmZ4tDuvesekSs4qM5ZBKpXiZGun7S2CYtEZRB3DYXkjGx",
    FileName:  "evidence.jpg",
    Size:      1024 * 1024, // 1MB
    MimeType:  "image/jpeg",
    Hash:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

// Get a reader for the content (from your IPFS client)
contentReader := getIPFSContent(caFile.ContentID)

// Add the file to the report
reportBuilder.AddContentAddressedFile(
    contentReader,
    caFile,
    nil, // Let the method create file details with content ID
)

// Submit the report
result, err := reportBuilder.Submit(ctx)
if err != nil {
    log.Fatalf("Failed to submit report: %v", err)
}
```

### Manual Report Workflow

If you need more control over the report submission process, you can use the individual API methods:

```go
// Open a report
reportXML := `<?xml version="1.0" encoding="UTF-8"?>
<report xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:noNamespaceSchemaLocation="https://report.cybertip.org/ispws/xsd">
    <incidentSummary>
        <incidentType>Child Pornography (possession, manufacture, and distribution)</incidentType>
        <incidentDateTime>2023-01-15T08:00:00-05:00</incidentDateTime>
    </incidentSummary>
    <reporter>
        <reportingPerson>
            <firstName>John</firstName>
            <lastName>Smith</lastName>
            <email>jsmith@example.com</email>
        </reportingPerson>
    </reporter>
</report>`

// Upload a file to the report
fileResult, err := client.UploadFile(ctx, reportID, "/path/to/file.jpg")
if err != nil {
	log.Fatalf("Failed to upload file: %v", err)
}

// Add file details
fileDetails := &ncmec.FileDetails{
	OriginalFileName: "original.jpg",
	IPCapture: &ncmec.IPCaptureEvent{
		IPAddress: "192.168.1.1",
		EventName: "Upload",
		DateTime:  time.Now(),
	},
}
err = client.AddFileDetails(ctx, reportID, fileResult.FileID, fileDetails)
if err != nil {
	log.Fatalf("Failed to add file details: %v", err)
}

// Finish the report
finishResult, err := client.FinishReport(ctx, reportID)
if err != nil {
	log.Fatalf("Failed to finish report: %v", err)
}
```

## Features

- Full support for the NCMEC CyberTipline API v1.5
- Fluent interface with expiration tracking for report deadlines
- Detailed error handling with NCMEC-specific error codes and context
- Automatic retry mechanism with exponential backoff
- Comprehensive XML validation against NCMEC schemas
- File uploads with metadata and precomputed hashes
- Content-addressed storage integration (IPFS, S3, etc)
- Report expiration tracking and warnings
- Concurrent-safe client implementation
- Detailed logging and diagnostics
- Configurable HTTP client and retry policies
- Production/Testing environment support
- Complete godoc documentation for all types and methods

## Error Handling and Diagnostics

The library provides rich error information including NCMEC-specific codes, request IDs, and contextual details:

```go
result, err := reportBuilder.Submit(ctx)
if err != nil {
    var ncmecErr *ncmec.Error
    if errors.As(err, &ncmecErr) {
        // Log full error context
        log.Printf("NCMEC Error %d: %s", ncmecErr.Code, ncmecErr.Description)
        log.Printf("Request ID: %s", ncmecErr.RequestID)
        
        // Include custom context for diagnostics
        ncmecErr.WithContext("reportID", result.ReportID)
               .WithContext("submissionTime", time.Now().Format(time.RFC3339))
        
        // Log structured error details
        log.Printf("Error Details: %+v", ncmecErr)
        
        // Check for specific error types
        if errors.Is(ncmecErr, ncmec.ErrAuthentication) {
            log.Fatal("Invalid credentials, check configuration")
        }
    } else {
        log.Printf("Unexpected error type: %T", err)
    }
    return
}
```

## Documentation and Validation

The library includes extensive godoc documentation and validation checks:

```go
// Validate XML structure before submission
validator, err := client.FetchSchema(ctx)
if err != nil {
    log.Fatal("Failed to fetch latest XSD schema:", err)
}

if err := validator.ValidateReport(reportXML); err != nil {
    log.Fatal("Report validation failed:", err)
}

// Access detailed documentation through godoc
// Run local documentation server:
//   go doc -all ./...
//   godoc -http=:6060
```
Full API documentation available at:  
https://pkg.go.dev/go.lumeweb.com/ncmec

NCMEC Official Documentation:  
https://report.cybertip.org/ispws/documentation/index.html

### File Hashing and Validation

The library provides utilities for hashing files and content, which is useful for integrity verification:

```go
// Create a hasher
hasher, err := ncmec.NewFileHasher(ncmec.SHA256)
if err != nil {
    log.Fatalf("Failed to create hasher: %v", err)
}

// Hash a file
fileHash, err := hasher.HashFile("/path/to/file.jpg")
if err != nil {
    log.Fatalf("Failed to hash file: %v", err)
}
fmt.Printf("File SHA-256: %s\n", fileHash)

// Hash content
content := []byte("file content to hash")
contentHash := hasher.HashBytes(content)
fmt.Printf("Content SHA-256: %s\n", contentHash)

// Compare with a hash from a content-addressed system
ipfsHash := "QmZ4tDuvesekSs4qM5ZBKpXiZGun7S2CYtEZRB3DYXkjGx"
multibaseHash, err := hasher.HashToMultibase(contentHash) 
if err != nil {
    log.Fatalf("Failed to convert hash: %v", err)
}

// Validate that hashes match (simplified example)
if strings.Contains(ipfsHash, multibaseHash) {
    fmt.Println("Hash verified, content integrity confirmed")
}

// Add the file with verified hash to a report
reportBuilder.AddFileContent(
    bytes.NewReader(content),
    "verified.txt",
    &ncmec.FileDetails{
        OriginalFileName: "verified.txt",
        AdditionalInfo: fmt.Sprintf("Hash verified: %s", contentHash),
    },
)
```

## Running Tests

### Integration Tests

Integration tests require valid NCMEC credentials to run against the NCMEC test environment.

You can provide credentials in three ways:

1. Set environment variables before running tests:
```bash
export NCMEC_USERNAME=your_username
export NCMEC_PASSWORD=your_password
go test -tags=integration ./...
```

2. Create a `.env` file in the project root:
```
NCMEC_USERNAME=your_username
NCMEC_PASSWORD=your_password
```

3. Create a `.env.test` file in the project root (takes precedence over `.env`):
```
NCMEC_USERNAME=your_test_username
NCMEC_PASSWORD=your_test_password
```

To run the integration tests:
```bash
go test -tags=integration ./...
```

## License

This library is licensed under the [MIT License](LICENSE).
