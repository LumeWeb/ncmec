package ncmec_test

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lumeweb.com/ncmec"
)

func TestFileUpload(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "test-upload-*.jpg")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Define test content constant
	const testContent = "test file content"

	// Calculate expected MD5 hash
	md5Hash := md5.Sum([]byte(testContent))
	expectedHash := hex.EncodeToString(md5Hash[:])

	// Write test content to file
	_, err = tmpFile.WriteString(testContent)
	require.NoError(t, err)
	err = tmpFile.Close()
	require.NoError(t, err)

	// Setup mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/upload" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Check auth
		user, pass, ok := r.BasicAuth()
		if !ok || user != "testuser" || pass != "testpass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Parse form
		err := r.ParseMultipartForm(10 << 20) // 10 MB
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Check report ID
		id := r.FormValue("id")
		if id != "12345" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Check file
		file, fileHeader, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Verify file name
		assert.Equal(t, filepath.Base(tmpFile.Name()), fileHeader.Filename)

		// Read and verify the file content
		content, err := io.ReadAll(file)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Verify content matches expected
		assert.Equal(t, testContent, string(content))

		// Calculate and verify MD5 hash of content
		actualHash := md5.Sum(content)
		assert.Equal(t, expectedHash, hex.EncodeToString(actualHash[:]))

		// Return success response with the same hash
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>12345</reportId>
    <fileId>abcdef123456</fileId>
    <hash>%s</hash>
</reportResponse>`, expectedHash)))
	}))
	defer mockServer.Close()

	// Create client
	client, err := ncmec.NewClient(
		ncmec.WithCredentials("testuser", "testpass"),
		ncmec.WithBaseURL(mockServer.URL),
	)
	require.NoError(t, err)

	ctx := context.Background()
	fileResult, err := client.UploadFile(ctx, "12345", tmpFile.Name())
	require.NoError(t, err)
	assert.Equal(t, "12345", fileResult.ReportID)
	assert.Equal(t, "abcdef123456", fileResult.FileID)

	// Verify hash in response matches expected MD5 hash
	assert.Equal(t, expectedHash, fileResult.Hash)

	// Verify hash calculation matches our FileHasher
	hasher := ncmec.NewFileHasher()
	calculatedHash, err := hasher.HashFile(tmpFile.Name())
	require.NoError(t, err)
	assert.Equal(t, expectedHash, calculatedHash)
}

func TestFileDetails(t *testing.T) {
	// Setup mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/fileinfo" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Check auth
		user, pass, ok := r.BasicAuth()
		if !ok || user != "testuser" || pass != "testpass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Check content type
		contentType := r.Header.Get("Content-Type")
		if !strings.Contains(contentType, "text/xml") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Read request body
		fileDetailsXML, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Simple validation - check for required elements
		detailsStr := string(fileDetailsXML)
		if !strings.Contains(detailsStr, "<reportId>12345</reportId>") ||
			!strings.Contains(detailsStr, "<fileId>abcdef123456</fileId>") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Return success response
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>12345</reportId>
</reportResponse>`))
	}))
	defer mockServer.Close()

	// Create client
	client, err := ncmec.NewClient(
		ncmec.WithCredentials("testuser", "testpass"),
		ncmec.WithBaseURL(mockServer.URL),
	)
	require.NoError(t, err)

	// Create file details
	fileDetails := &ncmec.FileDetails{
		OriginalFileName: "original.jpg",
		IPCapture: &ncmec.IPCaptureEvent{
			IPAddress: "192.168.1.1",
			EventName: "Upload",
			DateTime:  time.Now(),
		},
		AdditionalInfo: "File annotation",
	}

	ctx := context.Background()
	err = client.AddFileDetails(ctx, "12345", "abcdef123456", fileDetails)
	require.NoError(t, err)
}

func TestFileUploadErrorHandling(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "test-upload-*.jpg")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Write some test content
	_, err = tmpFile.WriteString("test file content")
	require.NoError(t, err)
	err = tmpFile.Close()
	require.NoError(t, err)

	// Setup mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/upload" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Return error response
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>2</responseCode>
    <responseDescription>Invalid report ID</responseDescription>
</reportResponse>`))
	}))
	defer mockServer.Close()

	// Create client
	client, err := ncmec.NewClient(
		ncmec.WithCredentials("testuser", "testpass"),
		ncmec.WithBaseURL(mockServer.URL),
	)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = client.UploadFile(ctx, "invalid-id", tmpFile.Name())
	require.Error(t, err)

	// Verify error details
	ncmecErr, ok := err.(*ncmec.Error)
	assert.True(t, ok, "Expected error to be of type *ncmec.Error")
	assert.Equal(t, 2, ncmecErr.Code)
	assert.Equal(t, "Invalid report ID", ncmecErr.Description)
}

func TestPrecomputedHashes(t *testing.T) {
	// Define test content and expected MD5 hash
	const testContent = "precomputed hash test content"
	md5Hash := md5.Sum([]byte(testContent))
	expectedHash := hex.EncodeToString(md5Hash[:])

	// Setup mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/upload" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Parse form
		err := r.ParseMultipartForm(10 << 20)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Get and verify file content
		file, _, err := r.FormFile("file")
		require.NoError(t, err)
		defer file.Close()

		content, err := io.ReadAll(file)
		require.NoError(t, err)
		assert.Equal(t, testContent, string(content))

		// Calculate actual MD5 hash of the content
		actualHash := md5.Sum(content)
		assert.Equal(t, expectedHash, hex.EncodeToString(actualHash[:]))

		// Return success with the same hash
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>12345</reportId>
    <fileId>content123</fileId>
    <hash>%s</hash>
</reportResponse>`, expectedHash)))
	}))
	defer mockServer.Close()

	// Create client
	client, err := ncmec.NewClient(
		ncmec.WithCredentials("testuser", "testpass"),
		ncmec.WithBaseURL(mockServer.URL),
	)
	require.NoError(t, err)

	// Create updater
	updater := client.UpdateReport("12345")

	// Add file content with precomputed hash
	updater.AddFileContentWithPrecomputedHash(
		strings.NewReader(testContent),
		"precomputed.txt",
		expectedHash,
		nil,
	)

	// Verify the precomputed hash is correctly stored
	require.Equal(t, 1, len(updater.Files()))
	assert.Equal(t, expectedHash, updater.Files()[0].Hash)

	// Verify the hash matches what our hasher would calculate
	hasher := ncmec.NewFileHasher()
	calculated := hasher.HashBytes([]byte(testContent))
	assert.Equal(t, expectedHash, calculated)

	// Using a temporary file for file-based test
	tmpFile, err := os.CreateTemp("", "precomputed-*.txt")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Write test content
	_, err = tmpFile.WriteString(testContent)
	require.NoError(t, err)
	tmpFile.Close()

	// Create a new updater
	updater2 := client.UpdateReport("12345")

	// Add file with precomputed hash
	updater2.AddFileWithPrecomputedHash(tmpFile.Name(), expectedHash, nil)

	// Verify hash is stored correctly
	require.Equal(t, 1, len(updater2.Files()))
	assert.Equal(t, expectedHash, updater2.Files()[0].Hash)
}

func TestContentAddressedFile(t *testing.T) {
	// Define test content and expected MD5 hash
	const testContent = "content addressed test file"
	md5Hash := md5.Sum([]byte(testContent))
	expectedHash := hex.EncodeToString(md5Hash[:])

	// Setup mock server for testing file upload with precomputed hash
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/upload" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Parse form
		err := r.ParseMultipartForm(10 << 20)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Get and verify file content
		file, _, err := r.FormFile("file")
		require.NoError(t, err)
		defer file.Close()

		content, err := io.ReadAll(file)
		require.NoError(t, err)
		assert.Equal(t, testContent, string(content))

		// Calculate actual MD5 hash of the content
		actualHash := md5.Sum(content)
		assert.Equal(t, expectedHash, hex.EncodeToString(actualHash[:]))

		// Return success with the same hash
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
    <reportId>12345</reportId>
    <fileId>content123</fileId>
    <hash>%s</hash>
</reportResponse>`, expectedHash)))
	}))
	defer mockServer.Close()

	// Create client
	client, err := ncmec.NewClient(
		ncmec.WithCredentials("testuser", "testpass"),
		ncmec.WithBaseURL(mockServer.URL),
	)
	require.NoError(t, err)

	// Create ContentAddressedFile with precomputed hash
	caFile := ncmec.ContentAddressedFile{
		ContentID: "content://test-123",
		FileName:  "test-content.txt",
		Size:      int64(len(testContent)),
		MimeType:  "text/plain",
		Hash:      expectedHash,
	}

	// Create a report updater
	updater := client.UpdateReport("12345")

	// Add the content addressed file
	updater.AddContentAddressedFile(
		strings.NewReader(testContent),
		caFile,
		&ncmec.FileDetails{
			OriginalFileName: "original-test.txt",
			AdditionalInfo:   "Testing content addressed file",
		},
	)

	// Verify the file was added with correct hash
	require.Equal(t, 1, len(updater.Files()))
	assert.Equal(t, expectedHash, updater.Files()[0].Hash)

	// Create a second file with raw MD5 hash bytes
	md5Sum := md5.Sum([]byte("second content"))
	hashBytes := md5Sum[:]

	// Create file with raw hash bytes
	caFile2 := ncmec.ContentAddressedFile{
		ContentID: "content://test-456",
		FileName:  "test-hash-bytes.txt",
		Size:      int64(len("second content")),
		MimeType:  "text/plain",
		HashBytes: hashBytes,
	}

	// Add second file
	updater.AddContentAddressedFile(
		strings.NewReader("second content"),
		caFile2,
		nil,
	)

	// Verify the second file has correct hash converted from bytes
	require.Equal(t, 2, len(updater.Files()))
	assert.Equal(t, hex.EncodeToString(hashBytes), updater.Files()[1].Hash)
}
