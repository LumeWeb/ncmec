package ncmec

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
)

// NewUploadRequest creates a new file upload request
func NewUploadRequest(url, reportID string, content io.Reader, filename string) (*http.Request, error) {
	// Create a buffer to store the multipart form
	body := &bytes.Buffer{}

	// Create a new multipart writer
	writer := multipart.NewWriter(body)

	// Add the report ID field
	if err := writer.WriteField("id", reportID); err != nil {
		return nil, fmt.Errorf("failed to write report ID field: %w", err)
	}

	// Create the form file field
	part, err := writer.CreateFormFile("file", filepath.Base(filename))
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}

	// Copy the file content to the form field
	if _, err := io.Copy(part, content); err != nil {
		return nil, fmt.Errorf("failed to copy file content: %w", err)
	}

	// Close the writer
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close writer: %w", err)
	}

	// Create the request
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the content type
	req.Header.Set("Content-Type", writer.FormDataContentType())

	return req, nil
}
