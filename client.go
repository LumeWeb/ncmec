// Package ncmec provides a client for interacting with the NCMEC (National Center for Missing & Exploited Children) CyberTipline API.
// 
// The package handles all aspects of report creation, submission, and management including:
// - Report building with fluent interface
// - File uploads and metadata management
// - XML generation and validation
// - Error handling and retries
// - Authentication and credential management
// 
// For official API documentation, see: https://report.cybertip.org/ispws/documentation/index.html
package ncmec

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"go.lumeweb.com/ncmec/build"
)

// Environment constants for the API
const (
	Production = "production"
	Testing    = "testing"
)

// Base URLs for each environment
const (
	ProductionBaseURL = "https://report.cybertip.org/ispws"
	TestingBaseURL    = "https://exttest.cybertip.org/ispws"
)

// Standard error types returned by the NCMEC API operations
var (
	// Authentication failure or invalid credentials
	ErrAuthentication     = errors.New("authentication failed")
	// Report data validation failed or missing required fields
	ErrInvalidReport      = errors.New("invalid report data")
	// Specified report ID could not be found
	ErrReportNotFound     = errors.New("report not found")
	// File upload failed due to network or API error
	ErrFileUpload         = errors.New("file upload failed")
	// Adding file metadata/details failed
	ErrFileDetailsFailure = errors.New("file details could not be added")
	// Final report submission failed
	ErrReportSubmission   = errors.New("report submission failed")
	// Network communication error
	ErrNetwork            = errors.New("network error")
	// Response parsing failed
	ErrParsing            = errors.New("parsing error")
	// API returned non-zero response code
	ErrAPI                = errors.New("API error")
)

// Client manages communication with the NCMEC API.
// 
// Create instances using NewClient with appropriate ClientOptions.
// The client handles:
// - Authentication
// - Request construction
// - Response handling
// - Error parsing
// - Retry logic
// 
// Client should be reused instead of created as needed. It is safe for concurrent use.
type Client struct {
	Username    string
	Password    string
	BaseURL     string
	Environment string
	HTTPClient  *http.Client
	MaxRetries  int
	Backoff     backoff.BackOff
	UserAgent   string
}

// ClientOption defines functions that configure Client instances.
// 
// Options can be passed to NewClient to customize:
// - Credentials
// - Environment (production vs testing)
// - HTTP client configuration
// - Retry policies
// - User agent
type ClientOption func(*Client) error

// WithCredentials sets the username and password for the client
func WithCredentials(username, password string) ClientOption {
	return func(c *Client) error {
		if username == "" || password == "" {
			return fmt.Errorf("username and password cannot be empty")
		}
		c.Username = username
		c.Password = password
		return nil
	}
}

// WithEnvironment sets the environment (production or testing)
func WithEnvironment(env string) ClientOption {
	return func(c *Client) error {
		switch env {
		case Production:
			c.Environment = Production
			c.BaseURL = ProductionBaseURL
		case Testing:
			c.Environment = Testing
			c.BaseURL = TestingBaseURL
		default:
			return fmt.Errorf("invalid environment: %s", env)
		}
		return nil
	}
}

// WithBaseURL sets a custom base URL for the client
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		c.BaseURL = baseURL
		return nil
	}
}

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) error {
		c.HTTPClient = httpClient
		return nil
	}
}

// WithRetries sets the number of retry attempts for transient errors
func WithRetries(maxRetries int) ClientOption {
	return func(c *Client) error {
		if maxRetries < 0 {
			return fmt.Errorf("retries must be >= 0")
		}
		c.MaxRetries = maxRetries
		return nil
	}
}

// WithBackoffPolicy sets the backoff policy for retries
func WithBackoffPolicy(b backoff.BackOff) ClientOption {
	return func(c *Client) error {
		c.Backoff = b
		return nil
	}
}

// WithUserAgent sets a custom User-Agent header
func WithUserAgent(userAgent string) ClientOption {
	return func(c *Client) error {
		c.UserAgent = userAgent
		return nil
	}
}

// NewClient creates a new NCMEC API client with the provided options
func NewClient(options ...ClientOption) (*Client, error) {
	// Create an exponential backoff with jitter
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = 1 * time.Second
	expBackoff.MaxInterval = 30 * time.Second
	expBackoff.MaxElapsedTime = 2 * time.Minute

	// Create client with defaults
	client := &Client{
		HTTPClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		MaxRetries:  3,
		Backoff:     backoff.WithMaxRetries(backoff.NewExponentialBackOff(), 3),
		UserAgent:   build.UserAgent(),
		Environment: Testing, // Default to testing environment
	}

	// Apply options
	for _, option := range options {
		if err := option(client); err != nil {
			return nil, err
		}
	}

	// Validate required fields
	if client.Username == "" || client.Password == "" {
		return nil, fmt.Errorf("username and password are required")
	}

	if client.BaseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}

	return client, nil
}

// VerifyCredentials checks if the client can authenticate with the API
func (c *Client) VerifyCredentials(ctx context.Context) error {
	_, err := c.DoRequest(ctx, http.MethodGet, "/status", nil, nil)
	if err != nil {
		// Check if it's an authentication error
		if errors.Is(err, ErrAuthentication) {
			return err
		}
		return fmt.Errorf("failed to verify credentials: %w", err)
	}
	return nil
}

// DoRequest makes an HTTP request to the API
func (c *Client) DoRequest(ctx context.Context, method, path string, body io.Reader, headers map[string]string) (*http.Response, error) {
	// Build URL
	url := c.BaseURL + path

	var resp *http.Response
	var lastErr error
	var bodyBytes []byte

	// If body is a ReadCloser, read it into memory so we can retry
	if body != nil {
		var err error
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
	}

	// Define the operation to retry
	operation := func() error {
		// Create request with body from our copy
		var bodyReader io.Reader
		if bodyBytes != nil {
			bodyReader = bytes.NewReader(bodyBytes)
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			lastErr = fmt.Errorf("failed to create request: %w", err)
			return lastErr
		}

		// Add headers
		req.SetBasicAuth(c.Username, c.Password)
		req.Header.Set("User-Agent", c.UserAgent)

		for key, value := range headers {
			req.Header.Set(key, value)
		}

		// Make request
		resp, err = c.HTTPClient.Do(req)

		// If we got an error making the request, consider it retryable
		if err != nil {
			lastErr = err
			return err
		}

		// If we got a 5xx status code, consider it retryable
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("server error: %d", resp.StatusCode)
			resp.Body.Close() // Don't leak resources
			return lastErr
		}

		// Otherwise, consider it a success and stop retrying
		return nil
	}

	// Create a retry context with the parent context
	retryCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Use the backoff library to handle retries
	go func() {
		select {
		case <-ctx.Done():
			cancel()
		}
	}()

	// Execute with retry
	err := backoff.Retry(operation, backoff.WithContext(c.Backoff, retryCtx))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: %v", ErrNetwork, lastErr)
	}

	// Process the successful response
	return c.ProcessResponse(resp, nil)
}

// ProcessResponse handles common response processing logic including:
// - HTTP status code validation
// - XML response parsing
// - Error type conversion
// Returns the response if successful, or an error with detailed context
func (c *Client) ProcessResponse(resp *http.Response, err error) (*http.Response, error) {
	// Handle request error
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNetwork, err)
	}

	// Handle HTTP error status codes
	switch resp.StatusCode {
	case http.StatusOK:
		// For HTTP 200, check if content is XML and validate it
		if strings.Contains(resp.Header.Get("Content-Type"), "application/xml") {
			// Try to read and parse XML to validate it
			bodyBytes, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				resp.Body.Close()
				return nil, fmt.Errorf("%w: failed to read response body: %v", ErrNetwork, readErr)
			}

			// Create a new body reader for continued use
			resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			// Try to parse as XML to validate
			var testResp ReportResponse
			if xmlErr := xml.Unmarshal(bodyBytes, &testResp); xmlErr != nil {
				// XML parsing error
				return nil, fmt.Errorf("%w: malformed XML response: %v", ErrParsing, xmlErr)
			}

			// XML is valid, check for API error codes
			if testResp.ResponseCode != 0 {
				return nil, &Error{
					Code:        testResp.ResponseCode,
					Description: testResp.ResponseDescription,
					Wrap:        ErrAPI,
				}
			}
		}
		// Valid response, continue
	case http.StatusUnauthorized:
		resp.Body.Close()
		return nil, fmt.Errorf("%w: invalid credentials", ErrAuthentication)
	case http.StatusNotFound:
		resp.Body.Close()
		return nil, fmt.Errorf("%w: endpoint not found", ErrNetwork)
	default:
		// For other status codes, try to parse the error response
		if strings.Contains(resp.Header.Get("Content-Type"), "application/xml") {
			// Try to decode as XML
			bodyBytes, readErr := io.ReadAll(resp.Body)
			resp.Body.Close() // Always close the body

			if readErr != nil {
				return nil, fmt.Errorf("%w: failed to read response body: %v", ErrNetwork, readErr)
			}

			// Try to parse as an API error response
			var errorResp ReportResponse
			if xmlErr := xml.Unmarshal(bodyBytes, &errorResp); xmlErr != nil {
				// XML parsing error
				return nil, fmt.Errorf("%w: failed to decode XML response: %v", ErrParsing, xmlErr)
			}

			// Successful XML parse, check for API error
			if errorResp.ResponseCode != 0 {
				return nil, &Error{
					Code:        errorResp.ResponseCode,
					Description: errorResp.ResponseDescription,
					Wrap:        ErrAPI,
				}
			}

			// XML parsed but no error code found
			return nil, fmt.Errorf("%w: unexpected status code %d", ErrNetwork, resp.StatusCode)
		}

		// Not XML, just return generic error
		resp.Body.Close()
		return nil, fmt.Errorf("%w: unexpected status code %d", ErrNetwork, resp.StatusCode)
	}

	return resp, nil
}

// NewReport creates a new report builder with initialized structures
func (c *Client) NewReport() *ReportBuilder {
	rb := &ReportBuilder{
		client: c,
		report: &Report{
			XMLNS:           "http://www.w3.org/2001/XMLSchema-instance",
			SchemaLocation:  "https://report.cybertip.org/ispws/xsd",
			IncidentSummary: IncidentSummary{},
			InternetDetails: InternetDetails{},
			Reporter:        Reporter{},
		},
		checkExpiration:  true,
		creationTime:     time.Now(),
		lastModifiedTime: time.Now(),
	}
	return rb
}

// UploadFile uploads a file to an existing report
func (c *Client) UploadFile(ctx context.Context, reportID, filePath string) (*FileUploadResult, error) {
	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to open file: %v", ErrFileUpload, err)
	}
	defer file.Close()

	return c.UploadFileContent(ctx, reportID, file, filePath)
}

// UploadFileContent uploads file content to an existing report
func (c *Client) UploadFileContent(ctx context.Context, reportID string, content io.Reader, filename string) (*FileUploadResult, error) {
	// Create multipart request
	request, err := NewUploadRequest(c.BaseURL+"/upload", reportID, content, filename)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create upload request: %v", ErrFileUpload, err)
	}

	// Add authentication
	request.SetBasicAuth(c.Username, c.Password)

	// Execute request
	resp, err := c.HTTPClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: network error: %v", ErrFileUpload, err)
	}
	defer resp.Body.Close()

	// Check for not found errors first
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: report ID %s not found", ErrReportNotFound, reportID)
	}

	// Parse response
	var response ReportResponse
	if err := xml.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("%w: failed to decode response: %v", ErrFileUpload, err)
	}

	// Check for API error
	if response.ResponseCode != 0 {
		// Check for report not found in the error description
		if strings.Contains(strings.ToLower(response.ResponseDescription), "not found") {
			return nil, fmt.Errorf("%w: %s", ErrReportNotFound, response.ResponseDescription)
		}

		// Other API errors
		return nil, &Error{
			Code:        response.ResponseCode,
			Description: response.ResponseDescription,
			Wrap:        ErrFileUpload,
		}
	}

	// Return successful result
	return &FileUploadResult{
		ReportID: response.ReportID,
		FileID:   response.FileID,
		Hash:     response.Hash,
	}, nil
}

// AddFileDetails adds details to an uploaded file
func (c *Client) AddFileDetails(ctx context.Context, reportID, fileID string, details *FileDetails) error {
	// Validate inputs
	if reportID == "" {
		return fmt.Errorf("%w: report ID is required", ErrInvalidReport)
	}
	if fileID == "" {
		return fmt.Errorf("%w: file ID is required", ErrFileUpload)
	}

	// Create file details structure
	fileDetailsXML := NewFileDetailsXML(reportID, fileID, details)

	// Create XML reader
	reader, err := NewXMLReader(fileDetailsXML)
	if err != nil {
		return fmt.Errorf("%w: failed to create file details XML: %v", ErrFileDetailsFailure, err)
	}

	// Prepare the request
	headers := map[string]string{
		"Content-Type": "text/xml; charset=utf-8",
	}

	// Send the request
	resp, err := c.DoRequest(
		ctx,
		http.MethodPost,
		"/fileinfo",
		reader,
		headers,
	)
	if err != nil {
		// Check if error might be due to report not found
		if strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("%w: report ID %s not found", ErrReportNotFound, reportID)
		}
		return fmt.Errorf("%w: %v", ErrFileDetailsFailure, err)
	}
	defer resp.Body.Close()

	// Check for not found errors based on status code
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: report ID %s or file ID %s not found", ErrReportNotFound, reportID, fileID)
	}

	// Parse the response
	var response ReportResponse
	if err := xml.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("%w: failed to decode response: %v", ErrFileDetailsFailure, err)
	}

	// Check for API error
	if response.ResponseCode != 0 {
		// Check for report or file not found in the error description
		desc := strings.ToLower(response.ResponseDescription)
		if strings.Contains(desc, "not found") || strings.Contains(desc, "invalid") {
			if strings.Contains(desc, "report") {
				return fmt.Errorf("%w: %s", ErrReportNotFound, response.ResponseDescription)
			} else if strings.Contains(desc, "file") {
				return fmt.Errorf("%w: %s", ErrFileUpload, response.ResponseDescription)
			}
		}

		return &Error{
			Code:        response.ResponseCode,
			Description: response.ResponseDescription,
			Wrap:        ErrFileDetailsFailure,
		}
	}

	return nil
}

// FinishReport completes a report submission
func (c *Client) FinishReport(ctx context.Context, reportID string) (*ReportDoneResult, error) {
	// Prepare request body
	body := fmt.Sprintf("id=%s", reportID)

	// Prepare headers
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}

	// Send request, but don't use ProcessResponse here since we need to handle ReportDoneResponse
	url := c.BaseURL + "/finish"

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %v", ErrReportSubmission, err)
	}

	// Add authentication and headers
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("User-Agent", c.UserAgent)

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Make request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: network error: %v", ErrReportSubmission, err)
	}
	defer resp.Body.Close()

	// Check for not found error
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: report ID %s not found", ErrReportNotFound, reportID)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: unexpected status code %d", ErrReportSubmission, resp.StatusCode)
	}

	// Parse response as ReportDoneResponse
	var response ReportDoneResponse
	if err := xml.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("%w: failed to decode response: %v", ErrReportSubmission, err)
	}

	// Check for API error
	if response.ResponseCode != 0 {
		// Check for report not found in the response description
		if strings.Contains(strings.ToLower(response.ResponseDescription), "not found") {
			return nil, fmt.Errorf("%w: %s", ErrReportNotFound, response.ResponseDescription)
		}

		return nil, &Error{
			Code:        response.ResponseCode,
			Description: response.ResponseDescription,
			Wrap:        ErrReportSubmission,
		}
	}

	// Parse file IDs
	fileIDs := make([]string, 0)
	for _, fileID := range response.Files {
		fileIDs = append(fileIDs, fileID)
	}

	// Return successful result
	return &ReportDoneResult{
		ReportID: response.ReportID,
		FileIDs:  fileIDs,
	}, nil
}

// CancelReport cancels a report submission
func (c *Client) CancelReport(ctx context.Context, reportID string) error {
	// Prepare request body
	body := fmt.Sprintf("id=%s", reportID)

	// Prepare headers
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}

	// Send request
	resp, err := c.DoRequest(
		ctx,
		http.MethodPost,
		"/retract",
		strings.NewReader(body),
		headers,
	)
	if err != nil {
		// Check if error might be due to report not found
		if strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("%w: report ID %s", ErrReportNotFound, reportID)
		}
		return err
	}
	defer resp.Body.Close()

	// Parse response
	var response ReportResponse
	if err := xml.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("%w: failed to decode response: %v", ErrParsing, err)
	}

	// Check for API error
	if response.ResponseCode != 0 {
		// Special case for report not found error in API response
		if strings.Contains(strings.ToLower(response.ResponseDescription), "not found") {
			return fmt.Errorf("%w: %s", ErrReportNotFound, response.ResponseDescription)
		}

		return &Error{
			Code:        response.ResponseCode,
			Description: response.ResponseDescription,
			Wrap:        ErrAPI,
		}
	}

	return nil
}


// UpdateReport creates a ReportUpdater for an existing report
// This allows adding new files or updating metadata for an unfinished report
func (c *Client) UpdateReport(reportID string) *ReportUpdater {
	return &ReportUpdater{
		client:      c,
		ReportID:    reportID,  // Changed to match exported field name
		LastUpdated: time.Now(),
	}
}
