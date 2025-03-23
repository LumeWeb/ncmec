package ncmec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lumeweb.com/ncmec"
)

func TestErrorHandling(t *testing.T) {
	// Setup mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/server-error":
			w.WriteHeader(http.StatusInternalServerError)

		case "/invalid-xml":
			w.Header().Set("Content-Type", "application/xml")
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>3<responseCode> <!-- Malformed XML -->
    <responseDescription>Error</responseDescription>
</reportResponse>`))

		case "/api-error":
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>5</responseCode>
    <responseDescription>API Error</responseDescription>
</reportResponse>`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	// Create client with custom error handler for testing
	client := &ncmec.Client{
		BaseURL: mockServer.URL,
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}

	tests := []struct {
		name         string
		endpoint     string
		expectedCode int
		expectedType error
	}{
		{
			name:         "server error",
			endpoint:     "/server-error",
			expectedCode: http.StatusInternalServerError,
			expectedType: ncmec.ErrNetwork,
		},
		{
			name:         "invalid XML",
			endpoint:     "/invalid-xml",
			expectedCode: 0,
			expectedType: ncmec.ErrParsing,
		},
		{
			name:         "API error",
			endpoint:     "/api-error",
			expectedCode: 5,
			expectedType: ncmec.ErrAPI,
		},
		{
			name:         "not found",
			endpoint:     "/not-found",
			expectedCode: http.StatusNotFound,
			expectedType: ncmec.ErrNetwork,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, mockServer.URL+tt.endpoint, nil)
			require.NoError(t, err)

			resp, err := client.HTTPClient.Do(req)

			// Process the response using the client's error handler
			_, err = client.ProcessResponse(resp, err)

			require.Error(t, err)
			assert.True(t, errors.Is(err, tt.expectedType), "Expected error to be of type %v, got %v", tt.expectedType, err)

			if tt.endpoint == "/api-error" {
				ncmecErr, ok := err.(*ncmec.Error)
				assert.True(t, ok, "Expected error to be of type *ncmec.Error")
				assert.Equal(t, tt.expectedCode, ncmecErr.Code)
				assert.Equal(t, "API Error", ncmecErr.Description)
			}
		})
	}
}

func TestRetryMechanism(t *testing.T) {
	// Setup a counter for tracking retry attempts
	attempts := 0
	maxAttempts := 3

	// Setup mock server that fails for the first 2 attempts then succeeds
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < maxAttempts {
			w.WriteHeader(http.StatusServiceUnavailable) // 503 should trigger retry
			return
		}

		// Success on the third attempt
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<reportResponse>
    <responseCode>0</responseCode>
    <responseDescription>Success</responseDescription>
</reportResponse>`))
	}))
	defer mockServer.Close()

	// Create client
	// Create a constant backoff for testing
	constantBackoff := backoff.NewConstantBackOff(50 * time.Millisecond)

	client, err := ncmec.NewClient(
		ncmec.WithCredentials("testuser", "testpass"),
		ncmec.WithBaseURL(mockServer.URL),
		ncmec.WithRetries(maxAttempts),
		ncmec.WithBackoffPolicy(backoff.WithMaxRetries(constantBackoff, uint64(maxAttempts))),
	)
	require.NoError(t, err)

	// Make a request that should eventually succeed after retries
	ctx := context.Background()
	resp, err := client.DoRequest(ctx, http.MethodGet, "/", nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, resp)

	// Verify that retries occurred
	assert.Equal(t, maxAttempts, attempts, "Expected exactly %d attempts", maxAttempts)

	// Reset for the next test
	attempts = 0

	// Create client with fewer retries than needed
	// Create a constant backoff for testing with only 1 retry
	limitedBackoff := backoff.NewConstantBackOff(50 * time.Millisecond)

	client, err = ncmec.NewClient(
		ncmec.WithCredentials("testuser", "testpass"),
		ncmec.WithBaseURL(mockServer.URL),
		ncmec.WithRetries(1), // Only 1 retry, not enough to reach success
		ncmec.WithBackoffPolicy(backoff.WithMaxRetries(limitedBackoff, 1)),
	)
	require.NoError(t, err)

	// Make a request that should fail even with retries
	ctx = context.Background()
	resp, err = client.DoRequest(ctx, http.MethodGet, "/", nil, nil)
	require.Error(t, err)
	assert.Nil(t, resp)

	// Verify error type
	assert.True(t, errors.Is(err, ncmec.ErrNetwork), "Expected network error")

	// Verify that exact number of retries were attempted
	assert.Equal(t, 2, attempts, "Expected exactly 2 attempts (original + 1 retry)")
}
