package ncmec

import (
	"errors"
	"fmt"
)

// Error encapsulates detailed information about API failures.
// 
// Contains both NCMEC-specific error codes and underlying error information.
// Implements the error interface and supports error wrapping/unwrapping.
type Error struct {
	Code        int                    // Response code from the API
	Description string                 // Description of the error
	RequestID   string                 // Request ID for troubleshooting
	Context     map[string]interface{} // Additional context for the error
	Wrap        error                  // The wrapped error
}

// Error returns a string representation of the error
func (e *Error) Error() string {
	return fmt.Sprintf("NCMEC API error %d: %s", e.Code, e.Description)
}

// Is implements the errors.Is interface
func (e *Error) Is(target error) bool {
	if target == nil {
		return false
	}

	// Check if the target is an Error and has the same code
	targetErr, ok := target.(*Error)
	if ok {
		return e.Code == targetErr.Code
	}

	// Check if the target is one of our standard errors
	return errors.Is(e.Wrap, target)
}

// Unwrap implements the errors.Unwrap interface
func (e *Error) Unwrap() error {
	return e.Wrap
}

// WithContext adds key-value context to the error for better diagnostics.
// The context is stored in the error and can be extracted using error unwrapping.
// Example: err.WithContext("reportID", "12345")
func (e *Error) WithContext(key string, value interface{}) *Error {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// WithRequestID attaches the NCMEC API request ID to the error.
// This ID is crucial for troubleshooting issues with NCMEC support.
func (e *Error) WithRequestID(requestID string) *Error {
	e.RequestID = requestID
	return e
}
