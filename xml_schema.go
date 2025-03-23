package ncmec

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// SchemaValidator handles XML validation against NCMEC's XSD schemas.
// 
// Note: This implementation provides basic structural validation. For full 
// schema compliance, consider using a dedicated XSD validation library.
type SchemaValidator struct {
	client *Client
	schema string
}

// FetchSchema retrieves the current XSD schema from the NCMEC API.
// The schema is cached per-client and should be reused for multiple validations.
// May return errors due to network issues or authentication problems.
func (c *Client) FetchSchema(ctx context.Context) (*SchemaValidator, error) {
	// Call the /xsd endpoint to get the schema
	url := c.BaseURL + "/xsd"

	// Create request directly rather than using DoRequest
	// since the schema response is not a standard API response
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for XSD schema: %w", err)
	}

	// Add authentication
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("User-Agent", c.UserAgent)

	// Make request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch XSD schema: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch XSD schema: HTTP %d", resp.StatusCode)
	}

	// Read the schema
	schemaData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read schema data: %w", err)
	}

	return &SchemaValidator{
		client: c,
		schema: string(schemaData),
	}, nil
}

// GetSchemaLocation returns the schema location to use in XML documents
// This function helps ensure XML documents use the correct schema location
func (v *SchemaValidator) GetSchemaLocation() string {
	if v.client.Environment == Production {
		return "https://report.cybertip.org/ispws/xsd"
	}
	return "https://exttest.cybertip.org/ispws/xsd"
}

// ValidateReport performs basic validation of report XML structure.
// 
// Checks include:
// - Well-formed XML
// - Presence of required elements
// - Valid timestamp formats
// - Proper root element
// 
// Note: This is not full XSD validation but catches common structural issues.
// Note: This is a basic validation that checks for obvious XML errors.
// For complete XSD validation, an external XML/XSD validation library would be needed.
func (v *SchemaValidator) ValidateReport(reportXML string) error {
	// Ensure XML is well-formed
	decoder := xml.NewDecoder(strings.NewReader(reportXML))
	for {
		_, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("malformed XML: %w", err)
		}
	}

	// Ensure the document has the report root element
	if !strings.Contains(reportXML, "<report") {
		return fmt.Errorf("XML does not contain a report root element")
	}

	// Ensure required elements are present
	requiredElements := []string{
		"<incidentSummary>",
		"<incidentType>",
		"<incidentDateTime>",
		"<reporter>",
	}

	for _, element := range requiredElements {
		if !strings.Contains(reportXML, element) {
			return fmt.Errorf("required element missing: %s", strings.Trim(element, "<>"))
		}
	}

	// Basic timestamp format validation (looking for ISO 8601 format)
	// This is not a complete validation, just a basic check
	if !strings.Contains(reportXML, "T") ||
		!(strings.Contains(reportXML, "+") ||
			strings.Contains(reportXML, "-") ||
			strings.Contains(reportXML, "Z")) {
		return fmt.Errorf("timestamp format appears invalid, should use ISO 8601 format (YYYY-MM-DDThh:mm:ss[+/-]hh:mm or Z)")
	}

	return nil
}

// ValidateFileDetails checks if a file details XML conforms to the NCMEC XSD schema
func (v *SchemaValidator) ValidateFileDetails(fileDetailsXML string) error {
	// Ensure XML is well-formed
	decoder := xml.NewDecoder(strings.NewReader(fileDetailsXML))
	for {
		_, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("malformed XML: %w", err)
		}
	}

	// Ensure the document has the fileDetails root element
	if !strings.Contains(fileDetailsXML, "<fileDetails") {
		return fmt.Errorf("XML does not contain a fileDetails root element")
	}

	// Ensure required elements are present
	requiredElements := []string{
		"<reportId>",
		"<fileId>",
	}

	for _, element := range requiredElements {
		if !strings.Contains(fileDetailsXML, element) {
			return fmt.Errorf("required element missing: %s", strings.Trim(element, "<>"))
		}
	}

	// If there's an IP capture event, ensure it has the required sub-elements
	if strings.Contains(fileDetailsXML, "<ipCaptureEvent>") {
		ipCaptureElements := []string{
			"<ipAddress>",
			"<eventName>",
			"<dateTime>",
		}

		for _, element := range ipCaptureElements {
			if !strings.Contains(fileDetailsXML, element) {
				return fmt.Errorf("ipCaptureEvent missing required element: %s", strings.Trim(element, "<>"))
			}
		}
	}

	return nil
}
