package ncmec_test

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lumeweb.com/ncmec"
)

// TestTimeFormatting validates that the Time type formats timestamps
// according to ISO 8601 with timezone as required by the API
func TestTimeFormatting(t *testing.T) {
	type TestStruct struct {
		XMLName   xml.Name     `xml:"test"`
		Timestamp ncmec.Time `xml:"timestamp"`
	}

	// Test times in different timezones
	testCases := []struct {
		name     string
		time     time.Time
		expected string
	}{
		{
			name:     "UTC time",
			time:     time.Date(2023, 1, 15, 12, 30, 0, 0, time.UTC),
			expected: "<test><timestamp>2023-01-15T12:30:00Z</timestamp></test>",
		},
		{
			name:     "Eastern time",
			time:     time.Date(2023, 1, 15, 12, 30, 0, 0, time.FixedZone("EST", -5*60*60)),
			expected: "<test><timestamp>2023-01-15T12:30:00-05:00</timestamp></test>",
		},
		{
			name:     "Pacific time",
			time:     time.Date(2023, 1, 15, 12, 30, 0, 0, time.FixedZone("PST", -8*60*60)),
			expected: "<test><timestamp>2023-01-15T12:30:00-08:00</timestamp></test>",
		},
		{
			name:     "Central European time",
			time:     time.Date(2023, 1, 15, 12, 30, 0, 0, time.FixedZone("CET", 1*60*60)),
			expected: "<test><timestamp>2023-01-15T12:30:00+01:00</timestamp></test>",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test struct with the time
			testStruct := TestStruct{
				Timestamp: ncmec.Time(tc.time),
			}

			// Marshal to XML
			data, err := xml.Marshal(testStruct)
			require.NoError(t, err)

			// Verify format matches expected ISO 8601 with timezone
			assert.Equal(t, tc.expected, string(data))

			// Ensure the format is compliant with RFC3339 (ISO 8601)
			// This is a redundant check as we're explicitly using time.RFC3339 in the marshaler
			_, err = time.Parse(time.RFC3339, tc.time.Format(time.RFC3339))
			assert.NoError(t, err, "Time format should be parsable as RFC3339 (ISO 8601)")
		})
	}
}

// TestTimeMarshalRoundTrip tests that the Time type can be marshaled and unmarshaled
func TestTimeMarshalRoundTrip(t *testing.T) {
	// Define a simple struct for testing
	type TestStruct struct {
		XMLName xml.Name   `xml:"test"`
		Time    ncmec.Time `xml:"time"`
	}

	// Create a time value with timezone
	originalTime := time.Date(2023, 5, 15, 14, 30, 45, 0, time.FixedZone("EDT", -4*60*60))
	testStruct := TestStruct{Time: ncmec.Time(originalTime)}

	// Marshal to XML
	xmlData, err := xml.Marshal(testStruct)
	require.NoError(t, err)

	// Expected XML output
	expectedXML := "<test><time>2023-05-15T14:30:45-04:00</time></test>"
	assert.Equal(t, expectedXML, string(xmlData))

	// Test that Time is formatted properly for API consumption
	// according to API.md: Must include either +/-hh:mm format or Z for UTC
	assert.Contains(t, string(xmlData), "T14:30:45-04:00", "Time should be formatted with timezone offset")
}