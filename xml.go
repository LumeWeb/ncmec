package ncmec

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
)

const (
	xmlDeclaration = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	xsiNamespace   = "http://www.w3.org/2001/XMLSchema-instance"
	xsdLocation    = "https://report.cybertip.org/ispws/xsd"
)

// XMLMarshaler defines the interface for NCMEC-specific XML serialization.
// Implemented by core types to ensure proper namespace declarations and
// schema location attributes are included in generated XML.
type XMLMarshaler interface {
	MarshalToXML() ([]byte, error)
}

// WithXMLNamespaces adds common XML namespaces to a report
func WithXMLNamespaces(report *Report) *Report {
	report.XMLNS = xsiNamespace
	report.SchemaLocation = xsdLocation
	return report
}

// MarshalWithHeader converts a Go struct to properly formatted XML with:
// - XML declaration
// - 4-space indentation
// - Proper namespace declarations
// Primarily used for generating NCMEC-compliant XML documents.
func MarshalWithHeader(v interface{}) ([]byte, error) {
	data, err := xml.MarshalIndent(v, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal to XML: %w", err)
	}

	// Add XML declaration
	result := append([]byte(xmlDeclaration), data...)
	return result, nil
}

// NewXMLReader converts an XML-marshallable object to an io.Reader.
// Handles proper XML formatting and declaration for NCMEC API compliance.
func NewXMLReader(v interface{}) (io.Reader, error) {
	data, err := MarshalWithHeader(v)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(data), nil
}

// NewFileDetailsXML creates a FileDetailsXML struct with proper XML namespaces
func NewFileDetailsXML(reportID, fileID string, details *FileDetails) *FileDetailsXML {
	fileDetailsXML := &FileDetailsXML{
		XMLNS:          xsiNamespace,
		SchemaLocation: xsdLocation,
		ReportID:       reportID,
		FileID:         fileID,
	}

	// Add details if provided
	if details != nil {
		fileDetailsXML.OriginalFileName = details.OriginalFileName
		fileDetailsXML.IPCapture = details.IPCapture
		fileDetailsXML.AdditionalInfo = details.AdditionalInfo
	}

	return fileDetailsXML
}

// MarshalToXML implements the XMLMarshaler interface for FileDetailsXML
func (f *FileDetailsXML) MarshalToXML() ([]byte, error) {
	return MarshalWithHeader(f)
}

// MarshalToXML implements the XMLMarshaler interface for Report
func (r *Report) MarshalToXML() ([]byte, error) {
	return MarshalWithHeader(r)
}
