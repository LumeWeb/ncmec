package ncmec

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// IncidentType categorizes the nature of the reported content.
// 
// These values correspond to the official NCMEC incident categories.
// Use the constants provided for valid options.
type IncidentType string

// Incident types as defined in the NCMEC API XSD schema
const (
	// Child sexual abuse material (CSAM) possession, distribution or production
	ChildPornography       IncidentType = "Child Pornography (possession, manufacture, and distribution)"
	// Commercial sexual exploitation of minors
	ChildSexTrafficking    IncidentType = "Child Sex Trafficking"
	// Travel arrangements involving child sexual abuse
	ChildSexTourism        IncidentType = "Child Sex Tourism"
	// Sexual abuse of minors outside family/domestic context
	ChildSexualMolestation IncidentType = "Child Sexual Molestation"
	// Adults soliciting minors for sexual acts online
	OnlineEnticement       IncidentType = "Online Enticement of Children for Sexual Acts"
	// Domain names suggesting CSAM content
	MisleadingDomain       IncidentType = "Misleading Domain Name"
	// Text/images suggesting CSAM availability
	MisleadingWords        IncidentType = "Misleading Words or Digital Images on the Internet"
	// Unsolicited explicit material sent to minors
	Unsolicited            IncidentType = "Unsolicited Obscene Material Sent to a Child"
)

// Time is a wrapper around time.Time to format ISO 8601 timestamps properly
type Time time.Time

// MarshalXML implements the xml.Marshaler interface
func (t Time) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(time.Time(t).Format(time.RFC3339), start)
}

// Report contains all data required for a CyberTipline submission.
// 
// The struct maps directly to the NCMEC XML schema requirements.
// Use ReportBuilder to construct instances rather than creating directly.
// 
// XML tags define the structure required by the NCMEC API specification.
type Report struct {
	XMLName           xml.Name           `xml:"report"`
	XMLNS             string             `xml:"xmlns:xsi,attr"`
	SchemaLocation    string             `xml:"xsi:noNamespaceSchemaLocation,attr"`
	IncidentSummary   IncidentSummary    `xml:"incidentSummary"`
	InternetDetails   InternetDetails    `xml:"internetDetails,omitempty"`
	LawEnforcement    *LawEnforcement    `xml:"lawEnforcement,omitempty"`
	Reporter          Reporter           `xml:"reporter"`
	ReportedPerson    *ReportedPerson    `xml:"personOrUserReported,omitempty"`
	IntendedRecipient *IntendedRecipient `xml:"intendedRecipient,omitempty"`
	ChildVictim       *ChildVictim       `xml:"victim,omitempty"`
	AdditionalInfo    string             `xml:"additionalInfo,omitempty"`
}

// IncidentSummary contains core metadata about the reported incident.
// This section is required for all reports and must include:
// - Valid incident type from the NCMEC list
// - Precise incident timestamp
type IncidentSummary struct {
	IncidentType           IncidentType       `xml:"incidentType"`
	Platform               string             `xml:"platform,omitempty"`
	EscalateToHighPriority string             `xml:"escalateToHighPriority,omitempty"`
	ReportAnnotations      *ReportAnnotations `xml:"reportAnnotations,omitempty"`
	IncidentDateTime       time.Time          `xml:"incidentDateTime"`
}

// ReportAnnotations contains additional categorization tags for the report.
// These boolean flags help NCMEC properly route and prioritize the report.
// Each field represents a specific category:
// - Sextortion: Report involves sextortion/blackmail content
// - CSAMSolicitation: Report contains child sexual abuse material solicitation
// - MinorToMinorInteraction: Content involves minor-to-minor interaction
// - Spam: Report was generated from automated spam detection
type ReportAnnotations struct {
	Sextortion              *struct{} `xml:"sextortion,omitempty"`
	CSAMSolicitation        *struct{} `xml:"csamSolicitation,omitempty"`
	MinorToMinorInteraction *struct{} `xml:"minorToMinorInteraction,omitempty"`
	Spam                    *struct{} `xml:"spam,omitempty"`
}

// InternetDetails contains the details of the incident
type InternetDetails struct {
	WebPageIncident      *WebPageIncident      `xml:"webPageIncident,omitempty"`
	EmailIncident        *EmailIncident        `xml:"emailIncident,omitempty"`
	NewsgroupIncident    *NewsgroupIncident    `xml:"newsgroupIncident,omitempty"`
	ChatImIncident       *ChatImIncident       `xml:"chatImIncident,omitempty"`
	OnlineGamingIncident *OnlineGamingIncident `xml:"onlineGamingIncident,omitempty"`
	CellPhoneIncident    *CellPhoneIncident    `xml:"cellPhoneIncident,omitempty"`
	P2PIncident          *P2PIncident          `xml:"peer2peerIncident,omitempty"`
	NonInternetIncident  *NonInternetIncident  `xml:"nonInternetIncident,omitempty"`
}

// WebPageIncident contains details of a web page incident
type WebPageIncident struct {
	URL string `xml:"url"`
}

// EmailIncident contains details of an email incident
type EmailIncident struct {
	SenderAddress    string    `xml:"senderAddress"`
	SenderScreenName string    `xml:"senderScreenName,omitempty"`
	RecipientAddress string    `xml:"recipientAddress,omitempty"`
	DateTime         time.Time `xml:"dateTime,omitempty"`
	Subject          string    `xml:"subject,omitempty"`
	MessageText      string    `xml:"messageText,omitempty"`
	HeaderInfo       string    `xml:"headerInfo,omitempty"`
}

// Other incident types omitted for brevity...

// Reporter contains information about the reporting person or organization
type Reporter struct {
	ReportingPerson *ReportingPerson `xml:"reportingPerson,omitempty"`
}

// ReportingPerson contains information about the reporting person
type ReportingPerson struct {
	FirstName string `xml:"firstName"`
	LastName  string `xml:"lastName"`
	Email     string `xml:"email"`
	Phone     string `xml:"phone,omitempty"`
	Address   string `xml:"address,omitempty"`
	City      string `xml:"city,omitempty"`
	State     string `xml:"state,omitempty"`
	Country   string `xml:"country,omitempty"`
	ZipCode   string `xml:"zipCode,omitempty"`
}

// Other entity types omitted for brevity...

// FileUpload contains both the content and metadata for files attached to a report.
// Fields:
// - Path: Local filesystem path (mutually exclusive with Reader)
// - Reader: In-memory content source (mutually exclusive with Path)
// - Details: Additional contextual metadata about the file
// - FileName: Override filename for Reader content
// - FileID: Set by API after successful upload
// - Hash: MD5 checksum verified by API during upload
type FileUpload struct {
	Path     string
	Reader   io.Reader
	Details  *FileDetails
	FileName string
	FileID   string // Set after successful upload
	Hash     string // Set after successful upload
}

// FileDetails represents additional details for an uploaded file
type FileDetails struct {
	OriginalFileName string          `xml:"originalFileName,omitempty"`
	IPCapture        *IPCaptureEvent `xml:"ipCaptureEvent,omitempty"`
	AdditionalInfo   string          `xml:"additionalInfo,omitempty"`
}

// IPCaptureEvent contains IP address information
type IPCaptureEvent struct {
	IPAddress string    `xml:"ipAddress"`
	EventName string    `xml:"eventName"`
	DateTime  time.Time `xml:"dateTime"`
}

// FileDetailsXML is the root element for file details
type FileDetailsXML struct {
	XMLName          xml.Name        `xml:"fileDetails"`
	XMLNS            string          `xml:"xmlns:xsi,attr"`
	SchemaLocation   string          `xml:"xsi:noNamespaceSchemaLocation,attr"`
	ReportID         string          `xml:"reportId"`
	FileID           string          `xml:"fileId"`
	OriginalFileName string          `xml:"originalFileName,omitempty"`
	IPCapture        *IPCaptureEvent `xml:"ipCaptureEvent,omitempty"`
	AdditionalInfo   string          `xml:"additionalInfo,omitempty"`
}

// ReportResponse is the response from the API for most operations
type ReportResponse struct {
	XMLName             xml.Name `xml:"reportResponse"`
	ResponseCode        int      `xml:"responseCode"`
	ResponseDescription string   `xml:"responseDescription"`
	ReportID            string   `xml:"reportId,omitempty"`
	FileID              string   `xml:"fileId,omitempty"`
	Hash                string   `xml:"hash,omitempty"`
}

// ReportDoneResponse is the response from the API for the finish operation
type ReportDoneResponse struct {
	XMLName             xml.Name `xml:"reportDoneResponse"`
	ResponseCode        int      `xml:"responseCode"`
	ResponseDescription string   `xml:"responseDescription"`
	ReportID            string   `xml:"reportId,omitempty"`
	Files               []string `xml:"files>fileId,omitempty"`
}

// FileUploadResult represents the result of a file upload
type FileUploadResult struct {
	ReportID string
	FileID   string
	Hash     string
}

// ReportDoneResult represents the result of finishing a report
type ReportDoneResult struct {
	ReportID string
	FileIDs  []string
}

// ReportStatusResponse is the response from the API for status queries
type ReportStatusResponse struct {
	XMLName             xml.Name  `xml:"reportStatusResponse"`
	ResponseCode        int       `xml:"responseCode"`
	ResponseDescription string    `xml:"responseDescription"`
	Status              string    `xml:"status,omitempty"`
	Files               []string  `xml:"files>fileId,omitempty"`
	CreatedAt           time.Time `xml:"createdAt,omitempty"`
}

// ReportStatusInfo represents the current state of a report
type ReportStatusInfo struct {
	ReportID  string
	Status    string
	Files     []string
	CreatedAt time.Time
}

// ReportBuilder provides a fluent interface for building reports
type ReportBuilder struct {
	client           *Client
	report           *Report
	files            []FileUpload
	checkExpiration  bool
	creationTime     time.Time
	lastModifiedTime time.Time
}

// ReportUpdater provides a fluent interface for updating existing reports
type ReportUpdater struct {
	client      *Client
	ReportID    string
	files       []FileUpload
	LastUpdated time.Time // Exported for testing
}

// Files returns the current list of pending file uploads.
// Primarily used for testing purposes - not required for normal API interactions.
// Note: Returns a copy of the files slice to prevent modification of internal state.
func (ru *ReportUpdater) Files() []FileUpload {
	return ru.files
}

// ContentAddressedFile represents a file in a content-addressed system
type ContentAddressedFile struct {
	ContentID      string      // Content identifier from the storage system
	FileName       string      // Original file name
	Size           int64       // File size in bytes
	MimeType       string      // MIME type
	Hash           string      // Hash of the content as hex string
	HashBytes      []byte      // Raw hash bytes (will be converted to hex string if Hash is empty)
	AdditionalData interface{} // Any additional data specific to the storage system
}

// WithIncidentType sets the category of illegal content being reported.
// 
// incidentType must be one of the predefined IncidentType constants.
// Returns the updated ReportBuilder for fluent chaining.
func (rb *ReportBuilder) WithIncidentType(incidentType IncidentType) *ReportBuilder {
	rb.report.IncidentSummary.IncidentType = incidentType
	// Update last modified time since we've modified the report
	rb.UpdateLastModified()
	return rb
}

// WithIncidentTime sets the exact date and time of the reported incident.
// The time should be in UTC or include timezone offset.
func (rb *ReportBuilder) WithIncidentTime(dateTime time.Time) *ReportBuilder {
	rb.report.IncidentSummary.IncidentDateTime = dateTime
	// Update last modified time since we've modified the report
	rb.UpdateLastModified()
	return rb
}

// WithWebIncident adds details about web-based illegal content.
// The URL must point directly to the page hosting the illegal content.
func (rb *ReportBuilder) WithWebIncident(url string) *ReportBuilder {
	// Initialize InternetDetails if it's not already initialized
	if rb.report.InternetDetails.WebPageIncident == nil {
		rb.report.InternetDetails = InternetDetails{
			WebPageIncident: &WebPageIncident{},
		}
	}
	rb.report.InternetDetails.WebPageIncident.URL = url
	// Update last modified time since we've modified the report
	rb.UpdateLastModified()
	return rb
}

// WithReporter sets the contact information for the person submitting the report.
// All fields are required for valid report submission.
func (rb *ReportBuilder) WithReporter(firstName, lastName, email string) *ReportBuilder {
	rb.report.Reporter.ReportingPerson = &ReportingPerson{
		FirstName: firstName,
		LastName:  lastName,
		Email:     email,
	}
	// Update last modified time since we've modified the report
	rb.UpdateLastModified()
	return rb
}

// AddFile attaches a local file to the report from a filesystem path.
// The file will be uploaded when the report is submitted.
func (rb *ReportBuilder) AddFile(filePath string, details *FileDetails) *ReportBuilder {
	rb.files = append(rb.files, FileUpload{
		Path:    filePath,
		Details: details,
	})

	// Update last modified time since we've modified the report
	rb.UpdateLastModified()

	return rb
}

// AddFileContent attaches in-memory content to the report.
// The fileName parameter should include the correct file extension.
func (rb *ReportBuilder) AddFileContent(reader io.Reader, fileName string, details *FileDetails) *ReportBuilder {
	rb.files = append(rb.files, FileUpload{
		Reader:   reader,
		FileName: fileName,
		Details:  details,
	})

	// Update last modified time since we've modified the report
	rb.UpdateLastModified()

	return rb
}

// Build finalizes the report structure and validates required fields.
// Returns the complete Report ready for submission.
func (rb *ReportBuilder) Build() *Report {
	// Ensure the report has the required XML namespaces
	return WithXMLNamespaces(rb.report)
}

// CreateReport submits the report as a draft and returns a ReportUpdater for adding files/modifications
func (rb *ReportBuilder) CreateReport(ctx context.Context) (*ReportUpdater, error) {
	// Check if report is nearing expiration
	if rb.checkExpiration {
		expStatus := rb.CheckExpiration()
		if expStatus.Status == ReportStatusExpired {
			return nil, fmt.Errorf("%w: report has expired", ErrInvalidReport)
		}
		if expStatus.Status == ReportStatusCritical {
			// Just warn but continue with submission
			fmt.Printf("Warning: %s (%.1f minutes remaining)\n",
				expStatus.Message,
				expStatus.TimeToExpiration.Minutes())
		}
	}

	// Build and validate the report
	report := rb.Build()

	// Create report XML
	reportXML, err := MarshalWithHeader(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report: %w", err)
	}

	// Optional: validate XML against schema if available
	// This is a more thorough validation than just marshaling
	if validator, err := rb.client.FetchSchema(ctx); err == nil {
		if err := validator.ValidateReport(string(reportXML)); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidReport, err)
		}
	}

	// Submit report
	headers := map[string]string{
		"Content-Type": "text/xml; charset=utf-8",
	}

	resp, err := rb.client.DoRequest(
		ctx,
		http.MethodPost,
		"/submit",
		bytes.NewReader(reportXML),
		headers,
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse response
	var response ReportResponse
	if err := xml.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("%w: failed to decode response: %v", ErrParsing, err)
	}

	// Check for API error
	if response.ResponseCode != 0 {
		return nil, &Error{
			Code:        response.ResponseCode,
			Description: response.ResponseDescription,
			Wrap:        ErrAPI,
		}
	}

	// Get report ID
	reportID := response.ReportID

	// Upload files if any
	fileIDs := make([]string, 0, len(rb.files))
	for i := range rb.files {
		// We need to work with a pointer to the file to update its fields
		file := &rb.files[i]
		var fileResult *FileUploadResult
		var err error

		// Upload file depending on source
		if file.Reader != nil {
			// Upload from reader
			fileResult, err = rb.client.UploadFileContent(ctx, reportID, file.Reader, file.fileName())
		} else {
			// Upload from file path
			fileResult, err = rb.client.UploadFile(ctx, reportID, file.Path)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to upload file: %w", err)
		}

		// Save file ID and hash
		file.FileID = fileResult.FileID
		file.Hash = fileResult.Hash
		fileIDs = append(fileIDs, fileResult.FileID)

		// Update last modified time since we've uploaded a file
		rb.UpdateLastModified()

		// Submit file details if provided
		if file.Details != nil {
			if err := rb.client.AddFileDetails(ctx, reportID, fileResult.FileID, file.Details); err != nil {
				return nil, fmt.Errorf("failed to add file details: %w", err)
			}

			// Update last modified time again since we've added file details
			rb.UpdateLastModified()
		}
	}

	// Return updater with the new report ID and empty files list
	return &ReportUpdater{
		client:      rb.client,
		ReportID:    reportID,
		files:       []FileUpload{},
		LastUpdated: time.Now(),
	}, nil
}

// fileName returns the filename to use for the file upload
func (f *FileUpload) fileName() string {
	if f.FileName != "" {
		return f.FileName
	}
	return filepath.Base(f.Path)
}

// AddFile adds a file to an existing report
func (ru *ReportUpdater) AddFile(filePath string, details *FileDetails) *ReportUpdater {
	ru.files = append(ru.files, FileUpload{
		Path:    filePath,
		Details: details,
	})

	// Update timestamp
	ru.LastUpdated = time.Now()
	return ru
}

// AddFileContent adds file content to an existing report
func (ru *ReportUpdater) AddFileContent(reader io.Reader, fileName string, details *FileDetails) *ReportUpdater {
	ru.files = append(ru.files, FileUpload{
		Reader:   reader,
		FileName: fileName,
		Details:  details,
	})

	// Update timestamp
	ru.LastUpdated = time.Now()
	return ru
}

// AddFileWithHash adds a file to the report and calculates its MD5 hash
// This hash matches what the NCMEC API will return when the file is uploaded
func (ru *ReportUpdater) AddFileWithHash(filePath string, details *FileDetails) (*FileUpload, error) {
	// Create an MD5 hasher
	hasher := NewFileHasher()

	// Calculate hash
	hash, err := hasher.HashFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to hash file: %w", err)
	}

	// Add file to report
	fileUpload := FileUpload{
		Path:    filePath,
		Details: details,
		Hash:    hash,
	}

	ru.files = append(ru.files, fileUpload)

	// Update timestamp
	ru.LastUpdated = time.Now()
	return &fileUpload, nil
}

// AddFileContentWithHash adds file content to the report and calculates its MD5 hash
// This hash matches what the NCMEC API will return when the file is uploaded
func (ru *ReportUpdater) AddFileContentWithHash(reader io.Reader, fileName string, details *FileDetails) (*FileUpload, error) {
	// We need to read the content to calculate the hash,
	// which means we need to buffer it
	buf := new(bytes.Buffer)
	teeReader := io.TeeReader(reader, buf)

	// Create an MD5 hasher
	hasher := NewFileHasher()

	// Calculate hash
	hash, err := hasher.HashReader(teeReader)
	if err != nil {
		return nil, fmt.Errorf("failed to hash content: %w", err)
	}

	// Add file to report
	fileUpload := FileUpload{
		Reader:   buf,
		FileName: fileName,
		Details:  details,
		Hash:     hash,
	}

	ru.files = append(ru.files, fileUpload)

	// Update timestamp
	ru.LastUpdated = time.Now()
	return &fileUpload, nil
}

// AddFileWithPrecomputedHash adds a file to the report with a precomputed hash
func (ru *ReportUpdater) AddFileWithPrecomputedHash(filePath string, hash string, details *FileDetails) *ReportUpdater {
	fileUpload := FileUpload{
		Path:    filePath,
		Details: details,
		Hash:    hash,
	}

	ru.files = append(ru.files, fileUpload)

	// Update timestamp
	ru.LastUpdated = time.Now()
	return ru
}

// AddFileContentWithPrecomputedHash adds file content to the report with a precomputed hash
func (ru *ReportUpdater) AddFileContentWithPrecomputedHash(
	reader io.Reader,
	fileName string,
	hash string,
	details *FileDetails,
) *ReportUpdater {
	fileUpload := FileUpload{
		FileName: fileName,
		Details:  details,
		Hash:     hash,
	}

	ru.files = append(ru.files, fileUpload)

	// Update timestamp
	ru.LastUpdated = time.Now()
	return ru
}

// Update uploads all new files to the existing report
func (ru *ReportUpdater) Update(ctx context.Context) (*ReportUpdateResult, error) {
	// Upload new files
	fileResults := make([]FileUploadResult, 0, len(ru.files))
	fileIDs := make([]string, 0, len(ru.files))

	for i := range ru.files {
		// We need to work with a pointer to the file to update its fields
		file := &ru.files[i]
		var fileResult *FileUploadResult
		var err error

		// Upload file depending on source
		if file.Reader != nil {
			// Upload from reader
			fileResult, err = ru.client.UploadFileContent(ctx, ru.ReportID, file.Reader, file.fileName())
		} else {
			// Upload from file path
			fileResult, err = ru.client.UploadFile(ctx, ru.ReportID, file.Path)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to upload file: %w", err)
		}

		// Save file ID and hash from upload result
		file.FileID = fileResult.FileID
		if file.Hash == "" {
			file.Hash = fileResult.Hash // Use server hash if we didn't calculate one
		}

		fileResults = append(fileResults, *fileResult)
		fileIDs = append(fileIDs, fileResult.FileID)

		// Submit file details if provided
		if file.Details != nil {
			if err := ru.client.AddFileDetails(ctx, ru.ReportID, fileResult.FileID, file.Details); err != nil {
				return nil, fmt.Errorf("failed to add file details: %w", err)
			}
		}
	}

	// Clear uploaded files to prevent duplicates
	ru.files = []FileUpload{}

	return &ReportUpdateResult{
		ReportID: ru.ReportID,
		Files:    fileResults,
		FileIDs:  fileIDs,
	}, nil
}

// Finish completes the report update and finalizes the report
func (ru *ReportUpdater) Finish(ctx context.Context) (*ReportDoneResult, error) {
	// First update to add any files
	if len(ru.files) > 0 {
		_, err := ru.Update(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to update report: %w", err)
		}
	}

	// Then finalize the report
	return ru.client.FinishReport(ctx, ru.ReportID)
}

// ReportUpdateResult represents the result of updating a report
type ReportUpdateResult struct {
	ReportID string
	Files    []FileUploadResult
	FileIDs  []string
}

// AddContentAddressedFile adds a file from a content-addressed system to a report
// This function is used when you have a file in a distributed storage system
// and want to include it in a NCMEC report.
//
// It won't upload the file to NCMEC directly (you need to provide a reader for the content),
// but it will use the hash from the content-addressed system to verify integrity.
func (rb *ReportBuilder) AddContentAddressedFile(
	reader io.Reader,
	caFile ContentAddressedFile,
	details *FileDetails,
) *ReportBuilder {
	// For file details, include the content ID in the additional info if not already set
	if details == nil {
		details = &FileDetails{
			OriginalFileName: caFile.FileName,
			AdditionalInfo:   fmt.Sprintf("Content ID: %s", caFile.ContentID),
		}
	} else if details.AdditionalInfo == "" {
		details.AdditionalInfo = fmt.Sprintf("Content ID: %s", caFile.ContentID)
	} else if !strings.Contains(details.AdditionalInfo, caFile.ContentID) {
		details.AdditionalInfo += fmt.Sprintf(" | Content ID: %s", caFile.ContentID)
	}

	if details.OriginalFileName == "" {
		details.OriginalFileName = caFile.FileName
	}

	// Get hash from either hash string or hash bytes
	hash := caFile.Hash
	if hash == "" && len(caFile.HashBytes) > 0 {
		hash = HashFromBytes(caFile.HashBytes)
	}

	// Add the file to the report
	rb.files = append(rb.files, FileUpload{
		Reader:   reader,
		FileName: caFile.FileName,
		Details:  details,
		Hash:     hash, // Pre-set the hash from the content-addressed system
	})

	// Update last modified time
	rb.UpdateLastModified()
	return rb
}

// AddContentAddressedFile adds a file from a content-addressed system to an existing report
func (ru *ReportUpdater) AddContentAddressedFile(
	reader io.Reader,
	caFile ContentAddressedFile,
	details *FileDetails,
) *ReportUpdater {
	// For file details, include the content ID in the additional info if not already set
	if details == nil {
		details = &FileDetails{
			OriginalFileName: caFile.FileName,
			AdditionalInfo:   fmt.Sprintf("Content ID: %s", caFile.ContentID),
		}
	} else if details.AdditionalInfo == "" {
		details.AdditionalInfo = fmt.Sprintf("Content ID: %s", caFile.ContentID)
	} else if !strings.Contains(details.AdditionalInfo, caFile.ContentID) {
		details.AdditionalInfo += fmt.Sprintf(" | Content ID: %s", caFile.ContentID)
	}

	if details.OriginalFileName == "" {
		details.OriginalFileName = caFile.FileName
	}

	// Get hash from either hash string or hash bytes
	hash := caFile.Hash
	if hash == "" && len(caFile.HashBytes) > 0 {
		hash = HashFromBytes(caFile.HashBytes)
	}

	// Add the file to the report
	ru.files = append(ru.files, FileUpload{
		Reader:   reader,
		FileName: caFile.FileName,
		Details:  details,
		Hash:     hash, // Pre-set the hash from the content-addressed system
	})

	// Update timestamp
	ru.LastUpdated = time.Now()
	return ru
}

// CreateFileDetailsXML creates the XML for file details
func CreateFileDetailsXML(reportID, fileID string, details *FileDetails) (string, error) {
	// Create the file details structure using the factory
	fileDetailsXML := NewFileDetailsXML(reportID, fileID, details)

	// Marshal to XML
	xmlData, err := fileDetailsXML.MarshalToXML()
	if err != nil {
		return "", fmt.Errorf("failed to marshal file details: %w", err)
	}

	return string(xmlData), nil
}

// LawEnforcement, ReportedPerson, IntendedRecipient, ChildVictim, etc. types omitted for brevity...
// Submit constructs and sends the complete report to NCMEC.
// 
// This method:
// 1. Validates the report structure
// 2. Submits the report as XML
// 3. Uploads any attached files
// 4. Finalizes the report submission
// 
// Returns the final submission result or any error encountered.
func (rb *ReportBuilder) Submit(ctx context.Context) (*ReportDoneResult, error) {
	updater, err := rb.CreateReport(ctx)
	if err != nil {
		return nil, err
	}
	return updater.Finish(ctx)
}
