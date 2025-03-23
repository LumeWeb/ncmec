package ncmec

import (
	"time"
)

// ReportExpirationStatus represents the status of a report with respect to its expiration
type ReportExpirationStatus int

const (
	// ReportStatusOk indicates the report is not in danger of expiring
	ReportStatusOk ReportExpirationStatus = iota

	// ReportStatusWarning indicates the report is approaching expiration
	ReportStatusWarning

	// ReportStatusCritical indicates the report is about to expire
	ReportStatusCritical

	// ReportStatusExpired indicates the report has likely expired already
	ReportStatusExpired
)

// Default thresholds for report expiration warnings
const (
	// Reports expire 24 hours after opening if not finished
	reportExpirationTime = 24 * time.Hour

	// Or 1 hour after last modification
	reportModificationExpirationTime = 1 * time.Hour

	// Warning threshold (75% of the way to expiration)
	warningThreshold = 0.75

	// Critical threshold (90% of the way to expiration)
	criticalThreshold = 0.90
)

// ReportStatus contains information about a report's expiration status
type ReportStatus struct {
	// Status indicates how close to expiration the report is
	Status ReportExpirationStatus

	// TimeToExpiration is the estimated time until the report expires
	TimeToExpiration time.Duration

	// Message provides a human-readable explanation of the status
	Message string
}

// CheckReportExpiration calculates the expiration status of an in-progress report.
// 
// NCMEC requires reports to be completed within specific time windows:
// - 24 hours from creation
// - 1 hour from last modification
// 
// Returns a ReportStatus indicating current expiration state and time remaining.
// creationTime is when the report was created
// lastModifiedTime is when the report was last modified (file upload, etc.)
func CheckReportExpiration(creationTime, lastModifiedTime time.Time) ReportStatus {
	now := time.Now()

	// Calculate expiration based on creation time (24 hours after creation)
	creationExpiration := creationTime.Add(reportExpirationTime)

	// Calculate expiration based on last modification (1 hour after last modification)
	modificationExpiration := lastModifiedTime.Add(reportModificationExpirationTime)

	// The later of the two times is the actual expiration time
	expirationTime := creationExpiration
	if modificationExpiration.After(expirationTime) {
		expirationTime = modificationExpiration
	}

	// If the report has already expired
	if now.After(expirationTime) || now.After(creationTime.Add(reportExpirationTime)) || now.After(lastModifiedTime.Add(reportModificationExpirationTime)) {
		return ReportStatus{
			Status:           ReportStatusExpired,
			TimeToExpiration: 0,
			Message:          "Report has expired",
		}
	}

	// Calculate time remaining until expiration
	remainingTime := expirationTime.Sub(now)

	// Determine which rule is active for percentage calculation
	var elapsedPercent float64
	if modificationExpiration.After(creationExpiration) {
		// Modification rule is active
		timeElapsed := time.Since(lastModifiedTime)
		elapsedPercent = float64(timeElapsed) / float64(reportModificationExpirationTime)
	} else {
		// Creation rule is active
		timeElapsed := time.Since(creationTime)
		elapsedPercent = float64(timeElapsed) / float64(reportExpirationTime)
	}

	// Determine status based on elapsed percentage
	if elapsedPercent >= criticalThreshold {
		return ReportStatus{
			Status:           ReportStatusCritical,
			TimeToExpiration: remainingTime,
			Message:          "Report is about to expire - submit immediately",
		}
	} else if elapsedPercent >= warningThreshold {
		return ReportStatus{
			Status:           ReportStatusWarning,
			TimeToExpiration: remainingTime,
			Message:          "Report is approaching expiration",
		}
	}

	// Report is not in danger of expiring
	return ReportStatus{
		Status:           ReportStatusOk,
		TimeToExpiration: remainingTime,
		Message:          "Report is not in danger of expiring",
	}
}

// IsReportExpired is a convenience function that returns true if the report
// has expired or is about to expire (in critical status)
func IsReportExpired(creationTime, lastModifiedTime time.Time) bool {
	status := CheckReportExpiration(creationTime, lastModifiedTime)
	return status.Status == ReportStatusExpired || status.Status == ReportStatusCritical
}

// AddExpirationChecking enables time tracking for report expiration deadlines.
// Once enabled, the builder will automatically track creation and modification times
// and check expiration status before submissions.
func (rb *ReportBuilder) AddExpirationChecking() *ReportBuilder {
	rb.checkExpiration = true
	rb.creationTime = time.Now()
	rb.lastModifiedTime = time.Now()
	return rb
}

// CheckExpiration checks if the report is in danger of expiring
// This should be called before attempting to submit a report that was created some time ago
func (rb *ReportBuilder) CheckExpiration() ReportStatus {
	// If expiration checking wasn't enabled, assume report was just created
	if !rb.checkExpiration {
		rb.creationTime = time.Now()
		rb.lastModifiedTime = time.Now()
		rb.checkExpiration = true
	}

	return CheckReportExpiration(rb.creationTime, rb.lastModifiedTime)
}

// UpdateLastModified updates the last modified time of the report
// This is called internally by the client after operations that modify the report
func (rb *ReportBuilder) UpdateLastModified() {
	if rb.checkExpiration {
		rb.lastModifiedTime = time.Now()
	}
}
