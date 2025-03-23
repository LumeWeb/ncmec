package ncmec

import "time"

// LawEnforcement contains information about law enforcement involvement.
// This section is optional and should only be included if law enforcement
// has already been contacted about this incident.
// Fields:
// - AgencyName: Name of investigating agency (required if section included)
// - OfficerName: Contact officer's name
// - PhoneNumber: Contact phone number with country code
// - Email: Official agency email address
// - ReportFiled: Whether official report was filed
// - ReportNumber: Agency's case reference number
// - DateTime: When law enforcement was contacted
type LawEnforcement struct {
	AgencyName   string    `xml:"agencyName,omitempty"`
	OfficerName  string    `xml:"officerName,omitempty"`
	PhoneNumber  string    `xml:"phoneNumber,omitempty"`
	Email        string    `xml:"email,omitempty"`
	ReportFiled  bool      `xml:"reportFiled,omitempty"`
	ReportNumber string    `xml:"reportNumber,omitempty"`
	DateTime     time.Time `xml:"dateTime,omitempty"`
}

// ReportedPerson contains identifying information about the person being reported.
// At least one identifying field must be provided (username, email, phone, or IP address).
// Fields:
// - Username: Online identifier used by suspect
// - Password: Known password (if obtained legally)
// - AgeRange: Estimated age range if unknown
// - IPAddress: IPv4 or IPv6 address associated with suspect
// - Email: Email address used by suspect
// - Phone: Phone number with country code
// - AdditionalURL: Profile page or other relevant URL
type ReportedPerson struct {
	Username      string `xml:"username,omitempty"`
	Password      string `xml:"password,omitempty"`
	AgeRange      string `xml:"ageRange,omitempty"`
	FirstName     string `xml:"firstName,omitempty"`
	LastName      string `xml:"lastName,omitempty"`
	IPAddress     string `xml:"ipAddress,omitempty"`
	Email         string `xml:"email,omitempty"`
	Phone         string `xml:"phone,omitempty"`
	AdditionalURL string `xml:"additionalUrl,omitempty"`
	Address       string `xml:"address,omitempty"`
	City          string `xml:"city,omitempty"`
	State         string `xml:"state,omitempty"`
	ZipCode       string `xml:"zipCode,omitempty"`
	Country       string `xml:"country,omitempty"`
}

// IntendedRecipient contains information about the intended recipient
type IntendedRecipient struct {
	Username  string `xml:"username,omitempty"`
	FirstName string `xml:"firstName,omitempty"`
	LastName  string `xml:"lastName,omitempty"`
	IPAddress string `xml:"ipAddress,omitempty"`
	Email     string `xml:"email,omitempty"`
	Phone     string `xml:"phone,omitempty"`
	Address   string `xml:"address,omitempty"`
	City      string `xml:"city,omitempty"`
	State     string `xml:"state,omitempty"`
	ZipCode   string `xml:"zipCode,omitempty"`
	Country   string `xml:"country,omitempty"`
}

// ChildVictim contains information about the child victim
type ChildVictim struct {
	FirstName   string `xml:"firstName,omitempty"`
	LastName    string `xml:"lastName,omitempty"`
	Age         int    `xml:"age,omitempty"`
	AgeEstimate string `xml:"ageEstimate,omitempty"`
	Gender      string `xml:"gender,omitempty"`
	Address     string `xml:"address,omitempty"`
	City        string `xml:"city,omitempty"`
	State       string `xml:"state,omitempty"`
	ZipCode     string `xml:"zipCode,omitempty"`
	Country     string `xml:"country,omitempty"`
}

// NewsgroupIncident contains details of illegal content found in usenet/newsgroups.
// Required fields:
// - NewsgroupName: Name of the newsgroup where content was found
// Optional fields:
// - DateTime: When the content was posted/observed
// - Message: Relevant message content or identifiers
// - SenderScreenName: Poster's identifier if available
type NewsgroupIncident struct {
	NewsgroupName    string    `xml:"newsgroupName"`
	DateTime         time.Time `xml:"dateTime,omitempty"`
	Message          string    `xml:"message,omitempty"`
	SenderScreenName string    `xml:"senderScreenName,omitempty"`
}

// ChatImIncident contains details of illegal interactions in chat/instant messaging platforms.
// Required fields:
// - Service: Name of the chat service/platform (e.g., "WhatsApp", "Telegram")
// Optional fields:
// - SenderScreenName: Perpetrator's chat identifier
// - RecipientScreenName: Victim's chat identifier
// - DateTime: When the interaction occurred
// - Message: Excerpt of concerning conversation
type ChatImIncident struct {
	Service             string    `xml:"service"`
	SenderScreenName    string    `xml:"senderScreenName,omitempty"`
	RecipientScreenName string    `xml:"recipientScreenName,omitempty"`
	DateTime            time.Time `xml:"dateTime,omitempty"`
	Message             string    `xml:"message,omitempty"`
}

// OnlineGamingIncident contains details of an online gaming incident
type OnlineGamingIncident struct {
	Service           string    `xml:"service"`
	SenderGameUser    string    `xml:"senderGameUser,omitempty"`
	RecipientGameUser string    `xml:"recipientGameUser,omitempty"`
	DateTime          time.Time `xml:"dateTime,omitempty"`
	Message           string    `xml:"message,omitempty"`
}

// CellPhoneIncident contains details of a cell phone incident
type CellPhoneIncident struct {
	SenderPhoneNumber    string    `xml:"senderPhoneNumber,omitempty"`
	RecipientPhoneNumber string    `xml:"recipientPhoneNumber,omitempty"`
	DateTime             time.Time `xml:"dateTime,omitempty"`
	Message              string    `xml:"message,omitempty"`
}

// P2PIncident contains details of a peer-to-peer incident
type P2PIncident struct {
	Network    string    `xml:"network"`
	Username   string    `xml:"username,omitempty"`
	IPAddress  string    `xml:"ipAddress,omitempty"`
	DateTime   time.Time `xml:"dateTime,omitempty"`
	SearchText string    `xml:"searchText,omitempty"`
}

// NonInternetIncident contains details of a non-internet incident
type NonInternetIncident struct {
	IncidentDescription string `xml:"incidentDescription"`
}
