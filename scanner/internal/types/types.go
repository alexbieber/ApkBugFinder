package types

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Confidence string

const (
	ConfidenceConfirmed     Confidence = "confirmed"
	ConfidenceHigh          Confidence = "high"
	ConfidenceMedium        Confidence = "medium"
	ConfidenceLow           Confidence = "low"
	ConfidenceInformational Confidence = "informational"
)

type FindingScope string

const (
	ScopeManifest FindingScope = "manifest"
	ScopeAppCode  FindingScope = "app-code"
	ScopeResource FindingScope = "resource"
	ScopeLibrary  FindingScope = "library"
	ScopeHygiene  FindingScope = "hygiene"
)

type Finding struct {
	ID             string       `json:"id"`
	Title          string       `json:"title"`
	Description    string       `json:"description"`
	Severity       Severity     `json:"severity"`
	Confidence     Confidence   `json:"confidence,omitempty"`
	Scope          FindingScope `json:"scope,omitempty"`
	Impact         int          `json:"impact,omitempty"`
	BountyEligible bool         `json:"bountyEligible,omitempty"`
	AttackSurface  string       `json:"attackSurface,omitempty"`
	ExploitHint    string       `json:"exploitHint,omitempty"`
	MASVS          string       `json:"masvs"`
	CWE            string       `json:"cwe,omitempty"`
	Category       string       `json:"category"`
	Evidence       string       `json:"evidence,omitempty"`
	File           string       `json:"file,omitempty"`
	Remediation    string       `json:"remediation"`
	Reference      string       `json:"reference,omitempty"`
}

type ComponentSummary struct {
	ExportedActivities int `json:"exportedActivities"`
	ExportedProviders  int `json:"exportedProviders"`
	ExportedReceivers  int `json:"exportedReceivers"`
	ExportedServices   int `json:"exportedServices"`
}

type AppInfo struct {
	PackageName          string           `json:"packageName,omitempty"`
	VersionName          string           `json:"versionName,omitempty"`
	VersionCode          string           `json:"versionCode,omitempty"`
	MinSDK               string           `json:"minSdk,omitempty"`
	TargetSDK            string           `json:"targetSdk,omitempty"`
	Permissions          []string         `json:"permissions"`
	Activities           []string         `json:"activities"`
	Services             []string         `json:"services"`
	Receivers            []string         `json:"receivers"`
	Providers            []string         `json:"providers"`
	Debuggable           *bool            `json:"debuggable,omitempty"`
	AllowBackup          *bool            `json:"allowBackup,omitempty"`
	UsesCleartextTraffic *bool            `json:"usesCleartextTraffic,omitempty"`
	FileName             string           `json:"fileName"`
	FileSize             int64            `json:"fileSize"`
	MD5                  string           `json:"md5,omitempty"`
	SHA256               string           `json:"sha256,omitempty"`
	ComponentSummary     ComponentSummary `json:"componentSummary"`
}

type ScanStats struct {
	Critical       int `json:"critical"`
	High           int `json:"high"`
	Medium         int `json:"medium"`
	Low            int `json:"low"`
	Info           int `json:"info"`
	Total          int `json:"total"`
	Actionable     int `json:"actionable"`
	Confirmed      int `json:"confirmed"`
	BountyEligible int `json:"bountyEligible"`
	BountyCritical int `json:"bountyCritical"`
	LiveSecrets    int `json:"liveSecrets"`
}

type ScanResult struct {
	ID         string       `json:"id"`
	ScannedAt  string       `json:"scannedAt"`
	DurationMs int64        `json:"durationMs"`
	Engine     string       `json:"engine"`
	AppInfo    AppInfo      `json:"appInfo"`
	Findings   []Finding    `json:"findings"`
	Stats      ScanStats    `json:"stats"`
	Recon      *ReconResult `json:"recon,omitempty"`
}

// ReconResult is the backend attack-surface dossier extracted from the APK.
type ReconResult struct {
	Endpoints     []Endpoint `json:"endpoints"`
	Hosts         []string   `json:"hosts"`
	S3Buckets     []string   `json:"s3Buckets"`
	FirebaseDBs   []string   `json:"firebaseDbs"`
	GraphQL       []string   `json:"graphql"`
	Secrets       []Secret   `json:"secrets"`
	AuthSchemes   []string   `json:"authSchemes"`
	SecretsTested bool       `json:"secretsTested"`
}

// Endpoint is an API path/URL discovered in the app.
type Endpoint struct {
	URL    string `json:"url"`
	Host   string `json:"host"`
	Scheme string `json:"scheme"`
	File   string `json:"file,omitempty"`
}

// VerifyStatus is the result of an opt-in, read-only liveness check.
type VerifyStatus string

const (
	VerifyUnknown   VerifyStatus = ""
	VerifyLive      VerifyStatus = "live"
	VerifyInvalid   VerifyStatus = "invalid"
	VerifyError     VerifyStatus = "error"
	VerifySkipped   VerifyStatus = "skipped"
	VerifyExpired   VerifyStatus = "expired"
)

// Secret is a credential discovered in the app, optionally verified live.
type Secret struct {
	Type        string       `json:"type"`
	Provider    string       `json:"provider"`
	Redacted    string       `json:"redacted"`
	File        string       `json:"file,omitempty"`
	Severity    Severity     `json:"severity"`
	Verified    VerifyStatus `json:"verified,omitempty"`
	VerifyNote  string       `json:"verifyNote,omitempty"`
	Reportable  bool         `json:"reportable"`
	fullValue   string
}

// SetFullValue stores the raw secret for verification (never serialized).
func (s *Secret) SetFullValue(v string) { s.fullValue = v }

// FullValue returns the raw secret for verification.
func (s *Secret) FullValue() string { return s.fullValue }

type ScanProgress struct {
	Stage    string  `json:"stage"`
	Progress float64 `json:"progress"`
	Message  string  `json:"message"`
}
