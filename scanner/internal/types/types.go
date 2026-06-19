package types

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	MASVS       string   `json:"masvs"`
	CWE         string   `json:"cwe,omitempty"`
	Category    string   `json:"category"`
	Evidence    string   `json:"evidence,omitempty"`
	File        string   `json:"file,omitempty"`
	Remediation string   `json:"remediation"`
	Reference   string   `json:"reference,omitempty"`
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
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

type ScanResult struct {
	ID         string    `json:"id"`
	ScannedAt  string    `json:"scannedAt"`
	DurationMs int64   `json:"durationMs"`
	Engine     string    `json:"engine"`
	AppInfo    AppInfo   `json:"appInfo"`
	Findings   []Finding `json:"findings"`
	Stats      ScanStats `json:"stats"`
}

type ScanProgress struct {
	Stage    string  `json:"stage"`
	Progress float64 `json:"progress"`
	Message  string  `json:"message"`
}
