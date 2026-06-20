package analyzer

import (
	"strings"

	"github.com/apkbugfinder/scanner/internal/filter"
	"github.com/apkbugfinder/scanner/internal/grep"
	"github.com/apkbugfinder/scanner/internal/types"
)

// manifestConfirmed rules are definitive when found in AndroidManifest.xml.
var manifestConfirmed = map[string]bool{
	"MSTG-CODE-2-DEBUGGABLE":      true,
	"MSTG-STORAGE-8-BACKUP":       true,
	"MSTG-NETWORK-2-CLEARTEXT":    true,
	"MSTG-PLATFORM-1-EXPORTED-NOPERM": true,
	"MSTG-NETWORK-4-TRUSTUSER":    true,
}

// codeConfirmed rules with high signal when evidence is in app code.
var codeConfirmed = map[string]bool{
	"ADV-SECRET-AWS":              true,
	"ADV-SECRET-STRIPE":           true,
	"ADV-SECRET-JWT":              true,
	"MSTG-NETWORK-3-WEBVIEWSSL":   true,
	"MSTG-PLATFORM-2-FRAGMENT":    true,
	"MSTG-NETWORK-4-CERTFILES":    true,
}

// informationalRules are hygiene/absence checks — not actionable vulns.
var informationalRules = map[string]bool{
	"MSTG-CODE-9-OBFUSC-MISSING":       true,
	"MSTG-CODE-9-OBFUSC-PRESENT":       true,
	"MSTG-RESILIENCE-1-ROOT-MISSING":   true,
	"MSTG-RESILIENCE-1-ROOT-PRESENT":   true,
	"MSTG-RESILIENCE-2-ANTIDEBUG-MISSING": true,
	"MSTG-RESILIENCE-2-ANTIDEBUG-PRESENT": true,
	"MSTG-RESILIENCE-3-INTEGRITY-MISSING": true,
	"MSTG-RESILIENCE-3-INTEGRITY-PRESENT": true,
	"MSTG-RESILIENCE-5-EMULATOR-MISSING":  true,
	"MSTG-RESILIENCE-5-EMULATOR-PRESENT":  true,
	"MSTG-RESILIENCE-7-SAFETYNET-MISSING": true,
	"MSTG-RESILIENCE-7-SAFETYNET-PRESENT": true,
	"MSTG-NETWORK-6-PROVIDER-MISSING":  true,
	"MSTG-NETWORK-6-PROVIDER-PRESENT":  true,
	"MSTG-PLATFORM-10-WCLEANUP-MISSING": true,
	"MSTG-PLATFORM-10-WCLEANUP-PRESENT": true,
	"MSTG-NETWORK-4-PINSET":            true,
	"MSTG-NETWORK-4-PINNER":            true,
	"MSTG-PLATFORM-1-PERMS":            true,
	"MSTG-PLATFORM-1-CUSTPERM":         true,
	"MSTG-AUTH-8-BIOMETRIC":            true,
	"MSTG-AUTH-8-BIOINVALID":           true,
	"MSTG-STORAGE-7-PASSWORD":          true,
	"MSTG-STORAGE-9-FLAGSECURE":         true,
	"MSTG-STORAGE-10-FLUSH":            true,
	"MSTG-ARCH-9-UPDATE":               true,
	"MSTG-PLATFORM-2-SAFEBROWSE":       true,
}

// ScoreFinding assigns confidence and scope to a finding based on rule and evidence.
func ScoreFinding(f *types.Finding, packageName string, matches []grep.Match) {
	if strings.HasSuffix(f.ID, "-MISSING") || strings.HasSuffix(f.ID, "-PRESENT") {
		f.Confidence = types.ConfidenceInformational
		f.Scope = types.ScopeHygiene
		return
	}

	if informationalRules[f.ID] {
		f.Confidence = types.ConfidenceInformational
		f.Scope = types.ScopeHygiene
		return
	}

	if f.File == "AndroidManifest.xml" || manifestConfirmed[f.ID] {
		f.Confidence = types.ConfidenceConfirmed
		f.Scope = types.ScopeManifest
		return
	}

	appMatches := filterAppMatches(matches, packageName)
	if len(appMatches) == 0 && len(matches) > 0 {
		// Only library evidence — suppress from actionable results.
		f.Confidence = types.ConfidenceLow
		f.Scope = types.ScopeLibrary
		return
	}

	if codeConfirmed[f.ID] && len(appMatches) > 0 {
		f.Confidence = types.ConfidenceConfirmed
		f.Scope = types.ScopeAppCode
		return
	}

	switch f.ID {
	case "MSTG-NETWORK-3-HOSTNAME", "MSTG-NETWORK-3-WEBVIEWSSL":
		if hasSSLBypassEvidence(appMatches) {
			f.Confidence = types.ConfidenceConfirmed
			f.Scope = types.ScopeAppCode
			return
		}
	case "ADV-SECRET-GOOGLE":
		// Public client keys are common; still flag but require manual validation.
		f.Confidence = types.ConfidenceMedium
		f.Scope = types.ScopeAppCode
		return
	case "MSTG-STORAGE-14-BEGIN":
		f.Confidence = types.ConfidenceHigh
		f.Scope = types.ScopeAppCode
		return
	case "MSTG-PLATFORM-7-JSINTERFACE", "MSTG-PLATFORM-6-FILEACCESS", "MSTG-PLATFORM-6-WEBDEBUG":
		if len(appMatches) > 0 {
			f.Confidence = types.ConfidenceHigh
			f.Scope = types.ScopeAppCode
			return
		}
	case "MSTG-PLATFORM-2-SQLI", "MSTG-PLATFORM-2-XSS", "MSTG-PLATFORM-2-RCE":
		if len(appMatches) > 0 {
			f.Confidence = types.ConfidenceHigh
			f.Scope = types.ScopeAppCode
			return
		}
	case "MSTG-NETWORK-1-NOCONFIG":
		f.Confidence = types.ConfidenceMedium
		f.Scope = types.ScopeResource
		return
	}

	if len(appMatches) > 0 {
		f.Confidence = types.ConfidenceMedium
		f.Scope = types.ScopeAppCode
		return
	}

	f.Confidence = types.ConfidenceLow
	f.Scope = types.ScopeLibrary
}

func filterAppMatches(matches []grep.Match, packageName string) []grep.Match {
	var out []grep.Match
	for _, m := range matches {
		if filter.IsAppCode(m.File, packageName) {
			out = append(out, m)
		}
	}
	return out
}

func hasSSLBypassEvidence(matches []grep.Match) bool {
	for _, m := range matches {
		line := strings.ToLower(m.Content)
		if strings.Contains(line, ".proceed(") ||
			strings.Contains(line, "allowallhostname") ||
			strings.Contains(line, "nullhostnameverifier") {
			return true
		}
	}
	return false
}

// IsActionable returns findings suitable for security review / bounty triage.
func IsActionable(f types.Finding) bool {
	switch f.Confidence {
	case types.ConfidenceConfirmed, types.ConfidenceHigh:
		return true
	case types.ConfidenceMedium:
		if f.Severity == types.SeverityCritical || f.Severity == types.SeverityHigh {
			return true
		}
		if strings.HasPrefix(f.ID, "ADV-SECRET") || f.ID == "MSTG-NETWORK-1-NOCONFIG" {
			return true
		}
		return false
	default:
		return false
	}
}
