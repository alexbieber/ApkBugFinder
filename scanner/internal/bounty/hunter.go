package bounty

import (
	"fmt"
	"strings"

	"github.com/apkbugfinder/scanner/internal/types"
)

// Analyze runs bounty-hunter checks focused on high-impact, exploitable vulnerabilities.
func Analyze(manifestPath string, javaFiles []string, packageName string, appInfo types.AppInfo) []types.Finding {
	var findings []types.Finding

	findings = append(findings, manifestFindings(manifestPath, appInfo)...)
	findings = append(findings, scanCodePatterns(javaFiles, packageName)...)
	findings = append(findings, detectWebViewChains(javaFiles, packageName)...)
	findings = append(findings, scanHardcodedSecrets(javaFiles, packageName)...)

	return dedupeBounty(findings)
}

func manifestFindings(manifestPath string, appInfo types.AppInfo) []types.Finding {
	var out []types.Finding

	if appInfo.Debuggable != nil && *appInfo.Debuggable {
		out = append(out, makeManifestFinding(
			"BOUNTY-DEBUG-PROD", "Production app is debuggable",
			"Debuggable release builds allow adb attachment, memory inspection, and runtime manipulation.",
			types.SeverityCritical, 10, "CWE-215",
			"AndroidManifest.xml", `android:debuggable="true"`,
			"adb shell run-as pkg; attach Frida/debugger to extract keys and bypass checks.",
			"Set android:debuggable=\"false\" in release builds.",
		))
	}

	if appInfo.AllowBackup != nil && *appInfo.AllowBackup {
		out = append(out, makeManifestFinding(
			"BOUNTY-BACKUP-EXTRACT", "App backup may expose local data",
			"allowBackup=true enables Google Drive backup / adb backup of app private data including tokens and DBs.",
			types.SeverityHigh, 7, "CWE-921",
			"AndroidManifest.xml", `android:allowBackup="true"`,
			"On test device: adb backup -f backup.ab -apk pkg; strings backup.ab | grep -i token/key/password",
			"Set allowBackup=false or exclude sensitive files via backup rules XML.",
		))
	}

	if appInfo.UsesCleartextTraffic != nil && *appInfo.UsesCleartextTraffic {
		out = append(out, makeManifestFinding(
			"BOUNTY-CLEARTEXT", "Cleartext HTTP traffic allowed",
			"Global cleartext permitted — credentials and tokens may be sent unencrypted.",
			types.SeverityHigh, 7, "CWE-319",
			"AndroidManifest.xml", `android:usesCleartextTraffic="true"`,
			"Capture traffic with mitmproxy; identify HTTP endpoints carrying auth/session data.",
			"Disable cleartext; enforce HTTPS via network security config.",
		))
	}

	components, err := ParseExportedComponents(manifestPath)
	if err == nil {
		for _, c := range components {
			if c.Permission != "" {
				continue
			}
			switch c.Type {
			case "provider":
				out = append(out, makeComponentFinding(c, 9,
					"BOUNTY-EXPORT-PROVIDER", "Exported ContentProvider without permission",
					"Unprotected exported provider may leak or allow modification of app data cross-app.",
					"Query/insert/update via adb content:// URI from another app or adb shell.",
				))
			case "activity":
				if IsDeepLinkComponent(c) {
					schemes := strings.Join(c.Schemes, ", ")
					out = append(out, makeComponentFinding(c, 8,
						"BOUNTY-DEEPLINK-EXPORT", "Exported deep-link handler without permission",
						fmt.Sprintf("Activity handles VIEW intents for schemes [%s] without permission — intent hijacking / open redirect surface.", schemes),
						fmt.Sprintf("adb am start -a android.intent.action.VIEW -d '%s://test/payload' -n %s/%s", firstScheme(c.Schemes), appInfo.PackageName, c.Name),
					))
				}
			case "receiver":
				out = append(out, makeComponentFinding(c, 7,
					"BOUNTY-EXPORT-RECEIVER", "Exported BroadcastReceiver without permission",
					"Any app can send broadcasts to this receiver — spoof events or trigger privileged actions.",
					"Send explicit broadcast via adb am broadcast -n pkg/Receiver -a action",
				))
			case "service":
				out = append(out, makeComponentFinding(c, 7,
					"BOUNTY-EXPORT-SERVICE", "Exported Service without permission",
					"External apps can bind/start this service — potential IPC abuse.",
					"adb am startservice -n pkg/Service; attempt binding from PoC app.",
				))
			}
		}
	}

	return out
}

func makeManifestFinding(id, title, desc string, sev types.Severity, impact int, cwe, file, evidence, hint, remediation string) types.Finding {
	return types.Finding{
		ID: id, Title: title, Description: desc,
		Severity: sev, Confidence: types.ConfidenceConfirmed,
		Scope: types.ScopeManifest, MASVS: "MSTG-PLATFORM-1", CWE: cwe,
		Category: "Bounty · Attack Surface", Impact: impact, BountyEligible: true,
		AttackSurface: "AndroidManifest.xml", ExploitHint: hint,
		File: file, Evidence: evidence, Remediation: remediation,
	}
}

func makeComponentFinding(c ExportedComponent, impact int, id, title, desc, hint string) types.Finding {
	ev := fmt.Sprintf("%s exported=true permission=none name=%s", c.Type, c.Name)
	if len(c.Schemes) > 0 {
		ev += " schemes=" + strings.Join(c.Schemes, ",")
	}
	sev := types.SeverityHigh
	if impact >= 9 {
		sev = types.SeverityCritical
	}
	return types.Finding{
		ID: id, Title: title, Description: desc,
		Severity: sev, Confidence: types.ConfidenceConfirmed,
		Scope: types.ScopeManifest, MASVS: "MSTG-PLATFORM-1", CWE: "CWE-926",
		Category: "Bounty · Attack Surface", Impact: impact, BountyEligible: true,
		AttackSurface: c.Type + ": " + c.Name,
		ExploitHint:   hint,
		File:          "AndroidManifest.xml",
		Evidence:      ev,
		Remediation:   "Set android:exported=false or require android:permission for external callers.",
	}
}

func firstScheme(schemes []string) string {
	if len(schemes) > 0 {
		return schemes[0]
	}
	return "app"
}

func dedupeBounty(findings []types.Finding) []types.Finding {
	seen := map[string]bool{}
	var out []types.Finding
	for _, f := range findings {
		key := f.ID + "|" + f.File + "|" + f.AttackSurface
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// EnrichFinding adds bounty impact metadata to existing MASVS findings.
func EnrichFinding(f *types.Finding) {
	if f.BountyEligible {
		return
	}
	impact, eligible, hint := scoreExisting(f)
	if impact > 0 {
		f.Impact = impact
		f.BountyEligible = eligible
		if f.ExploitHint == "" {
			f.ExploitHint = hint
		}
	}
}

func scoreExisting(f *types.Finding) (impact int, eligible bool, hint string) {
	switch f.ID {
	case "MSTG-CODE-2-DEBUGGABLE":
		return 10, true, "Attach debugger via adb; dump memory and extract secrets."
	case "MSTG-STORAGE-8-BACKUP":
		return 7, true, "Extract backup via adb backup; search for auth tokens in shared_prefs/."
	case "MSTG-NETWORK-2-CLEARTEXT":
		return 7, true, "MITM HTTP traffic; capture credentials in transit."
	case "MSTG-PLATFORM-1-EXPORTED-NOPERM":
		return 8, true, "Map exported components with drozer; test IPC and content:// access."
	case "MSTG-PLATFORM-7-JSINTERFACE":
		if f.Confidence == types.ConfidenceHigh || f.Scope == types.ScopeAppCode {
			return 8, true, "Inject JS in WebView context; invoke exposed bridge methods."
		}
	case "MSTG-PLATFORM-2-RCE", "BOUNTY-RCE-EXEC":
		return 8, true, "Trace user input to exec(); inject shell metacharacters."
	case "MSTG-PLATFORM-2-SQLI", "BOUNTY-SQLI-DYNAMIC":
		return 8, true, "Test ContentProvider query parameters with SQLi payloads."
	case "MSTG-NETWORK-3-WEBVIEWSSL":
		return 8, f.Confidence == types.ConfidenceConfirmed, "Confirm sslErrorHandler.proceed() is called on attacker MITM cert."
	case "ADV-SECRET-STRIPE":
		return 10, true, "Verify sk_live key against Stripe API."
	case "ADV-SECRET-AWS":
		return 9, true, "Validate AKIA key with aws sts get-caller-identity."
	case "ADV-SECRET-JWT":
		return 8, true, "Decode and replay JWT against API."
	case "MSTG-STORAGE-14-HARDCODE", "MSTG-STORAGE-14-BEGIN":
		if f.Severity == types.SeverityCritical || f.Severity == types.SeverityHigh {
			return 7, f.Scope == types.ScopeAppCode, "Test extracted secret against app APIs."
		}
	case "MSTG-CRYPTO-3-STATICIV", "MSTG-CRYPTO-1-SYMKEY":
		if f.Scope == types.ScopeAppCode {
			return 6, false, "Decrypt local data with static key/IV from source."
		}
	}
	if f.Confidence == types.ConfidenceConfirmed && f.Severity == types.SeverityHigh {
		return 6, false, "Validate with dynamic testing on a rooted/emulator device."
	}
	return 0, false, ""
}

// CountBountyEligible counts high-value findings.
func CountBountyEligible(findings []types.Finding) (eligible, critical int) {
	for _, f := range findings {
		if f.BountyEligible {
			eligible++
			if f.Impact >= 9 {
				critical++
			}
		}
	}
	return
}
