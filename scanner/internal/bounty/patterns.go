package bounty

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apkbugfinder/scanner/internal/filter"
	"github.com/apkbugfinder/scanner/internal/grep"
	"github.com/apkbugfinder/scanner/internal/types"
)

type codePattern struct {
	id, title, desc, cwe, masvs, category, remediation, exploitHint string
	severity                                                        types.Severity
	impact                                                          int
	pattern                                                         string
	regex                                                           bool
	validator                                                       func(string) bool
}

var bountyPatterns = []codePattern{
	{
		id: "BOUNTY-SSL-PROCEED", title: "WebView accepts invalid SSL certificates",
		desc: "sslErrorHandler.proceed() bypasses certificate validation — enables MITM on WebView traffic.",
		cwe: "CWE-295", masvs: "MSTG-NETWORK-3", category: "Bounty · Network", impact: 9,
		severity: types.SeverityCritical, pattern: `(?i)(sslErrorHandler\.proceed\s*\(|\.proceed\s*\(\s*\)\s*;)`,
		regex: true,
		exploitHint: "Proxy WebView traffic with mitmproxy; confirm proceed() is reachable on attacker-controlled URLs.",
		remediation: "Call sslErrorHandler.cancel() on all SSL errors.",
		validator: func(line string) bool {
			return strings.Contains(strings.ToLower(line), "proceed")
		},
	},
	{
		id: "BOUNTY-SSL-TRUST-ALL", title: "Trust-all certificate validation",
		desc: "Custom TrustManager or HostnameVerifier disables TLS certificate verification.",
		cwe: "CWE-295", masvs: "MSTG-NETWORK-3", category: "Bounty · Network", impact: 9,
		severity: types.SeverityCritical,
		pattern: `(?i)(TrustAllHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|NullHostnameVerifier|checkServerTrusted\s*\([^)]*\)\s*\{\s*\})`,
		regex: true,
		exploitHint: "Intercept HTTPS with Burp/mitmproxy; verify app accepts your CA without pinning bypass.",
		remediation: "Use system default TrustManager and HostnameVerifier.",
	},
	{
		id: "BOUNTY-KEY-PRIVATE", title: "Private key embedded in APK",
		desc: "RSA/EC PRIVATE KEY block found in app source — full cryptographic compromise if key is active.",
		cwe: "CWE-321", masvs: "MSTG-STORAGE-14", category: "Bounty · Secrets", impact: 10,
		severity: types.SeverityCritical, pattern: `-BEGIN (RSA |EC )?PRIVATE KEY-`,
		exploitHint: "Extract key, test against app API endpoints or decrypt local data stores.",
		remediation: "Remove private keys; use Android Keystore or server-side HSM.",
	},
	{
		id: "BOUNTY-SECRET-STRIPE", title: "Stripe live secret key",
		desc: "sk_live_ Stripe key in app code enables unauthorized payments and financial access.",
		cwe: "CWE-798", masvs: "MSTG-STORAGE-14", category: "Bounty · Secrets", impact: 10,
		severity: types.SeverityCritical, pattern: `sk_live_[0-9a-zA-Z]{24,}`,
		regex: true,
		exploitHint: "Verify key via Stripe API /v1/balance — report immediately if active.",
		remediation: "Revoke key; move payment logic server-side.",
	},
	{
		id: "BOUNTY-SECRET-AWS", title: "AWS access key in app code",
		desc: "AKIA* AWS access key may grant cloud infrastructure access.",
		cwe: "CWE-798", masvs: "MSTG-STORAGE-14", category: "Bounty · Secrets", impact: 9,
		severity: types.SeverityCritical, pattern: `AKIA[0-9A-Z]{16}`,
		regex: true,
		exploitHint: "Run aws sts get-caller-identity with the key; enumerate S3/IAM scope.",
		remediation: "Rotate key; use Cognito/IAM roles instead of static keys.",
	},
	{
		id: "BOUNTY-SECRET-JWT", title: "Long-lived JWT / bearer token",
		desc: "Embedded JWT may grant persistent API access without user interaction.",
		cwe: "CWE-798", masvs: "MSTG-STORAGE-14", category: "Bounty · Secrets", impact: 8,
		severity: types.SeverityHigh, pattern: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{20,}`,
		regex: true,
		exploitHint: "Decode JWT at jwt.io; replay token against API endpoints.",
		remediation: "Never embed JWTs; use OAuth refresh flow with short-lived tokens.",
	},
	{
		id: "BOUNTY-SQLI-DYNAMIC", title: "Dynamic SQL query construction",
		desc: "User-influenced string concatenation in rawQuery/execSQL — classic SQL injection vector.",
		cwe: "CWE-89", masvs: "MSTG-PLATFORM-2", category: "Bounty · Injection", impact: 8,
		severity: types.SeverityHigh,
		pattern: `(?i)(rawQuery|execSQL)\s*\([^)]*\+`,
		regex: true,
		exploitHint: "Identify injectable parameter via ContentProvider/query() or app inputs; test with ' OR 1=1--",
		remediation: "Use parameterized queries with ? placeholders.",
	},
	{
		id: "BOUNTY-INTENT-REDIRECT", title: "Unvalidated intent/deeplink redirection",
		desc: "Intent data or URI passed to startActivity/loadUrl without validation — open redirect or arbitrary component launch.",
		cwe: "CWE-939", masvs: "MSTG-PLATFORM-3", category: "Bounty · Platform", impact: 8,
		severity: types.SeverityHigh,
		pattern: `(?i)(getIntent\(\)\.getData\(\)|getDataString\(\)|getStringExtra\([^)]+\)).*(startActivity|loadUrl|setResult)`,
		regex: true,
		exploitHint: "adb am start -a android.intent.action.VIEW -d 'evil://payload' -n pkg/Activity; test for redirect.",
		remediation: "Allowlist schemes/hosts; validate all external intent data.",
	},
	{
		id: "BOUNTY-PATH-TRAVERSAL", title: "Path traversal in file access",
		desc: "File path built from external input without sanitization — read/write arbitrary files.",
		cwe: "CWE-22", masvs: "MSTG-PLATFORM-2", category: "Bounty · Injection", impact: 8,
		severity: types.SeverityHigh,
		pattern: `(?i)(\.\./|\.\.\\\\|getCanonicalPath|openFileOutput|openFileInput).*(\+.*getString|getData|getPath)`,
		regex: true,
		exploitHint: "Pass ../../data/data/pkg/shared_prefs/ via ContentProvider or deeplink.",
		remediation: "Canonicalize paths; reject .. segments; use internal storage only.",
	},
	{
		id: "BOUNTY-PENDING-MUTABLE", title: "Mutable PendingIntent",
		desc: "FLAG_MUTABLE PendingIntent allows intent hijacking on Android 12+.",
		cwe: "CWE-927", masvs: "MSTG-PLATFORM-4", category: "Bounty · Platform", impact: 7,
		severity: types.SeverityHigh, pattern: `(?i)PendingIntent\.(getActivity|getService|getBroadcast)[^(]*\([^)]*FLAG_MUTABLE`,
		regex: true,
		exploitHint: "Replace PendingIntent extras via malicious app with same signature; test notification/deeplink flows.",
		remediation: "Use FLAG_IMMUTABLE unless mutability is strictly required.",
	},
	{
		id: "BOUNTY-WEBVIEW-JSBRIDGE", title: "WebView JavaScript bridge on untrusted content",
		desc: "addJavascriptInterface exposes native methods to JavaScript — RCE on Android < 17, data theft on all versions.",
		cwe: "CWE-749", masvs: "MSTG-PLATFORM-7", category: "Bounty · WebView", impact: 8,
		severity: types.SeverityHigh, pattern: `addJavascriptInterface\(`,
		exploitHint: "Load attacker HTML in WebView; call bridge methods via JS to exfiltrate tokens/files.",
		remediation: "Remove JS bridge or restrict to trusted origin-only content with @JavascriptInterface on API 17+.",
	},
	{
		id: "BOUNTY-WEBVIEW-FILEACCESS", title: "WebView universal file access",
		desc: "setAllowUniversalAccessFromFileURLs enables cross-origin file theft from WebView.",
		cwe: "CWE-749", masvs: "MSTG-PLATFORM-6", category: "Bounty · WebView", impact: 8,
		severity: types.SeverityHigh, pattern: `setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)`,
		exploitHint: "Load file:// page that reads file:///data/data/pkg/ via XHR.",
		remediation: "Disable universal file access; use WebViewAssetLoader.",
	},
	{
		id: "BOUNTY-RCE-EXEC", title: "Shell command execution",
		desc: "Runtime.exec/ProcessBuilder with potentially user-controlled arguments.",
		cwe: "CWE-78", masvs: "MSTG-PLATFORM-2", category: "Bounty · RCE", impact: 8,
		severity: types.SeverityHigh, pattern: `(?i)(Runtime\.getRuntime\(\)\.exec\s*\(|new ProcessBuilder\s*\()`,
		regex: true,
		exploitHint: "Trace input source to exec args; inject via exported component or IPC.",
		remediation: "Avoid shell execution; sanitize and allowlist commands.",
	},
	{
		id: "BOUNTY-DESERIALIZE", title: "Unsafe Java deserialization",
		desc: "ObjectInputStream/readObject on externally supplied data can lead to RCE gadget chains.",
		cwe: "CWE-502", masvs: "MSTG-PLATFORM-8", category: "Bounty · RCE", impact: 7,
		severity: types.SeverityHigh, pattern: `(?i)(ObjectInputStream|readObject\s*\(|readSerializable\s*\()`,
		exploitHint: "Identify entry point for serialized blob; test with ysoserial gadget chain.",
		remediation: "Avoid Java serialization; use JSON with schema validation.",
	},
}

func scanCodePatterns(javaFiles []string, packageName string) []types.Finding {
	var out []types.Finding
	for _, p := range bountyPatterns {
		opts := grep.Options{Patterns: []string{p.pattern}, UseRegex: p.regex}
		var matches []grep.Match
		for _, f := range javaFiles {
			if !filter.IsAppCode(f, packageName) {
				continue
			}
			hits, err := grep.SearchFile(f, opts)
			if err != nil {
				continue
			}
			for _, h := range hits {
				if p.validator != nil && !p.validator(h.Content) {
					continue
				}
				matches = append(matches, h)
			}
		}
		if len(matches) == 0 {
			continue
		}
		out = append(out, types.Finding{
			ID:            p.id,
			Title:         p.title,
			Description:   p.desc,
			Severity:      p.severity,
			Confidence:    types.ConfidenceHigh,
			Scope:         types.ScopeAppCode,
			MASVS:         p.masvs,
			CWE:           p.cwe,
			Category:      p.category,
			Impact:        p.impact,
			BountyEligible: true,
			AttackSurface: "Application code",
			ExploitHint:   p.exploitHint,
			Evidence:      grep.FormatEvidence(matches, 8),
			File:          filepath.Base(matches[0].File),
			Remediation:   p.remediation,
		})
	}
	return out
}

// detectWebViewChains finds files combining JS bridge + file access + JS enabled.
func detectWebViewChains(javaFiles []string, packageName string) []types.Finding {
	type flags struct{ js, bridge, fileAccess, debug bool }
	byFile := map[string]*flags{}

	checks := []struct {
		key string
		pat string
	}{
		{"js", `(?i)setJavaScriptEnabled\s*\(\s*true`},
		{"bridge", `addJavascriptInterface\(`},
		{"fileAccess", `(?i)setAllow(UniversalAccessFromFileURLs|FileAccessFromFileURLs|ContentAccess)\s*\(\s*true`},
		{"debug", `(?i)setWebContentsDebuggingEnabled\s*\(\s*true`},
	}

	for _, f := range javaFiles {
		if !filter.IsAppCode(f, packageName) {
			continue
		}
		rel := filepath.Base(f)
		fl := &flags{}
		for _, c := range checks {
			opts := grep.Options{Patterns: []string{c.pat}, UseRegex: true}
			if m, _ := grep.SearchFile(f, opts); len(m) > 0 {
				switch c.key {
				case "js":
					fl.js = true
				case "bridge":
					fl.bridge = true
				case "fileAccess":
					fl.fileAccess = true
				case "debug":
					fl.debug = true
				}
			}
		}
		if fl.js || fl.bridge || fl.fileAccess {
			byFile[rel] = fl
		}
	}

	var out []types.Finding
	for file, fl := range byFile {
		score := 0
		var parts []string
		if fl.bridge {
			score += 3
			parts = append(parts, "JS bridge")
		}
		if fl.fileAccess {
			score += 3
			parts = append(parts, "file access")
		}
		if fl.js {
			score += 2
			parts = append(parts, "JS enabled")
		}
		if fl.debug {
			score += 2
			parts = append(parts, "remote debugging")
		}
		if score < 5 {
			continue
		}
		impact := 7
		if fl.bridge && fl.fileAccess {
			impact = 9
		} else if fl.bridge && fl.js {
			impact = 8
		}
		out = append(out, types.Finding{
			ID:    "BOUNTY-WEBVIEW-CHAIN",
			Title: "WebView exploit chain — " + strings.Join(parts, " + "),
			Description: "Multiple dangerous WebView settings combined in one component — high risk of token theft or local file read.",
			Severity: types.SeverityCritical, Confidence: types.ConfidenceHigh,
			Scope: types.ScopeAppCode, MASVS: "MSTG-PLATFORM-7", CWE: "CWE-749",
			Category: "Bounty · WebView Chain", Impact: impact, BountyEligible: true,
			AttackSurface: "WebView component",
			ExploitHint:   "Host malicious HTML/JS in WebView context; chain bridge methods with file:// access.",
			File:          file,
			Evidence:      "Combined: " + strings.Join(parts, ", "),
			Remediation:   "Disable JS bridge on untrusted content; disable file access; use WebViewAssetLoader.",
		})
	}
	return out
}

var reHardSecret = regexp.MustCompile(`(?i)String\s+(password|api[_-]?key|secret|token|auth[_-]?token|private[_-]?key)\s*=\s*"([^"]{8,})"`)

func scanHardcodedSecrets(javaFiles []string, packageName string) []types.Finding {
	var matches []grep.Match
	for _, f := range javaFiles {
		if !filter.IsAppCode(f, packageName) {
			continue
		}
		hits, err := grep.SearchFile(f, grep.Options{Patterns: []string{`(?i)String\s+(password|secret|token|apikey|api_key)\s*=\s*"`}, UseRegex: true})
		if err != nil {
			continue
		}
		for _, h := range hits {
			if m := reHardSecret.FindStringSubmatch(h.Content); len(m) > 2 {
				val := m[2]
				if len(val) >= 12 && !isPlaceholder(val) {
					matches = append(matches, h)
				}
			}
		}
	}
	if len(matches) == 0 {
		return nil
	}
	return []types.Finding{{
		ID: "BOUNTY-HARDCODE-SECRET", Title: "High-entropy hardcoded credential",
		Description: "Non-trivial secret string literal in app code — may grant API or account access.",
		Severity: types.SeverityHigh, Confidence: types.ConfidenceHigh,
		Scope: types.ScopeAppCode, MASVS: "MSTG-STORAGE-14", CWE: "CWE-798",
		Category: "Bounty · Secrets", Impact: 7, BountyEligible: true,
		AttackSurface: "Application code",
		ExploitHint:   "Extract string; test against app API login, encryption, or third-party services.",
		Evidence:      grep.FormatEvidence(matches, 5),
		File:          filepath.Base(matches[0].File),
		Remediation:   "Move secrets to secure backend; use Android Keystore for local keys.",
	}}
}

func isPlaceholder(s string) bool {
	lower := strings.ToLower(s)
	for _, p := range []string{"placeholder", "example", "changeme", "your_", "xxx", "test", "dummy", "sample", "todo"} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
