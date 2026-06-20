package analyzer

import (
	"regexp"
	"strings"

	"github.com/apkbugfinder/scanner/internal/grep"
)

var (
	reLiteralByteArray = regexp.MustCompile(`(?i)(new\s+byte\s*\[\s*\]\s*\{|byte\s*\[\s*\]\s*\w+\s*=\s*\{|\{0,\s*0,)`)
	reSQLDDL           = regexp.MustCompile(`(?i)(CREATE\s+TABLE|DROP\s+TABLE|ALTER\s+TABLE|PRAGMA\s+journal_mode)`)
	reSQLDynamic       = regexp.MustCompile(`(?i)(\+|\|\||String\.format|append\s*\()`)
	rePublicPEM        = regexp.MustCompile(`(?i)(BEGIN\s+PUBLIC|PUBLIC\s+KEY|RSAPublicKey|X509EncodedKeySpec)`)
	reHostnameBypass   = regexp.MustCompile(`(?i)(HostnameVerifier|setHostnameVerifier|setDefaultHostnameVerifier|NullHostnameVerifier|ALLOW_ALL_HOSTNAME|AllowAllHostnameVerifier|NO_VERIFY)`)
	reSSLProceed       = regexp.MustCompile(`(?i)(sslErrorHandler\.proceed\s*\(|\.proceed\s*\(\s*\))`)
	reWeakMD5          = regexp.MustCompile(`(?i)(MessageDigest\.getInstance\s*\(\s*"MD5"|"MD5"\s*\))`)
	reWeakECB          = regexp.MustCompile(`(?i)AES/ECB`)
)

// ValidateMatch applies rule-specific logic to drop obvious false positives.
func ValidateMatch(ruleID string, match grep.Match) bool {
	line := match.Content

	switch ruleID {
	case "MSTG-NETWORK-3-HOSTNAME":
		return reHostnameBypass.MatchString(line) &&
			(strings.Contains(line, "verify") || strings.Contains(line, "HostnameVerifier") || strings.Contains(line, "setHostnameVerifier"))

	case "MSTG-NETWORK-3-WEBVIEWSSL":
		return strings.Contains(strings.ToLower(line), "onreceivedsslerror") ||
			reSSLProceed.MatchString(line)

	case "MSTG-PLATFORM-2-RCE":
		return strings.Contains(line, ".exec(") || strings.Contains(line, "ProcessBuilder(")

	case "MSTG-PLATFORM-2-SQLI":
		if reSQLDDL.MatchString(line) {
			return false
		}
		if strings.Contains(line, "rawQuery") || strings.Contains(line, "execSQL") {
			return reSQLDynamic.MatchString(line)
		}
		return false

	case "MSTG-CRYPTO-1-SYMKEY":
		return strings.Contains(line, "SecretKeySpec(") ||
			(strings.Contains(line, "IvParameterSpec(") && reLiteralByteArray.MatchString(line))

	case "MSTG-CRYPTO-3-STATICIV":
		return reLiteralByteArray.MatchString(line)

	case "MSTG-NETWORK-1-MITM":
		lower := strings.ToLower(line)
		if strings.Contains(lower, "getinsecure") || strings.Contains(lower, "trustall") ||
			strings.Contains(lower, "allowallhostname") || strings.Contains(lower, "hostnameverifier") {
			return true
		}
		// HttpURLConnection alone is not a vulnerability.
		return false

	case "MSTG-STORAGE-14-BEGIN":
		if rePublicPEM.MatchString(line) {
			return false
		}
		return strings.Contains(line, "-BEGIN ") &&
			(strings.Contains(strings.ToUpper(line), "PRIVATE") || strings.Contains(strings.ToUpper(line), "RSA PRIVATE"))

	case "MSTG-STORAGE-14-HARDCODE":
		lower := strings.ToLower(line)
		for _, noise := range []string{`key = "f"`, `userName = ""`, `String key = "`, `name="list_secret"`, `name="msg_secret"`} {
			if strings.Contains(lower, strings.ToLower(noise)) {
				return false
			}
		}
		return true

	case "MSTG-STORAGE-14-EMAIL":
		// Skip binary/encoded certificate blobs misidentified as emails.
		return !strings.Contains(line, `\u0082`) && !strings.Contains(line, "zzbO(")

	case "MSTG-STORAGE-14-STRINGS":
		lower := strings.ToLower(line)
		if strings.Contains(lower, "public.xml") || strings.Contains(lower, "drawable") {
			return false
		}
		return strings.Contains(lower, "_key") || strings.Contains(lower, "_secret") ||
			strings.Contains(lower, "_token") || strings.Contains(lower, "api_key")

	case "MSTG-PLATFORM-6-WEBDEBUG":
		return strings.Contains(line, "setWebContentsDebuggingEnabled(") &&
			!strings.Contains(line, "false") && !strings.Contains(line, "&&")

	case "MSTG-PLATFORM-2-XSS":
		if strings.Contains(line, "evaluateJavascript") {
			return true
		}
		return strings.Contains(strings.ToLower(line), "javascript:")

	case "ADV-CRYPTO-MD5":
		return reWeakMD5.MatchString(line)

	case "ADV-CRYPTO-ECB":
		return reWeakECB.MatchString(line)

	case "ADV-SECRET-GOOGLE", "ADV-SECRET-AWS", "ADV-SECRET-STRIPE", "ADV-SECRET-JWT":
		return len(strings.TrimSpace(line)) > 10

	default:
		return true
	}
}

// FilterValidatedMatches applies ValidateMatch to each match.
func FilterValidatedMatches(ruleID string, matches []grep.Match) []grep.Match {
	var out []grep.Match
	for _, m := range matches {
		if ValidateMatch(ruleID, m) {
			out = append(out, m)
		}
	}
	return out
}
