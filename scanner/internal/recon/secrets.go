package recon

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apkbugfinder/scanner/internal/filter"
	"github.com/apkbugfinder/scanner/internal/types"
)

const maxFileBytes = 8 << 20 // 8 MB per file cap for recon reads

type secretDef struct {
	typ, provider string
	re            *regexp.Regexp
	severity      types.Severity
	// verifiable indicates a read-only liveness check exists.
	verifiable bool
}

var secretDefs = []secretDef{
	{"AWS Access Key", "aws", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), types.SeverityCritical, true},
	{"AWS Secret Key", "aws", regexp.MustCompile(`(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]`), types.SeverityCritical, false},
	{"Google API Key", "google", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), types.SeverityHigh, true},
	{"Stripe Live Secret", "stripe", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`), types.SeverityCritical, true},
	{"Stripe Restricted Key", "stripe", regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24,}`), types.SeverityHigh, true},
	{"Firebase Database URL", "firebase", regexp.MustCompile(`https?://[a-z0-9-]+\.firebaseio\.com`), types.SeverityHigh, true},
	{"JWT", "jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), types.SeverityHigh, true},
	{"GitHub Token", "github", regexp.MustCompile(`(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}`), types.SeverityCritical, true},
	{"Slack Token", "slack", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`), types.SeverityHigh, true},
	{"Twilio API Key", "twilio", regexp.MustCompile(`SK[0-9a-fA-F]{32}`), types.SeverityHigh, false},
	{"SendGrid Key", "sendgrid", regexp.MustCompile(`SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}`), types.SeverityCritical, false},
	{"Mapbox Token", "mapbox", regexp.MustCompile(`pk\.eyJ[0-9A-Za-z_-]{50,}`), types.SeverityMedium, false},
	{"Private Key Block", "pem", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`), types.SeverityCritical, false},
}

var placeholderRe = regexp.MustCompile(`(?i)(your[_-]?|example|placeholder|changeme|xxxx|dummy|sample|test[_-]?key|<.*>|abcdef0123|0000000)`)

// ExtractSecrets finds candidate credentials across app code and resources.
func ExtractSecrets(javaFiles, xmlFiles []string, packageName string) []types.Secret {
	seen := map[string]bool{}
	var out []types.Secret

	process := func(files []string, appOnly bool) {
		for _, f := range files {
			if appOnly && !filter.IsAppCode(f, packageName) {
				continue
			}
			content, err := readFileLimited(f)
			if err != nil {
				continue
			}
			base := filepath.Base(f)
			for _, def := range secretDefs {
				for _, m := range def.re.FindAllString(content, -1) {
					val := strings.TrimSpace(m)
					if placeholderRe.MatchString(val) {
						continue
					}
					key := def.typ + "|" + val
					if seen[key] {
						continue
					}
					seen[key] = true
					s := types.Secret{
						Type:       def.typ,
						Provider:   def.provider,
						Redacted:   redact(val),
						File:       base,
						Severity:   def.severity,
						Reportable: false,
					}
					if def.verifiable {
						s.Verified = types.VerifyUnknown
					} else {
						s.Verified = types.VerifySkipped
						s.VerifyNote = "No automated liveness check for this type — verify manually."
					}
					s.SetFullValue(val)
					out = append(out, s)
				}
			}
		}
	}

	process(javaFiles, true)
	process(xmlFiles, false)
	return out
}

func redact(s string) string {
	if len(s) <= 10 {
		return s[:2] + strings.Repeat("*", len(s)-2)
	}
	return s[:6] + strings.Repeat("*", 6) + s[len(s)-4:]
}

func readFileLimited(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.Size() > maxFileBytes {
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer f.Close()
		buf := make([]byte, maxFileBytes)
		n, _ := f.Read(buf)
		return string(buf[:n]), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
