package engine

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/apkbugfinder/scanner/internal/decompile"
	"github.com/apkbugfinder/scanner/internal/grep"
	"github.com/apkbugfinder/scanner/internal/manifest"
	"github.com/apkbugfinder/scanner/internal/rules"
	"github.com/apkbugfinder/scanner/internal/types"
	"github.com/google/uuid"
)

type Options struct {
	WorkDir string
	OnProgress func(stage string, progress float64, message string)
}

func Scan(apkPath string, opts Options) (*types.ScanResult, error) {
	start := time.Now()
	report := func(stage string, p float64, msg string) {
		if opts.OnProgress != nil {
			opts.OnProgress(stage, p, msg)
		}
	}

	report("extracting", 5, "Checking scanner requirements…")
	if err := decompile.CheckRequirements(); err != nil {
		return nil, err
	}

	workDir := opts.WorkDir
	if workDir == "" {
		workDir = filepath.Join(os.TempDir(), "apkbugfinder")
	}

	fi, err := os.Stat(apkPath)
	if err != nil {
		return nil, err
	}

	report("extracting", 15, "Running d2j-dex2jar…")
	dec, err := decompile.Decompile(apkPath, workDir)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dec.JadxPath)
	defer os.Remove(dec.Dex2JarPath)

	report("analyzing", 35, "Decompiling with JADX…")
	appInfo, netConfName, err := manifest.Parse(dec.ManifestPath, filepath.Base(apkPath), fi.Size())
	if err != nil {
		return nil, fmt.Errorf("manifest parse: %w", err)
	}

	md5Hash, sha256Hash, err := hashFile(apkPath)
	if err == nil {
		appInfo.MD5 = md5Hash
		appInfo.SHA256 = sha256Hash
	}

	javaFiles, _ := decompile.WalkFiles(dec.SourcesPath, map[string]bool{".java": true})
	xmlResFiles, _ := decompile.WalkFiles(dec.ResourcesPath, map[string]bool{".xml": true})

	report("analyzing", 55, "Running OWASP MASVS rules (APKHunt parity)…")
	var findings []types.Finding

	for _, rule := range rules.All() {
		if f := runRule(rule, dec, javaFiles, xmlResFiles); f != nil {
			findings = append(findings, *f)
		}
	}

	// Manifest-specific: exported components without permission
	if exp, err := manifest.ExportedWithoutPermission(dec.ManifestPath); err == nil && len(exp) > 0 {
		findings = append(findings, types.Finding{
			ID:          "MSTG-PLATFORM-1-EXPORTED-NOPERM",
			Title:       "Exported components without permission",
			Description: "Exported activity/service/provider/receiver without android:permission set.",
			Severity:    types.SeverityHigh,
			MASVS:       "MSTG-PLATFORM-1",
			CWE:         "CWE-276",
			Category:    "Platform",
			File:        "AndroidManifest.xml",
			Evidence:    grep.FormatEvidence(exp, 10),
			Remediation: "Set android:permission on exported components.",
			Reference:   "https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment",
		})
	}

	// Network security config file presence (APKHunt MSTG-NETWORK-1)
	netConfPath := filepath.Join(dec.ResourcesPath, "res", "xml", "network_security_config.xml")
	if netConfName != "" {
		netConfPath = filepath.Join(dec.ResourcesPath, "res", "xml", netConfName+".xml")
	}
	if _, err := os.Stat(netConfPath); os.IsNotExist(err) {
		findings = append(findings, types.Finding{
			ID:          "MSTG-NETWORK-1-NOCONFIG",
			Title:       "Network Security Configuration missing",
			Description: "No network_security_config.xml found. Configure cleartext, CAs, and pinning.",
			Severity:    types.SeverityMedium,
			MASVS:       "MSTG-NETWORK-1",
			CWE:         "CWE-693",
			Category:    "Network",
			Remediation: "Add res/xml/network_security_config.xml and reference in manifest.",
			Reference:   "https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements",
		})
	}

	report("analyzing", 85, "Running advanced checks…")
	findings = append(findings, advancedChecks(javaFiles)...)

	findings = dedupeFindings(findings)
	sortFindings(findings)
	stats := computeStats(findings)

	report("complete", 100, "Scan complete")

	return &types.ScanResult{
		ID:         uuid.New().String(),
		ScannedAt:  time.Now().UTC().Format(time.RFC3339),
		DurationMs: time.Since(start).Milliseconds(),
		Engine:     "apkbugfinder-scanner/1.0 (APKHunt-parity + advanced)",
		AppInfo:    appInfo,
		Findings:   findings,
		Stats:      stats,
	}, nil
}

func runRule(rule rules.Rule, dec *decompile.Result, javaFiles, xmlFiles []string) *types.Finding {
	switch rule.Scope {
	case rules.ScopeCertFiles:
		return runCertRule(rule, dec.ResourcesPath)
	case rules.ScopeManifest:
		return runManifestRule(rule, dec.ManifestPath)
	default:
		files := javaFiles
		if rule.Scope == rules.ScopeResourceXML {
			files = xmlFiles
		}
		return runFileRule(rule, files)
	}
}

func runFileRule(rule rules.Rule, files []string) *types.Finding {
	opts := grep.Options{
		Patterns:        rule.Patterns,
		UseRegex:        rule.Regex,
		CaseInsensitive: rule.CaseInsensitive,
	}
	var all []grep.Match
	for _, f := range files {
		matches, err := grep.SearchFile(f, opts)
		if err != nil {
			continue
		}
		for _, m := range matches {
			if len(rule.OutputMustContain) > 0 {
				combined := m.Content
				if !grep.ContainsAny(combined, rule.OutputMustContain, true) {
					continue
				}
			}
			all = append(all, m)
		}
	}

	if rule.Absence {
		if len(all) == 0 {
			sev := rule.AbsenceSeverity
			if sev == "" {
				sev = types.SeverityInfo
			}
			return &types.Finding{
				ID:          rule.ID + "-MISSING",
				Title:       rule.Title + " — not detected",
				Description: rule.Remediation,
				Severity:    sev,
				MASVS:       rule.MASVS,
				CWE:         rule.CWE,
				Category:    rule.Category,
				Remediation: rule.Remediation,
				Reference:   rule.Reference,
			}
		}
		if rule.ID == "MSTG-CODE-9-OBFUSC" || strings.HasPrefix(rule.ID, "MSTG-RESILIENCE") || rule.ID == "MSTG-NETWORK-6-PROVIDER" || rule.ID == "MSTG-PLATFORM-10-WCLEANUP" {
			// APKHunt also reports when present as info — presence is good
			return &types.Finding{
				ID:          rule.ID + "-PRESENT",
				Title:       rule.Title + " — detected",
				Description: "Control appears implemented; verify manually.",
				Severity:    types.SeverityInfo,
				MASVS:       rule.MASVS,
				CWE:         rule.CWE,
				Category:    rule.Category,
				Evidence:    grep.FormatEvidence(all, 5),
				Remediation: rule.Remediation,
				Reference:   rule.Reference,
			}
		}
		return nil
	}

	if len(all) == 0 {
		return nil
	}

	sev := rule.Severity
	if sev == "" {
		sev = types.SeverityMedium
	}
	desc := rule.Description
	if desc == "" {
		desc = rule.Remediation
	}

	return &types.Finding{
		ID:          rule.ID,
		Title:       rule.Title,
		Description: desc,
		Severity:    sev,
		MASVS:       rule.MASVS,
		CWE:         rule.CWE,
		Category:    rule.Category,
		Evidence:    grep.FormatEvidence(all, 10),
		File:        filepath.Base(all[0].File),
		Remediation: rule.Remediation,
		Reference:   rule.Reference,
	}
}

func runManifestRule(rule rules.Rule, manifestPath string) *types.Finding {
	opts := grep.Options{Patterns: rule.Patterns, UseRegex: rule.Regex, CaseInsensitive: rule.CaseInsensitive}
	matches, err := grep.SearchFile(manifestPath, opts)
	if err != nil || len(matches) == 0 {
		return nil
	}
	return &types.Finding{
		ID:          rule.ID,
		Title:       rule.Title,
		Description: rule.Remediation,
		Severity:    rule.Severity,
		MASVS:       rule.MASVS,
		CWE:         rule.CWE,
		Category:    rule.Category,
		File:        "AndroidManifest.xml",
		Evidence:    grep.FormatEvidence(matches, 5),
		Remediation: rule.Remediation,
		Reference:   rule.Reference,
	}
}

func runCertRule(rule rules.Rule, resourcesPath string) *types.Finding {
	extSet := map[string]bool{}
	for _, e := range rule.CertExtensions {
		extSet[e] = true
	}
	var found []string
	filepath.Walk(resourcesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if extSet[filepath.Ext(path)] {
			found = append(found, path)
		}
		return nil
	})
	if len(found) == 0 {
		return nil
	}
	evidence := strings.Join(found[:min(5, len(found))], "\n")
	if len(found) > 5 {
		evidence += fmt.Sprintf("\n... and %d more", len(found)-5)
	}
	return &types.Finding{
		ID:          rule.ID,
		Title:       rule.Title,
		Description: rule.Remediation,
		Severity:    rule.Severity,
		MASVS:       rule.MASVS,
		CWE:         rule.CWE,
		Category:    rule.Category,
		Evidence:    evidence,
		Remediation: rule.Remediation,
		Reference:   rule.Reference,
	}
}

// advancedChecks — capabilities beyond APKHunt baseline.
func advancedChecks(javaFiles []string) []types.Finding {
	advanced := []struct {
		id, title, masvs, cwe, pattern, remediation string
		severity                                    types.Severity
	}{
		{"ADV-SECRET-AWS", "AWS Access Key exposed", "MSTG-STORAGE-14", "CWE-798", `AKIA[0-9A-Z]{16}`, "Rotate key and use IAM roles / secrets manager.", types.SeverityCritical},
		{"ADV-SECRET-GOOGLE", "Google API Key exposed", "MSTG-STORAGE-14", "CWE-798", `AIza[0-9A-Za-z\-_]{35}`, "Restrict API key and move to backend.", types.SeverityCritical},
		{"ADV-SECRET-JWT", "JWT token in source", "MSTG-STORAGE-14", "CWE-798", `eyJ[A-Za-z0-9_-]+\.eyJ`, "Never embed JWTs in mobile apps.", types.SeverityHigh},
		{"ADV-SECRET-STRIPE", "Stripe live key exposed", "MSTG-STORAGE-14", "CWE-798", `sk_live_[0-9a-zA-Z]{24,}`, "Remove Stripe secret keys from the app.", types.SeverityCritical},
		{"ADV-CRYPTO-ECB", "AES/ECB mode detected", "MSTG-CRYPTO-3", "CWE-327", `AES/ECB`, "Use AES/GCM instead of ECB.", types.SeverityHigh},
		{"ADV-CRYPTO-MD5", "MD5 hash usage", "MSTG-CRYPTO-4", "CWE-327", `"MD5"`, "Replace MD5 with SHA-256 or stronger.", types.SeverityMedium},
	}

	var out []types.Finding
	for _, a := range advanced {
		opts := grep.Options{Patterns: []string{a.pattern}, UseRegex: true}
		matches := grep.SearchFiles(javaFiles, opts)
		if len(matches) == 0 {
			continue
		}
		out = append(out, types.Finding{
			ID: a.id, Title: a.title, Description: a.remediation,
			Severity: a.severity, MASVS: a.masvs, CWE: a.cwe, Category: "Advanced",
			Evidence: grep.FormatEvidence(matches, 5), Remediation: a.remediation,
		})
	}
	return out
}

func hashFile(path string) (string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	md5h := md5.New()
	sha := sha256.New()
	if _, err := io.Copy(io.MultiWriter(md5h, sha), f); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(md5h.Sum(nil)), hex.EncodeToString(sha.Sum(nil)), nil
}

func computeStats(findings []types.Finding) types.ScanStats {
	s := types.ScanStats{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case types.SeverityCritical:
			s.Critical++
		case types.SeverityHigh:
			s.High++
		case types.SeverityMedium:
			s.Medium++
		case types.SeverityLow:
			s.Low++
		case types.SeverityInfo:
			s.Info++
		}
	}
	return s
}

func sortFindings(findings []types.Finding) {
	order := map[types.Severity]int{
		types.SeverityCritical: 0,
		types.SeverityHigh:     1,
		types.SeverityMedium:   2,
		types.SeverityLow:      3,
		types.SeverityInfo:     4,
	}
	sort.Slice(findings, func(i, j int) bool {
		return order[findings[i].Severity] < order[findings[j].Severity]
	})
}

func dedupeFindings(findings []types.Finding) []types.Finding {
	seen := map[string]bool{}
	var out []types.Finding
	for _, f := range findings {
		key := f.ID + f.Title
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
