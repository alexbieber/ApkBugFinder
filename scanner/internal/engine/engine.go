package engine

import (
	"context"
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

	"github.com/apkbugfinder/scanner/internal/analyzer"
	"github.com/apkbugfinder/scanner/internal/bounty"
	"github.com/apkbugfinder/scanner/internal/decompile"
	"github.com/apkbugfinder/scanner/internal/filter"
	"github.com/apkbugfinder/scanner/internal/grep"
	"github.com/apkbugfinder/scanner/internal/manifest"
	"github.com/apkbugfinder/scanner/internal/recon"
	"github.com/apkbugfinder/scanner/internal/rules"
	"github.com/apkbugfinder/scanner/internal/types"
	"github.com/apkbugfinder/scanner/internal/verify"
	"github.com/google/uuid"
)

type Options struct {
	WorkDir                string
	PackageName            string // optional override; otherwise read from manifest
	IncludeLibraryFindings bool
	// VerifySecrets enables OPT-IN, READ-ONLY liveness checks on discovered secrets.
	VerifySecrets bool
	OnProgress    func(stage string, progress float64, message string)
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

	report("analyzing", 55, "Running OWASP MASVS rules (strict mode)…")
	packageName := appInfo.PackageName
	var findings []types.Finding

	for _, rule := range rules.All() {
		if f, matches := runRule(rule, dec, javaFiles, xmlResFiles, packageName); f != nil {
			analyzer.ScoreFinding(f, packageName, matches)
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
			Confidence:  types.ConfidenceConfirmed,
			Scope:       types.ScopeManifest,
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
			Confidence:  types.ConfidenceMedium,
			Scope:       types.ScopeResource,
			MASVS:       "MSTG-NETWORK-1",
			CWE:         "CWE-693",
			Category:    "Network",
			Remediation: "Add res/xml/network_security_config.xml and reference in manifest.",
			Reference:   "https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements",
		})
	}

	report("analyzing", 85, "Running advanced checks…")
	findings = append(findings, advancedChecks(javaFiles, packageName)...)

	report("analyzing", 90, "Running bounty-hunter (high-impact vulns)…")
	findings = mergeFindings(findings, bounty.Analyze(dec.ManifestPath, javaFiles, packageName, appInfo))

	for i := range findings {
		bounty.EnrichFinding(&findings[i])
	}

	report("analyzing", 94, "Mapping backend attack surface…")
	reconResult := recon.Analyze(javaFiles, xmlResFiles, packageName)
	reconResult.Secrets = recon.ExtractSecrets(javaFiles, xmlResFiles, packageName)

	if opts.VerifySecrets && len(reconResult.Secrets) > 0 {
		report("analyzing", 97, "Verifying secrets (read-only liveness checks)…")
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		reconResult.Secrets = verify.New().VerifyAll(ctx, reconResult.Secrets)
		cancel()
		reconResult.SecretsTested = true
		findings = append(findings, verifiedSecretFindings(reconResult.Secrets)...)
	}

	findings = filterFindings(findings, opts.IncludeLibraryFindings)
	findings = dedupeFindings(findings)
	sortByBountyImpact(findings)
	stats := computeStats(findings)
	stats.LiveSecrets = countLiveSecrets(reconResult.Secrets)

	report("complete", 100, "Scan complete")

	return &types.ScanResult{
		ID:         uuid.New().String(),
		ScannedAt:  time.Now().UTC().Format(time.RFC3339),
		DurationMs: time.Since(start).Milliseconds(),
		Engine:     "apkbugfinder-scanner/4.0 (MASVS + bounty + recon + verify)",
		AppInfo:    appInfo,
		Findings:   findings,
		Stats:      stats,
		Recon:      reconResult,
	}, nil
}

// verifiedSecretFindings promotes confirmed-live secrets to top-priority findings.
func verifiedSecretFindings(secrets []types.Secret) []types.Finding {
	var out []types.Finding
	for _, s := range secrets {
		if s.Verified != types.VerifyLive || !s.Reportable {
			continue
		}
		out = append(out, types.Finding{
			ID:             "VERIFIED-LIVE-" + strings.ToUpper(s.Provider),
			Title:          "VERIFIED LIVE secret — " + s.Type,
			Description:    s.VerifyNote,
			Severity:       types.SeverityCritical,
			Confidence:     types.ConfidenceConfirmed,
			Scope:          types.ScopeAppCode,
			Impact:         10,
			BountyEligible: true,
			AttackSurface:  s.Provider + " credential (" + s.Redacted + ")",
			ExploitHint:    "Confirmed live via read-only check. Capture request/response as PoC and submit. " + s.VerifyNote,
			MASVS:          "MSTG-STORAGE-14",
			CWE:            "CWE-798",
			Category:       "Bounty · Verified Secret",
			Evidence:       s.Type + " in " + s.File + " — " + s.Redacted,
			File:           s.File,
			Remediation:    "Revoke/rotate immediately; move secret server-side.",
		})
	}
	return out
}

func countLiveSecrets(secrets []types.Secret) int {
	n := 0
	for _, s := range secrets {
		if s.Verified == types.VerifyLive {
			n++
		}
	}
	return n
}

func runRule(rule rules.Rule, dec *decompile.Result, javaFiles, xmlFiles []string, packageName string) (*types.Finding, []grep.Match) {
	switch rule.Scope {
	case rules.ScopeCertFiles:
		f := runCertRule(rule, dec.ResourcesPath)
		return f, nil
	case rules.ScopeManifest:
		f := runManifestRule(rule, dec.ManifestPath)
		if f == nil {
			return nil, nil
		}
		return f, nil
	default:
		files := javaFiles
		if rule.Scope == rules.ScopeResourceXML {
			files = xmlFiles
		}
		return runFileRule(rule, files, packageName)
	}
}

func runFileRule(rule rules.Rule, files []string, packageName string) (*types.Finding, []grep.Match) {
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
			if !analyzer.ValidateMatch(rule.ID, m) {
				continue
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
			}, nil
		}
		if rule.ID == "MSTG-CODE-9-OBFUSC" || strings.HasPrefix(rule.ID, "MSTG-RESILIENCE") || rule.ID == "MSTG-NETWORK-6-PROVIDER" || rule.ID == "MSTG-PLATFORM-10-WCLEANUP" {
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
			}, all
		}
		return nil, nil
	}

	if len(all) == 0 {
		return nil, nil
	}

	// Prefer app-code evidence in report output.
	display := preferAppMatches(all, packageName)

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
		Evidence:    grep.FormatEvidence(display, 10),
		File:        filepath.Base(display[0].File),
		Remediation: rule.Remediation,
		Reference:   rule.Reference,
	}, all
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
		Confidence:  types.ConfidenceConfirmed,
		Scope:       types.ScopeManifest,
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

// advancedChecks — high-signal secret and crypto patterns in app code.
func advancedChecks(javaFiles []string, packageName string) []types.Finding {
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
		matches = analyzer.FilterValidatedMatches(a.id, matches)
		if len(matches) == 0 {
			continue
		}
		display := preferAppMatches(matches, packageName)
		if len(display) == 0 {
			continue
		}
		f := types.Finding{
			ID: a.id, Title: a.title, Description: a.remediation,
			Severity: a.severity, MASVS: a.masvs, CWE: a.cwe, Category: "Advanced",
			Evidence: grep.FormatEvidence(display, 5), Remediation: a.remediation,
			File: filepath.Base(display[0].File),
		}
		analyzer.ScoreFinding(&f, packageName, matches)
		if f.Confidence == types.ConfidenceLow && f.Scope == types.ScopeLibrary {
			continue
		}
		out = append(out, f)
	}
	return out
}

func preferAppMatches(matches []grep.Match, packageName string) []grep.Match {
	var app []grep.Match
	for _, m := range matches {
		if filter.IsAppCode(m.File, packageName) {
			app = append(app, m)
		}
	}
	if len(app) > 0 {
		return app
	}
	return matches
}

func filterFindings(findings []types.Finding, includeLibrary bool) []types.Finding {
	if includeLibrary {
		return findings
	}
	var out []types.Finding
	for _, f := range findings {
		if f.Confidence == types.ConfidenceLow && f.Scope == types.ScopeLibrary {
			continue
		}
		out = append(out, f)
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
		if f.Confidence == types.ConfidenceConfirmed {
			s.Confirmed++
		}
		if analyzer.IsActionable(f) {
			s.Actionable++
		}
		if f.BountyEligible {
			s.BountyEligible++
			if f.Impact >= 9 {
				s.BountyCritical++
			}
		}
	}
	return s
}

func sortByBountyImpact(findings []types.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.BountyEligible != b.BountyEligible {
			return a.BountyEligible
		}
		if a.Impact != b.Impact {
			return a.Impact > b.Impact
		}
		order := map[types.Severity]int{
			types.SeverityCritical: 0,
			types.SeverityHigh:     1,
			types.SeverityMedium:   2,
			types.SeverityLow:      3,
			types.SeverityInfo:     4,
		}
		return order[a.Severity] < order[b.Severity]
	})
}

func mergeFindings(base, extra []types.Finding) []types.Finding {
	seen := map[string]bool{}
	for _, f := range base {
		seen[f.ID+"|"+f.File] = true
	}
	for _, f := range extra {
		key := f.ID + "|" + f.File
		if seen[key] {
			continue
		}
		seen[key] = true
		base = append(base, f)
	}
	return base
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
