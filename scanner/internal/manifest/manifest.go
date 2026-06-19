package manifest

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	"github.com/apkbugfinder/scanner/internal/grep"
	"github.com/apkbugfinder/scanner/internal/types"
)

var (
	rePackage      = regexp.MustCompile(`package="([^"]+)"`)
	reVersionName  = regexp.MustCompile(`versionName="([^"]+)"`)
	reVersionCode  = regexp.MustCompile(`versionCode="([^"]+)"`)
	reMinSDK       = regexp.MustCompile(`minSdkVersion="([^"]+)"`)
	reTargetSDK    = regexp.MustCompile(`targetSdkVersion="([^"]+)"`)
	rePermission   = regexp.MustCompile(`<uses-permission[^>]+android:name="([^"]+)"`)
	reActivity     = regexp.MustCompile(`<activity[^>]+android:name="([^"]+)"`)
	reService      = regexp.MustCompile(`<service[^>]+android:name="([^"]+)"`)
	reReceiver     = regexp.MustCompile(`<receiver[^>]+android:name="([^"]+)"`)
	reProvider     = regexp.MustCompile(`<provider[^>]+android:name="([^"]+)"`)
	reAllowBackup  = regexp.MustCompile(`android:allowBackup="true"`)
	reDebuggable   = regexp.MustCompile(`android:debuggable="true"`)
	reCleartext    = regexp.MustCompile(`android:usesCleartextTraffic="true"`)
	reExportedTrue = regexp.MustCompile(`android:exported="true"`)
	reNetSecConf   = regexp.MustCompile(`android:networkSecurityConfig="@xml/([^"]+)"`)
)

func Parse(manifestPath string, fileName string, fileSize int64) (types.AppInfo, string, error) {
	info := types.AppInfo{
		FileName:    fileName,
		FileSize:    fileSize,
		Permissions: []string{},
		Activities:  []string{},
		Services:    []string{},
		Receivers:   []string{},
		Providers:   []string{},
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return info, "", err
	}
	content := string(data)

	if m := rePackage.FindStringSubmatch(content); len(m) > 1 {
		info.PackageName = m[1]
	}
	if m := reVersionName.FindStringSubmatch(content); len(m) > 1 {
		info.VersionName = m[1]
	}
	if m := reVersionCode.FindStringSubmatch(content); len(m) > 1 {
		info.VersionCode = m[1]
	}
	if m := reMinSDK.FindStringSubmatch(content); len(m) > 1 {
		info.MinSDK = m[1]
	}
	if m := reTargetSDK.FindStringSubmatch(content); len(m) > 1 {
		info.TargetSDK = m[1]
	}

	info.Permissions = unique(rePermission.FindAllStringSubmatch(content, -1))
	info.Activities = unique(reActivity.FindAllStringSubmatch(content, -1))
	info.Services = unique(reService.FindAllStringSubmatch(content, -1))
	info.Receivers = unique(reReceiver.FindAllStringSubmatch(content, -1))
	info.Providers = unique(reProvider.FindAllStringSubmatch(content, -1))

	if reAllowBackup.MatchString(content) {
		t := true
		info.AllowBackup = &t
	}
	if reDebuggable.MatchString(content) {
		t := true
		info.Debuggable = &t
	}
	if reCleartext.MatchString(content) {
		t := true
		info.UsesCleartextTraffic = &t
	}

	info.ComponentSummary = ComponentSummary(content)

	netConf := ""
	if m := reNetSecConf.FindStringSubmatch(content); len(m) > 1 {
		netConf = m[1]
	}

	return info, netConf, nil
}

func unique(matches [][]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		if len(m) > 1 && !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

func ComponentSummary(content string) types.ComponentSummary {
	return types.ComponentSummary{
		ExportedActivities: countExportedBlocks(content, "<activity"),
		ExportedProviders:  countExportedBlocks(content, "<provider"),
		ExportedReceivers:  countExportedBlocks(content, "<receiver"),
		ExportedServices:   countExportedBlocks(content, "<service"),
	}
}

func countExportedBlocks(content, tag string) int {
	count := 0
	idx := 0
	for {
		start := strings.Index(content[idx:], tag)
		if start == -1 {
			break
		}
		start += idx
		end := strings.Index(content[start:], ">")
		if end == -1 {
			break
		}
		block := content[start : start+end]
		if strings.Contains(block, `android:exported="true"`) {
			count++
		}
		idx = start + end
	}
	return count
}

func ExportedWithoutPermission(manifestPath string) ([]grep.Match, error) {
	f, err := os.Open(manifestPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var matches []grep.Match
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if !strings.Contains(line, `<service`) &&
			!strings.Contains(line, `<activity`) &&
			!strings.Contains(line, `<provider`) &&
			!strings.Contains(line, `<receiver`) {
			continue
		}
		if strings.Contains(line, `android:exported="true"`) && !strings.Contains(line, `android:permission="`) {
			matches = append(matches, grep.Match{
				File:    manifestPath,
				Line:    lineNum,
				Content: strings.TrimSpace(line),
			})
		}
	}
	return matches, scanner.Err()
}

func GrepManifest(manifestPath string, opts grep.Options) ([]grep.Match, error) {
	return grep.SearchFile(manifestPath, opts)
}
