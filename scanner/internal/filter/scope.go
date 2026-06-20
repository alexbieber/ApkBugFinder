package filter

import (
	"path/filepath"
	"strings"
)

// Third-party SDK/library path prefixes under JADX sources/ (lowercase, trailing slash).
var sdkPrefixes = []string{
	"com/google/",
	"androidx/",
	"android/support/",
	"android/arch/",
	"android/app/",
	"android/content/",
	"android/os/",
	"android/webkit/",
	"android/net/",
	"android/media/",
	"android/graphics/",
	"android/view/",
	"android/util/",
	"android/text/",
	"android/database/",
	"android/hardware/",
	"android/security/",
	"org/apache/",
	"org/chromium/",
	"org/json/",
	"org/xmlpull/",
	"org/jetbrains/",
	"org/intellij/",
	"okhttp3/",
	"okio/",
	"retrofit2/",
	"kotlin/",
	"kotlinx/",
	"io/realm/",
	"com/facebook/",
	"com/squareup/",
	"com/bumptech/",
	"com/crashlytics/",
	"com/adjust/",
	"com/appsflyer/",
	"com/amplitude/",
	"com/fasterxml/",
	"com/airbnb/",
	"com/github/",
	"dalvik/",
	"javax/",
	"sun/",
	"junit/",
	"org/junit/",
	"org/hamcrest/",
	"org/mockito/",
}

// PackagePath converts org.telegram.messenger → org/telegram/messenger.
func PackagePath(packageName string) string {
	if packageName == "" {
		return ""
	}
	return strings.ToLower(strings.ReplaceAll(packageName, ".", "/"))
}

// SourceRelativePath returns the path under sources/ (e.g. org/telegram/Foo.java).
func SourceRelativePath(filePath string) string {
	norm := filepath.ToSlash(filePath)
	idx := strings.Index(norm, "/sources/")
	if idx >= 0 {
		return strings.ToLower(norm[idx+len("/sources/"):])
	}
	return strings.ToLower(filepath.Base(norm))
}

// IsThirdPartyLibrary reports whether a decompiled file belongs to a known SDK path.
func IsThirdPartyLibrary(filePath string) bool {
	rel := SourceRelativePath(filePath)
	for _, prefix := range sdkPrefixes {
		if strings.HasPrefix(rel, prefix) {
			return true
		}
	}
	return false
}

// IsAppCode reports whether the file is likely application code (not a bundled SDK).
func IsAppCode(filePath, packageName string) bool {
	rel := SourceRelativePath(filePath)
	pkg := PackagePath(packageName)
	if pkg != "" && strings.HasPrefix(rel, pkg+"/") {
		return true
	}
	if IsThirdPartyLibrary(filePath) {
		return false
	}
	if pkg != "" {
		if strings.Contains(rel, "/"+pkg+"/") {
			return true
		}
		parts := strings.Split(pkg, "/")
		if len(parts) >= 2 {
			base := parts[0] + "/" + parts[1]
			if strings.HasPrefix(rel, base+"/") {
				return true
			}
		}
	}
	return rel != ""
}

// FilterAppJavaFiles keeps only application-scoped Java sources for code analysis.
func FilterAppJavaFiles(files []string, packageName string) []string {
	var out []string
	for _, f := range files {
		if IsAppCode(f, packageName) {
			out = append(out, f)
		}
	}
	return out
}

// FilterMatches keeps matches that hit application code (or all for manifest/resources).
func FilterMatches(matches []Match, packageName string) []Match {
	var out []Match
	for _, m := range matches {
		if IsAppCode(m.File, packageName) {
			out = append(out, m)
		}
	}
	return out
}

// Match mirrors grep.Match to avoid import cycles in filter helpers used by analyzer.
type Match struct {
	File    string
	Line    int
	Content string
}
