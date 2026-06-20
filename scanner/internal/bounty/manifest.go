package bounty

import (
	"os"
	"regexp"
	"strings"
)

// ExportedComponent is a manifest component with export and intent metadata.
type ExportedComponent struct {
	Type       string
	Name       string
	Exported   bool
	Permission string
	Schemes    []string
	Actions    []string
}

var (
	reComponentOpen  = regexp.MustCompile(`(?i)<(activity|service|receiver|provider)\s+([^>]+)>`)
	reAttrName       = regexp.MustCompile(`android:name="([^"]+)"`)
	reAttrExported   = regexp.MustCompile(`android:exported="(true|false)"`)
	reAttrPermission = regexp.MustCompile(`android:permission="([^"]+)"`)
	reIntentFilter   = regexp.MustCompile(`(?is)<intent-filter>(.*?)</intent-filter>`)
	reAction         = regexp.MustCompile(`android:name="([^"]+)"`)
	reDataScheme     = regexp.MustCompile(`android:scheme="([^"]+)"`)
)

// ParseExportedComponents extracts exported components and their intent filters.
func ParseExportedComponents(manifestPath string) ([]ExportedComponent, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	content := string(data)

	var components []ExportedComponent
	for _, m := range reComponentOpen.FindAllStringSubmatch(content, -1) {
		if len(m) < 3 {
			continue
		}
		compType := strings.ToLower(m[1])
		attrs := m[2]

		nameM := reAttrName.FindStringSubmatch(attrs)
		if len(nameM) < 2 {
			continue
		}
		name := nameM[1]

		exported := false
		if em := reAttrExported.FindStringSubmatch(attrs); len(em) > 1 {
			exported = em[1] == "true"
		}

		if !exported {
			continue
		}

		perm := ""
		if pm := reAttrPermission.FindStringSubmatch(attrs); len(pm) > 1 {
			perm = pm[1]
		}

		// Grab intent filters near this component (within next 2k chars).
		idx := strings.Index(content, m[0])
		end := idx + 2048
		if end > len(content) {
			end = len(content)
		}
		block := content[idx:end]

		var schemes, actions []string
		for _, f := range reIntentFilter.FindAllStringSubmatch(block, -1) {
			if len(f) < 2 {
				continue
			}
			filter := f[1]
			for _, a := range reAction.FindAllStringSubmatch(filter, -1) {
				if len(a) > 1 {
					actions = append(actions, a[1])
				}
			}
			for _, s := range reDataScheme.FindAllStringSubmatch(filter, -1) {
				if len(s) > 1 {
					schemes = append(schemes, s[1])
				}
			}
		}

		components = append(components, ExportedComponent{
			Type:       compType,
			Name:       name,
			Exported:   true,
			Permission: perm,
			Schemes:    uniqueStr(schemes),
			Actions:    uniqueStr(actions),
		})
	}
	return components, nil
}

func uniqueStr(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// IsDeepLinkComponent returns true if component handles VIEW/BROWSABLE deep links.
func IsDeepLinkComponent(c ExportedComponent) bool {
	for _, a := range c.Actions {
		if a == "android.intent.action.VIEW" {
			return len(c.Schemes) > 0
		}
	}
	return false
}
