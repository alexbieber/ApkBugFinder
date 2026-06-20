package recon

import (
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/apkbugfinder/scanner/internal/filter"
	"github.com/apkbugfinder/scanner/internal/types"
)

var (
	reURL        = regexp.MustCompile(`https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}`)
	reS3         = regexp.MustCompile(`(?i)([a-z0-9.-]+\.s3[a-z0-9.-]*\.amazonaws\.com|s3://[a-z0-9.-]+|[a-z0-9.-]+\.s3\.amazonaws\.com)`)
	reFirebase   = regexp.MustCompile(`https?://[a-z0-9-]+\.firebaseio\.com|https?://[a-z0-9-]+\.firebasedatabase\.app`)
	reGraphQL    = regexp.MustCompile(`(?i)https?://[a-zA-Z0-9._-]+/[a-zA-Z0-9/_-]*graphql[a-zA-Z0-9/_-]*`)
	reBearerHdr  = regexp.MustCompile(`(?i)(Authorization|X-Api-Key|X-Auth-Token|api[_-]?key|Bearer\s|HMAC|X-Signature)`)
	reNoisyHost  = regexp.MustCompile(`(?i)(w3\.org|schemas\.android\.com|apache\.org|xmlpull\.org|googleapis\.com/auth|gstatic\.com|googletagmanager|crashlytics|google-analytics|fonts\.g|play\.google\.com|developer\.android)`)
)

// Analyze extracts the backend attack surface from decompiled sources and resources.
func Analyze(javaFiles, xmlFiles []string, packageName string) *types.ReconResult {
	res := &types.ReconResult{}

	hosts := map[string]bool{}
	endpoints := map[string]types.Endpoint{}
	s3 := map[string]bool{}
	fb := map[string]bool{}
	gql := map[string]bool{}
	auth := map[string]bool{}

	scan := func(files []string, appOnly bool) {
		for _, f := range files {
			if appOnly && !filter.IsAppCode(f, packageName) {
				continue
			}
			content, err := readFileLimited(f)
			if err != nil {
				continue
			}
			base := filepath.Base(f)

			for _, m := range reURL.FindAllString(content, -1) {
				clean := trimURL(m)
				u, err := url.Parse(clean)
				if err != nil || u.Host == "" {
					continue
				}
				if !isValidHost(u.Host) || reNoisyHost.MatchString(u.Host) {
					continue
				}
				hosts[u.Host] = true
				key := u.Scheme + "://" + u.Host + u.Path
				if _, ok := endpoints[key]; !ok && looksLikeAPI(u) {
					endpoints[key] = types.Endpoint{
						URL:    key,
						Host:   u.Host,
						Scheme: u.Scheme,
						File:   base,
					}
				}
			}
			for _, m := range reS3.FindAllString(content, -1) {
				s3[strings.ToLower(m)] = true
			}
			for _, m := range reFirebase.FindAllString(content, -1) {
				fb[m] = true
			}
			for _, m := range reGraphQL.FindAllString(content, -1) {
				gql[trimURL(m)] = true
			}
			for _, m := range reBearerHdr.FindAllString(content, -1) {
				auth[normalizeAuth(m)] = true
			}
		}
	}

	scan(javaFiles, true)
	scan(xmlFiles, false)

	res.Hosts = sortedKeys(hosts)
	res.S3Buckets = sortedKeys(s3)
	res.FirebaseDBs = sortedKeys(fb)
	res.GraphQL = sortedKeys(gql)
	res.AuthSchemes = sortedKeys(auth)
	for _, e := range endpoints {
		res.Endpoints = append(res.Endpoints, e)
	}
	sort.Slice(res.Endpoints, func(i, j int) bool { return res.Endpoints[i].URL < res.Endpoints[j].URL })

	return res
}

// looksLikeAPI keeps endpoints that resemble backend APIs, drops static asset/doc links.
func looksLikeAPI(u *url.URL) bool {
	host := strings.ToLower(u.Host)
	path := strings.ToLower(u.Path)

	if strings.HasPrefix(host, "api.") || strings.Contains(host, "api-") || strings.Contains(host, ".api.") {
		return true
	}
	for _, kw := range []string{"/api", "/v1", "/v2", "/v3", "/rest", "/graphql", "/oauth", "/auth", "/token", "/login", "/user", "/account", "/mobile", "/gateway", "/rpc"} {
		if strings.Contains(path, kw) {
			return true
		}
	}
	// Hosts with no path are useful as attack surface even without API keywords.
	return false
}

var reValidHost = regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:\d+)?$`)

// isValidHost rejects parse artifacts and malformed hosts.
func isValidHost(h string) bool {
	if len(h) < 4 || len(h) > 253 {
		return false
	}
	return reValidHost.MatchString(h)
}

func trimURL(s string) string {
	s = strings.TrimRight(s, `.,;:'")\`)
	s = strings.Split(s, `\n`)[0]
	s = strings.Split(s, `"`)[0]
	return s
}

func normalizeAuth(s string) string {
	s = strings.TrimSpace(s)
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "bearer"):
		return "Bearer token"
	case strings.Contains(lower, "x-api-key") || strings.Contains(lower, "api_key") || strings.Contains(lower, "apikey") || strings.Contains(lower, "api-key"):
		return "API key header"
	case strings.Contains(lower, "hmac") || strings.Contains(lower, "x-signature"):
		return "HMAC request signing"
	case strings.Contains(lower, "authorization"):
		return "Authorization header"
	case strings.Contains(lower, "x-auth-token"):
		return "X-Auth-Token"
	default:
		return s
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
