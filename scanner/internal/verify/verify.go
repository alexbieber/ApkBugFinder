// Package verify performs OPT-IN, READ-ONLY liveness checks on discovered secrets.
//
// Safety contract:
//   - Only unauthenticated or read-only/identity endpoints are called.
//   - No write, delete, charge, or state-changing operation is ever performed.
//   - Verification only runs when the caller explicitly enables it.
package verify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/apkbugfinder/scanner/internal/types"
)

// Verifier runs read-only liveness checks with a bounded HTTP client.
type Verifier struct {
	client *http.Client
}

// New returns a Verifier with a conservative timeout.
func New() *Verifier {
	return &Verifier{client: &http.Client{Timeout: 12 * time.Second}}
}

// VerifyAll mutates secrets in place with liveness results. Read-only.
func (v *Verifier) VerifyAll(ctx context.Context, secrets []types.Secret) []types.Secret {
	for i := range secrets {
		s := &secrets[i]
		if s.Verified != types.VerifyUnknown {
			continue // skipped types stay skipped
		}
		status, note, reportable := v.verifyOne(ctx, s.Provider, s.FullValue())
		s.Verified = status
		s.VerifyNote = note
		s.Reportable = reportable
	}
	return secrets
}

func (v *Verifier) verifyOne(ctx context.Context, provider, value string) (types.VerifyStatus, string, bool) {
	switch provider {
	case "google":
		return v.verifyGoogle(ctx, value)
	case "stripe":
		return v.verifyStripe(ctx, value)
	case "aws":
		return v.verifyAWS(value)
	case "github":
		return v.verifyGitHub(ctx, value)
	case "slack":
		return v.verifySlack(ctx, value)
	case "firebase":
		return v.verifyFirebase(ctx, value)
	case "jwt":
		return verifyJWT(value)
	default:
		return types.VerifySkipped, "No liveness check available.", false
	}
}

// verifyGoogle tests a key against billable Maps endpoints (read-only).
// Static Maps abuse is the classic payable finding for an unrestricted key.
func (v *Verifier) verifyGoogle(ctx context.Context, key string) (types.VerifyStatus, string, bool) {
	// 1) Static Maps — a 200 image means the key is billable & unrestricted.
	body, code, err := v.get(ctx, "https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key="+key, nil)
	if err == nil {
		if code == 200 && len(body) > 0 && !strings.Contains(string(body), "denied") {
			return types.VerifyLive, "Key generates billable Static Maps images (unrestricted) — attacker can run up charges. Reportable.", true
		}
		if code == 403 || code == 401 {
			// fall through to geocoding to distinguish dead vs API-restricted
		}
	}

	// 2) Geocoding fallback.
	gbody, _, gerr := v.get(ctx, "https://maps.googleapis.com/maps/api/geocode/json?address=test&key="+key, nil)
	if gerr != nil {
		return types.VerifyError, gerr.Error(), false
	}
	var r struct {
		Status       string `json:"status"`
		ErrorMessage string `json:"error_message"`
	}
	_ = json.Unmarshal(gbody, &r)
	switch r.Status {
	case "OK", "ZERO_RESULTS":
		return types.VerifyLive, "Key accepted by Google Geocoding API (unrestricted). Reportable.", true
	case "REQUEST_DENIED":
		lower := strings.ToLower(r.ErrorMessage)
		if strings.Contains(lower, "not activated") || strings.Contains(lower, "not authorized") {
			return types.VerifyInvalid, "Key is valid but API-restricted (geocoding/staticmap not enabled). Likely not exploitable: "+r.ErrorMessage, false
		}
		return types.VerifyInvalid, "Request denied: "+r.ErrorMessage, false
	default:
		return types.VerifyError, "Unexpected status: "+r.Status, false
	}
}

// verifyStripe calls the read-only /v1/balance endpoint (no charges).
func (v *Verifier) verifyStripe(ctx context.Context, key string) (types.VerifyStatus, string, bool) {
	body, code, err := v.get(ctx, "https://api.stripe.com/v1/balance", map[string]string{
		"Authorization": "Bearer " + key,
	})
	if err != nil {
		return types.VerifyError, err.Error(), false
	}
	if code == 200 {
		return types.VerifyLive, "LIVE Stripe secret key — /v1/balance returned 200. Critical, immediately reportable.", true
	}
	if code == 401 {
		return types.VerifyInvalid, "Stripe key rejected (401).", false
	}
	return types.VerifyError, fmt.Sprintf("Stripe responded %d: %s", code, snippet(body)), false
}

// verifyAWS validates an access key shape only (full STS check needs the secret).
func (v *Verifier) verifyAWS(key string) (types.VerifyStatus, string, bool) {
	if len(key) == 20 && strings.HasPrefix(key, "AKIA") {
		return types.VerifySkipped,
			"AWS access key ID found. Run read-only check manually: aws sts get-caller-identity (needs paired secret).",
			false
	}
	return types.VerifyInvalid, "Malformed AWS key ID.", false
}

// verifyGitHub calls the read-only /user endpoint.
func (v *Verifier) verifyGitHub(ctx context.Context, token string) (types.VerifyStatus, string, bool) {
	body, code, err := v.get(ctx, "https://api.github.com/user", map[string]string{
		"Authorization": "Bearer " + token,
		"User-Agent":    "apkbugfinder",
	})
	if err != nil {
		return types.VerifyError, err.Error(), false
	}
	if code == 200 {
		var r struct {
			Login string `json:"login"`
		}
		_ = json.Unmarshal(body, &r)
		return types.VerifyLive, "LIVE GitHub token for user @" + r.Login + ". Reportable.", true
	}
	if code == 401 {
		return types.VerifyInvalid, "GitHub token invalid/revoked (401).", false
	}
	return types.VerifyError, fmt.Sprintf("GitHub responded %d", code), false
}

// verifySlack calls auth.test (read-only).
func (v *Verifier) verifySlack(ctx context.Context, token string) (types.VerifyStatus, string, bool) {
	body, _, err := v.get(ctx, "https://slack.com/api/auth.test", map[string]string{
		"Authorization": "Bearer " + token,
	})
	if err != nil {
		return types.VerifyError, err.Error(), false
	}
	var r struct {
		OK   bool   `json:"ok"`
		Team string `json:"team"`
	}
	_ = json.Unmarshal(body, &r)
	if r.OK {
		return types.VerifyLive, "LIVE Slack token for team " + r.Team + ". Reportable.", true
	}
	return types.VerifyInvalid, "Slack token invalid.", false
}

// verifyFirebase checks for an open (no-auth) database read.
func (v *Verifier) verifyFirebase(ctx context.Context, dbURL string) (types.VerifyStatus, string, bool) {
	u := strings.TrimRight(dbURL, "/") + "/.json"
	body, code, err := v.get(ctx, u, nil)
	if err != nil {
		return types.VerifyError, err.Error(), false
	}
	if code == 200 && !strings.Contains(string(body), "Permission denied") {
		return types.VerifyLive, "Firebase DB readable WITHOUT auth — data exposure. Reportable.", true
	}
	switch code {
	case 401, 403:
		return types.VerifyInvalid, "Firebase rules deny anonymous read (protected).", false
	case 423:
		return types.VerifyInvalid, "Firebase DB is locked/disabled (423) — not accessible.", false
	case 404:
		return types.VerifyInvalid, "Firebase DB not found (404) — likely decommissioned.", false
	}
	if strings.Contains(string(body), "Permission denied") {
		return types.VerifyInvalid, "Firebase rules deny anonymous read (protected).", false
	}
	return types.VerifyError, fmt.Sprintf("Firebase responded %d", code), false
}

// verifyJWT decodes the JWT locally and inspects expiry (no network call).
func verifyJWT(token string) (types.VerifyStatus, string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return types.VerifyInvalid, "Malformed JWT.", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return types.VerifyError, "Cannot decode JWT payload.", false
	}
	var claims struct {
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return types.VerifyError, "Cannot parse JWT claims.", false
	}
	if claims.Exp == 0 {
		return types.VerifyLive, "JWT has no expiry (exp missing) — never expires. High risk if backend accepts it.", true
	}
	if time.Now().Unix() > claims.Exp {
		return types.VerifyExpired, fmt.Sprintf("JWT expired at %s.", time.Unix(claims.Exp, 0).UTC().Format(time.RFC3339)), false
	}
	return types.VerifyLive, fmt.Sprintf("JWT valid until %s (iss=%s). Replay against API to confirm.", time.Unix(claims.Exp, 0).UTC().Format(time.RFC3339), claims.Iss), true
}

// get performs a read-only GET with one retry on transient (network/timeout) errors.
func (v *Verifier) get(ctx context.Context, url string, headers map[string]string) ([]byte, int, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, 0, err
		}
		for k, val := range headers {
			req.Header.Set(k, val)
		}
		resp, err := v.client.Do(req)
		if err != nil {
			lastErr = err
			continue // retry transient failures
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return body, resp.StatusCode, nil
	}
	return nil, 0, lastErr
}

func snippet(b []byte) string {
	s := string(b)
	if len(s) > 120 {
		return s[:120]
	}
	return s
}
