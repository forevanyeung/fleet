package sso

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/fleetdm/fleet/v4/server/datastore/redis"
	redigo "github.com/gomodule/redigo/redis"
)

// fleetctl login with SSO follows the shape of an OAuth 2.0 authorization code
// grant for native apps (RFC 8252) protected with PKCE (RFC 7636):
//
//  1. fleetctl listens on a loopback port, then opens the browser at Fleet's
//     fleetctl SSO endpoint with its loopback redirect URI, an opaque state and
//     an S256 code challenge.
//  2. Fleet starts a regular SAML login, remembering the fleetctl request
//     against the SSO session.
//  3. When the IdP posts back, Fleet verifies the SAML response as usual and,
//     instead of handing the browser a session, asks the user to approve the
//     login. The page shows a verification code derived from the code
//     challenge, which fleetctl also prints, so that the user can tell their
//     own fleetctl apart from another app that started a login.
//  4. Once approved, Fleet redirects the browser to the loopback URI with a
//     short-lived, single-use authorization code.
//  5. fleetctl redeems the code together with the code verifier for a regular
//     Fleet session token.
//
// The session token never goes through the browser, and an intercepted code is
// useless without the verifier that only the fleetctl process holds.

const (
	fleetctlRequestKeyPrefix = "sso:fleetctl:request:"
	fleetctlCodeKeyPrefix    = "sso:fleetctl:code:"
	fleetctlConsentKeyPrefix = "sso:fleetctl:consent:"

	// FleetctlCodeLifetimeSecs is how long an authorization code can be
	// redeemed for. fleetctl redeems it as soon as the browser hits the loopback
	// listener, so this only needs to cover a round trip.
	FleetctlCodeLifetimeSecs = 60

	// FleetctlConsentLifetimeSecs is how long the user has to approve a login.
	FleetctlConsentLifetimeSecs = 5 * 60

	// FleetctlCallbackPath is the path fleetctl's loopback listener serves.
	FleetctlCallbackPath = "/callback"
)

// FleetctlRequest is the fleetctl state carried across the SAML round trip.
type FleetctlRequest struct {
	RedirectURI   string `json:"redirect_uri"`
	State         string `json:"state"`
	CodeChallenge string `json:"code_challenge"`
}

// FleetctlCode is what an authorization code can be redeemed for.
type FleetctlCode struct {
	UserID        uint   `json:"user_id"`
	RedirectURI   string `json:"redirect_uri"`
	CodeChallenge string `json:"code_challenge"`
}

// FleetctlConsent is a login awaiting the user's approval.
type FleetctlConsent struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
	FleetctlRequest
}

// getDelScript atomically reads and deletes a key, so that a value can only be
// consumed once even if requests race. GETDEL would do, but needs Redis 6.2.
var getDelScript = redigo.NewScript(1, `
local v = redis.call('GET', KEYS[1])
if v then redis.call('DEL', KEYS[1]) end
return v
`)

func (s *store) getDel(key string) (string, error) {
	conn := redis.ConfigureDoer(s.pool, s.pool.Get())
	defer conn.Close()
	return redigo.String(getDelScript.Do(conn, key))
}

func (s *store) setJSON(key string, v any, lifetimeSecs uint) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	conn := redis.ConfigureDoer(s.pool, s.pool.Get())
	defer conn.Close()
	_, err = conn.Do("SETEX", key, lifetimeSecs, b)
	return err
}

func (s *store) CreateFleetctlRequest(sessionID string, req FleetctlRequest, lifetimeSecs uint) error {
	if _, ok := sessionKey(sessionID); !ok {
		return errors.New("invalid session ID format")
	}
	return s.setJSON(fleetctlRequestKeyPrefix+sessionID, req, lifetimeSecs)
}

func (s *store) ConsumeFleetctlRequest(sessionID string) (*FleetctlRequest, error) {
	if _, ok := sessionKey(sessionID); !ok {
		return nil, nil
	}
	val, err := s.getDel(fleetctlRequestKeyPrefix + sessionID)
	if err != nil {
		if errors.Is(err, redigo.ErrNil) {
			return nil, nil
		}
		return nil, fmt.Errorf("consume fleetctl sso request: %w", err)
	}
	var req FleetctlRequest
	if err := json.Unmarshal([]byte(val), &req); err != nil {
		return nil, fmt.Errorf("decode fleetctl sso request: %w", err)
	}
	return &req, nil
}

// Bearer tokens are stored by their hash so a Redis dump doesn't leak
// redeemable values.
func hashedKey(prefix, token string) string {
	sum := sha256.Sum256([]byte(token))
	return prefix + base64.RawURLEncoding.EncodeToString(sum[:])
}

// consumeJSON loads and deletes the value at key into v, returning
// ErrSessionNotFound if it doesn't exist or has expired.
func (s *store) consumeJSON(key string, v any) error {
	val, err := s.getDel(key)
	if err != nil {
		if errors.Is(err, redigo.ErrNil) {
			return ErrSessionNotFound
		}
		return err
	}
	return json.Unmarshal([]byte(val), v)
}

func (s *store) CreateFleetctlCode(code string, data FleetctlCode) error {
	return s.setJSON(hashedKey(fleetctlCodeKeyPrefix, code), data, FleetctlCodeLifetimeSecs)
}

func (s *store) ConsumeFleetctlCode(code string) (*FleetctlCode, error) {
	var data FleetctlCode
	if err := s.consumeJSON(hashedKey(fleetctlCodeKeyPrefix, code), &data); err != nil {
		return nil, err
	}
	return &data, nil
}

func (s *store) CreateFleetctlConsent(consentID string, data FleetctlConsent) error {
	return s.setJSON(hashedKey(fleetctlConsentKeyPrefix, consentID), data, FleetctlConsentLifetimeSecs)
}

func (s *store) ConsumeFleetctlConsent(consentID string) (*FleetctlConsent, error) {
	var data FleetctlConsent
	if err := s.consumeJSON(hashedKey(fleetctlConsentKeyPrefix, consentID), &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// verificationCodeAlphabet leaves out vowels so codes can't spell words, and
// look-alike characters.
const verificationCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// FleetctlVerificationCode derives the code shown both by fleetctl and on the
// consent page, formatted as XXXX-XXXX. It is not a secret: it only lets the
// user check that the login they are approving is the one their terminal
// started.
func FleetctlVerificationCode(codeChallenge string) string {
	sum := sha256.Sum256([]byte("fleetctl-verification-code:" + codeChallenge))
	code := make([]byte, 0, 9)
	for i, b := range sum[:8] {
		if i == 4 {
			code = append(code, '-')
		}
		code = append(code, verificationCodeAlphabet[int(b)%len(verificationCodeAlphabet)])
	}
	return string(code)
}

// ValidateFleetctlRedirectURI only accepts plain-HTTP loopback URIs, as RFC
// 8252 section 7.3 prescribes for native apps. Anything else would let a
// crafted login link send the authorization code off the user's machine.
func ValidateFleetctlRedirectURI(redirectURI string) error {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return errors.New("invalid redirect_uri")
	}
	if u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != FleetctlCallbackPath {
		return fmt.Errorf("redirect_uri must be of the form http://127.0.0.1:<port>%s", FleetctlCallbackPath)
	}
	// "localhost" is deliberately not accepted: it can resolve to a non-loopback
	// address (RFC 8252 section 8.3).
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		return errors.New("redirect_uri must point to a loopback IP address")
	}
	if u.Port() == "" {
		return errors.New("redirect_uri must include a port")
	}
	return nil
}

// ValidateFleetctlCodeChallenge checks that the challenge is a base64url
// encoded SHA-256 digest, the only method (S256) supported.
func ValidateFleetctlCodeChallenge(challenge string) error {
	b, err := base64.RawURLEncoding.Strict().DecodeString(challenge)
	if err != nil || len(b) != sha256.Size {
		return errors.New("code_challenge must be a base64url encoded SHA-256 digest (S256)")
	}
	return nil
}

// VerifyFleetctlCodeVerifier reports whether the verifier matches the S256
// challenge it was created for.
func VerifyFleetctlCodeVerifier(challenge, verifier string) bool {
	// RFC 7636 section 4.1.
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
