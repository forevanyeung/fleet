package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/fleetdm/fleet/v4/server/datastore/redis/redistest"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mock"
	"github.com/fleetdm/fleet/v4/server/sso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fleetctlTestPKCE() (verifier, challenge string) {
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func newFleetctlSSOTestService(t *testing.T) (fleet.Service, context.Context, *mock.Store, sso.SessionStore) {
	ds := new(mock.Store)
	pool := redistest.SetupRedis(t, "sso:", false, false, false)
	svc, ctx := newTestServiceWithConfig(t, ds, config.TestConfig(), nil, nil, &TestServerOpts{
		Pool:    pool,
		License: &fleet.LicenseInfo{Tier: fleet.TierPremium},
	})
	ds.AppConfigFunc = func(ctx context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{
			ServerSettings: fleet.ServerSettings{ServerURL: "https://fleet.example.com"},
			SSOSettings: &fleet.SSOSettings{
				EnableSSO: true,
				EntityID:  "fleet",
				IDPName:   "TestIDP",
				Metadata:  testSSOMetadata(),
			},
		}, nil
	}
	return svc, ctx, ds, sso.NewSessionStore(pool)
}

func TestInitiateFleetctlSSO(t *testing.T) {
	svc, ctx, _, store := newFleetctlSSOTestService(t)
	_, challenge := fleetctlTestPKCE()
	const redirectURI = "http://127.0.0.1:4321/callback"

	t.Run("invalid arguments", func(t *testing.T) {
		_, _, _, err := svc.InitiateFleetctlSSO(ctx, "https://evil.example.com/callback", "", "plain")
		var invalid *fleet.InvalidArgumentError
		require.ErrorAs(t, err, &invalid)
		assert.Len(t, invalid.Errors, 3)
	})

	t.Run("success", func(t *testing.T) {
		sessionID, _, idpURL, err := svc.InitiateFleetctlSSO(ctx, redirectURI, "the-state", challenge)
		require.NoError(t, err)
		require.NotEmpty(t, idpURL)

		req, err := store.ConsumeFleetctlRequest(sessionID)
		require.NoError(t, err)
		assert.Equal(t, &sso.FleetctlRequest{RedirectURI: redirectURI, State: "the-state", CodeChallenge: challenge}, req)
	})
}

func TestFleetctlSSOCallback(t *testing.T) {
	svc, ctx, _, _ := newFleetctlSSOTestService(t)
	_, challenge := fleetctlTestPKCE()

	// SSO sessions not started by fleetctl are left to the regular callback.
	sessionID, _, _, err := svc.InitiateSSO(ctx, "/dashboard")
	require.NoError(t, err)
	_, _, handled, err := svc.FleetctlSSOCallback(ctx, sessionID, []byte("<Response/>"))
	require.NoError(t, err)
	require.False(t, handled)

	// A failed fleetctl login still sends the browser back to fleetctl, so that
	// it stops waiting.
	sessionID, _, _, err = svc.InitiateFleetctlSSO(ctx, "http://127.0.0.1:4321/callback", "the-state", challenge)
	require.NoError(t, err)
	consent, redirectURL, handled, err := svc.FleetctlSSOCallback(ctx, sessionID, []byte("<Response/>"))
	require.Error(t, err)
	require.True(t, handled)
	require.Nil(t, consent)
	u, err := url.Parse(redirectURL)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:4321", u.Host)
	assert.Equal(t, "/callback", u.Path)
	assert.Equal(t, "the-state", u.Query().Get("state"))
	assert.Equal(t, "access_denied", u.Query().Get("error"))
	assert.Empty(t, u.Query().Get("code"))

	// The fleetctl request is single use.
	_, _, handled, err = svc.FleetctlSSOCallback(ctx, sessionID, []byte("<Response/>"))
	require.NoError(t, err)
	require.False(t, handled)
}

func TestConfirmFleetctlSSO(t *testing.T) {
	svc, ctx, _, store := newFleetctlSSOTestService(t)
	verifier, challenge := fleetctlTestPKCE()
	req := sso.FleetctlRequest{RedirectURI: "http://127.0.0.1:4321/callback", State: "the-state", CodeChallenge: challenge}

	newConsent := func(t *testing.T, id string) {
		require.NoError(t, store.CreateFleetctlConsent(id, sso.FleetctlConsent{UserID: 7, Email: "sso@example.com", FleetctlRequest: req}))
	}
	parse := func(t *testing.T, redirectURL string) url.Values {
		u, err := url.Parse(redirectURL)
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1:4321", u.Host)
		require.Equal(t, "the-state", u.Query().Get("state"))
		return u.Query()
	}

	t.Run("unknown", func(t *testing.T) {
		_, err := svc.ConfirmFleetctlSSO(ctx, "nope", true)
		var authFailed *fleet.AuthFailedError
		require.ErrorAs(t, err, &authFailed)
	})

	t.Run("denied", func(t *testing.T) {
		newConsent(t, "consent-1")
		redirectURL, err := svc.ConfirmFleetctlSSO(ctx, "consent-1", false)
		require.NoError(t, err)
		q := parse(t, redirectURL)
		assert.Equal(t, "access_denied", q.Get("error"))
		assert.Equal(t, "denied", q.Get("error_description"))
		assert.Empty(t, q.Get("code"))

		// Denying consumes the consent.
		_, err = svc.ConfirmFleetctlSSO(ctx, "consent-1", true)
		require.Error(t, err)
	})

	t.Run("approved", func(t *testing.T) {
		newConsent(t, "consent-2")
		redirectURL, err := svc.ConfirmFleetctlSSO(ctx, "consent-2", true)
		require.NoError(t, err)
		code := parse(t, redirectURL).Get("code")
		require.NotEmpty(t, code)

		data, err := store.ConsumeFleetctlCode(code)
		require.NoError(t, err)
		assert.Equal(t, &sso.FleetctlCode{UserID: 7, RedirectURI: req.RedirectURI, CodeChallenge: challenge}, data)
		assert.True(t, sso.VerifyFleetctlCodeVerifier(data.CodeChallenge, verifier))

		_, err = svc.ConfirmFleetctlSSO(ctx, "consent-2", true)
		require.Error(t, err)
	})
}

func TestFleetctlSSOConsentPage(t *testing.T) {
	resp, err := newFleetctlSSOConsentPage(t.Context(), "/prefix", &fleet.FleetctlSSOConsent{
		ID:               "the-id",
		Email:            `<script>alert(1)</script>@example.com`,
		VerificationCode: "BCDF-GHJK",
	})
	require.NoError(t, err)
	page := resp.(fleetctlSSOPageResponse).Html()
	assert.Contains(t, page, `action="/prefix/api/v1/fleet/sso/fleetctl/consent"`)
	assert.Contains(t, page, `name="consent_id" value="the-id"`)
	assert.Contains(t, page, "BCDF-GHJK")
	assert.NotContains(t, page, "<script>")
}

func TestExchangeFleetctlSSOCode(t *testing.T) {
	svc, ctx, ds, store := newFleetctlSSOTestService(t)
	verifier, challenge := fleetctlTestPKCE()
	const redirectURI = "http://127.0.0.1:4321/callback"

	user := &fleet.User{ID: 7, Email: "sso@example.com", SSOEnabled: true, GlobalRole: new(fleet.RoleAdmin)}
	ds.UserByIDFunc = func(ctx context.Context, id uint) (*fleet.User, error) {
		require.Equal(t, user.ID, id)
		return user, nil
	}
	ds.NewSessionFunc = func(ctx context.Context, userID uint, sessionKeySize int) (*fleet.Session, error) {
		return &fleet.Session{UserID: userID, Key: "session-key"}, nil
	}

	newCode := func(t *testing.T, code string) {
		require.NoError(t, store.CreateFleetctlCode(code, sso.FleetctlCode{
			UserID:        user.ID,
			RedirectURI:   redirectURI,
			CodeChallenge: challenge,
		}))
	}

	t.Run("unknown code", func(t *testing.T) {
		_, _, err := svc.ExchangeFleetctlSSOCode(ctx, "nope", verifier, redirectURI)
		var authFailed *fleet.AuthFailedError
		require.ErrorAs(t, err, &authFailed)
	})

	t.Run("wrong verifier burns the code", func(t *testing.T) {
		newCode(t, "code-1")
		_, _, err := svc.ExchangeFleetctlSSOCode(ctx, "code-1", verifier[1:]+"x", redirectURI)
		var authFailed *fleet.AuthFailedError
		require.ErrorAs(t, err, &authFailed)

		_, _, err = svc.ExchangeFleetctlSSOCode(ctx, "code-1", verifier, redirectURI)
		require.ErrorAs(t, err, &authFailed)
	})

	t.Run("wrong redirect URI", func(t *testing.T) {
		newCode(t, "code-2")
		_, _, err := svc.ExchangeFleetctlSSOCode(ctx, "code-2", verifier, "http://127.0.0.1:9999/callback")
		var authFailed *fleet.AuthFailedError
		require.ErrorAs(t, err, &authFailed)
	})

	t.Run("user no longer SSO enabled", func(t *testing.T) {
		newCode(t, "code-3")
		user.SSOEnabled = false
		t.Cleanup(func() { user.SSOEnabled = true })
		_, _, err := svc.ExchangeFleetctlSSOCode(ctx, "code-3", verifier, redirectURI)
		require.Error(t, err)
		assert.False(t, ds.NewSessionFuncInvoked)
	})

	t.Run("success", func(t *testing.T) {
		newCode(t, "code-4")
		gotUser, session, err := svc.ExchangeFleetctlSSOCode(ctx, "code-4", verifier, redirectURI)
		require.NoError(t, err)
		assert.Equal(t, user, gotUser)
		assert.Equal(t, "session-key", session.Key)

		// Single use.
		_, _, err = svc.ExchangeFleetctlSSOCode(ctx, "code-4", verifier, redirectURI)
		require.Error(t, err)
	})
}
