package fleetctl

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeFleetctlSSOServer plays Fleet and the IdP: the login URL immediately
// redirects the browser back to fleetctl with a code (or with callbackErr).
func fakeFleetctlSSOServer(t *testing.T, fleetctlSSO bool, callbackErr string) *httptest.Server {
	var challenge, redirectURI string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/fleet/sso", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"settings": fleet.SessionSSOSettings{SSOEnabled: true, FleetctlSSO: fleetctlSSO},
		})
	})
	mux.HandleFunc("GET /api/v1/fleet/sso/fleetctl", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		assert.Equal(t, "S256", q.Get("code_challenge_method"))
		challenge, redirectURI = q.Get("code_challenge"), q.Get("redirect_uri")

		params := url.Values{"state": {q.Get("state")}}
		if callbackErr != "" {
			params.Set("error", "access_denied")
			params.Set("error_description", callbackErr)
		} else {
			params.Set("code", "the-code")
		}
		http.Redirect(w, r, redirectURI+"?"+params.Encode(), http.StatusSeeOther)
	})
	mux.HandleFunc("POST /api/v1/fleet/sso/fleetctl/token", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		sum := sha256.Sum256([]byte(req["code_verifier"]))
		if req["code"] != "the-code" || req["redirect_uri"] != redirectURI ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": "Authentication failed"})
			return
		}
		_ = json.NewEncoder(w).Encode(fleet.LoginResponse{
			User:  &fleet.User{Email: "sso@example.com"},
			Token: "sso-token",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func playBrowser(t *testing.T) {
	prev := openBrowser
	t.Cleanup(func() { openBrowser = prev })
	openBrowser = func(u string) error {
		go func() {
			resp, err := http.Get(u) //nolint:gosec // test URL
			if assert.NoError(t, err) {
				resp.Body.Close()
			}
		}()
		return nil
	}
}

// writeLoginConfig points fleetctl at address. Under test, fleetctl takes the
// address from FLEET_SERVER_ADDRESS rather than the config file.
func writeLoginConfig(t *testing.T, address string) string {
	t.Setenv("FLEET_SERVER_ADDRESS", address)
	configPath := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.WriteFile(configPath, []byte("contexts:\n  default:\n    address: "+address+"\n"), configFilePerms))
	return configPath
}

func TestLoginSSO(t *testing.T) {
	t.Run("detected automatically", func(t *testing.T) {
		srv := fakeFleetctlSSOServer(t, true, "")
		playBrowser(t)
		configPath := writeLoginConfig(t, srv.URL)

		out := runAppForTest(t, []string{"login", "--config", configPath})
		assert.Contains(t, out, "Fleet login successful as sso@example.com")
		assert.Regexp(t, `confirm that the browser shows this code: [A-Z]{4}-[A-Z]{4}`, out)

		token, err := getConfigValue(configPath, "default", "token")
		require.NoError(t, err)
		assert.Equal(t, "sso-token", token)
		email, err := getConfigValue(configPath, "default", "email")
		require.NoError(t, err)
		assert.Equal(t, "sso@example.com", email)
	})

	t.Run("failed in the browser", func(t *testing.T) {
		srv := fakeFleetctlSSOServer(t, true, "account_disabled")
		playBrowser(t)
		configPath := writeLoginConfig(t, srv.URL)

		runAppCheckErr(t, []string{"login", "--config", configPath}, "your Fleet account is not configured to use SSO")
	})

	t.Run("denied in the browser", func(t *testing.T) {
		srv := fakeFleetctlSSOServer(t, true, "denied")
		playBrowser(t)
		configPath := writeLoginConfig(t, srv.URL)

		runAppCheckErr(t, []string{"login", "--config", configPath}, "SSO login was denied in the browser")
	})

	t.Run("server does not support it", func(t *testing.T) {
		srv := fakeFleetctlSSOServer(t, false, "")
		configPath := writeLoginConfig(t, srv.URL)

		runAppCheckErr(t, []string{"login", "--sso", "--config", configPath}, "does not support fleetctl SSO login")
	})
}
