package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

// Login attempts to login to the current Fleet instance. If login is successful,
// an auth token is returned.
func (c *Client) Login(email, password string) (string, error) {
	params := fleet.LoginRequest{
		Email:    email,
		Password: password,
	}

	response, err := c.Do("POST", "/api/latest/fleet/login", "", params)
	if err != nil {
		return "", fmt.Errorf("POST /api/latest/fleet/login: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		return "", notSetupErr{}
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf(
			"login received status %d %s",
			response.StatusCode,
			extractServerErrorText(response.Body),
		)
	}

	var responseBody fleet.LoginResponse
	err = json.NewDecoder(response.Body).Decode(&responseBody)
	if err != nil {
		return "", fmt.Errorf("decode login response: %w", err)
	}

	if responseBody.Err != nil {
		return "", fmt.Errorf("login: %s", responseBody.Err)
	}

	return responseBody.Token, nil
}

// SSOSettings returns the SSO settings for the current Fleet instance.
// This endpoint is unauthenticated and can be called before login.
func (c *Client) SSOSettings() (*fleet.SessionSSOSettings, error) {
	response, err := c.Do("GET", "/api/v1/fleet/sso", "", nil)
	if err != nil {
		return nil, fmt.Errorf("GET /api/v1/fleet/sso: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get SSO settings received status %d %s", response.StatusCode, extractServerErrorText(response.Body))
	}

	var responseBody struct {
		Settings *fleet.SessionSSOSettings `json:"settings"`
	}
	if err := json.NewDecoder(response.Body).Decode(&responseBody); err != nil {
		return nil, fmt.Errorf("decode SSO settings response: %w", err)
	}

	return responseBody.Settings, nil
}

// FleetctlSSOURL returns the URL to open in the browser to log fleetctl in with
// SSO. Once logged in, the browser is redirected to redirectURI with an
// authorization code to pass to ExchangeFleetctlSSOCode.
func (c *Client) FleetctlSSOURL(redirectURI, state, codeChallenge string) string {
	q := url.Values{
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	return c.URL("/api/v1/fleet/sso/fleetctl", q.Encode()).String()
}

// ExchangeFleetctlSSOCode redeems the authorization code received at the end of
// an SSO login started with FleetctlSSOURL for a session token.
func (c *Client) ExchangeFleetctlSSOCode(code, codeVerifier, redirectURI string) (*fleet.LoginResponse, error) {
	params := map[string]string{
		"code":          code,
		"code_verifier": codeVerifier,
		"redirect_uri":  redirectURI,
	}
	response, err := c.Do("POST", "/api/v1/fleet/sso/fleetctl/token", "", params)
	if err != nil {
		return nil, fmt.Errorf("POST /api/v1/fleet/sso/fleetctl/token: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"SSO login received status %d %s",
			response.StatusCode,
			extractServerErrorText(response.Body),
		)
	}

	var responseBody fleet.LoginResponse
	if err := json.NewDecoder(response.Body).Decode(&responseBody); err != nil {
		return nil, fmt.Errorf("decode SSO login response: %w", err)
	}
	if responseBody.Err != nil {
		return nil, fmt.Errorf("SSO login: %w", responseBody.Err)
	}
	return &responseBody, nil
}

// Logout attempts to logout to the current Fleet instance.
func (c *Client) Logout() error {
	verb, path := "POST", "/api/latest/fleet/logout"
	var responseBody fleet.LogoutResponse
	return c.authenticatedRequest(nil, verb, path, &responseBody)
}
