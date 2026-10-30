package fleetctl

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/service"
	"github.com/fleetdm/fleet/v4/server/sso"
	"github.com/skratchdot/open-golang/open"
)

// ssoLoginTimeout is how long fleetctl waits for the user to finish logging in
// in the browser.
const ssoLoginTimeout = 5 * time.Minute

// openBrowser is a variable so that tests can play the browser.
var openBrowser = open.Start

// ssoCallbackPath must match the path Fleet accepts in loopback redirect URIs.
const ssoCallbackPath = "/callback"

var ssoResultPage = template.Must(template.New("sso-result").Parse(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>fleetctl login</title></head>
<body style="font-family: sans-serif; text-align: center; margin-top: 4em;">
{{ if .Err }}<h2>Login failed</h2><p>{{ .Err }}</p>{{ else }}<h2>Login successful</h2>{{ end }}
<p>You can close this window and return to the terminal.</p>
</body>
</html>
`))

type ssoCallbackResult struct {
	code string
	err  error
}

// ssoLogin logs in to Fleet with SSO in the browser, following the OAuth 2.0
// for native apps pattern (RFC 8252): Fleet redirects the browser back to a
// listener on a loopback port with a single-use authorization code, which is
// then exchanged for a session token using PKCE (RFC 7636).
func ssoLogin(fleetClient *service.Client, stdout, stderr io.Writer) (*fleet.LoginResponse, error) {
	// Port 0 lets the OS pick a free port. Listening on the loopback IP rather
	// than "localhost" avoids resolving to a non-loopback interface.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for SSO callback: %w", err)
	}
	defer listener.Close()
	redirectURI := fmt.Sprintf("http://%s%s", listener.Addr().String(), ssoCallbackPath)

	state, err := randomURLSafe(16)
	if err != nil {
		return nil, err
	}
	codeVerifier, err := randomURLSafe(32)
	if err != nil {
		return nil, err
	}
	challenge := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challenge[:])

	results := make(chan ssoCallbackResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(ssoCallbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		// Ignore anything that wasn't sent by this login attempt, e.g. a stale
		// tab from a previous one.
		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
			http.Error(w, "Invalid or expired login request. Run fleetctl login again.", http.StatusBadRequest)
			return
		}

		var res ssoCallbackResult
		switch {
		case q.Get("error") != "":
			res.err = ssoCallbackError(q.Get("error_description"))
		case q.Get("code") == "":
			res.err = errors.New("Fleet did not return an authorization code")
		default:
			res.code = q.Get("code")
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = ssoResultPage.Execute(w, struct{ Err error }{res.err})

		select {
		case results <- res:
		default:
		}
	})
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go server.Serve(listener) //nolint:errcheck // returns once the server is closed
	defer func() { _ = server.Close() }()

	loginURL := fleetClient.FleetctlSSOURL(redirectURI, state, codeChallenge)
	fmt.Fprintln(stdout, "Opening your browser to log in with SSO...")
	fmt.Fprintf(stdout, "If the browser does not open, visit this URL on this machine:\n\n  %s\n\n", loginURL)
	if err := openBrowser(loginURL); err != nil {
		fmt.Fprintf(stderr, "Could not open the browser: %s\n", err)
	}
	fmt.Fprintf(stdout, "When asked, confirm that the browser shows this code: %s\n\n", sso.FleetctlVerificationCode(codeChallenge))
	fmt.Fprintln(stdout, "Waiting for login to complete...")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, ssoLoginTimeout)
	defer cancelTimeout()

	var res ssoCallbackResult
	select {
	case res = <-results:
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("timed out after %s waiting for SSO login to complete", ssoLoginTimeout)
		}
		return nil, errors.New("SSO login canceled")
	}
	if res.err != nil {
		return nil, res.err
	}

	return fleetClient.ExchangeFleetctlSSOCode(res.code, codeVerifier, redirectURI)
}

// ssoCallbackError explains the reason Fleet reported for a failed SSO login.
func ssoCallbackError(reason string) error {
	switch reason {
	case "denied":
		return errors.New("SSO login was denied in the browser")
	case "account_disabled":
		return errors.New("SSO login failed: your Fleet account is not configured to use SSO. Run fleetctl login --sso=false to log in with email and password")
	case "account_invalid":
		return errors.New("SSO login failed: no Fleet account matches your SSO identity")
	case "org_disabled":
		return errors.New("SSO login failed: SSO is not enabled on this Fleet instance")
	default:
		return errors.New("SSO login failed, check the Fleet server logs for details")
	}
}

func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
