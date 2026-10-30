package service

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/fleetdm/fleet/v4/server"
	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/contexts/logging"
	"github.com/fleetdm/fleet/v4/server/contexts/publicip"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/platform/endpointer"
	"github.com/fleetdm/fleet/v4/server/sso"
)

// See server/sso/fleetctl.go for an overview of the fleetctl SSO login flow.

////////////////////////////////////////////////////////////////////////////////
// Initiate fleetctl SSO
////////////////////////////////////////////////////////////////////////////////

type initiateFleetctlSSORequest struct {
	RedirectURI         string `query:"redirect_uri"`
	State               string `query:"state"`
	CodeChallenge       string `query:"code_challenge"`
	CodeChallengeMethod string `query:"code_challenge_method"`
}

type initiateFleetctlSSOResponse struct {
	Err error `json:"error,omitempty"`

	idpURL                 string
	sessionID              string
	sessionDurationSeconds int
}

func (r initiateFleetctlSSOResponse) Error() error { return r.Err }

func (r initiateFleetctlSSOResponse) SetCookies(_ context.Context, w http.ResponseWriter) {
	if r.sessionID != "" {
		setSSOCookie(w, r.sessionID, r.sessionDurationSeconds)
	}
}

// The browser is sent here by fleetctl, so send it straight on to the IdP.
func (r initiateFleetctlSSOResponse) HijackRender(_ context.Context, w http.ResponseWriter) {
	w.Header().Set("Location", r.idpURL)
	w.WriteHeader(http.StatusSeeOther)
}

func initiateFleetctlSSOEndpoint(ctx context.Context, request any, svc fleet.Service) (fleet.Errorer, error) {
	req := request.(*initiateFleetctlSSORequest)
	if req.CodeChallengeMethod != "S256" {
		return initiateFleetctlSSOResponse{
			Err: fleet.NewInvalidArgumentError("code_challenge_method", "only S256 is supported"),
		}, nil
	}
	sessionID, sessionDurationSeconds, idpURL, err := svc.InitiateFleetctlSSO(ctx, req.RedirectURI, req.State, req.CodeChallenge)
	if err != nil {
		return initiateFleetctlSSOResponse{Err: err}, nil
	}
	return initiateFleetctlSSOResponse{
		idpURL:                 idpURL,
		sessionID:              sessionID,
		sessionDurationSeconds: sessionDurationSeconds,
	}, nil
}

// maxFleetctlSSOStateLen bounds the opaque state fleetctl round-trips through
// Fleet, which is stored in Redis for the duration of the SSO session.
const maxFleetctlSSOStateLen = 256

func (svc *Service) InitiateFleetctlSSO(ctx context.Context, redirectURI, state, codeChallenge string) (sessionID string, sessionDurationSeconds int, idpURL string, err error) {
	// skipauth: User context does not yet exist. Unauthenticated users may
	// initiate SSO.
	svc.authz.SkipAuthorization(ctx)

	invalid := &fleet.InvalidArgumentError{}
	if err := sso.ValidateFleetctlRedirectURI(redirectURI); err != nil {
		invalid.Append("redirect_uri", err.Error())
	}
	if state == "" || len(state) > maxFleetctlSSOStateLen {
		invalid.Append("state", "must be between 1 and 256 characters")
	}
	if err := sso.ValidateFleetctlCodeChallenge(codeChallenge); err != nil {
		invalid.Append("code_challenge", err.Error())
	}
	if invalid.HasErrors() {
		return "", 0, "", ctxerr.Wrap(ctx, invalid)
	}

	// The loopback URI also becomes the SSO session's original URL, but the
	// callback never redirects there directly: it goes through the code
	// exchange below.
	sessionID, sessionDurationSeconds, idpURL, err = svc.InitiateSSO(ctx, redirectURI)
	if err != nil {
		return "", 0, "", err
	}

	if err := svc.ssoSessionStore.CreateFleetctlRequest(sessionID, sso.FleetctlRequest{
		RedirectURI:   redirectURI,
		State:         state,
		CodeChallenge: codeChallenge,
	}, uint(sessionDurationSeconds)); err != nil { //nolint:gosec // dismiss G115
		return "", 0, "", ctxerr.Wrap(ctx, err, "store fleetctl sso request")
	}
	return sessionID, sessionDurationSeconds, idpURL, nil
}

////////////////////////////////////////////////////////////////////////////////
// fleetctl SSO callback (the IdP posts to the regular SSO callback endpoint)
////////////////////////////////////////////////////////////////////////////////

func (svc *Service) FleetctlSSOCallback(ctx context.Context, sessionID string, samlResponse []byte) (consent *fleet.FleetctlSSOConsent, redirectURL string, handled bool, err error) {
	// skipauth: User context does not yet exist. Unauthenticated users may
	// hit the SSO callback.
	svc.authz.SkipAuthorization(ctx)

	req, err := svc.ssoSessionStore.ConsumeFleetctlRequest(sessionID)
	if err != nil {
		return nil, "", false, ctxerr.Wrap(ctx, err, "load fleetctl sso request")
	}
	if req == nil {
		return nil, "", false, nil
	}

	logging.WithLevel(logging.WithNoUser(ctx), slog.LevelInfo)

	consent, userID, err := svc.newFleetctlSSOConsent(ctx, sessionID, samlResponse, req)
	if err != nil {
		if err := svc.NewActivity(ctx, nil, fleet.ActivityTypeUserFailedLogin{
			Email:    userID,
			PublicIP: publicip.FromContext(ctx),
		}); err != nil {
			logging.WithLevel(logging.WithExtras(logging.WithNoUser(ctx),
				"msg", "failed to generate failed login activity",
			), slog.LevelInfo)
		}

		status := ssoOtherError
		if ssoErr, ok := errors.AsType[*ssoError](err); ok {
			status = ssoErr.code
		}
		// If this fails, the empty URL sends the browser to the login page instead.
		redirectURL, _ := fleetctlRedirectURL(req, url.Values{
			"error":             {"access_denied"},
			"error_description": {string(status)},
		})
		return nil, redirectURL, true, err
	}
	return consent, "", true, nil
}

func fleetctlRedirectURL(req *sso.FleetctlRequest, params url.Values) (string, error) {
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return "", err
	}
	params.Set("state", req.State)
	u.RawQuery = params.Encode()
	return u.String(), nil
}

// newFleetctlSSOConsent verifies the SAML response and stores the login for the
// user to approve. It returns the IdP user ID, if known, for failed login
// activity.
func (svc *Service) newFleetctlSSOConsent(ctx context.Context, sessionID string, samlResponse []byte, req *sso.FleetctlRequest) (consent *fleet.FleetctlSSOConsent, userID string, err error) {
	auth, _, err := svc.InitSSOCallback(ctx, sessionID, samlResponse)
	if err != nil {
		return nil, "", err
	}
	user, err := svc.GetSSOUser(ctx, auth)
	if err != nil {
		return nil, auth.UserID(), err
	}
	if err := ssoUserCanLogin(ctx, user); err != nil {
		return nil, auth.UserID(), err
	}

	consentID, err := server.GenerateRandomURLSafeText(32)
	if err != nil {
		return nil, auth.UserID(), ctxerr.Wrap(ctx, err, "generate fleetctl sso consent id")
	}
	if err := svc.ssoSessionStore.CreateFleetctlConsent(consentID, sso.FleetctlConsent{
		UserID:          user.ID,
		Email:           user.Email,
		FleetctlRequest: *req,
	}); err != nil {
		return nil, auth.UserID(), ctxerr.Wrap(ctx, err, "store fleetctl sso consent")
	}
	return &fleet.FleetctlSSOConsent{
		ID:               consentID,
		Email:            user.Email,
		VerificationCode: sso.FleetctlVerificationCode(req.CodeChallenge),
	}, auth.UserID(), nil
}

func (svc *Service) ConfirmFleetctlSSO(ctx context.Context, consentID string, approve bool) (redirectURL string, err error) {
	// skipauth: User context does not yet exist. The consent ID, only known to
	// the browser that completed SSO, is the credential.
	svc.authz.SkipAuthorization(ctx)

	logging.WithLevel(logging.WithNoUser(ctx), slog.LevelInfo)

	consent, err := svc.ssoSessionStore.ConsumeFleetctlConsent(consentID)
	if err != nil {
		if errors.Is(err, sso.ErrSessionNotFound) {
			return "", ctxerr.Wrap(ctx, fleet.NewAuthFailedError("fleetctl login request not found or expired"))
		}
		return "", ctxerr.Wrap(ctx, err, "load fleetctl sso consent")
	}
	if !approve {
		redirectURL, err := fleetctlRedirectURL(&consent.FleetctlRequest, url.Values{
			"error":             {"access_denied"},
			"error_description": {"denied"},
		})
		if err != nil {
			return "", ctxerr.Wrap(ctx, err, "build fleetctl sso redirect url")
		}
		return redirectURL, nil
	}

	code, err := server.GenerateRandomURLSafeText(32)
	if err != nil {
		return "", ctxerr.Wrap(ctx, err, "generate fleetctl sso code")
	}
	if err := svc.ssoSessionStore.CreateFleetctlCode(code, sso.FleetctlCode{
		UserID:        consent.UserID,
		RedirectURI:   consent.RedirectURI,
		CodeChallenge: consent.CodeChallenge,
	}); err != nil {
		return "", ctxerr.Wrap(ctx, err, "store fleetctl sso code")
	}
	redirectURL, err = fleetctlRedirectURL(&consent.FleetctlRequest, url.Values{"code": {code}})
	if err != nil {
		return "", ctxerr.Wrap(ctx, err, "build fleetctl sso redirect url")
	}
	return redirectURL, nil
}

////////////////////////////////////////////////////////////////////////////////
// fleetctl SSO consent
////////////////////////////////////////////////////////////////////////////////

// fleetctlSSOPage is both the consent prompt (when ConsentID is set) and the
// page explaining why a login can't proceed.
var fleetctlSSOPage = template.Must(template.New("fleetctl-sso").Parse(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fleetctl login</title>
<style nonce="{{ .Nonce }}">
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #192147; max-width: 32em; margin: 4em auto; padding: 0 1em; line-height: 1.5; }
.code { font-family: monospace; font-size: 2em; letter-spacing: 0.1em; text-align: center; padding: 0.5em; border: 1px solid #c5c7d1; border-radius: 6px; }
.warning { color: #8b6a00; }
button { font-size: 1em; padding: 0.6em 1.4em; margin-right: 0.5em; border-radius: 6px; border: 1px solid #6a67fe; cursor: pointer; }
button[value=approve] { background: #6a67fe; color: #fff; }
button[value=deny] { background: #fff; color: #6a67fe; }
</style>
</head>
<body>
{{ if .ConsentID }}
<h2>Log in to fleetctl?</h2>
<p>fleetctl on your computer is asking to log in to Fleet as <strong>{{ .Email }}</strong>. It will be able to do anything you can do in Fleet.</p>
<p>Check that this code matches the one shown in your terminal:</p>
<p class="code">{{ .VerificationCode }}</p>
<p class="warning">Only continue if you just ran <code>fleetctl login</code> yourself and the codes match. If you didn't, deny this request.</p>
<form method="post" action="{{ .Action }}">
<input type="hidden" name="consent_id" value="{{ .ConsentID }}">
<button type="submit" name="action" value="approve">Approve</button>
<button type="submit" name="action" value="deny">Deny</button>
</form>
{{ else }}
<h2>fleetctl login failed</h2>
<p>{{ .Message }}</p>
{{ end }}
</body>
</html>
`))

type fleetctlSSOPageData struct {
	Nonce            string
	Action           string
	ConsentID        string
	Email            string
	VerificationCode string
	Message          string
}

type fleetctlSSOPageResponse struct {
	content string
	Err     error `json:"error,omitempty"`
}

func (r fleetctlSSOPageResponse) Error() error { return r.Err }

func (r fleetctlSSOPageResponse) Html() string { return r.content }

func (r fleetctlSSOPageResponse) SetCookies(_ context.Context, w http.ResponseWriter) {
	deleteSSOCookie(w)
}

func newFleetctlSSOPage(ctx context.Context, data fleetctlSSOPageData, pageErr error) (fleet.Errorer, error) {
	nonce, err := endpointer.CSPNonce(ctx)
	if err != nil {
		return nil, err
	}
	data.Nonce = nonce
	var buf bytes.Buffer
	if err := fleetctlSSOPage.Execute(&buf, data); err != nil {
		return nil, err
	}
	return fleetctlSSOPageResponse{content: buf.String(), Err: pageErr}, nil
}

func newFleetctlSSOConsentPage(ctx context.Context, urlPrefix string, consent *fleet.FleetctlSSOConsent) (fleet.Errorer, error) {
	return newFleetctlSSOPage(ctx, fleetctlSSOPageData{
		Action:           urlPrefix + "/api/v1/fleet/sso/fleetctl/consent",
		ConsentID:        consent.ID,
		Email:            consent.Email,
		VerificationCode: consent.VerificationCode,
	}, nil)
}

type confirmFleetctlSSORequest struct {
	consentID string
	approve   bool
}

// The consent page posts a plain HTML form.
func (confirmFleetctlSSORequest) DecodeRequest(ctx context.Context, r *http.Request) (any, error) {
	if err := r.ParseForm(); err != nil {
		return nil, ctxerr.Wrap(ctx, &fleet.BadRequestError{Message: "failed to parse form", InternalErr: err})
	}
	req := &confirmFleetctlSSORequest{consentID: r.PostForm.Get("consent_id")}
	switch r.PostForm.Get("action") {
	case "approve":
		req.approve = true
	case "deny":
	default:
		return nil, ctxerr.Wrap(ctx, &fleet.BadRequestError{Message: "action must be approve or deny"})
	}
	return req, nil
}

type fleetctlSSORedirectResponse struct {
	redirectURL string
}

func (r fleetctlSSORedirectResponse) Error() error { return nil }

func (r fleetctlSSORedirectResponse) HijackRender(_ context.Context, w http.ResponseWriter) {
	w.Header().Set("Location", r.redirectURL)
	w.WriteHeader(http.StatusSeeOther)
}

func confirmFleetctlSSOEndpoint(ctx context.Context, request any, svc fleet.Service) (fleet.Errorer, error) {
	req := request.(*confirmFleetctlSSORequest)
	redirectURL, err := svc.ConfirmFleetctlSSO(ctx, req.consentID, req.approve)
	if err != nil {
		return newFleetctlSSOPage(ctx, fleetctlSSOPageData{
			Message: "This login request has expired or was already used. Run fleetctl login again.",
		}, err)
	}
	return fleetctlSSORedirectResponse{redirectURL: redirectURL}, nil
}

////////////////////////////////////////////////////////////////////////////////
// Exchange fleetctl SSO code
////////////////////////////////////////////////////////////////////////////////

type exchangeFleetctlSSOCodeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
}

func exchangeFleetctlSSOCodeEndpoint(ctx context.Context, request any, svc fleet.Service) (fleet.Errorer, error) {
	req := request.(*exchangeFleetctlSSOCodeRequest)
	user, session, err := svc.ExchangeFleetctlSSOCode(ctx, req.Code, req.CodeVerifier, req.RedirectURI)
	if err != nil {
		return fleet.LoginResponse{Err: err}, nil
	}
	return newLoginResponse(ctx, svc, user, session), nil
}

func (svc *Service) ExchangeFleetctlSSOCode(ctx context.Context, code, codeVerifier, redirectURI string) (*fleet.User, *fleet.Session, error) {
	// skipauth: User context does not yet exist. The code and verifier are the
	// credentials.
	svc.authz.SkipAuthorization(ctx)

	logging.WithLevel(logging.WithNoUser(ctx), slog.LevelInfo)

	data, err := svc.ssoSessionStore.ConsumeFleetctlCode(code)
	if err != nil {
		if errors.Is(err, sso.ErrSessionNotFound) {
			return nil, nil, ctxerr.Wrap(ctx, fleet.NewAuthFailedError("invalid or expired code"))
		}
		return nil, nil, ctxerr.Wrap(ctx, err, "load fleetctl sso code")
	}
	// The code is consumed either way, so a wrong guess at the verifier burns it.
	if data.RedirectURI != redirectURI || !sso.VerifyFleetctlCodeVerifier(data.CodeChallenge, codeVerifier) {
		return nil, nil, ctxerr.Wrap(ctx, fleet.NewAuthFailedError("code verifier or redirect URI does not match"))
	}

	user, err := svc.ds.UserByID(ctx, data.UserID)
	if err != nil {
		return nil, nil, ctxerr.Wrap(ctx, err, "load user for fleetctl sso code")
	}
	// Check again in case the user was changed since the code was issued.
	if err := ssoUserCanLogin(ctx, user); err != nil {
		return nil, nil, ctxerr.Wrap(ctx, fleet.NewAuthFailedError(err.Error()))
	}

	session, err := svc.makeSession(ctx, user.ID)
	if err != nil {
		return nil, nil, ctxerr.Wrap(ctx, err, "make session for fleetctl sso")
	}
	if err := svc.NewActivity(ctx, user, fleet.ActivityTypeUserLoggedIn{
		PublicIP: publicip.FromContext(ctx),
	}); err != nil {
		return nil, nil, ctxerr.Wrap(ctx, err, "create activity for fleetctl sso")
	}
	return user, session, nil
}
