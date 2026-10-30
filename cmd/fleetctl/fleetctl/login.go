package fleetctl

import (
	"errors"
	"fmt"
	"os"

	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/service"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh/terminal"
)

func loginCommand() *cli.Command {
	var (
		flEmail    string
		flPassword string
		flSSO      bool
	)
	return &cli.Command{
		Name:  "login",
		Usage: "Login to Fleet",
		UsageText: `
fleetctl login [options]

If SSO is enabled on the Fleet server, opens the browser to log in with SSO, then returns to
fleetctl to finish. Use --sso=false to log in with email and password instead, for accounts that
are not SSO-enabled.

Otherwise, interactively prompts for email and password if not specified in the flags or
environment variables.
`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "email",
				EnvVars:     []string{"EMAIL"},
				Value:       "",
				Destination: &flEmail,
				Usage:       "Email to use to log in",
			},
			&cli.StringFlag{
				Name:        "password",
				EnvVars:     []string{"PASSWORD"},
				Value:       "",
				Destination: &flPassword,
				Usage:       "Password to use to log in (recommended to use interactive entry)",
			},
			&cli.BoolFlag{
				Name:        "sso",
				Destination: &flSSO,
				Usage:       "Log in with SSO in the browser (default: true if SSO is enabled on the Fleet server and --password is not set)",
			},
			configFlag(),
			contextFlag(),
			debugFlag(),
		},
		Action: func(c *cli.Context) error {
			fleet, err := unauthenticatedClientFromCLI(c)
			if err != nil {
				return err
			}

			configPath, context := c.String("config"), c.String("context")

			ssoSettings, ssoErr := fleet.SSOSettings()
			ssoEnabled := ssoErr == nil && ssoSettings != nil && ssoSettings.SSOEnabled
			fleetctlSSO := ssoEnabled && ssoSettings.FleetctlSSO

			useSSO := fleetctlSSO && flPassword == ""
			if c.IsSet("sso") {
				useSSO = flSSO
			}
			if useSSO {
				switch {
				case !ssoEnabled:
					return errors.New("SSO is not enabled on this Fleet instance. Run fleetctl login without --sso to log in with email and password.")
				case !fleetctlSSO:
					return fmt.Errorf("this Fleet server does not support fleetctl SSO login.\n%s", ssoAuthInstructions)
				}

				resp, err := ssoLogin(fleet, c.App.Writer, c.App.ErrWriter)
				if err != nil {
					return fmt.Errorf("Login failed: %w", err)
				}
				if err := setConfigValue(configPath, context, "email", resp.User.Email); err != nil {
					return fmt.Errorf("error setting email for the current context: %w", err)
				}
				if err := setConfigValue(configPath, context, "token", resp.Token); err != nil {
					return fmt.Errorf("error setting token for the current context: %w", err)
				}
				fmt.Fprintf(c.App.Writer, "[+] Fleet login successful as %s and context configured!\n", resp.User.Email)
				return nil
			}

			// Servers that predate fleetctl SSO login only support it via API tokens.
			if ssoEnabled && !fleetctlSSO {
				fmt.Fprintf(os.Stderr, "Warning: %s\n\n", ssoAuthInstructions)
			}

			definedAsEnvOnly := func(flagName, envName string) bool {
				cliArgPresent := false
				for _, arg := range os.Args {
					if arg == flagName {
						cliArgPresent = true
					}
				}
				return os.Getenv(envName) != "" && !cliArgPresent
			}

			// Allow interactive entry to discourage passwords in
			// CLI history.
			if flEmail == "" {
				fmt.Println("Log in using the standard Fleet credentials.")
				fmt.Print("Email: ")
				_, err := fmt.Scanln(&flEmail)
				if err != nil {
					return fmt.Errorf("error reading email: %w", err)
				}
			} else if definedAsEnvOnly("--email", "EMAIL") {
				fmt.Printf("Using value of environment variable $EMAIL as email.\n")
			}
			if flPassword == "" {
				fmt.Print("Password: ")
				passBytes, err := terminal.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return fmt.Errorf("error reading password: %w", err)
				}
				fmt.Println()
				flPassword = string(passBytes)
			} else if definedAsEnvOnly("--password", "PASSWORD") {
				fmt.Printf("Using value of environment variable $PASSWORD as password.\n")
			}

			token, err := fleet.Login(flEmail, flPassword)
			if err != nil {
				root := ctxerr.Cause(err)
				switch root.(type) { //nolint:gocritic // ignore singleCaseSwitch
				case service.NotSetupErr:
					return err
				}
				fmt.Fprintf(os.Stderr, "\n%s\n", mfaAuthInstructions)
				return fmt.Errorf("Login failed: %w", err)
			}

			if err := setConfigValue(configPath, context, "email", flEmail); err != nil {
				return fmt.Errorf("error setting email for the current context: %w", err)
			}

			if err := setConfigValue(configPath, context, "token", token); err != nil {
				return fmt.Errorf("error setting token for the current context: %w", err)
			}

			fmt.Printf("[+] Fleet login successful and context configured!\n")

			return nil
		},
	}
}
