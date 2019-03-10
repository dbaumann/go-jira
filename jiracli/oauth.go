package jiracli

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/dghubble/oauth1"
	"gopkg.in/AlecAivazis/survey.v1"
)

func (o *GlobalOptions) SetOauthCredentials() error {
	if o.PasswordSource.Value == "keyring" {
		var path string
		if path := os.Getenv("JIRA_PRIVATE_KEY"); path == "" {
			err := survey.AskOne(
				&survey.Input{
					Message: fmt.Sprint("Private key for signing OAuth: "),
				},
				&path,
				nil,
			)
			if err != nil {
				log.Errorf("Failed to determine location of signing key. %v", err)
				return err
			}
		}

		err := o.credentialSave("oauth.signingKeyPath", path)
		if err != nil {
			return err
		}

		config, err := oauthConfig(o)
		if err != nil {
			log.Errorf("Failed to generate OAuth configuration. %v", err)
			return err
		}

		requestToken, requestSecret, err := config.RequestToken()
		if err != nil {
			log.Errorf("Failed to get request token. %v", err)
			return err
		}
		authorizationURL, err := config.AuthorizationURL(requestToken)
		if err != nil {
			log.Errorf("Failed to get authorization url. %v", err)
			return err
		}

		code := ""
		err = survey.AskOne(
			&survey.Input{
				Message: fmt.Sprintf("Go to the following link in your browser then type the "+
					"authorization code: \n%s\n", authorizationURL.String()),
			},
			&code,
			nil,
		)
		if err != nil {
			log.Errorf("Failed to read authorization code. %v", err)
			return err
		}

		accessToken, accessSecret, err := config.AccessToken(requestToken, requestSecret, code)
		if err != nil {
			log.Errorf("Failed to get access token. %v", err)
			return err
		}

		err = o.credentialSave("oauth.accessToken", accessToken)
		if err != nil {
			return err
		}

		err = o.credentialSave("oauth.accessSecret", accessSecret)
		if err != nil {
			return err
		}
	}
	return nil
}

func NewOAuthTransport(o *GlobalOptions) (*http.RoundTripper, error) {
	config, err := oauthConfig(o)
	if err != nil {
		log.Errorf("Failed to generate OAuth configuration. %v", err)
		return nil, err
	}

	token := getToken(o)
	if token != nil {
		return nil, errors.New("Failed to load OAuth token from credential manager")
	}

	ctx := context.Background()
	oauthClient := oauth1.NewClient(ctx, config, token)
	return &oauthClient.Transport, nil
}

func oauthConfig(o *GlobalOptions) (*oauth1.Config, error) {
	keyPath := o.credentialLoad("oauth.signingKeyPath")
	if keyPath == nil {
		return nil, errors.New("Failed to load OAuth signing key path from credential manager")
	}

	keyBytes, err := ioutil.ReadFile(*keyPath)
	if err != nil {
		log.Errorf("Failed to read signing key from %s. %s", keyPath, err)
		return nil, err
	}
	keyDERBlock, _ := pem.Decode(keyBytes)
	if keyDERBlock == nil {
		return nil, errors.New("Failed to decode key PEM block")
	}
	if !(keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY")) {
		log.Errorf("Unexpected key DER block type: %s", keyDERBlock.Type)
		return nil, err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey([]byte(keyDERBlock.Bytes))
	if err != nil {
		log.Errorf("Failed to parse PKCS1 private key. %s", err)
		return nil, err
	}

	config := &oauth1.Config{
		ConsumerKey: o.ConsumerKey.Value,
		CallbackURL: "oob", // https://oauth.net/core/1.0a/#rfc.section.6.1.1
		Endpoint: oauth1.Endpoint{
			RequestTokenURL: o.Endpoint.Value + "plugins/servlet/oauth/request-token",
			AuthorizeURL:    o.Endpoint.Value + "plugins/servlet/oauth/authorize",
			AccessTokenURL:  o.Endpoint.Value + "plugins/servlet/oauth/access-token",
		},
		Signer: &oauth1.RSASigner{
			PrivateKey: privateKey,
		},
	}

	return config, nil
}

func getToken(o *GlobalOptions) *oauth1.Token {
	accessToken := o.credentialLoad("oauth.accessToken")
	accessSecret := o.credentialLoad("oauth.accessSecret")
	if accessToken != nil && accessSecret != nil {
		return oauth1.NewToken(*accessToken, *accessSecret)
	}
	return nil
}

func (o *GlobalOptions) credentialLoad(key string) *string {
	credential := ""
	if o.PasswordSource.Value != "" {
		if o.PasswordSource.Value == "keyring" {
			var err error
			credential, err = keyringGet(key)
			if err != nil {
				log.Errorf("Failed to get credential in keyring [%s]. %v", key, err)
			}
		} else if o.PasswordSource.Value == "pass" {
			if o.PasswordDirectory.Value != "" {
				orig := os.Getenv("PASSWORD_STORE_DIR")
				os.Setenv("PASSWORD_STORE_DIR", o.PasswordDirectory.Value)
				defer os.Setenv("PASSWORD_STORE_DIR", orig)
			}
			if bin, err := exec.LookPath("pass"); err == nil {
				buf := bytes.NewBufferString("")
				cmd := exec.Command(bin, key)
				cmd.Stdout = buf
				cmd.Stderr = buf
				if err := cmd.Run(); err != nil {
					log.Errorf("Failed to get credential in password manager [%s]. %v", key, err)
				} else {
					credential = strings.TrimSpace(buf.String())
				}
			}
		} else {
			log.Warningf("Unknown password-source: %s", o.PasswordSource)
		}
	}

	if credential != "" {
		return &credential
	}
	return nil
}

func (o *GlobalOptions) credentialSave(key string, value string) error {
	if o.PasswordSource.Value == "keyring" {
		err := keyringSet(key, value)
		if err != nil {
			log.Errorf("Failed to set credential in keyring [%s]. %v", key, err)
			return err
		}
	} else if o.PasswordSource.Value == "pass" {
		if o.PasswordDirectory.Value != "" {
			orig := os.Getenv("PASSWORD_STORE_DIR")
			os.Setenv("PASSWORD_STORE_DIR", o.PasswordDirectory.Value)
			defer os.Setenv("PASSWORD_STORE_DIR", orig)
		}
		if bin, err := exec.LookPath("pass"); err == nil {
			log.Debugf("using %s", bin)
			if value != "" {
				in := bytes.NewBufferString(fmt.Sprintf("%s\n%s\n", value, value))
				out := bytes.NewBufferString("")
				cmd := exec.Command(bin, "insert", "--force", key)
				cmd.Stdin = in
				cmd.Stdout = out
				cmd.Stderr = out
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("Failed to set credential in password manager [%s]", out.String())
				}
			} else {
				// clear the `pass` entry on empty credential
				if err := exec.Command(bin, "rm", "--force", key).Run(); err != nil {
					return fmt.Errorf("Failed to clear credential in password manager [%s]", key)
				}
			}
		}
	} else if o.PasswordSource.Value != "" {
		return fmt.Errorf("Unknown password-source: %s", o.PasswordSource)
	}
	return nil
}
