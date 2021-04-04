package okta

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func (re *RequestExecutor) NewAuthTransport(next http.RoundTripper) (http.RoundTripper, error) {
	switch re.config.Okta.Client.AuthorizationMode {

	case "SSWS":
		return &httpAuthTransportSSWS{
			next:  next,
			token: re.config.Okta.Client.Token,
		}, nil

	case "PrivateKey":
		t := httpAuthTransportPrivateKey{
			re:     re,
			signer: re.config.PrivateKeySigner,
		}

		// Create a HTTP client based on the RequestExecutor base client with the current transport stack.
		t.httpClient = &http.Client{
			Transport:     next,
			CheckRedirect: re.httpClient.CheckRedirect,
			Jar:           re.httpClient.Jar,
			Timeout:       re.httpClient.Timeout,
		}

		// If the private key auth transport signer is not provided, generate a new one based on
		// the supplied PrivateKey config field.
		if t.signer == nil {
			raw := []byte(strings.ReplaceAll(re.config.Okta.Client.PrivateKey, `\n`, "\n"))
			block, _ := pem.Decode(raw)
			if block == nil {
				return nil, errors.New("invalid private key")
			}

			var key interface{}
			switch block.Type {
			case "RSA PRIVATE KEY":
				priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("invalid RSA private key: %w", err)
				}
				key = priv

			default:
				return nil, errors.New("unsupported private key type: " + block.Type)
			}

			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
			if err != nil {
				return nil, fmt.Errorf("private key signer initialization error: %w", err)
			}

			t.signer = signer
		}

		return &t, nil

	default:
		return nil, errors.New("unsupported authorization mode: " + re.config.Okta.Client.AuthorizationMode)
	}
}

type httpAuthTransportSSWS struct {
	next  http.RoundTripper
	token string
}

func (t httpAuthTransportSSWS) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "SSWS "+t.token)
	return t.next.RoundTrip(req)
}

type ClientAssertionClaims struct {
	Issuer   string           `json:"iss,omitempty"`
	Subject  string           `json:"sub,omitempty"`
	Audience string           `json:"aud,omitempty"`
	Expiry   *jwt.NumericDate `json:"exp,omitempty"`
	IssuedAt *jwt.NumericDate `json:"iat,omitempty"`
	ID       string           `json:"jti,omitempty"`
}

type httpAuthTransportPrivateKey struct {
	re         *RequestExecutor
	httpClient *http.Client
	signer     jose.Signer
}

func (t *httpAuthTransportPrivateKey) RoundTrip(req *http.Request) (*http.Response, error) {
	// Try using the cached access token if one exits. If Okta returns an Unauthorized error, retry
	// the request after refreshing the token.
	if t.re.cache.Has(AccessTokenCacheKey) {
		req.Header.Set("Authorization", "Bearer "+t.re.cache.GetString(AccessTokenCacheKey))
		res, err := t.httpClient.Transport.RoundTrip(req)
		if err != nil || res.StatusCode != http.StatusUnauthorized {
			return res, err
		}
	}

	accessToken, err := t.Refresh()
	if err != nil {
		return nil, fmt.Errorf("access token exchange failed: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	return t.httpClient.Transport.RoundTrip(req)
}

func (t *httpAuthTransportPrivateKey) Refresh() (string, error) {
	claims := ClientAssertionClaims{
		Subject:  t.re.config.Okta.Client.ClientId,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Issuer:   t.re.config.Okta.Client.ClientId,
		Audience: t.re.config.Okta.Client.OrgUrl + "/oauth2/v1/token",
	}

	jwtBuilder := jwt.Signed(t.signer).Claims(claims)
	assertion, err := jwtBuilder.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to build client assertion: %w", err)
	}

	endpoint, err := t.re.baseURL.Parse("/oauth2/v1/token")
	if err != nil {
		return "", fmt.Errorf("invalid client assertion endpoint: %w", err)
	}

	// TODO: ask maintainers why this is being passed into the URL query params when the Okta API example uses the request body?
	endpoint.Query().Set("grant_type", "client_credentials")
	endpoint.Query().Set("scope", strings.Join(t.re.config.Okta.Client.Scopes, " "))
	endpoint.Query().Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	endpoint.Query().Set("client_assertion", assertion)

	req, err := http.NewRequest("POST", endpoint.String(), nil)
	if err != nil {
		return "", fmt.Errorf("error building client assertion http request: %w", err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := t.re.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	resp, err := t.re.ParseResponse(res)
	if err != nil {
		return "", err
	}

	var accessToken RequestAccessToken
	if err := resp.UnmarshalBody(&accessToken); err != nil {
		return "", fmt.Errorf("failed to unmarshal access token: %w", err)
	}

	// Cache and return the access token.
	t.re.cache.SetString(AccessTokenCacheKey, accessToken.AccessToken)
	return accessToken.AccessToken, nil
}
