/*
 * Copyright 2018 - Present Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/okta/okta-sdk-golang/v2/okta/cache"
)

const AccessTokenCacheKey = "OKTA_ACCESS_TOKEN"

type RequestExecutor struct {
	httpClient  *http.Client
	config      *config
	cache       cache.Cache
	baseURL     *url.URL
	baseHeaders http.Header
}

type RequestAccessToken struct {
	TokenType   string `json:"token_type,omitempty"`
	ExpireIn    int    `json:"expire_in,omitempty"`
	AccessToken string `json:"access_token,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

func NewRequestExecutor(httpClient *http.Client, cache cache.Cache, config *config) (*RequestExecutor, error) {
	re := RequestExecutor{
		config: config,
		cache:  cache,
	}

	baseURL, err := url.Parse(config.Okta.Client.OrgUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid org url: %w", err)
	}
	re.baseURL = baseURL

	// Set default headers.
	re.baseHeaders = make(http.Header)
	re.baseHeaders.Set("User-Agent", NewUserAgent(config).String())
	re.baseHeaders.Set("Accept", "application/json")
	re.baseHeaders.Set("Content-Type", "application/json")

	re.httpClient = httpClient
	if re.httpClient == nil {
		tr := &http.Transport{
			IdleConnTimeout: 30 * time.Second,
		}
		re.httpClient = &http.Client{
			Transport: tr,
			Timeout:   time.Second * time.Duration(re.config.Okta.Client.ConnectionTimeout),
		}
	}

	rtBackoff, err := re.NewBackoffTransport(re.httpClient.Transport)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize backoff transport: %w", err)
	}

	rtAuthorization, err := re.NewAuthTransport(rtBackoff)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize authorization transport: %w", err)
	}

	rtCache, err := re.NewCacheTransport(rtAuthorization)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cache transport: %w", err)
	}

	re.httpClient.Transport = rtCache
	return &re, nil
}

func (re *RequestExecutor) NewRequestLegacy(method string, url string, body interface{}) (*http.Request, error) {
	var buff io.ReadWriter
	if body != nil {
		buff = new(bytes.Buffer)
		encoder := json.NewEncoder(buff)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(body)
		if err != nil {
			return nil, err
		}
	}
	url = re.config.Okta.Client.OrgUrl + url

	req, err := http.NewRequest(method, url, buff)
	if err != nil {
		return nil, err
	}

	req.Header.Add("User-Agent", NewUserAgent(re.config).String())

	return req, nil
}

func (re *RequestExecutor) Do(ctx context.Context, req *Request, v interface{}) (*Response, error) {

	r, err := req.Build(re.baseURL)
	if err != nil {
		return nil, err
	}

	if req.freshCache {
		re.cache.Delete(cache.CreateCacheKey(r))
	}

	res, err := re.httpClient.Do(r)
	if err != nil {
		return nil, err
	}

	resp, err := re.ParseResponse(res)
	if err != nil {
		return nil, err
	}

	if err := resp.UnmarshalBody(v); err != nil {
		return nil, err
	}

	return resp, nil

}
