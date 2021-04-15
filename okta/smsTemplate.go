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

// Code generated by okta openapi generator. DO NOT EDIT.

package okta

import (
	"context"
	"fmt"
	"time"

	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

type SmsTemplateResource resource

type SmsTemplate struct {
	Created      *time.Time               `json:"created,omitempty"`
	Id           string                   `json:"id,omitempty"`
	LastUpdated  *time.Time               `json:"lastUpdated,omitempty"`
	Name         string                   `json:"name,omitempty"`
	Template     string                   `json:"template,omitempty"`
	Translations *SmsTemplateTranslations `json:"translations,omitempty"`
	Type         string                   `json:"type,omitempty"`
}

// Adds a new custom SMS template to your organization.
func (m *SmsTemplateResource) CreateSmsTemplate(ctx context.Context, body SmsTemplate) (*SmsTemplate, *Response, error) {
	url := fmt.Sprintf("/api/v1/templates/sms")

	req := m.client.requestExecutor.NewRequest("POST", url, body).WithAccept("application/json").WithContentType("application/json")

	var smsTemplate *SmsTemplate

	resp, err := m.client.requestExecutor.Do(ctx, req, &smsTemplate)
	if err != nil {
		return nil, resp, err
	}

	return smsTemplate, resp, nil
}

// Fetches a specific template by &#x60;id&#x60;
func (m *SmsTemplateResource) GetSmsTemplate(ctx context.Context, templateId string) (*SmsTemplate, *Response, error) {
	url := fmt.Sprintf("/api/v1/templates/sms/%v", templateId)

	req := m.client.requestExecutor.NewRequest("GET", url, nil).WithAccept("application/json").WithContentType("application/json")

	var smsTemplate *SmsTemplate

	resp, err := m.client.requestExecutor.Do(ctx, req, &smsTemplate)
	if err != nil {
		return nil, resp, err
	}

	return smsTemplate, resp, nil
}

// Updates the SMS template.
func (m *SmsTemplateResource) UpdateSmsTemplate(ctx context.Context, templateId string, body SmsTemplate) (*SmsTemplate, *Response, error) {
	url := fmt.Sprintf("/api/v1/templates/sms/%v", templateId)

	req := m.client.requestExecutor.NewRequest("PUT", url, body).WithAccept("application/json").WithContentType("application/json")

	var smsTemplate *SmsTemplate

	resp, err := m.client.requestExecutor.Do(ctx, req, &smsTemplate)
	if err != nil {
		return nil, resp, err
	}

	return smsTemplate, resp, nil
}

// Removes an SMS template.
func (m *SmsTemplateResource) DeleteSmsTemplate(ctx context.Context, templateId string) (*Response, error) {
	url := fmt.Sprintf("/api/v1/templates/sms/%v", templateId)

	req := m.client.requestExecutor.NewRequest("DELETE", url, nil).WithAccept("application/json").WithContentType("application/json")

	resp, err := m.client.requestExecutor.Do(ctx, req, nil)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

// Enumerates custom SMS templates in your organization. A subset of templates can be returned that match a template type.
func (m *SmsTemplateResource) ListSmsTemplates(ctx context.Context, qp *query.Params) ([]*SmsTemplate, *Response, error) {
	url := fmt.Sprintf("/api/v1/templates/sms")
	if qp != nil {
		url = url + qp.String()
	}

	req := m.client.requestExecutor.NewRequest("GET", url, nil).WithAccept("application/json").WithContentType("application/json")

	var smsTemplate []*SmsTemplate

	resp, err := m.client.requestExecutor.Do(ctx, req, &smsTemplate)
	if err != nil {
		return nil, resp, err
	}

	return smsTemplate, resp, nil
}

// Updates only some of the SMS template properties:
func (m *SmsTemplateResource) PartialUpdateSmsTemplate(ctx context.Context, templateId string, body SmsTemplate) (*SmsTemplate, *Response, error) {
	url := fmt.Sprintf("/api/v1/templates/sms/%v", templateId)

	req := m.client.requestExecutor.NewRequest("POST", url, body).WithAccept("application/json").WithContentType("application/json")

	var smsTemplate *SmsTemplate

	resp, err := m.client.requestExecutor.Do(ctx, req, &smsTemplate)
	if err != nil {
		return nil, resp, err
	}

	return smsTemplate, resp, nil
}
