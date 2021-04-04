package okta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type Request struct {
	binary     bool
	body       interface{}
	freshCache bool
	headers    http.Header
	method     string
	path       string
}

func (re *RequestExecutor) NewRequest(method string, path string, body interface{}) *Request {
	return &Request{
		method:  method,
		path:    path,
		headers: re.baseHeaders.Clone(),
		body:    body,
	}
}

func (r *Request) AsBinary() *Request {
	r.binary = true
	return r
}

func (r *Request) WithAccept(acceptHeader string) *Request {
	r.headers.Set("Accept", acceptHeader)
	return r
}

func (r *Request) WithContentType(contentTypeHeader string) *Request {
	r.headers.Set("Content-Type", contentTypeHeader)
	return r
}

func (r *Request) RefreshNext() *Request {
	r.freshCache = true
	return r
}

func (r *Request) Build(baseURL *url.URL) (*http.Request, error) {

	u, err := baseURL.Parse(r.path)
	if err != nil {
		return nil, fmt.Errorf("invalid uri: %w", err)
	}

	var body io.Reader
	if r.body == nil {
		r.headers.Del("Content-Type")
	} else {
		buf := bytes.NewBuffer([]byte{})
		encoder := json.NewEncoder(buf)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(r.body); err != nil {
			return nil, fmt.Errorf("unable to encode request body: %w", err)
		}
		body = buf
	}

	req, err := http.NewRequest(r.method, u.String(), body)
	if err != nil {
		return nil, err
	}

	return req, nil

}
