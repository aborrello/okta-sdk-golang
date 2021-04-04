package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/BurntSushi/toml"
)

type Response struct {
	*http.Response
	re       *RequestExecutor
	data     []byte
	Self     string
	NextPage string
}

func (re *RequestExecutor) ParseResponse(res *http.Response) (*Response, error) {
	if res == nil {
		return nil, fmt.Errorf("must supply http response")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	res.Body.Close()

	response := &Response{Response: res, re: re, data: body}
	// Wrap the pre-read body with a NOP Closer to allow it to be read again.
	response.Body = response.GetBody()

	if err := response.CheckForError(); err != nil {
		return response, err
	}

	if links, ok := res.Header["Link"]; ok {
		for _, link := range links {
			splitLinkHeader := strings.Split(link, ";")
			if len(splitLinkHeader) < 2 {
				continue
			}
			rawLink := strings.TrimRight(strings.TrimLeft(splitLinkHeader[0], "<"), ">")
			rawUrl, _ := url.Parse(rawLink)
			rawUrl.Scheme = ""
			rawUrl.Host = ""

			if strings.Contains(link, `rel="self"`) {
				response.Self = rawUrl.String()
			}

			if strings.Contains(link, `rel="next"`) {
				response.NextPage = rawUrl.String()
			}
		}
	}

	return response, nil
}

func (resp *Response) GetBody() io.ReadCloser {
	return ioutil.NopCloser(bytes.NewReader(resp.data))
}

func (resp *Response) UnmarshalBody(dest interface{}) error {
	var err error
	switch resp.Header.Get("Content-Type") {

	case "application/json":
		err = json.NewDecoder(resp.GetBody()).Decode(dest)

	case "application/xml":
		err = xml.NewDecoder(resp.GetBody()).Decode(dest)

	case "application/octet-stream":
		return nil

	default:
		return errors.New("could not build a response for type: " + resp.Header.Get("Content-Type"))

	}

	if err == io.EOF {
		return nil
	}
	return err
}

func (resp *Response) CheckForError() error {
	statusCode := resp.StatusCode
	if statusCode >= http.StatusOK && statusCode < http.StatusBadRequest {
		return nil
	}
	e := Error{}
	if statusCode == http.StatusUnauthorized && strings.Contains(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		for _, v := range strings.Split(resp.Header.Get("WWW-Authenticate"), ", ") {
			if strings.Contains(v, "error_description") {
				_, err := toml.Decode(v, &e)
				if err != nil {
					e.ErrorSummary = "unauthorized"
				}
				return &e
			}
		}
	}
	// TODO: ask maintainers why this error is being discarded.
	_ = json.NewDecoder(resp.GetBody()).Decode(&e)
	return &e
}

func (r *Response) Next(ctx context.Context, dest interface{}) (*Response, error) {
	if r.re == nil {
		return nil, errors.New("no initial response provided from previous request")
	}
	req := r.re.NewRequest("GET", r.NextPage, nil)
	return r.re.Do(ctx, req, dest)
}

func (r *Response) HasNextPage() bool {
	return r.NextPage != ""
}
