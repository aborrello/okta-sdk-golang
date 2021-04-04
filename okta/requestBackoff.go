package okta

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v4"
)

type backoffTransport struct {
	next    http.RoundTripper
	policy  func(context.Context) *backoffPolicy
	timeout time.Duration
}

func (re *RequestExecutor) NewBackoffTransport(next http.RoundTripper) (http.RoundTripper, error) {
	t := backoffTransport{
		next:    next,
		timeout: time.Duration(re.config.Okta.Client.RequestTimeout) * time.Second,
	}

	t.policy = func(ctx context.Context) *backoffPolicy {
		return &backoffPolicy{
			ctx:        ctx,
			maxBackoff: time.Duration(re.config.Okta.Client.RateLimit.MaxBackoff) * time.Second,
			maxRetries: re.config.Okta.Client.RateLimit.MaxRetries,
		}
	}

	return &t, nil
}

func (t *backoffTransport) RoundTrip(req *http.Request) (res *http.Response, err error) {

	var body func() io.ReadCloser
	if req.Body != nil {
		data, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body.Close()

		body = func() io.ReadCloser {
			return ioutil.NopCloser(bytes.NewReader(data))
		}
	}

	ctx := req.Context()
	if t.timeout > 0 {
		timeoutCtx, cancel := context.WithTimeout(ctx, t.timeout)
		ctx = timeoutCtx
		defer cancel()
	}

	policy := t.policy(ctx)
	op := func() error {

		if body != nil {
			req.Body = body()
		}

		res, err = t.next.RoundTrip(req)
		if errors.Is(err, io.EOF) {
			return err
		} else if err != nil {
			return backoff.Permanent(err)
		}

		if res.StatusCode != http.StatusTooManyRequests {
			return nil
		}

		// TODO: Ask maintainers why they drained the body instead of just called res.Body.Close().

		policy.retryCount++
		if err := policy.SetNextBackOffFromRes(res); err != nil {
			return backoff.Permanent(err)
		}

		req.Header.Add("X-Okta-Retry-For", res.Header.Get("X-Okta-Request-Id"))
		req.Header.Add("X-Okta-Retry-Count", fmt.Sprint(policy.retryCount))
		return errors.New("to many requests")

	}

	err = backoff.Retry(op, policy)
	return

}

type backoffPolicy struct {
	ctx                         context.Context
	retryCount, maxRetries      int32
	backoffDuration, maxBackoff time.Duration
}

// NextBackOff returns the duration to wait before retrying the operation. backoff.Stop will be
// returned if the retry count meets or exceeds the user specified max retries.
func (policy *backoffPolicy) NextBackOff() time.Duration {
	if policy.retryCount > policy.maxRetries {
		return backoff.Stop
	}
	return policy.backoffDuration
}

// SetNextBackOff defines the next backoff duration to be the time.Duration supplied.
func (policy *backoffPolicy) SetNextBackOffFromRes(res *http.Response) error {

	if res == nil {
		return errors.New("no response to derive backoff time from")
	}

	requestDate, err := time.Parse("Mon, 02 Jan 2006 15:04:05 GMT", res.Header.Get("Date"))
	if err != nil {
		return fmt.Errorf("date header is missing or invalid: %w", err)
	}

	rateLimitReset, err := strconv.ParseInt(res.Header.Get("X-Rate-Limit-Reset"), 10, 64)
	if err != nil {
		// this is error is considered to be permanent and should not be retried
		return fmt.Errorf("X-Rate-Limit-Reset header is missing or invalid: %w", err)
	}

	policy.backoffDuration = time.Unix(rateLimitReset, 0).Sub(requestDate)
	if policy.backoffDuration > policy.maxBackoff {
		policy.backoffDuration = policy.maxBackoff
	}

	return nil

}

// Context returns the context of the backoff policy to satiate the BackoffWithContext interface.
func (policy *backoffPolicy) Context() context.Context {
	return policy.ctx
}

// Reset sets the retry count to zero and saciates the BackoffWithContext interface.
func (policy *backoffPolicy) Reset() {
	policy.retryCount = 0
}
