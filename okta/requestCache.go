package okta

import (
	"net/http"

	"github.com/okta/okta-sdk-golang/v2/okta/cache"
)

type cacheTransport struct {
	next  http.RoundTripper
	cache cache.Cache
}

func (re *RequestExecutor) NewCacheTransport(next http.RoundTripper) (http.RoundTripper, error) {
	return &cacheTransport{
		next:  next,
		cache: re.cache,
	}, nil
}

func (t *cacheTransport) RoundTrip(r *http.Request) (*http.Response, error) {

	switch r.Method {
	case http.MethodGet:
		return t.DoWithCache(r)
	default:
		return t.next.RoundTrip(r)
	}

}

func (t *cacheTransport) DoWithCache(req *http.Request) (*http.Response, error) {

	key := cache.CreateCacheKey(req)
	if t.cache.Has(key) {
		return t.cache.Get(key), nil
	}

	res, err := t.next.RoundTrip(req)
	if err != nil {
		return res, err
	}

	if res.StatusCode >= 200 && res.StatusCode <= 299 {
		t.cache.Set(key, res)
	}

	return res, nil

}
