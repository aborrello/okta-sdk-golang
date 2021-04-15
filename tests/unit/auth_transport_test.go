package unit

import (
	"context"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestAuthTransport_ssws(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	_, client, err := tests.NewClient(
		context.Background(),
		okta.WithOrgUrl("https://golang.oktapreview.com"),
		okta.WithAuthorizationMode("SSWS"),
		okta.WithToken("abc123"),
	)
	if err != nil {
		t.Error(err)
		return
	}

	httpmock.RegisterResponder("POST", "/api/v1/fake",
		tests.MockResponse(
			tests.MockValidResponse(),
		),
	)

	re := client.GetRequestExecutor()
	authTransport, err := re.NewAuthTransport(http.DefaultClient.Transport)
	if err != nil {
		t.Error(err)
		return
	}

	req, err := http.NewRequest("POST", "https://golang.oktapreview.com/api/v1/fake", nil)
	if err != nil {
		t.Error(err)
		return
	}

	_, err = authTransport.RoundTrip(req)
	if err != nil {
		t.Error(err)
		return
	}

	assert.Equal(t, req.Header.Get("Authorization"), "SSWS abc123", "does not contain a bearer token for the request")

	httpmock.GetTotalCallCount()
	info := httpmock.GetCallCountInfo()
	require.Equal(t, 1, info["POST /api/v1/fake"], "did not make exactly 1 call to /api/v1/fake")

}
