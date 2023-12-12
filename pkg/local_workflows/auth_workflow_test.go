package localworkflows

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func testInitAuthWorkflow(ctrl *gomock.Controller, config configuration.Configuration) (workflow.Engine, error) {
	engine := mocks.NewMockEngine(ctrl)
	engine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes().Return(&workflow.EntryImpl{}, nil)
	engine.EXPECT().GetConfiguration().Return(config).AnyTimes()
	return engine, InitAuth(engine)
}

func testGetOAuthMockHTTPClient(t *testing.T, responsePayload []byte) *http.Client {
	mockClient := newTestClient(func(req *http.Request) *http.Response {
		// Test request parameters
		require.Equal(t, "/oauth2/token", req.URL.String())
		require.Equal(t, "GET", req.Method)
		require.Equal(t, "application/json", req.Header.Get("Content-Type"))

		return &http.Response{
			StatusCode: 200,
			// Send response to be tested
			Body: io.NopCloser(bytes.NewBuffer(responsePayload)),
			// Must be set to non-nil value or it panics
			Header: make(http.Header),
		}
	})
	return mockClient
}

func Test_authEntryPoint(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.NewInMemory()
	orgId := "orgId"

	config.Set(configuration.ORGANIZATION, orgId)
	config.Set(authClientIdFlag, "clientId")
	config.Set(authClientSecretFlag, "clientSecret")
	config.Set(authTypeParameter, authTypeOAuth)
	config.Set("openBrowserFunc", func(authUrl string) {
		logger.Printf("openBrowserFunc: %s", authUrl)
	})

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	engine, err := testInitAuthWorkflow(ctrl, config)
	require.NoError(t, err)

	token := oauth2.Token{
		AccessToken:  "accessToken",
		TokenType:    "oauth2",
		RefreshToken: "refreshToken",
		Expiry:       time.Now().Add(time.Hour),
	}

	responsePayload, err := json.Marshal(token)
	require.NoError(t, err)

	mockClient := testGetOAuthMockHTTPClient(t, responsePayload)

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEngine().Return(engine).AnyTimes()
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	networkAccessMock.EXPECT().GetUnauthorizedHttpClient().Return(mockClient).AnyTimes()

	_, err = authEntryPoint(invocationContextMock, []workflow.Data{})

	require.NoError(t, err)
}
