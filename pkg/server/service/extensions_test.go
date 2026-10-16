package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/runtime"
)

type extensionBuilder struct{}

func (extensionBuilder) BuildHTTP(_ context.Context, name string) (http.Handler, error) {
	if name != "example@gogw" {
		return nil, nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), nil
}

func TestExtensionBuilder(t *testing.T) {
	factory := &ManagerFactory{}
	factory.AddServiceBuilder(extensionBuilder{})
	manager := factory.Build(&runtime.Configuration{})
	h, err := manager.BuildHTTP(t.Context(), "example@gogw")
	require.NoError(t, err)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, 204, response.Code)
	_, err = manager.BuildHTTP(t.Context(), "unknown@gogw")
	assert.Error(t, err)
	h, err = manager.BuildHTTP(t.Context(), "noop@internal")
	require.NoError(t, err)
	response = httptest.NewRecorder()
	h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusTeapot, response.Code)
}
