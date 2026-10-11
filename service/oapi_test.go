package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

var (
	oapiRouter     routers.Router
	oapiRouterOnce sync.Once
	oapiRouterErr  error
)

func openAPIRouter(t *testing.T) routers.Router {
	t.Helper()
	oapiRouterOnce.Do(func() {
		_, thisFile, _, ok := runtime.Caller(0)
		if !ok {
			oapiRouterErr = errString("failed to locate test file")
			return
		}
		specPath := filepath.Join(filepath.Dir(thisFile), "..", "backend_oapi.json")

		loader := &openapi3.Loader{
			Context:               context.Background(),
			IsExternalRefsAllowed: true,
		}
		doc, err := loader.LoadFromFile(specPath)
		if err != nil {
			oapiRouterErr = err
			return
		}
		// beacon-APIs type files put description next to $ref; OpenAPI 3.0 ignores those siblings.
		if err := doc.Validate(loader.Context, openapi3.AllowExtraSiblingFields("description")); err != nil {
			oapiRouterErr = err
			return
		}
		oapiRouter, oapiRouterErr = gorillamux.NewRouter(doc)
	})
	if oapiRouterErr != nil {
		t.Fatalf("failed to load OpenAPI router: %v", oapiRouterErr)
	}
	return oapiRouter
}

type errString string

func (e errString) Error() string { return string(e) }

// assertOpenAPIResponse validates a response body against backend_oapi.json.
func assertOpenAPIResponse(t *testing.T, method, path string, status int, body []byte) {
	t.Helper()

	req, err := http.NewRequest(method, path, nil)
	if err != nil {
		t.Fatalf("failed to create request for OpenAPI validation: %v", err)
	}

	route, pathParams, err := openAPIRouter(t).FindRoute(req)
	if err != nil {
		t.Fatalf("failed to match OpenAPI route for %s %s: %v", method, path, err)
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")

	input := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request:    req,
			PathParams: pathParams,
			Route:      route,
		},
		Status: status,
		Header: header,
	}
	input.SetBodyBytes(body)

	if err := openapi3filter.ValidateResponse(t.Context(), input); err != nil {
		t.Fatalf("response for %s %s does not match OpenAPI schema: %v\nbody: %s", method, path, err, body)
	}
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return body
}
