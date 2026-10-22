package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/onhotpath/tempogate/buildinfo"
)

// healthBody is the public liveness answer. It carries no build version:
// the public listener is reachable by anyone, and the version only helps an
// attacker match the deployment to known issues.
type healthBody struct {
	Status string `json:"status" example:"ok" doc:"Liveness status"`
}

type healthOutput struct {
	Body healthBody
}

type adminHealthBody struct {
	Status  string `json:"status" example:"ok" doc:"Liveness status"`
	Version string `json:"version" example:"dev" doc:"Build version of the running binary"`
}

type adminHealthOutput struct {
	Body adminHealthBody
}

type readyBody struct {
	Status string `json:"status" example:"ready"`
}

type readyOutput struct {
	Body readyBody
}

// registerAdminHealth mounts a liveness probe on the admin surface. There is
// deliberately no readiness counterpart: the admin listener is private and
// pinned to loopback by default, so it has no role in cluster traffic shaping.
// The path is /admin/healthz (not /healthz) so an operator running curl by
// hand against either listener can tell from the path which surface answered.
func registerAdminHealth(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-healthz",
		Method:      http.MethodGet,
		Path:        "/admin/healthz",
		Summary:     "Admin liveness probe",
		Tags:        []string{"admin"},
	}, func(_ context.Context, _ *struct{}) (*adminHealthOutput, error) {
		return &adminHealthOutput{Body: adminHealthBody{
			Status:  "ok",
			Version: buildinfo.Version(),
		}}, nil
	})
}

func registerHealth(api huma.API, readiness *Readiness) {
	huma.Register(api, huma.Operation{
		OperationID: "healthz",
		Method:      http.MethodGet,
		Path:        "/healthz",
		Summary:     "Liveness probe",
		Tags:        []string{"health"},
	}, func(_ context.Context, _ *struct{}) (*healthOutput, error) {
		return &healthOutput{Body: healthBody{Status: "ok"}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "readyz",
		Method:      http.MethodGet,
		Path:        "/readyz",
		Summary:     "Readiness probe (503 until the HTTP listener is bound, and while the state store is unavailable)",
		Tags:        []string{"health"},
	}, func(ctx context.Context, _ *struct{}) (*readyOutput, error) {
		if err := readiness.Check(ctx); err != nil {
			return nil, huma.Error503ServiceUnavailable("not ready: " + err.Error())
		}
		return &readyOutput{Body: readyBody{Status: "ready"}}, nil
	})
}
