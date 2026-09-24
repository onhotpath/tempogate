package servercmd

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/suite"

	"github.com/onhotpath/tempogate/api"
)

type GenOASCmdSuite struct {
	suite.Suite

	ctx     context.Context
	servers *api.Servers
}

func TestGenOASCmdSuite(t *testing.T) {
	suite.Run(t, new(GenOASCmdSuite))
}

func (s *GenOASCmdSuite) SetupTest() {
	s.ctx = context.Background()

	// adminProbe stands in for the real /admin/keys handler; the goal of
	// gen-oas tests is the spec-split contract, not the handler's
	// schema (admin/keys_test.go covers that).
	adminProbe := func(a huma.API) {
		type out struct {
			Body struct {
				OK bool `json:"ok"`
			}
		}
		huma.Register(a, huma.Operation{
			OperationID: "admin-probe",
			Method:      "GET",
			Path:        "/admin/probe",
			Summary:     "admin probe",
			Tags:        []string{"admin"},
		}, func(_ context.Context, _ *struct{}) (*out, error) {
			o := &out{}
			o.Body.OK = true
			return o, nil
		})
	}
	publicProbe := func(a huma.API) {
		type out struct {
			Body struct {
				OK bool `json:"ok"`
			}
		}
		huma.Register(a, huma.Operation{
			OperationID: "public-probe",
			Method:      "GET",
			Path:        "/public/probe",
			Summary:     "public probe",
			Tags:        []string{"public"},
		}, func(_ context.Context, _ *struct{}) (*out, error) {
			o := &out{}
			o.Body.OK = true
			return o, nil
		})
	}

	s.servers = api.New(api.NewReadiness(),
		api.WithRegistrar(publicProbe),
		api.WithAdminRegistrar(adminProbe),
	)
}

func (s *GenOASCmdSuite) run(args ...string) (string, error) {
	cmd := newGenOASCmd(genOASParams{Servers: s.servers})
	cmd.SetArgs(args)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(new(testWriter))
	err := cmd.ExecuteContext(s.ctx)
	return out.String(), err
}

// TestPublicSpecOmitsAdminPaths is the structural guarantee gen-oas exists
// to surface: the public spec must not mention any /admin/* path. If admin
// ever leaks onto the public surface, the diff against this assertion is
// what catches it.
func (s *GenOASCmdSuite) TestPublicSpecOmitsAdminPaths() {
	out, err := s.run("-f", "json")
	s.Require().NoError(err)

	paths := pathsOf(s.T(), out)
	s.Contains(paths, "/public/probe", "public spec must contain the public probe")
	s.Contains(paths, "/healthz", "public spec must contain /healthz")
	for p := range paths {
		s.NotContains(p, "/admin/", "public spec must not contain admin paths: %s", p)
	}
}

// TestAdminSpecIsAdminOnly is the converse: the admin spec must not leak
// public/OIDC routes.
func (s *GenOASCmdSuite) TestAdminSpecIsAdminOnly() {
	out, err := s.run("--admin", "-f", "json")
	s.Require().NoError(err)

	paths := pathsOf(s.T(), out)
	s.Contains(paths, "/admin/healthz", "admin spec must contain /admin/healthz")
	s.Contains(paths, "/admin/probe", "admin spec must contain the admin probe")
	for p := range paths {
		s.True(len(p) >= len("/admin/") && p[:len("/admin/")] == "/admin/",
			"admin spec contained a non-admin path: %s", p)
	}
}

func (s *GenOASCmdSuite) TestYAMLDefaultFormat() {
	out, err := s.run()
	s.Require().NoError(err)
	s.Contains(out, "openapi:", "default format must be YAML (key starts a line)")
}

func (s *GenOASCmdSuite) TestUnknownFormatRejected() {
	_, err := s.run("-f", "xml")
	s.Require().Error(err)
	s.Contains(err.Error(), `unknown format "xml"`)
}

// pathsOf parses a JSON OpenAPI document and returns the set of paths it
// declares. Only paths matter for the structural-split assertions; the rest
// of the schema is huma's responsibility and tested upstream.
func pathsOf(t *testing.T, raw string) map[string]struct{} {
	t.Helper()
	var doc struct {
		Paths map[string]any `json:"paths"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("decode openapi json: %v", err)
	}
	out := make(map[string]struct{}, len(doc.Paths))
	for p := range doc.Paths {
		out[p] = struct{}{}
	}
	return out
}
