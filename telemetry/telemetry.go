// Package telemetry implements observe over OpenTelemetry: the SDK
// (Provider), an observe.Meter backed by it, and the Prometheus exposition
// of every instrument on the admin listener's /metrics.
//
// It declares no instrument of its own except build_info: each feature
// package declares its metrics from the observe.Meter fx injects, and never
// imports OpenTelemetry. Only the full server build links this package; the
// lean CLI never does.
package telemetry

// scope names the instrumentation scope every instrument belongs to.
const scope = "github.com/onhotpath/tempogate/telemetry"
