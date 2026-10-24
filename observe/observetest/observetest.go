// Package observetest is an in-memory observe.Meter and observe.Tracer for
// asserting what a package declares, records and traces.
package observetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/onhotpath/tempogate/observe"
)

// Measurement is one recorded value with its instrument and labels.
type Measurement struct {
	Name  string
	Value float64
	Attrs map[string]string
}

// Meter records every declaration and measurement. Safe for concurrent use.
type Meter struct {
	mu           sync.Mutex
	declared     map[string]observe.InstrumentConfig
	measurements []Measurement
	failWith     error
}

func NewMeter() *Meter {
	return &Meter{declared: map[string]observe.InstrumentConfig{}}
}

// FailingMeter refuses every declaration with err.
func FailingMeter(err error) *Meter {
	m := NewMeter()
	m.failWith = err
	return m
}

var errRedeclared = errors.New("observetest: instrument declared twice with different options")

func (m *Meter) declare(name string, opts []observe.InstrumentOption) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failWith != nil {
		return m.failWith
	}
	cfg := observe.NewInstrumentConfig(opts...)
	if prev, ok := m.declared[name]; ok && !sameConfig(prev, cfg) {
		return errRedeclared
	}
	m.declared[name] = cfg
	return nil
}

func sameConfig(a, b observe.InstrumentConfig) bool {
	if a.Description != b.Description || a.Unit != b.Unit || len(a.Buckets) != len(b.Buckets) {
		return false
	}
	for i := range a.Buckets {
		if a.Buckets[i] != b.Buckets[i] {
			return false
		}
	}
	return true
}

func (m *Meter) Int64Counter(name string, opts ...observe.InstrumentOption) (observe.Int64Counter, error) {
	if err := m.declare(name, opts); err != nil {
		return nil, err
	}
	return instrument{m: m, name: name}, nil
}

func (m *Meter) Float64Histogram(name string, opts ...observe.InstrumentOption) (observe.Float64Histogram, error) {
	if err := m.declare(name, opts); err != nil {
		return nil, err
	}
	return instrument{m: m, name: name}, nil
}

// Declared returns how name was declared.
func (m *Meter) Declared(name string) (observe.InstrumentConfig, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, ok := m.declared[name]
	return cfg, ok
}

// Measurements returns everything recorded on any of names, in the order
// it was recorded.
func (m *Meter) Measurements(names ...string) []Measurement {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Measurement
	for _, ms := range m.measurements {
		if slices.Contains(names, ms.Name) {
			out = append(out, ms)
		}
	}
	return out
}

func (m *Meter) record(name string, v float64, attrs []observe.Attr) {
	labels := make(map[string]string, len(attrs))
	for _, a := range attrs {
		labels[a.Key] = fmt.Sprint(a.Value())
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.measurements = append(m.measurements, Measurement{Name: name, Value: v, Attrs: labels})
}

type instrument struct {
	m    *Meter
	name string
}

func (i instrument) Add(_ context.Context, incr int64, attrs ...observe.Attr) {
	i.m.record(i.name, float64(incr), attrs)
}

func (i instrument) Record(_ context.Context, v float64, attrs ...observe.Attr) {
	i.m.record(i.name, v, attrs)
}
