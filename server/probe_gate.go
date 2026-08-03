package server

import (
	"log"
	"time"
)

const (
	lightProbeConcurrency = 2
	heavyProbeConcurrency = 1
)

type probeGate struct {
	name  string
	slots chan struct{}
}

var (
	lightProbeGate = newProbeGate("latency", lightProbeConcurrency)
	heavyProbeGate = newProbeGate("quality", heavyProbeConcurrency)
)

func newProbeGate(name string, concurrency int) *probeGate {
	if concurrency < 1 {
		concurrency = 1
	}
	return &probeGate{name: name, slots: make(chan struct{}, concurrency)}
}

func (gate *probeGate) run(task string, fn func()) {
	queuedAt := time.Now()
	gate.slots <- struct{}{}
	defer func() { <-gate.slots }()
	if waited := time.Since(queuedAt); waited >= time.Second {
		log.Printf("%s probe %s waited %s for a concurrency slot", gate.name, task, waited.Round(time.Millisecond))
	}
	fn()
}
