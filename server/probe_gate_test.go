package server

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeGateBoundsConcurrency(t *testing.T) {
	gate := newProbeGate("test", 2)
	var active atomic.Int32
	var maximum atomic.Int32
	var wait sync.WaitGroup

	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			gate.run(fmt.Sprintf("task-%d", index), func() {
				current := active.Add(1)
				for {
					previous := maximum.Load()
					if current <= previous || maximum.CompareAndSwap(previous, current) {
						break
					}
				}
				time.Sleep(10 * time.Millisecond)
				active.Add(-1)
			})
		}(index)
	}
	wait.Wait()

	if got := maximum.Load(); got != 2 {
		t.Fatalf("maximum concurrency = %d, want 2", got)
	}
}
