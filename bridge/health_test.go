package bridge

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func healthBridge() *Bridge {
	return &Bridge{cfg: Config{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}}
}

func healthSnapshot(b *Bridge) Status {
	var s Status
	b.populateHealth(&s)
	return s
}

func TestWholeSweepFailureCannotBeMaskedByLaterNoOp(t *testing.T) {
	b := healthBridge()
	ok := func(context.Context) error { return nil }
	if healthSnapshot(b).Healthy {
		t.Fatal("a bridge without a completed sweep is healthy")
	}
	if err := b.runSweep(context.Background(), []bridgeStep{{"pay_withdrawals", ok}, {"fund_plasma", ok}}); err != nil {
		t.Fatal(err)
	}
	previousOK := b.lastOK
	if !healthSnapshot(b).Healthy {
		t.Fatal("a complete successful sweep did not restore health")
	}
	failure := func(context.Context) error { return errors.New("fixture payout refused") }
	noOp := func(context.Context) error {
		s := healthSnapshot(b)
		if s.Healthy || !s.Sweeping || s.Steps["pay_withdrawals"].State != "failed" {
			t.Fatalf("failure was hidden before the later no-op: %+v", s)
		}
		return nil
	}
	if err := b.runSweep(context.Background(), []bridgeStep{{"pay_withdrawals", failure}, {"fund_plasma", noOp}}); err != nil {
		t.Fatal(err)
	}
	s := healthSnapshot(b)
	if s.Healthy || s.Sweeping || !b.lastOK.Equal(previousOK) || !strings.Contains(s.LastError, "pay_withdrawals") {
		t.Fatalf("later no-op masked the payout failure: %+v", s)
	}
	for name, step := range s.Steps {
		if _, err := time.Parse(time.RFC3339Nano, step.FinishedAt); err != nil {
			t.Fatalf("%s has no completion time: %+v", name, step)
		}
	}
	if s.Steps["fund_plasma"].State != "succeeded" || s.LastSweepAt == "" {
		t.Fatalf("independent work or sweep age was lost: %+v", s)
	}
	// A returned snapshot must not share a mutable map with the running bridge.
	s.Steps["pay_withdrawals"] = StepStatus{State: "succeeded"}
	if healthSnapshot(b).Steps["pay_withdrawals"].State != "failed" {
		t.Fatal("status map aliases live health state")
	}
	if err := b.runSweep(context.Background(), []bridgeStep{{"pay_withdrawals", ok}, {"fund_plasma", ok}}); err != nil {
		t.Fatal(err)
	}
	if s := healthSnapshot(b); !s.Healthy || s.Steps["pay_withdrawals"].Error != "" {
		t.Fatalf("complete recovery did not restore health: %+v", s)
	}
}

func TestCanceledSweepStopsWorkAndCannotRestoreHealth(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "before work", false: "during step"}[before], func(t *testing.T) {
			b := healthBridge()
			b.healthy = true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if before {
				cancel()
			}
			called := false
			err := b.runSweep(ctx, []bridgeStep{
				{"pay_withdrawals", func(context.Context) error { cancel(); return nil }},
				{"fund_plasma", func(context.Context) error { called = true; return nil }},
			})
			s := healthSnapshot(b)
			if !errors.Is(err, context.Canceled) || called || s.Healthy || s.Sweeping || s.Steps["pay_withdrawals"].State != "canceled" || s.Steps["fund_plasma"].State != "not_run" {
				t.Fatalf("cancellation was accepted as success: err=%v called=%v status=%+v", err, called, s)
			}
		})
	}
}

func TestInProgressSweepDoesNotReusePreviousHealth(t *testing.T) {
	b := healthBridge()
	ok := func(context.Context) error { return nil }
	steps := []bridgeStep{{"receive_deposits", ok}, {"scan_withdrawals", ok}, {"pay_withdrawals", ok}, {"confirm_payouts", ok}, {"fund_plasma", ok}}
	if err := b.runSweep(context.Background(), steps); err != nil {
		t.Fatal(err)
	}
	prior := healthSnapshot(b)
	entered, release := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	joined := false
	defer func() {
		cancel()
		if !joined {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("owned sweep did not stop after cancellation")
			}
		}
	}()
	steps[0].fn = func(ctx context.Context) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	go func() { done <- b.runSweep(ctx, steps) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("owned sweep did not enter its first critical step")
	}
	during := healthSnapshot(b)
	if during.Healthy || !during.Sweeping || during.LastOKAt != prior.LastOKAt || during.Steps["receive_deposits"].State != "running" {
		t.Fatalf("incomplete sweep reused previous health: %+v", during)
	}
	close(release)
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("owned sweep did not complete")
	}
	after := healthSnapshot(b)
	if !after.Healthy || after.Sweeping || len(after.Steps) != 5 {
		t.Fatalf("complete five-step sweep did not recover: %+v", after)
	}
}
