package bridge

import (
	"testing"

	"github.com/Zenoglyphs-VM/zvm-core/rollup"
)

// A vault fusion is only worth planning if the ZVM will see it. Found on chain 69
// on 2026-09-19: the committee fused 25 QSR twice, the vault's fused total on NoM
// went 5,000 -> 5,050, and ZVMBridge.fusedQSR() stayed at 0 — because the mirror
// that calls markFused is gated on the gas fork, which chain 69 does not have.
// fundableQSR() is feesQSR - fusedQSR, so it never fell, and the only thing left
// bounding the next fusion was the vault's liquid QSR: the balance backing
// everybody's deposits.
func TestFusionIsDerivableOnlyFromTheGasFork(t *testing.T) {
	for _, tc := range []struct {
		name     string
		forks    *rollup.Forks
		momentum uint64
		want     bool
	}{
		{"no forks at all, which is how chain 69 was genesised", nil, 1_000_000, false},
		{"gas fork unscheduled", &rollup.Forks{Gas: 0, Wire: 500}, 1_000_000, false},
		{"gas fork scheduled but not reached", &rollup.Forks{Gas: 2_000}, 1_999, false},
		{"gas fork at exactly this momentum", &rollup.Forks{Gas: 2_000}, 2_000, true},
		{"gas fork long past", &rollup.Forks{Gas: 2_000}, 1_000_000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &rollup.Config{Forks: tc.forks}
			if got := FusionIsDerivable(cfg, tc.momentum); got != tc.want {
				t.Fatalf("FusionIsDerivable(momentum %d) = %v, want %v", tc.momentum, got, tc.want)
			}
		})
	}
}
