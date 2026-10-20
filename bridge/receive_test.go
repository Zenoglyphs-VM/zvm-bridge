package bridge

import (
	"math/big"
	"testing"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func deposit(zts znn.TokenStandard, whole int64) *znn.AccountBlock {
	return &znn.AccountBlock{
		TokenStandard: zts,
		Amount:        znn.NewBigInt(new(big.Int).Mul(big.NewInt(whole), big.NewInt(100_000_000))),
	}
}

// Receiving a deposit costs the vault the same ~21,000 plasma whatever the
// deposit is worth, and that plasma is what also pays withdrawals — so a floor
// exists to stop dust crowding out payouts (docs/PLASMA.md, D8). A token with
// no floor is always worth receiving.
func TestWorthReceivingAppliesThePerTokenFloor(t *testing.T) {
	b := &Bridge{cfg: Config{MinReceive: map[znn.TokenStandard]*big.Int{
		znn.ZNN: big.NewInt(1 * 100_000_000),
	}}}

	for _, tc := range []struct {
		name string
		blk  *znn.AccountBlock
		want bool
	}{
		{"above the floor", deposit(znn.ZNN, 5), true},
		{"exactly the floor", deposit(znn.ZNN, 1), true},
		{"dust", deposit(znn.ZNN, 0), false},
		{"a token with no floor is never dust", deposit(znn.QSR, 0), true},
	} {
		if got := b.worthReceiving(tc.blk); got != tc.want {
			t.Errorf("%s: worthReceiving = %v, want %v", tc.name, got, tc.want)
		}
	}

	// No floors configured at all is the default, and must not defer anything.
	none := &Bridge{cfg: Config{}}
	if !none.worthReceiving(deposit(znn.ZNN, 0)) {
		t.Error("a bridge with no -min-receive deferred a deposit")
	}
}

// A floor of zero is the same as no floor: it must not defer a zero-value
// block, or the vault would stop receiving anything the moment someone wrote
// `-min-receive ZNN:0`.
func TestZeroFloorDefersNothing(t *testing.T) {
	b := &Bridge{cfg: Config{MinReceive: map[znn.TokenStandard]*big.Int{znn.ZNN: big.NewInt(0)}}}
	if !b.worthReceiving(deposit(znn.ZNN, 0)) {
		t.Error("a zero floor deferred a deposit")
	}
}
