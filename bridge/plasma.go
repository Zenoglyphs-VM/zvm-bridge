package bridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/Zenoglyphs-VM/zvm-core/derive"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// NoM's fusion rules (go-zenon vm/constants/plasma.go): at least ten QSR, in
// whole QSR. The per-account ceiling is *not* a constant — dynamic plasma
// raises it by four orders of magnitude — so it is read from the ruleset in
// force, through znn.MaxFusedAmountForAccount.
var fuseMinAmount = new(big.Int).Mul(big.NewInt(10), znn.OneQSR)

// FusionIsDerivable reports whether a vault fusion published into a momentum at
// this height would be mirrored into ZVM state.
//
// It is the precondition for D8 self-funding, and it is not optional. The mirror
// that calls ZVMBridge.markFused is gated on the gas fork
// (internal/derive/plan.go, KindFuse), so before that fork fusedQSR stays zero
// however much the vault has actually fused. fundableQSR() is feesQSR - fusedQSR,
// so it would never fall: the coordinator would fuse the same revenue every
// cycle, and the only remaining bound is Liquid — the QSR backing everybody's
// balances. Forks are monotonic, so an active fork at the frontier is active for
// every momentum the fusion could land in.
func FusionIsDerivable(cfg *rollup.Config, momentum uint64) bool {
	return cfg.Forks.GasActive(momentum)
}

// Funding is what the vault may fuse to its own plasma from the bridge's fee
// revenue right now, and the numbers that decide it (D8, docs/PLASMA.md).
//
// Every figure a committee member acts on comes from its own nodes, and the
// revenue side comes from ZVM state alone: fees kept minus fusions already
// derived. Reading the vault's NoM balance for that instead would race — a
// deposit the vault has received but the ZVM has not yet credited looks like
// surplus — so the balance is only used to check that the QSR is there.
type Funding struct {
	// Fundable is ZVMBridge.fundableQSR(): fees kept, less what has been fused.
	Fundable *big.Int `json:"fundable"`
	// FusedToVault is the QSR fused to the vault on NoM, from any source.
	FusedToVault *big.Int `json:"fusedToVault"`
	// Headroom is how much more fusion the vault can use before NoM's
	// per-account ceiling makes more pointless.
	Headroom *big.Int `json:"headroom"`
	// Liquid is the vault's QSR balance less the payouts still owed from it.
	Liquid *big.Int `json:"liquid"`
	// Amount is what may be fused now, in whole QSR and at least NoM's
	// minimum, or zero with Reason saying why not.
	Amount *big.Int `json:"amount"`
	Reason string   `json:"reason,omitempty"`
}

// PlanFunding works out a Funding for the vault as of the ZVM head.
//
// It refuses to plan while the ZVM has not yet derived every block the vault
// has published: until then fusedQSR can be missing a fusion that already
// happened, and planning on it would fuse the same revenue twice.
func PlanFunding(ctx context.Context, l1 *znn.Client, eth *ethclient.Client, cfg *rollup.Config) (*Funding, error) {
	f := &Funding{Fundable: new(big.Int), FusedToVault: new(big.Int), Headroom: new(big.Int), Liquid: new(big.Int), Amount: new(big.Int)}
	vault := cfg.Vault

	unconfirmed, err := l1.UnconfirmedBlocks(ctx, vault, 0, 1)
	if err != nil {
		return nil, err
	}
	if unconfirmed.Count > 0 {
		f.Reason = "the vault has blocks NoM has not confirmed yet"
		return f, nil
	}
	head, err := eth.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, err
	}
	derived := cfg.MomentumForL2Block(head.Number.Uint64())
	if frontier, err := l1.FrontierAccountBlock(ctx, vault); err != nil {
		return nil, err
	} else if frontier != nil {
		if frontier.ConfirmationDetail == nil {
			f.Reason = "the vault's latest block is not confirmed yet"
			return f, nil
		}
		if frontier.ConfirmationDetail.MomentumHeight > derived {
			f.Reason = fmt.Sprintf("the ZVM has derived to momentum %d and the vault's latest block is in %d",
				derived, frontier.ConfirmationDetail.MomentumHeight)
			return f, nil
		}
	}

	at := head.Number
	if f.Fundable, err = callUint(ctx, eth, "fundableQSR()", at); err != nil {
		return nil, err
	}
	pending, err := callUint(ctx, eth, "pendingQSR()", at)
	if err != nil {
		return nil, err
	}
	info, err := l1.AccountInfo(ctx, vault)
	if err != nil {
		return nil, err
	}
	f.Liquid.Sub(info.Balance(znn.QSR), pending)
	if f.Liquid.Sign() < 0 {
		f.Liquid.SetInt64(0)
	}
	plasma, err := l1.PlasmaInfo(ctx, vault)
	if err != nil {
		return nil, err
	}
	// The ceiling depends on which ruleset this L1 runs, so it is read rather
	// than assumed: on a dynamic-plasma network the v1 figure would report a
	// vault that has barely started as already full, and D8 would never fund
	// anything.
	m, err := l1.FrontierMomentum(ctx)
	if err != nil {
		return nil, err
	}
	// Before the gas fork the vault's fusion is not a derived fact: the mirror
	// that calls markFused is gated on it (internal/derive/plan.go, KindFuse),
	// so fusedQSR stays zero however much has actually been fused. Funding on
	// that reading is not a rounding error, it is unbounded: fundableQSR() never
	// falls, so every cycle would fuse again until the only thing left stopping
	// it is Liquid — which is the QSR backing everybody's balances. Refuse, and
	// say so. CheckFuse runs this too, so each member refuses independently.
	f.FusedToVault = plasma.QsrAmount.Big()
	f.Headroom.Sub(znn.MaxFusedAmountForAccount(m), f.FusedToVault)
	if f.Headroom.Sign() < 0 {
		f.Headroom.SetInt64(0)
	}
	if !FusionIsDerivable(cfg, m.Height) {
		f.Reason = "the gas fork is not active, so a fusion would not be derived back into fusedQSR and D8 could not tell it had already happened"
		return f, nil
	}

	amount := new(big.Int).Set(f.Fundable)
	for _, limit := range []*big.Int{f.Headroom, f.Liquid} {
		if limit.Cmp(amount) < 0 {
			amount.Set(limit)
		}
	}
	amount.Sub(amount, new(big.Int).Mod(amount, znn.OneQSR))
	switch {
	case f.Fundable.Sign() == 0:
		f.Reason = "no fee revenue left to fuse"
	case f.Headroom.Sign() == 0:
		f.Reason = "the vault is already at NoM's per-account plasma ceiling"
	case amount.Cmp(fuseMinAmount) < 0:
		f.Reason = fmt.Sprintf("%s QSR is fundable now, and NoM fuses at least 10", formatQSR(amount))
	default:
		f.Amount = amount
	}
	return f, nil
}

// CheckFuse is the committee policy for a vault fusion: QSR, to the plasma
// contract, for the vault itself, in whole QSR, and no more than PlanFunding
// allows as this member's own nodes see it.
func CheckFuse(ctx context.Context, l1 *znn.Client, eth *ethclient.Client, cfg *rollup.Config, b *znn.AccountBlock) error {
	if b.ToAddress != derive.PlasmaContract || !bytes.Equal(b.Data, derive.EncodePlasmaFuse(cfg.Vault)) {
		return errors.New("a vault fusion must be plasma.Fuse(vault)")
	}
	if b.TokenStandard != znn.QSR || b.Amount == nil {
		return errors.New("a vault fusion spends QSR")
	}
	amount := b.Amount.Big()
	if amount.Cmp(fuseMinAmount) < 0 || new(big.Int).Mod(amount, znn.OneQSR).Sign() != 0 {
		return fmt.Errorf("%s is not a fusion NoM accepts: at least 10, in whole QSR", formatQSR(amount))
	}
	f, err := PlanFunding(ctx, l1, eth, cfg)
	if err != nil {
		return err
	}
	if f.Amount.Sign() == 0 {
		return fmt.Errorf("nothing may be fused now: %s", f.Reason)
	}
	if amount.Cmp(f.Amount) > 0 {
		return fmt.Errorf("the fusion is %s QSR and fee revenue allows %s", formatQSR(amount), formatQSR(f.Amount))
	}
	return nil
}

func callUint(ctx context.Context, eth *ethclient.Client, sig string, at *big.Int) (*big.Int, error) {
	to := rollup.BridgeAddr
	out, err := eth.CallContract(ctx, ethereum.CallMsg{To: &to, Data: crypto.Keccak256([]byte(sig))[:4]}, at)
	if err != nil {
		return nil, fmt.Errorf("ZVMBridge.%s: %w", sig, err)
	}
	if len(out) != 32 {
		return nil, fmt.Errorf("ZVMBridge.%s returned %d bytes; is this bridge older than the withdrawal fee?", sig, len(out))
	}
	return new(big.Int).SetBytes(out), nil
}

func formatQSR(v *big.Int) string {
	q, r := new(big.Int).QuoRem(v, znn.OneQSR, new(big.Int))
	if r.Sign() == 0 {
		return q.String()
	}
	return fmt.Sprintf("%s.%08d", q, r.Int64())
}
