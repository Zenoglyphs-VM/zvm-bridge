// Package bridge is the vault committee: the one party the ZVM trusts. It
// receives deposits into the vault on NoM (so they can be spent later) and
// pays withdrawals out of it once the ZVM block that recorded them is final.
//
// It cannot mint on the ZVM — deposits are derived by every node from the
// NoM send, nobody signs them — and every payout it makes is derived back into
// the bridge contract, which flags any payout that matches no withdrawal. What
// it can do is refuse to pay, or pay the wrong party: that is the committee
// trust, and it is exactly what a TSS bridge asks for. On devnet the vault is
// one dev key; with -signers it is a FROST quorum (internal/committee), and the
// bridge is only the coordinator that asks it.
package bridge

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/Zenoglyphs-VM/zvm-core/derive"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

var (
	TopicWithdrawalInitiated = crypto.Keccak256Hash([]byte("WithdrawalInitiated(uint256,address,address,bytes10,uint256)"))
	TopicWithdrawalPaid      = crypto.Keccak256Hash([]byte("WithdrawalPaid(uint256,bytes32)"))
	TopicPayoutAnomaly       = crypto.Keccak256Hash([]byte("PayoutAnomaly(uint256,bytes32,uint8)"))
	TopicQSRDeposited        = crypto.Keccak256Hash([]byte("QSRDeposited(bytes32,address,uint256)"))

	selectorWithdrawal = crypto.Keccak256([]byte("withdrawal(uint256)"))[:4]
)

const schema = `
CREATE TABLE IF NOT EXISTS payouts (
	id           INTEGER PRIMARY KEY,
	l2_block     INTEGER NOT NULL,
	l2_tx        TEXT    NOT NULL,
	from_addr    TEXT    NOT NULL,
	to_addr      TEXT    NOT NULL,
	zts          TEXT    NOT NULL,
	amount       TEXT    NOT NULL,
	status       TEXT    NOT NULL,
	nom_hash     TEXT,
	error        TEXT,
	seen_at      INTEGER NOT NULL,
	published_at INTEGER,
	paid_at      INTEGER
);
CREATE INDEX IF NOT EXISTS payouts_status ON payouts(status, id);
CREATE TABLE IF NOT EXISTS bridge_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
`

const (
	StatusPending   = "pending"   // recorded on the ZVM, not yet final
	StatusPublished = "published" // payout block sent from the vault
	StatusPaid      = "paid"      // the ZVM has derived the payout
	StatusFailed    = "failed"    // cannot be paid (e.g. an unsupported token)
)

type Config struct {
	Rollup *rollup.Config
	L1     *znn.Client
	Eth    *ethclient.Client
	Vault  *znn.Account
	DB     *sql.DB
	Poll   time.Duration

	// MinReceive is the amount, per token, below which a deposit is not
	// received promptly. Receiving costs the vault about 21,000 plasma
	// whatever the deposit is worth, and the vault's plasma is the same
	// plasma that pays withdrawals — so without a floor, a flood of dust
	// deposits occupies the vault and queues in front of real payouts
	// (docs/PLASMA.md, D8). Tokens absent from the map are always received.
	MinReceive map[znn.TokenStandard]*big.Int

	// FundPlasma fuses the QSR the withdrawal fee has earned to the vault's
	// own plasma, which is what receives deposits and publishes payouts (D8).
	// Checked at most every FundEvery, and only while no payout is waiting.
	FundPlasma bool
	FundEvery  time.Duration

	Log *slog.Logger
}

type Bridge struct {
	cfg Config

	mu          sync.Mutex
	lastError   string
	lastErrorAt time.Time
	lastOK      time.Time
	healthy     bool
	sweepAt     time.Time
	sweeping    bool
	steps       map[string]StepStatus
	received    uint64
	deferred    int

	fundedAt    time.Time
	lastFunding *Funding
	fusedBlocks []string
}

func New(cfg Config) (*Bridge, error) {
	if cfg.Poll == 0 {
		cfg.Poll = 3 * time.Second
	}
	if cfg.FundEvery == 0 {
		cfg.FundEvery = 5 * time.Minute
	}
	if _, err := cfg.DB.Exec(schema); err != nil {
		return nil, err
	}
	return &Bridge{cfg: cfg}, nil
}

func (b *Bridge) Run(ctx context.Context) error {
	ticker := time.NewTicker(b.cfg.Poll)
	defer ticker.Stop()
	for {
		if err := b.runSweep(ctx, []bridgeStep{
			{"receive_deposits", b.receiveDeposits},
			{"scan_withdrawals", b.scanWithdrawals},
			{"pay_withdrawals", b.payWithdrawals},
			{"confirm_payouts", b.confirmPayouts},
			{"fund_plasma", b.fundPlasma},
		}); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type bridgeStep struct {
	name string
	fn   func(context.Context) error
}

// StepStatus describes the current sweep's work, not a cumulative success
// counter. Times let observers distinguish an idle step from a stopped loop.
type StepStatus struct {
	State      string `json:"state"`
	StartedAt  string `json:"startedAt,omitempty"`
	FinishedAt string `json:"finishedAt,omitempty"`
	Error      string `json:"error,omitempty"`
}

// runSweep continues independent work after an operational error, so receiving
// trouble does not itself prevent withdrawal reconciliation. Only a complete
// successful sweep restores health. Cancellation stops further work immediately.
func (b *Bridge) runSweep(ctx context.Context, steps []bridgeStep) error {
	b.mu.Lock()
	b.sweeping = true
	b.healthy = false
	b.steps = make(map[string]StepStatus, len(steps))
	for _, step := range steps {
		b.steps[step.name] = StepStatus{State: "not_run"}
	}
	b.mu.Unlock()
	success := len(steps) > 0
	var canceled error
	for _, step := range steps {
		started := time.Now().UTC().Format(time.RFC3339Nano)
		b.mu.Lock()
		b.steps[step.name] = StepStatus{State: "running", StartedAt: started}
		b.mu.Unlock()
		err := ctx.Err()
		if err == nil {
			err = step.fn(ctx)
		}
		// A step that returned nil after its caller canceled is incomplete.
		if err == nil {
			err = ctx.Err()
		}
		now := time.Now()
		result := StepStatus{State: "succeeded", StartedAt: started, FinishedAt: now.UTC().Format(time.RFC3339Nano)}
		if err != nil {
			success = false
			result.State, result.Error = "failed", err.Error()
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				result.State, canceled = "canceled", err
			}
			b.cfg.Log.Warn(step.name, "err", err)
		}
		b.mu.Lock()
		b.steps[step.name] = result
		if err != nil {
			b.healthy = false
			b.lastError, b.lastErrorAt = fmt.Sprintf("%s: %v", step.name, err), now
		}
		b.mu.Unlock()
		if canceled != nil {
			break
		}
	}
	b.mu.Lock()
	b.sweeping, b.sweepAt, b.healthy = false, time.Now(), success
	if success {
		b.lastOK = b.sweepAt
	}
	b.mu.Unlock()
	return canceled
}

// receiveDeposits publishes a receive for every unreceived send to the vault.
// Deposits are credited on the ZVM without this; it is what lets the vault
// spend them.
func (b *Bridge) receiveDeposits(ctx context.Context) error {
	list, err := b.cfg.L1.UnreceivedBlocks(ctx, b.cfg.Vault.Address(), 0, 50)
	if err != nil {
		return err
	}
	var worth, dust []*znn.AccountBlock
	for _, blk := range list.List {
		if b.worthReceiving(blk) {
			worth = append(worth, blk)
		} else {
			dust = append(dust, blk)
		}
	}

	// Dust waits for a quiet moment rather than being refused. Deferring is
	// safe in a way that refusing would not be: the ZVM credits a deposit from
	// the *send*, which every node derives independently, so the depositor
	// already has their balance. What waits is only the vault's ability to
	// re-spend those coins on NoM — and that is exactly the resource a dust
	// flood was competing for.
	todo := worth
	if len(worth) == 0 && len(dust) > 0 {
		outstanding, err := b.payoutsOutstanding()
		if err != nil {
			return err
		}
		if outstanding == 0 {
			todo = dust
		}
	}
	b.mu.Lock()
	b.deferred = len(list.List) - len(todo)
	b.mu.Unlock()

	for _, blk := range todo {
		if _, err := b.cfg.Vault.Receive(ctx, blk.Hash); err != nil {
			b.cfg.Vault.Reset()
			return fmt.Errorf("receiving %s: %w", blk.Hash, err)
		}
		b.mu.Lock()
		b.received++
		b.mu.Unlock()
	}
	return nil
}

// worthReceiving reports whether a deposit clears the floor for its token. A
// token with no floor configured always does.
func (b *Bridge) worthReceiving(blk *znn.AccountBlock) bool {
	min := b.cfg.MinReceive[blk.TokenStandard]
	if min == nil || min.Sign() <= 0 {
		return true
	}
	return blk.AmountBig().Cmp(min) >= 0
}

// payoutsOutstanding counts the withdrawals still waiting on the vault. While
// any are, the vault's plasma belongs to them and not to dust.
func (b *Bridge) payoutsOutstanding() (int, error) {
	var n int
	err := b.cfg.DB.QueryRow(
		"SELECT COUNT(*) FROM payouts WHERE status IN (?, ?)", StatusPending, StatusPublished).Scan(&n)
	return n, err
}

func (b *Bridge) meta(key string) (uint64, error) {
	var v uint64
	err := b.cfg.DB.QueryRow("SELECT value FROM bridge_meta WHERE key = ?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

func (b *Bridge) setMeta(key string, v uint64) error {
	_, err := b.cfg.DB.Exec("INSERT INTO bridge_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, v)
	return err
}

// scanWithdrawals records withdrawals from ZVM blocks labelled finalized.
func (b *Bridge) scanWithdrawals(ctx context.Context) error {
	final, err := b.cfg.Eth.HeaderByNumber(ctx, big.NewInt(int64(rpc.FinalizedBlockNumber)))
	if err != nil {
		return err
	}
	last, err := b.meta("scanned")
	if err != nil {
		return err
	}
	to := final.Number.Uint64()
	if to <= last {
		return nil
	}
	for from := last + 1; from <= to; from += 2000 {
		end := min(from+1999, to)
		logs, err := b.cfg.Eth.FilterLogs(ctx, ethereum.FilterQuery{
			FromBlock: new(big.Int).SetUint64(from), ToBlock: new(big.Int).SetUint64(end),
			Addresses: []common.Address{rollup.BridgeAddr}, Topics: [][]common.Hash{{TopicWithdrawalInitiated}},
		})
		if err != nil {
			return err
		}
		for _, l := range logs {
			if len(l.Topics) != 4 || len(l.Data) != 64 {
				continue
			}
			id := new(big.Int).SetBytes(l.Topics[1][:])
			fromAddr := common.BytesToAddress(l.Topics[2][:])
			toAddr := znn.Address(common.BytesToAddress(l.Topics[3][:]))
			var zts znn.TokenStandard
			copy(zts[:], l.Data[:10])
			amount := new(big.Int).SetBytes(l.Data[32:64])
			if _, err := b.cfg.DB.Exec(`INSERT OR IGNORE INTO payouts
				(id, l2_block, l2_tx, from_addr, to_addr, zts, amount, status, seen_at) VALUES (?,?,?,?,?,?,?,?,?)`,
				id.Uint64(), l.BlockNumber, l.TxHash.Hex(), fromAddr.Hex(), toAddr.String(), zts.String(),
				amount.String(), StatusPending, time.Now().Unix()); err != nil {
				return err
			}
			b.cfg.Log.Info("withdrawal final", "id", id, "to", toAddr, "token", zts, "amount", amount, "l2Block", l.BlockNumber)
		}
		if err := b.setMeta("scanned", end); err != nil {
			return err
		}
	}
	return nil
}

type payout struct {
	id     uint64
	to     znn.Address
	zts    znn.TokenStandard
	amount *big.Int
	nom    string
}

func (b *Bridge) payouts(status string) ([]payout, error) {
	rows, err := b.cfg.DB.Query("SELECT id, to_addr, zts, amount, COALESCE(nom_hash, '') FROM payouts WHERE status = ? ORDER BY id", status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []payout
	for rows.Next() {
		var p payout
		var to, zts, amount string
		if err := rows.Scan(&p.id, &to, &zts, &amount, &p.nom); err != nil {
			return nil, err
		}
		var perr error
		if p.to, perr = znn.ParseAddress(to); perr != nil {
			return nil, perr
		}
		if p.zts, perr = znn.ParseZTS(zts); perr != nil {
			return nil, perr
		}
		p.amount, _ = new(big.Int).SetString(amount, 10)
		out = append(out, p)
	}
	return out, rows.Err()
}

func payoutData(id uint64) []byte {
	return append(append([]byte{}, rollup.PayoutMagic...), common.LeftPadBytes(new(big.Int).SetUint64(id).Bytes(), 32)...)
}

func (b *Bridge) payWithdrawals(ctx context.Context) error {
	pending, err := b.payouts(StatusPending)
	if err != nil || len(pending) == 0 {
		return err
	}
	info, err := b.cfg.L1.AccountInfo(ctx, b.cfg.Vault.Address())
	if err != nil {
		return err
	}
	balances := map[znn.TokenStandard]*big.Int{znn.ZNN: info.Balance(znn.ZNN), znn.QSR: info.Balance(znn.QSR)}
	for _, p := range pending {
		if p.zts != znn.ZNN && p.zts != znn.QSR {
			b.cfg.DB.Exec("UPDATE payouts SET status = ?, error = ? WHERE id = ?", StatusFailed, "unsupported token", p.id)
			continue
		}
		// Crash safety: a payout published before a restart is adopted, not
		// sent twice.
		if existing, err := b.findPayoutBlock(ctx, p.id); err != nil {
			return err
		} else if existing != nil {
			b.cfg.DB.Exec("UPDATE payouts SET status = ?, nom_hash = ?, published_at = ? WHERE id = ?",
				StatusPublished, existing.Hash.String(), time.Now().Unix(), p.id)
			continue
		}
		if balances[p.zts].Cmp(p.amount) < 0 {
			return fmt.Errorf("vault holds %s of %s, withdrawal %d needs %s", balances[p.zts], p.zts, p.id, p.amount)
		}
		blk, err := b.cfg.Vault.Send(ctx, p.to, p.zts, p.amount, payoutData(p.id))
		if err != nil {
			b.cfg.Vault.Reset()
			b.cfg.DB.Exec("UPDATE payouts SET error = ? WHERE id = ?", err.Error(), p.id)
			return fmt.Errorf("paying withdrawal %d: %w", p.id, err)
		}
		balances[p.zts].Sub(balances[p.zts], p.amount)
		if _, err := b.cfg.DB.Exec("UPDATE payouts SET status = ?, nom_hash = ?, published_at = ?, error = NULL WHERE id = ?",
			StatusPublished, blk.Hash.String(), time.Now().Unix(), p.id); err != nil {
			return err
		}
		b.cfg.Log.Info("paid withdrawal", "id", p.id, "to", p.to, "amount", p.amount, "token", p.zts, "nomBlock", blk.Hash)
	}
	return nil
}

// findPayoutBlock looks through the vault's recent and unconfirmed blocks for
// one already tagged with this withdrawal id.
func (b *Bridge) findPayoutBlock(ctx context.Context, id uint64) (*znn.AccountBlock, error) {
	want := payoutData(id)
	unconfirmed, err := b.cfg.L1.UnconfirmedBlocks(ctx, b.cfg.Vault.Address(), 0, 50)
	if err != nil {
		return nil, err
	}
	for _, blk := range unconfirmed.List {
		if bytes.Equal(blk.Data, want) {
			return blk, nil
		}
	}
	info, err := b.cfg.L1.AccountInfo(ctx, b.cfg.Vault.Address())
	if err != nil {
		return nil, err
	}
	if info.AccountHeight == 0 {
		return nil, nil
	}
	start := uint64(1)
	if info.AccountHeight > 100 {
		start = info.AccountHeight - 99
	}
	recent, err := b.cfg.L1.AccountBlocksByHeight(ctx, b.cfg.Vault.Address(), start, 100)
	if err != nil {
		return nil, err
	}
	for _, blk := range recent.List {
		if bytes.Equal(blk.Data, want) {
			return blk, nil
		}
	}
	return nil, nil
}

// fundPlasma fuses what the withdrawal fee has earned to the vault's plasma.
// Payouts come first: the vault's next block goes to a withdrawal if one is
// waiting, since a fusion only helps later blocks.
func (b *Bridge) fundPlasma(ctx context.Context) error {
	if !b.cfg.FundPlasma {
		return nil
	}
	b.mu.Lock()
	due := time.Since(b.fundedAt) >= b.cfg.FundEvery
	b.mu.Unlock()
	if !due {
		return nil
	}
	if n, err := b.payoutsOutstanding(); err != nil || n > 0 {
		return err
	}
	f, err := PlanFunding(ctx, b.cfg.L1, b.cfg.Eth, b.cfg.Rollup)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.fundedAt, b.lastFunding = time.Now(), f
	b.mu.Unlock()
	if f.Amount.Sign() == 0 {
		b.cfg.Log.Debug("not funding plasma", "reason", f.Reason, "fundable", f.Fundable)
		return nil
	}
	blk, err := b.cfg.Vault.Send(ctx, derive.PlasmaContract, znn.QSR, f.Amount, derive.EncodePlasmaFuse(b.cfg.Vault.Address()))
	if err != nil {
		b.cfg.Vault.Reset()
		return fmt.Errorf("fusing %s QSR: %w", formatQSR(f.Amount), err)
	}
	b.mu.Lock()
	b.fusedBlocks = append(b.fusedBlocks, blk.Hash.String())
	b.mu.Unlock()
	b.cfg.Log.Info("fused fee revenue to the vault's plasma", "qsr", formatQSR(f.Amount), "nomBlock", blk.Hash,
		"fundable", formatQSR(f.Fundable), "alreadyFused", formatQSR(f.FusedToVault))
	return nil
}

// confirmPayouts marks payouts the ZVM has derived.
func (b *Bridge) confirmPayouts(ctx context.Context) error {
	published, err := b.payouts(StatusPublished)
	if err != nil {
		return err
	}
	for _, p := range published {
		w, err := ReadWithdrawal(ctx, b.cfg.Eth, p.id)
		if err != nil {
			return err
		}
		if w.PaidIn != (common.Hash{}) {
			b.cfg.DB.Exec("UPDATE payouts SET status = ?, paid_at = ? WHERE id = ?", StatusPaid, time.Now().Unix(), p.id)
		}
	}
	return nil
}

// Withdrawal is ZVMBridge.withdrawal(id).
type Withdrawal struct {
	From    common.Address    `json:"from"`
	To      znn.Address       `json:"to"`
	Token   znn.TokenStandard `json:"token"`
	Amount  uint64            `json:"amount"`
	L2Block uint64            `json:"l2Block"`
	PaidIn  common.Hash       `json:"paidIn"`
	// Fee is what the withdrawal paid and the vault keeps; Amount is already
	// net of it, so a payout sends exactly Amount.
	Fee uint64 `json:"fee"`
}

func ReadWithdrawal(ctx context.Context, eth *ethclient.Client, id uint64) (*Withdrawal, error) {
	return ReadWithdrawalAt(ctx, eth, id, nil)
}

// ReadWithdrawalAt reads ZVMBridge.withdrawal(id) as of an L2 block; nil is the head.
func ReadWithdrawalAt(ctx context.Context, eth *ethclient.Client, id uint64, block *big.Int) (*Withdrawal, error) {
	data := append(append([]byte{}, selectorWithdrawal...), common.LeftPadBytes(new(big.Int).SetUint64(id).Bytes(), 32)...)
	to := rollup.BridgeAddr
	out, err := eth.CallContract(ctx, ethereum.CallMsg{To: &to, Data: data}, block)
	if err != nil {
		return nil, err
	}
	// Six words before the withdrawal fee existed, seven after.
	if len(out) != 6*32 && len(out) != 7*32 {
		return nil, fmt.Errorf("withdrawal(%d) returned %d bytes", id, len(out))
	}
	w := &Withdrawal{
		From:    common.BytesToAddress(out[0:32]),
		To:      znn.Address(common.BytesToAddress(out[32:64])),
		Amount:  new(big.Int).SetBytes(out[96:128]).Uint64(),
		L2Block: new(big.Int).SetBytes(out[128:160]).Uint64(),
		PaidIn:  common.BytesToHash(out[160:192]),
	}
	if len(out) == 7*32 {
		w.Fee = new(big.Int).SetBytes(out[192:224]).Uint64()
	}
	copy(w.Token[:], out[64:74])
	return w, nil
}

// Status is the committee's view of the peg.
type Status struct {
	Vault         string            `json:"vault"`
	VaultBalances map[string]string `json:"vaultBalances"`
	Unreceived    uint64            `json:"unreceivedDeposits"`
	Received      uint64            `json:"receivedThisRun"`
	// Deferred is how many unreceived deposits are below their token's floor
	// and are waiting for the vault to be otherwise idle (see MinReceive).
	Deferred       int            `json:"deferredDeposits"`
	Payouts        map[string]int `json:"payouts"`
	PendingZNN     string         `json:"pendingZNN"`
	PaidZNN        string         `json:"paidZNN"`
	PendingQSR     string         `json:"pendingQSR"`
	PaidQSR        string         `json:"paidQSR"`
	DepositedQSR   string         `json:"depositedQSR"`
	LockedZNNOnZVM string         `json:"lockedZNNOnZVM"`
	// The withdrawal fee (D8): what it has earned, and what of the QSR part has
	// gone to the vault's plasma.
	FeesZNN     string                `json:"feesZNN,omitempty"`
	FeesQSR     string                `json:"feesQSR,omitempty"`
	FusedQSR    string                `json:"fusedQSR,omitempty"`
	Funding     *Funding              `json:"funding,omitempty"`
	FusedBlocks []string              `json:"fusedBlocksThisRun,omitempty"`
	LastError   string                `json:"lastError,omitempty"`
	LastErrorAt string                `json:"lastErrorAt,omitempty"`
	LastOKAt    string                `json:"lastOkAt,omitempty"`
	Healthy     bool                  `json:"healthy"`
	LastSweepAt string                `json:"lastSweepAt,omitempty"`
	Sweeping    bool                  `json:"sweepInProgress"`
	Steps       map[string]StepStatus `json:"steps"`
}

func (b *Bridge) Status(ctx context.Context) (*Status, error) {
	s := &Status{Vault: b.cfg.Vault.Address().String(), VaultBalances: map[string]string{}, Payouts: map[string]int{}}
	if info, err := b.cfg.L1.AccountInfo(ctx, b.cfg.Vault.Address()); err == nil {
		s.VaultBalances["ZNN"] = info.Balance(znn.ZNN).String()
		s.VaultBalances["QSR"] = info.Balance(znn.QSR).String()
	}
	if list, err := b.cfg.L1.UnreceivedBlocks(ctx, b.cfg.Vault.Address(), 0, 1); err == nil {
		s.Unreceived = list.Count
	}
	rows, err := b.cfg.DB.Query("SELECT status, COUNT(*) FROM payouts GROUP BY status")
	if err == nil {
		for rows.Next() {
			var st string
			var n int
			rows.Scan(&st, &n)
			s.Payouts[st] = n
		}
		rows.Close()
	}
	for _, v := range []struct {
		sig string
		out *string
	}{
		{"pendingZNN()", &s.PendingZNN}, {"paidZNN()", &s.PaidZNN}, {"pendingQSR()", &s.PendingQSR},
		{"paidQSR()", &s.PaidQSR}, {"depositedQSR()", &s.DepositedQSR},
		{"feesZNN()", &s.FeesZNN}, {"feesQSR()", &s.FeesQSR}, {"fusedQSR()", &s.FusedQSR},
	} {
		to := rollup.BridgeAddr
		out, err := b.cfg.Eth.CallContract(ctx, ethereum.CallMsg{To: &to, Data: crypto.Keccak256([]byte(v.sig))[:4]}, nil)
		if err == nil && len(out) == 32 {
			*v.out = new(big.Int).SetBytes(out).String()
		}
	}
	if bal, err := b.cfg.Eth.BalanceAt(ctx, rollup.BridgeAddr, nil); err == nil {
		s.LockedZNNOnZVM = bal.String()
	}
	b.populateHealth(s)
	return s, nil
}

func (b *Bridge) populateHealth(s *Status) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s.Received, s.LastError, s.Deferred = b.received, b.lastError, b.deferred
	s.Funding, s.FusedBlocks = b.lastFunding, append([]string(nil), b.fusedBlocks...)
	if !b.lastErrorAt.IsZero() {
		s.LastErrorAt = b.lastErrorAt.UTC().Format(time.RFC3339)
	}
	if !b.lastOK.IsZero() {
		s.LastOKAt = b.lastOK.UTC().Format(time.RFC3339)
	}
	if !b.sweepAt.IsZero() {
		s.LastSweepAt = b.sweepAt.UTC().Format(time.RFC3339Nano)
	}
	s.Healthy, s.Sweeping = b.healthy, b.sweeping
	s.Steps = make(map[string]StepStatus, len(b.steps))
	for name, step := range b.steps {
		s.Steps[name] = step
	}
}

// EncodeWithdrawZNN is calldata for withdrawZNN(nomRecipient).
func EncodeWithdrawZNN(to znn.Address) []byte {
	return append(crypto.Keccak256([]byte("withdrawZNN(address)"))[:4], common.LeftPadBytes(to[:], 32)...)
}

// EncodeWithdrawQSR is calldata for withdrawQSR(nomRecipient, amount).
func EncodeWithdrawQSR(to znn.Address, amount *big.Int) []byte {
	out := append(crypto.Keccak256([]byte("withdrawQSR(address,uint256)"))[:4], common.LeftPadBytes(to[:], 32)...)
	return append(out, common.LeftPadBytes(amount.Bytes(), 32)...)
}

var _ = types.Log{}
