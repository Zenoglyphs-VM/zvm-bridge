package committee

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/Zenoglyphs-VM/zvm-bridge/bridge"
	"github.com/Zenoglyphs-VM/zvm-core/derive"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// Policy is what one committee member is willing to sign, checked against that
// member's own NoM node and ZVM node. The committee exists so that a
// coordinator cannot move the vault's funds on its own; a signer that signs
// whatever the coordinator sends would make it one key again with extra steps.
//
// The vault signs exactly three shapes of block:
//
//   - a receive of a send whose recipient is the vault (a deposit),
//   - a send tagged "ZVMW" ‖ id that pays withdrawal id exactly as ZVMBridge
//     recorded it, once that withdrawal's ZVM block is finalized and its
//     momentum is PayoutDepth below NoM's frontier, and never twice, and
//   - plasma.Fuse(vault) with QSR the withdrawal fee has earned and has not
//     already been fused, as ZVM state records it (D8). The QSR stays the
//     vault's — a fusion can be cancelled back into it — so this moves no
//     value out; it is checked so that a coordinator cannot lock up the QSR
//     payouts need.
type Policy struct {
	Rollup      *rollup.Config
	L1          *znn.Client
	Eth         *ethclient.Client
	PayoutDepth uint64
	// Tiers hold a large withdrawal longer than a small one. Wormhole's
	// Governor does the same with a 24-hour delay above a notional limit: the
	// point is that a quorum that has been compromised cannot drain the vault
	// inside the window someone would need to notice. A withdrawal waits the
	// depth of the first tier whose threshold it meets, or PayoutDepth.
	Tiers []Tier
	// Outflow caps how much this signer will help move in a window, whatever
	// the size of any single withdrawal. The tiers above delay a large payout;
	// they do nothing about a thousand small ones, which is the same drain
	// spelled differently. Wormhole's Governor pairs a per-transfer limit with
	// a rolling daily total for exactly that reason.
	Outflow []OutflowLimit
	DB      *sql.DB
}

// Tier is "at or above this much of this token, wait this many momentums".
type Tier struct {
	Token  znn.TokenStandard
	Amount uint64 // in NoM base units
	Depth  uint64
}

// OutflowLimit is "at most this much of this token signed in any window this
// long". A signer that has already helped move its limit stops signing until
// the window has moved on, so a compromised quorum cannot empty the vault in
// one pass — it can only do it at the rate the honest members allow.
type OutflowLimit struct {
	Token  znn.TokenStandard
	Amount uint64 // in NoM base units
	Window time.Duration
}

// depthFor is how deep a payout of this size must be before this signer signs it.
func (p *Policy) depthFor(zts znn.TokenStandard, amount uint64) uint64 {
	depth := p.PayoutDepth
	for _, t := range p.Tiers {
		if t.Token == zts && amount >= t.Amount && t.Depth > depth {
			depth = t.Depth
		}
	}
	return depth
}

const signerSchema = `
CREATE TABLE IF NOT EXISTS signed_payouts (
	withdrawal INTEGER NOT NULL,
	height     INTEGER NOT NULL,
	hash       TEXT    NOT NULL,
	signed_at  INTEGER NOT NULL,
	PRIMARY KEY (withdrawal, hash)
);
CREATE INDEX IF NOT EXISTS signed_payouts_when ON signed_payouts(signed_at);`

func (p *Policy) Init() error {
	if _, err := p.DB.Exec(signerSchema); err != nil {
		return err
	}
	// What a payout moved, so the rolling total can be summed. Added after the
	// first signers were running, so an existing journal is migrated rather
	// than rebuilt: rows from before this have no amount and count as zero,
	// which is the safe direction on a window measured in hours.
	for _, col := range []string{
		"ALTER TABLE signed_payouts ADD COLUMN token TEXT",
		"ALTER TABLE signed_payouts ADD COLUMN amount INTEGER",
	} {
		if _, err := p.DB.Exec(col); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	return nil
}

// withinOutflow refuses a payout that would take this signer past what it has
// agreed to help move in a window.
//
// It counts what *this signer* signed, not what the vault paid: a member that
// has been asked to sign more than its policy allows stops, and the quorum
// stops with it once enough members have. That is the property worth having —
// it does not depend on the coordinator being honest, only on the members
// disagreeing with it.
func (p *Policy) withinOutflow(ctx context.Context, zts znn.TokenStandard, amount uint64) error {
	for _, l := range p.Outflow {
		if l.Token != zts || l.Amount == 0 || l.Window <= 0 {
			continue
		}
		since := time.Now().Add(-l.Window).Unix()
		var signed uint64
		if err := p.DB.QueryRowContext(ctx,
			"SELECT COALESCE(SUM(amount),0) FROM signed_payouts WHERE token = ? AND signed_at >= ?",
			zts.String(), since).Scan(&signed); err != nil {
			return err
		}
		if signed+amount > l.Amount {
			return fmt.Errorf("this signer has already signed %d of %s in the last %s, and %d more would pass its limit of %d",
				signed, zts, l.Window, amount, l.Amount)
		}
	}
	return nil
}

func (p *Policy) Check(ctx context.Context, b *znn.AccountBlock) error {
	if b.Address != p.Rollup.Vault {
		return fmt.Errorf("the block is for %s, not the vault", b.Address)
	}
	if b.ChainIdentifier != p.Rollup.L1ChainID || b.Version != 1 {
		return errors.New("the block is for another network or block version")
	}
	if len(b.DescendantBlocks) != 0 {
		return errors.New("a user block has no descendants")
	}
	frontier, err := p.L1.FrontierAccountBlock(ctx, b.Address)
	if err != nil {
		return fmt.Errorf("reading the vault's frontier: %w", err)
	}
	var fh znn.Hash
	var fheight uint64
	if frontier != nil {
		fh, fheight = frontier.Hash, frontier.Height
	}
	// Only the next block on the chain as this signer's node sees it. Signing
	// ahead of the frontier would let a coordinator collect a payout signed on
	// top of a block it has not published yet.
	if b.PreviousHash != fh || b.Height != fheight+1 {
		return fmt.Errorf("the block is at height %d, the vault's next height here is %d", b.Height, fheight+1)
	}
	switch b.BlockType {
	case znn.BlockTypeUserReceive:
		return p.checkReceive(ctx, b)
	case znn.BlockTypeUserSend:
		if b.ToAddress == derive.PlasmaContract {
			return bridge.CheckFuse(ctx, p.L1, p.Eth, p.Rollup, b)
		}
		return p.checkPayout(ctx, b, fheight)
	}
	return fmt.Errorf("the vault does not sign block type %d", b.BlockType)
}

func (p *Policy) checkReceive(ctx context.Context, b *znn.AccountBlock) error {
	if len(b.Data) != 0 || (b.Amount != nil && b.Amount.Big().Sign() != 0) {
		return errors.New("a receive carries no data or amount of its own")
	}
	from, err := p.L1.AccountBlockByHash(ctx, b.FromBlockHash)
	if err != nil {
		return err
	}
	if from == nil {
		return fmt.Errorf("the block being received (%s) is not on NoM", b.FromBlockHash)
	}
	if !from.IsSend() || from.ToAddress != p.Rollup.Vault {
		return errors.New("the block being received is not a send to the vault")
	}
	return nil
}

func (p *Policy) checkPayout(ctx context.Context, b *znn.AccountBlock, frontierHeight uint64) error {
	magic := rollup.PayoutMagic
	if len(b.Data) != len(magic)+32 || !bytes.HasPrefix(b.Data, magic) {
		return errors.New("a vault send must be a tagged withdrawal payout")
	}
	idBig := new(big.Int).SetBytes(b.Data[len(magic):])
	if !idBig.IsUint64() {
		return errors.New("withdrawal id out of range")
	}
	id := idBig.Uint64()
	final, err := p.Eth.HeaderByNumber(ctx, big.NewInt(int64(rpc.FinalizedBlockNumber)))
	if err != nil {
		return fmt.Errorf("reading the finalized ZVM block: %w", err)
	}
	w, err := bridge.ReadWithdrawalAt(ctx, p.Eth, id, final.Number)
	if err != nil {
		return err
	}
	if w.From == (common.Address{}) {
		return fmt.Errorf("withdrawal %d does not exist in finalized ZVM state", id)
	}
	if w.PaidIn != (common.Hash{}) {
		return fmt.Errorf("withdrawal %d is already paid by %s", id, w.PaidIn)
	}
	if w.To != b.ToAddress || w.Token != b.TokenStandard || b.Amount == nil || !b.Amount.Big().IsUint64() || b.Amount.Big().Uint64() != w.Amount {
		return fmt.Errorf("the payout does not match withdrawal %d (to %s, %d of %s)", id, w.To, w.Amount, w.Token)
	}
	m, err := p.L1.FrontierMomentum(ctx)
	if err != nil {
		return err
	}
	momentum := p.Rollup.L1StartHeight + w.L2Block - 1
	depth := p.depthFor(w.Token, w.Amount)
	if momentum+depth > m.Height {
		return fmt.Errorf("withdrawal %d (%d of %s) is from momentum %d, which is not yet %d below the frontier %d",
			id, w.Amount, w.Token, momentum, depth, m.Height)
	}
	if err := p.withinOutflow(ctx, w.Token, w.Amount); err != nil {
		return err
	}
	return p.neverTwice(ctx, id, b, frontierHeight)
}

// neverTwice refuses a second payout for one withdrawal. A signature this
// signer gave earlier is harmless only if its block can no longer land: its
// height is taken by a different block. A block at the very height being
// signed now conflicts with this one, so at most one of them can land.
func (p *Policy) neverTwice(ctx context.Context, id uint64, b *znn.AccountBlock, frontierHeight uint64) error {
	rows, err := p.DB.QueryContext(ctx, "SELECT height, hash FROM signed_payouts WHERE withdrawal = ?", id)
	if err != nil {
		return err
	}
	type prior struct {
		height uint64
		hash   string
	}
	var priors []prior
	for rows.Next() {
		var pr prior
		if err := rows.Scan(&pr.height, &pr.hash); err != nil {
			rows.Close()
			return err
		}
		priors = append(priors, pr)
	}
	rows.Close()
	for _, pr := range priors {
		if pr.height == b.Height {
			continue
		}
		if pr.height > frontierHeight {
			return fmt.Errorf("withdrawal %d already has a payout signed at height %d that could still land", id, pr.height)
		}
		at, err := p.blockAtHeight(ctx, pr.height)
		if err != nil {
			return err
		}
		if at == nil || at.Hash.String() == pr.hash {
			return fmt.Errorf("withdrawal %d was already paid at vault height %d", id, pr.height)
		}
	}
	h := b.ComputeHash()
	var amount uint64
	if b.Amount != nil && b.Amount.Big().IsUint64() {
		amount = b.Amount.Big().Uint64()
	}
	_, err = p.DB.ExecContext(ctx,
		"INSERT OR IGNORE INTO signed_payouts (withdrawal, height, hash, signed_at, token, amount) VALUES (?,?,?,?,?,?)",
		id, b.Height, h.String(), time.Now().Unix(), b.TokenStandard.String(), amount)
	return err
}

func (p *Policy) blockAtHeight(ctx context.Context, height uint64) (*znn.AccountBlock, error) {
	list, err := p.L1.AccountBlocksByHeight(ctx, p.Rollup.Vault, height, 1)
	if err != nil {
		return nil, err
	}
	if len(list.List) == 1 && list.List[0].Height == height {
		return list.List[0], nil
	}
	unconfirmed, err := p.L1.UnconfirmedBlocks(ctx, p.Rollup.Vault, 0, 50)
	if err != nil {
		return nil, err
	}
	for _, blk := range unconfirmed.List {
		if blk.Height == height {
			return blk, nil
		}
	}
	return nil, nil
}

// Signer serves one committee member's share over HTTP.
type Signer struct {
	Share  *Share
	Group  *GroupFile
	Policy *Policy
	Token  []byte
	Log    *slog.Logger

	mu       sync.Mutex
	sessions map[string]*session
}

type session struct {
	nonces     *Nonces
	commitment *Commitment
	created    time.Time
}

const (
	sessionTTL  = 2 * time.Minute
	maxSessions = 256
)

type InfoResponse struct {
	ID         Identifier  `json:"id"`
	CeremonyID string      `json:"ceremonyId"`
	GroupKey   string      `json:"groupKey"`
	Address    znn.Address `json:"address"`
	Threshold  int         `json:"threshold"`
}

type CommitRequest struct {
	Session string `json:"session"`
}

type SignRequest struct {
	Session     string            `json:"session"`
	Block       *znn.AccountBlock `json:"block"`
	Commitments []*Commitment     `json:"commitments"`
}

func (s *Signer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /info", s.auth(s.info))
	mux.HandleFunc("POST /commit", s.auth(s.commit))
	mux.HandleFunc("POST /sign", s.auth(s.sign))
	return mux
}

func (s *Signer) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), s.Token) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next(w, r)
	}
}

func (s *Signer) info(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, InfoResponse{
		ID: s.Share.ID, CeremonyID: s.Group.CeremonyID, GroupKey: hex.EncodeToString(s.Group.GroupKey),
		Address: s.Group.Address, Threshold: s.Group.Threshold,
	})
}

func (s *Signer) commit(w http.ResponseWriter, r *http.Request) {
	var req CommitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Session) < 16 || len(req.Session) > 128 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	nonces, com, err := s.Share.Commit()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	if s.sessions == nil {
		s.sessions = map[string]*session{}
	}
	for k, v := range s.sessions {
		if time.Since(v.created) > sessionTTL {
			delete(s.sessions, k)
		}
	}
	if _, exists := s.sessions[req.Session]; exists || len(s.sessions) >= maxSessions {
		s.mu.Unlock()
		http.Error(w, "session exists or too many sessions", http.StatusTooManyRequests)
		return
	}
	s.sessions[req.Session] = &session{nonces: nonces, commitment: com, created: time.Now()}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, com)
}

func (s *Signer) sign(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Block == nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// The nonces leave the table before anything else happens: whatever the
	// outcome, they are never used for a second request.
	s.mu.Lock()
	sess := s.sessions[req.Session]
	delete(s.sessions, req.Session)
	s.mu.Unlock()
	if sess == nil || time.Since(sess.created) > sessionTTL {
		http.Error(w, "unknown or expired session", http.StatusConflict)
		return
	}
	mine := false
	for _, c := range req.Commitments {
		if c != nil && c.ID == s.Share.ID {
			if !bytes.Equal(c.Hiding, sess.commitment.Hiding) || !bytes.Equal(c.Binding, sess.commitment.Binding) {
				http.Error(w, "the commitment list misstates this signer's commitment", http.StatusBadRequest)
				return
			}
			mine = true
		}
	}
	if !mine || len(req.Commitments) < s.Group.Threshold {
		http.Error(w, "the commitment list is not a quorum including this signer", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.Policy.Check(ctx, req.Block); err != nil {
		s.Log.Warn("refused", "height", req.Block.Height, "type", req.Block.BlockType, "reason", err)
		http.Error(w, "refused: "+err.Error(), http.StatusForbidden)
		return
	}
	hash := req.Block.ComputeHash()
	share, err := s.Share.Sign(hash[:], sess.nonces, req.Commitments)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.Log.Info("signed", "height", req.Block.Height, "type", req.Block.BlockType, "hash", hash)
	writeJSON(w, http.StatusOK, share)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func randomSession() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
