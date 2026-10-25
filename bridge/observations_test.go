package bridge

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
	_ "modernc.org/sqlite"
)

// This fixture has no key, signer, wallet, publisher or EVM. It exercises the
// production read paths over owned HTTP and SQLite, using synthetic replies.
type observationFixture struct {
	t             *testing.T
	b             *Bridge
	phase         string
	head, genesis *types.Header
	calls         atomic.Int64
	frontiers     atomic.Int64
	finalized     atomic.Int64
	pinned        atomic.Int64
	started       chan struct{}
	once          sync.Once
}

func newObservationFixture(t *testing.T, phase string) *observationFixture {
	t.Helper()
	f := &observationFixture{t: t, phase: phase, started: make(chan struct{})}
	f.genesis = &types.Header{Number: big.NewInt(0), GasLimit: 30_000_000, Time: 1, Difficulty: big.NewInt(0), Extra: []byte("owned-genesis")}
	f.head = &types.Header{Number: big.NewInt(10), GasLimit: 30_000_000, Time: 11, Difficulty: big.NewInt(0), Extra: []byte("owned-finalized")}
	cfg := &rollup.Config{L1ChainID: 70, L2ChainID: 7340470, L1StartHeight: 5, L2GenesisHash: f.genesis.Hash(), Vault: znn.Address{19: 1}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	eth, err := ethclient.Dial(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eth.Close)
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "observations.db"))+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(1000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	f.b = &Bridge{cfg: Config{Rollup: cfg, L1: znn.NewClient(srv.URL), Eth: eth, DB: db}}
	return f
}

func (f *observationFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	var req struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&req) != nil {
		f.t.Error("unexpected fixture request")
		http.Error(w, "fixture request", 400)
		return
	}
	if f.phase == "blocked" {
		f.once.Do(func() { close(f.started) })
		<-r.Context().Done()
		return
	}
	var result any
	switch req.Method {
	case "eth_chainId":
		id := f.b.cfg.Rollup.L2ChainID
		if f.phase == "wrong-l2-chain" {
			id++
		}
		result = hexutil.EncodeUint64(id)
	case "eth_getBlockByNumber":
		var tag string
		json.Unmarshal(req.Params[0], &tag)
		if tag == "0x0" {
			genesis := *f.genesis
			if f.phase == "wrong-genesis" {
				genesis.Extra = []byte("other")
			}
			result = &genesis
		} else {
			head := *f.head
			if tag == "finalized" {
				if f.finalized.Add(1) > 1 && f.phase == "finality-retreat" {
					head.Number = big.NewInt(9)
				}
			} else {
				if tag != "0xa" {
					f.t.Errorf("unexpected block %s", tag)
				}
				if f.phase == "canonical-change" {
					head.Extra = []byte("replacement")
				}
			}
			result = &head
		}
	case "eth_call":
		var call struct {
			To    string `json:"to"`
			Input string `json:"input"`
			Data  string `json:"data"`
		}
		var at struct {
			Hash string `json:"blockHash"`
		}
		if len(req.Params) != 2 || json.Unmarshal(req.Params[0], &call) != nil || json.Unmarshal(req.Params[1], &at) != nil || at.Hash != f.head.Hash().Hex() {
			f.t.Error("contract read escaped its exact block hash")
		}
		f.pinned.Add(1)
		input := call.Input
		if input == "" {
			input = call.Data
		}
		var amount int64
		switch input {
		case hexutil.Encode(crypto.Keccak256([]byte("pendingZNN()"))[:4]):
			amount = 900
		case hexutil.Encode(crypto.Keccak256([]byte("pendingQSR()"))[:4]):
			amount = 700
		case hexutil.Encode(crypto.Keccak256([]byte("totalSupply()"))[:4]):
			amount = 5000
			if common.HexToAddress(call.To) != common.HexToAddress("0x4200000000000000000000000000000000000101") {
				f.t.Error("wrong QSR target")
			}
		default:
			f.t.Error("unexpected contract read")
		}
		word := common.LeftPadBytes(big.NewInt(amount).Bytes(), 32)
		if f.phase == "short-contract-word" {
			word = word[:31]
		}
		if f.phase == "liability-overflow" && amount == 5000 {
			word = bytes.Repeat([]byte{255}, 32)
		}
		if f.phase == "hash-call-refused" {
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32602, "message": "fixture hash port unavailable"}})
			return
		}
		result = hexutil.Encode(word)
	case "ledger.getFrontierAccountBlock":
		n := f.frontiers.Add(1)
		hash := znn.Hash{0: 1}
		momentum, chain := uint64(12), uint64(70)
		if f.phase == "frontier-change" && n > 1 {
			hash[0]++
		}
		if f.phase == "vault-ahead" {
			momentum = 15
		}
		if f.phase == "wrong-l1-chain" {
			chain++
		}
		confirmedIn := znn.Hash{0: 2}
		if f.phase == "confirmation-change" && n > 1 {
			confirmedIn[0]++
		}
		confirmation := any(map[string]any{"momentumHeight": momentum, "momentumHash": confirmedIn, "numConfirmations": 3})
		if f.phase == "unconfirmed-frontier" {
			confirmation = nil
		}
		result = map[string]any{"address": f.b.cfg.Rollup.Vault, "chainIdentifier": chain, "height": 7, "hash": hash, "confirmationDetail": confirmation}
	case "ledger.getAccountInfoByAddress":
		amount := any("800")
		switch f.phase {
		case "negative-balance":
			amount = "-1"
		case "null-balance":
			amount = nil
		case "numeric-balance":
			amount = 800
		case "leading-zero-balance":
			amount = "0800"
		case "oversized-balance":
			amount = strings.Repeat("9", 79)
		case "large-exact-balance":
			amount = "900719925474099312345"
		}
		height := 7
		if f.phase == "balance-height-change" {
			height++
		}
		result = map[string]any{"address": f.b.cfg.Rollup.Vault, "accountHeight": height, "balanceInfoMap": map[string]any{znn.ZNN.String(): map[string]any{"balance": amount}, znn.QSR.String(): map[string]any{"balance": "4000"}}}
	case "ledger.getUnconfirmedBlocksByAddress", "ledger.getUnreceivedBlocksByAddress":
		count := 0
		if f.phase == "unreceived" && req.Method == "ledger.getUnreceivedBlocksByAddress" {
			count = 1
		}
		if f.phase == "unconfirmed" && req.Method == "ledger.getUnconfirmedBlocksByAddress" {
			count = 1
		}
		result = map[string]any{"count": count, "list": []any{}}
		if f.phase == "missing-count" {
			result = map[string]any{}
		}
	default:
		f.t.Errorf("observation attempted non-read method %s", req.Method)
		http.Error(w, "non-read method refused", 400)
		return
	}
	if strings.HasPrefix(req.Method, "ledger.") {
		switch f.phase {
		case "reader-error":
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -1, "message": "fixture-private-diagnostic"}})
			return
		case "missing-result":
			w.Write([]byte(`{"jsonrpc":"2.0","id":1}`))
			return
		case "duplicate-result":
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{},"result":{}}`))
			return
		case "oversized-response":
			w.Write([]byte(strings.Repeat(" ", 129<<10)))
			return
		case "redirect":
			w.Header().Set("Location", "/redirect-target")
			w.WriteHeader(302)
			return
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	if f.phase == "trailing-json" && strings.HasPrefix(req.Method, "ledger.") {
		w.Write([]byte(`{}`))
	}
}

func observationPayout(t *testing.T, db *sql.DB, id int, state string, at any) {
	t.Helper()
	if _, err := db.Exec("INSERT INTO payouts(id,l2_block,l2_tx,from_addr,to_addr,zts,amount,status,seen_at) VALUES(?,1,'fixture','fixture','fixture','fixture','1',?,?)", id, state, at); err != nil {
		t.Fatal(err)
	}
}

func TestOperationalObservationsUsePinnedReadsAndPreservePayouts(t *testing.T) {
	f := newObservationFixture(t, "")
	now := time.Now().Unix()
	for i, state := range []string{"pending", "unknown", "failed", "paid"} {
		observationPayout(t, f.b.cfg.DB, i+1, state, now-int64(i+1)*200)
	}
	var before, after int64
	f.b.cfg.DB.QueryRow("SELECT total_changes()").Scan(&before)
	out := f.b.Observations(context.Background())
	f.b.cfg.DB.QueryRow("SELECT total_changes()").Scan(&after)
	if before != after || out.Schema != 1 || out.Queue.State != "observed" || out.Queue.Outstanding != 3 || out.Queue.OldestSeenAt != now-600 || out.Queue.OldestAgeSeconds < 600 || out.Queue.OldestAgeSeconds > 602 {
		t.Fatalf("queue age or read-only invariant failed: %+v, changes %d -> %d", out.Queue, before, after)
	}
	peg := out.Peg
	if peg.State != "observed" || peg.L2BlockNumber != 10 || peg.L2BlockHash != f.head.Hash().Hex() || peg.DerivedMomentum != 14 || peg.VaultAccountHeight != 7 || peg.VaultConfirmedAt != 12 || len(peg.ConfigurationSHA256) != 64 || f.pinned.Load() != 3 {
		t.Fatalf("source binding failed: %+v", peg)
	}
	znnAsset, qsr := peg.Assets["ZNN"], peg.Assets["QSR"]
	if znnAsset.LiquidBaseUnits != "800" || znnAsset.PendingBaseUnits != "900" || znnAsset.PayoutLiquidityDeficit != "100" || znnAsset.TotalBackingState != "not_established" || znnAsset.UserLiabilityBaseUnits != "" {
		t.Fatalf("native liquidity was confused with full backing: %+v", znnAsset)
	}
	if qsr.UserLiabilityBaseUnits != "5700" || qsr.BackingDeficitBaseUnits != "1700" || qsr.PayoutLiquidityDeficit != "0" || qsr.TotalBackingState != "reader_observed" {
		t.Fatalf("QSR liability arithmetic failed: %+v", qsr)
	}
	var states int
	if err := f.b.cfg.DB.QueryRow("SELECT COUNT(*) FROM payouts WHERE status IN ('pending','unknown','failed','paid')").Scan(&states); err != nil || states != 4 {
		t.Fatal("observation rewrote payout states")
	}
}

func TestOperationalObservationsRefuseIncompleteOrUnalignedReaders(t *testing.T) {
	for _, phase := range []string{"wrong-l2-chain", "wrong-genesis", "vault-ahead", "wrong-l1-chain", "unconfirmed-frontier", "balance-height-change", "unreceived", "unconfirmed", "missing-count", "frontier-change", "confirmation-change", "canonical-change", "finality-retreat", "short-contract-word", "hash-call-refused", "liability-overflow", "negative-balance", "null-balance", "numeric-balance", "leading-zero-balance", "oversized-balance", "reader-error", "missing-result", "duplicate-result", "oversized-response", "redirect", "trailing-json"} {
		t.Run(phase, func(t *testing.T) {
			f := newObservationFixture(t, phase)
			rec := httptest.NewRecorder()
			f.b.ObservationHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/observations", nil))
			var out OperationalObservations
			if rec.Code != 503 || rec.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Peg.State != "unavailable" || out.Peg.Reason == "" || out.Peg.Assets != nil {
				t.Fatalf("unavailable reader manufactured an economic observation: status=%d body=%s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "fixture-private-diagnostic") || strings.Contains(rec.Body.String(), f.b.cfg.L1.URL()) {
				t.Fatal("observation exported a private diagnostic or endpoint")
			}
		})
	}
}

func TestOperationalQueueRefusesUnknownAndInvalidAges(t *testing.T) {
	for _, item := range []struct {
		name, state string
		at          any
	}{
		{"unknown-state", "unrecognized", int64(10)},
		{"zero-time", "pending", int64(0)},
		{"negative-time", "pending", int64(-1)},
		{"future-time", "pending", time.Now().Unix() + 3600},
		{"text-time", "pending", "not-a-time"},
		{"interior-real-time", "pending", 10.5},
	} {
		t.Run(item.name, func(t *testing.T) {
			f := newObservationFixture(t, "")
			observationPayout(t, f.b.cfg.DB, 1, "pending", int64(1))
			observationPayout(t, f.b.cfg.DB, 2, item.state, item.at)
			observationPayout(t, f.b.cfg.DB, 3, "pending", time.Now().Unix()-1)
			out := f.b.observeQueue(context.Background(), time.Now().Unix())
			if out.State != "unavailable" || out.Payouts != nil || out.Outstanding != 0 {
				t.Fatalf("invalid persisted evidence manufactured queue age: %+v", out)
			}
		})
	}
}

func TestOperationalObservationsKeepAmountsExactAboveJavaScriptIntegers(t *testing.T) {
	f := newObservationFixture(t, "large-exact-balance")
	out := f.b.Observations(context.Background())
	if out.Peg.State != "observed" || out.Peg.Assets["ZNN"].LiquidBaseUnits != "900719925474099312345" || out.Peg.Assets["ZNN"].PayoutLiquidityDeficit != "0" {
		t.Fatalf("base-unit amount was rounded: %+v", out.Peg)
	}
}

func TestOperationalHTTPAdmissionIsBoundedAndReleasesTheSQLReader(t *testing.T) {
	f := newObservationFixture(t, "blocked")
	h := f.b.ObservationHandler()
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "/observations", nil))
		if rec.Code != 405 || rec.Header().Get("Allow") != http.MethodGet || f.calls.Load() != 0 {
			t.Fatal("non-GET observation performed work")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/observations", nil).WithContext(ctx))
	}()
	select {
	case <-f.started:
	case <-time.After(3 * time.Second):
		t.Fatal("owned RPC did not start")
	}
	busy := httptest.NewRecorder()
	h.ServeHTTP(busy, httptest.NewRequest(http.MethodGet, "/observations", nil))
	if busy.Code != 503 || f.calls.Load() != 1 {
		t.Fatal("a concurrent collection escaped its admission bound")
	}
	writer, writerCancel := context.WithTimeout(context.Background(), time.Second)
	defer writerCancel()
	if _, err := f.b.cfg.DB.ExecContext(writer, "INSERT INTO payouts(id,l2_block,l2_tx,from_addr,to_addr,zts,amount,status,seen_at) VALUES(1,1,'fixture','fixture','fixture','fixture','1','pending',1)"); err != nil {
		t.Fatalf("RPC held the only SQL connection: %v", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("owned observation did not join after cancellation")
	}
}

func TestOperationalObservationsRefuseMissingDependenciesAndCanceledCalls(t *testing.T) {
	for _, phase := range []string{"database-closed", "configuration-missing", "canceled"} {
		t.Run(phase, func(t *testing.T) {
			f := newObservationFixture(t, "")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch phase {
			case "database-closed":
				f.b.cfg.DB.Close()
			case "configuration-missing":
				f.b.cfg.Rollup = nil
			case "canceled":
				cancel()
			}
			rec := httptest.NewRecorder()
			f.b.ObservationHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/observations", nil).WithContext(ctx))
			if rec.Code != 503 {
				t.Fatalf("missing dependency looked complete: %s", rec.Body.String())
			}
			if phase == "canceled" && f.calls.Load() != 0 {
				t.Fatal("a canceled observation performed RPC work")
			}
		})
	}
}

func TestOperationalHTTPReportsDeficitsAsDataAndDoesNotImplyHealth(t *testing.T) {
	f := newObservationFixture(t, "")
	rec := httptest.NewRecorder()
	f.b.ObservationHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/observations", nil))
	var fields map[string]json.RawMessage
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &fields) != nil || fields["healthy"] != nil {
		t.Fatalf("collection was mislabeled as health: %s", rec.Body.String())
	}
	var out OperationalObservations
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Peg.Assets["QSR"].BackingDeficitBaseUnits != "1700" {
		t.Fatal("positive backing deficit was not published")
	}
}
