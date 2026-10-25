package bridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

const observationTimeout = 15 * time.Second

// OperationalObservations contains read-only evidence for alert policies.
// "observed" describes a complete, self-consistent reader sample. It does not
// establish independent canonicality, custody authority or economic acceptance.
type OperationalObservations struct {
	Schema              int                `json:"schema"`
	ObservedAt          int64              `json:"observedAt"`
	ConfigurationSHA256 string             `json:"configurationSha256"`
	Queue               QueueObservation   `json:"queue"`
	Peg                 PegObservation     `json:"peg"`
	Signers             SignerObservations `json:"signers"`
}

type QueueObservation struct {
	State            string           `json:"state"`
	Reason           string           `json:"reason,omitempty"`
	Payouts          map[string]int64 `json:"payouts,omitempty"`
	Outstanding      int64            `json:"outstanding"`
	OldestSeenAt     int64            `json:"oldestSeenAt"`
	OldestAgeSeconds int64            `json:"oldestAgeSeconds"`
}

type AssetObservation struct {
	LiquidBaseUnits         string `json:"liquidBaseUnits"`
	PendingBaseUnits        string `json:"pendingBaseUnits"`
	PayoutLiquidityDeficit  string `json:"payoutLiquidityDeficitBaseUnits"`
	TotalBackingState       string `json:"totalBackingState"`
	UserLiabilityBaseUnits  string `json:"userLiabilityBaseUnits,omitempty"`
	BackingDeficitBaseUnits string `json:"backingDeficitBaseUnits,omitempty"`
}

type PegObservation struct {
	State               string                      `json:"state"`
	Reason              string                      `json:"reason,omitempty"`
	ConfigurationSHA256 string                      `json:"configurationSha256,omitempty"`
	L2BlockNumber       uint64                      `json:"l2BlockNumber"`
	L2BlockHash         string                      `json:"l2BlockHash,omitempty"`
	DerivedMomentum     uint64                      `json:"derivedMomentum"`
	VaultAccountHeight  uint64                      `json:"vaultAccountHeight"`
	VaultAccountHash    string                      `json:"vaultAccountHash,omitempty"`
	VaultConfirmedAt    uint64                      `json:"vaultConfirmedAtMomentum"`
	VaultConfirmedIn    string                      `json:"vaultConfirmationMomentumHash,omitempty"`
	Assets              map[string]AssetObservation `json:"assets,omitempty"`
}

func (b *Bridge) Observations(ctx context.Context) OperationalObservations {
	ctx, cancel := context.WithTimeout(ctx, observationTimeout)
	defer cancel()
	now := time.Now().Unix()
	out := OperationalObservations{Schema: 1, ObservedAt: now, Queue: b.observeQueue(ctx, now)}
	if b.cfg.Rollup != nil {
		if raw, err := json.Marshal(b.cfg.Rollup); err == nil {
			digest := sha256.Sum256(raw)
			out.ConfigurationSHA256 = hex.EncodeToString(digest[:])
		}
	}
	var reads sync.WaitGroup
	reads.Add(2)
	go func() { defer reads.Done(); out.Peg = b.observePeg(ctx) }()
	go func() { defer reads.Done(); out.Signers = b.observeSigners(ctx) }()
	reads.Wait()
	return out
}

// ObservationHandler admits one collection per installed handler. Rejected
// concurrent requests cannot create additional RPC work or wait on a writer.
func (b *Bridge) ObservationHandler() http.Handler {
	gate := make(chan struct{}, 1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "read-only observations require GET", http.StatusMethodNotAllowed)
			return
		}
		select {
		case gate <- struct{}{}:
			defer func() { <-gate }()
		default:
			http.Error(w, "observation collection is busy", http.StatusServiceUnavailable)
			return
		}
		out := b.Observations(r.Context())
		code := http.StatusOK
		if out.Queue.State != "observed" || out.Peg.State != "observed" {
			code = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(out)
	})
}

func (b *Bridge) observeQueue(ctx context.Context, now int64) QueueObservation {
	out := QueueObservation{State: "unavailable", Reason: "payout_queue_unavailable"}
	if b.cfg.DB == nil || now <= 0 {
		return out
	}
	tx, err := b.cfg.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT status, COUNT(*), MIN(seen_at), MAX(seen_at), SUM(CASE WHEN typeof(seen_at)='integer' AND seen_at>0 AND seen_at<=? THEN 0 ELSE 1 END) FROM payouts GROUP BY status LIMIT 17", now)
	if err != nil {
		return out
	}
	defer rows.Close()
	counts := map[string]int64{}
	var count, oldest int64
	for rows.Next() {
		var state string
		var n, invalid int64
		var first, last sql.NullInt64
		if rows.Scan(&state, &n, &first, &last, &invalid) != nil || n <= 0 || len(counts) >= 16 {
			return out
		}
		switch state {
		case "pending", "published", "intent", "unknown", "legacy_unknown", "disputed", "paid", "failed":
		default:
			out.Reason = "unknown_payout_state"
			return out
		}
		counts[state] = n
		if state == "paid" {
			continue
		}
		if invalid != 0 || !first.Valid || !last.Valid || first.Int64 <= 0 || last.Int64 > now || count > math.MaxInt64-n {
			out.Reason = "invalid_payout_age"
			return out
		}
		count += n
		if oldest == 0 || first.Int64 < oldest {
			oldest = first.Int64
		}
	}
	if rows.Err() != nil || rows.Close() != nil || tx.Commit() != nil {
		return out
	}
	out = QueueObservation{State: "observed", Payouts: counts, Outstanding: count, OldestSeenAt: oldest}
	if oldest > 0 {
		out.OldestAgeSeconds = now - oldest
	}
	return out
}

func observationField[T any](raw json.RawMessage) (T, error) {
	var value *T
	err := json.Unmarshal(raw, &value)
	if err != nil || value == nil {
		var zero T
		return zero, errors.New("required observation field is unavailable")
	}
	return *value, nil
}

// Bound duplicate keys, nesting, token count and trailing values before any
// critical field is decoded. Critical names are selected case-sensitively.
func observationJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tokens := 0
	var value func(int) error
	value = func(depth int) error {
		tokens++
		if depth > 16 || tokens > 8192 {
			return errors.New("observation exceeds its JSON budget")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); ok {
			keys := map[string]bool{}
			for d.More() {
				if delimiter == '{' {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || keys[name] {
						return errors.New("ambiguous observation field")
					}
					keys[name] = true
				}
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || (delimiter == '{' && end != json.Delim('}')) || (delimiter == '[' && end != json.Delim(']')) || (delimiter != '{' && delimiter != '[') {
				return errors.New("invalid observation JSON")
			}
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing observation JSON")
	}
	return nil
}

func observationRPC(ctx context.Context, endpoint, method string, params []any) (map[string]json.RawMessage, error) {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("observation request unavailable")
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.New("observation reader unavailable")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, (128<<10)+1))
	if err != nil || res.StatusCode != http.StatusOK || len(raw) > 128<<10 || observationJSON(raw) != nil {
		return nil, errors.New("invalid observation response")
	}
	fields, err := observationField[map[string]json.RawMessage](raw)
	if err != nil || string(fields["jsonrpc"]) != `"2.0"` || string(fields["id"]) != "1" || (len(fields["error"]) != 0 && string(fields["error"]) != "null") {
		return nil, errors.New("observation RPC envelope unavailable")
	}
	return observationField[map[string]json.RawMessage](fields["result"])
}

type observedFrontier struct {
	height, momentum  uint64
	hash, confirmedIn znn.Hash
}

func (b *Bridge) observationFrontier(ctx context.Context) (observedFrontier, error) {
	var out observedFrontier
	fields, err := observationRPC(ctx, b.cfg.L1.URL(), "ledger.getFrontierAccountBlock", []any{b.cfg.Rollup.Vault})
	if err != nil {
		return out, err
	}
	address, aerr := observationField[znn.Address](fields["address"])
	chain, cerr := observationField[uint64](fields["chainIdentifier"])
	out.height, err = observationField[uint64](fields["height"])
	out.hash, _ = observationField[znn.Hash](fields["hash"])
	confirmation, derr := observationField[map[string]json.RawMessage](fields["confirmationDetail"])
	out.momentum, _ = observationField[uint64](confirmation["momentumHeight"])
	hash, herr := observationField[znn.Hash](confirmation["momentumHash"])
	out.confirmedIn = hash
	n, nerr := observationField[uint64](confirmation["numConfirmations"])
	if aerr != nil || cerr != nil || err != nil || derr != nil || herr != nil || nerr != nil || n == 0 || address != b.cfg.Rollup.Vault || chain != b.cfg.Rollup.L1ChainID || out.height == 0 || out.hash == (znn.Hash{}) || out.momentum == 0 || hash == (znn.Hash{}) {
		return observedFrontier{}, errors.New("confirmed vault frontier unavailable")
	}
	return out, nil
}

func observationAmount(raw json.RawMessage) (*big.Int, error) {
	text, err := observationField[string](raw)
	if err != nil || len(text) == 0 || len(text) > 78 || (len(text) > 1 && text[0] == '0') {
		return nil, errors.New("invalid observation amount")
	}
	for _, c := range text {
		if c < '0' || c > '9' {
			return nil, errors.New("invalid observation amount")
		}
	}
	value, ok := new(big.Int).SetString(text, 10)
	if !ok || value.BitLen() > 256 {
		return nil, errors.New("observation amount out of range")
	}
	return value, nil
}

func observationDeficit(liability, liquid *big.Int) string {
	difference := new(big.Int).Sub(liability, liquid)
	if difference.Sign() < 0 {
		difference.SetInt64(0)
	}
	return difference.String()
}

func (b *Bridge) observePeg(ctx context.Context) PegObservation {
	out := PegObservation{State: "unavailable", Reason: "readers_unavailable"}
	if b.cfg.Rollup == nil || b.cfg.L1 == nil || b.cfg.Eth == nil || ctx.Err() != nil {
		return out
	}
	cfg := b.cfg.Rollup
	if cfg.L1StartHeight == 0 || cfg.L1ChainID == 0 || cfg.L2ChainID == 0 || cfg.L2GenesisHash == (common.Hash{}) || cfg.Vault == (znn.Address{}) {
		out.Reason = "configuration_unavailable"
		return out
	}
	configuration, err := json.Marshal(cfg)
	if err != nil {
		out.Reason = "configuration_unavailable"
		return out
	}
	chain, err := b.cfg.Eth.ChainID(ctx)
	if err != nil || !chain.IsUint64() || chain.Uint64() != cfg.L2ChainID {
		out.Reason = "l2_identity_unavailable"
		return out
	}
	genesis, err := b.cfg.Eth.HeaderByNumber(ctx, big.NewInt(0))
	if err != nil || genesis == nil || genesis.Hash() != cfg.L2GenesisHash {
		out.Reason = "l2_identity_unavailable"
		return out
	}
	head, err := b.cfg.Eth.HeaderByNumber(ctx, big.NewInt(int64(rpc.FinalizedBlockNumber)))
	if err != nil || head == nil || head.Number == nil || !head.Number.IsUint64() || head.Number.Sign() <= 0 || head.Number.Uint64() > math.MaxUint64-cfg.L1StartHeight+1 {
		out.Reason = "finalized_block_unavailable"
		return out
	}
	height, blockHash := head.Number.Uint64(), head.Hash()
	derived := cfg.MomentumForL2Block(height)
	frontier, err := b.observationFrontier(ctx)
	if err != nil {
		out.Reason = "vault_frontier_unavailable"
		return out
	}
	if frontier.momentum > derived {
		out.Reason = "vault_ahead_of_finalized_derivation"
		return out
	}
	info, err := observationRPC(ctx, b.cfg.L1.URL(), "ledger.getAccountInfoByAddress", []any{cfg.Vault})
	if err != nil {
		out.Reason = "vault_balance_unavailable"
		return out
	}
	address, aerr := observationField[znn.Address](info["address"])
	accountHeight, herr := observationField[uint64](info["accountHeight"])
	balances, berr := observationField[map[string]json.RawMessage](info["balanceInfoMap"])
	if aerr != nil || herr != nil || berr != nil || address != cfg.Vault || accountHeight != frontier.height {
		out.Reason = "vault_balance_unaligned"
		return out
	}
	liquid := map[string]*big.Int{}
	for name, token := range map[string]znn.TokenStandard{"ZNN": znn.ZNN, "QSR": znn.QSR} {
		amount := new(big.Int)
		if raw, exists := balances[token.String()]; exists {
			entry, err := observationField[map[string]json.RawMessage](raw)
			if err != nil {
				out.Reason = "vault_balance_unavailable"
				return out
			}
			amount, err = observationAmount(entry["balance"])
			if err != nil {
				out.Reason = "vault_balance_unavailable"
				return out
			}
		}
		liquid[name] = amount
	}
	queuesEmpty := func() bool {
		for _, method := range []string{"ledger.getUnconfirmedBlocksByAddress", "ledger.getUnreceivedBlocksByAddress"} {
			fields, err := observationRPC(ctx, b.cfg.L1.URL(), method, []any{cfg.Vault, 0, 1})
			if err != nil {
				return false
			}
			count, err := observationField[uint64](fields["count"])
			if err != nil || count != 0 {
				return false
			}
		}
		return true
	}
	if !queuesEmpty() {
		out.Reason = "vault_queue_unavailable_or_unsettled"
		return out
	}
	pending := map[string]*big.Int{}
	var supply *big.Int
	qsr := common.HexToAddress("0x4200000000000000000000000000000000000101")
	for _, call := range []struct {
		name, signature string
		to              common.Address
	}{{"ZNN", "pendingZNN()", rollup.BridgeAddr}, {"QSR", "pendingQSR()", rollup.BridgeAddr}, {"supply", "totalSupply()", qsr}} {
		word, err := b.cfg.Eth.CallContractAtHash(ctx, ethereum.CallMsg{To: &call.to, Data: crypto.Keccak256([]byte(call.signature))[:4]}, blockHash)
		if err != nil || len(word) != 32 {
			out.Reason = "hash_pinned_contract_read_unavailable"
			return out
		}
		value := new(big.Int).SetBytes(word)
		if call.name == "supply" {
			supply = value
		} else {
			pending[call.name] = value
		}
	}
	liability := new(big.Int).Add(supply, pending["QSR"])
	if liability.BitLen() > 256 {
		out.Reason = "contract_liability_out_of_range"
		return out
	}
	after, err := b.observationFrontier(ctx)
	if err != nil || after != frontier || !queuesEmpty() {
		out.Reason = "vault_changed_during_observation"
		return out
	}
	canonical, err := b.cfg.Eth.HeaderByNumber(ctx, new(big.Int).SetUint64(height))
	if err != nil || canonical == nil || canonical.Number == nil || !canonical.Number.IsUint64() || canonical.Number.Uint64() != height || canonical.Hash() != blockHash {
		out.Reason = "l2_block_changed_during_observation"
		return out
	}
	finalized, err := b.cfg.Eth.HeaderByNumber(ctx, big.NewInt(int64(rpc.FinalizedBlockNumber)))
	if err != nil || finalized == nil || finalized.Number == nil || !finalized.Number.IsUint64() || finalized.Number.Uint64() < height {
		out.Reason = "finalized_reader_retreated"
		return out
	}
	again, err := json.Marshal(cfg)
	if err != nil || !bytes.Equal(again, configuration) || ctx.Err() != nil {
		out.Reason = "configuration_or_deadline_changed"
		return out
	}
	digest := sha256.Sum256(configuration)
	out = PegObservation{State: "observed", ConfigurationSHA256: hex.EncodeToString(digest[:]), L2BlockNumber: height, L2BlockHash: blockHash.Hex(), DerivedMomentum: derived,
		VaultAccountHeight: frontier.height, VaultAccountHash: frontier.hash.String(), VaultConfirmedAt: frontier.momentum, VaultConfirmedIn: frontier.confirmedIn.String(),
		Assets: map[string]AssetObservation{
			"ZNN": {LiquidBaseUnits: liquid["ZNN"].String(), PendingBaseUnits: pending["ZNN"].String(), PayoutLiquidityDeficit: observationDeficit(pending["ZNN"], liquid["ZNN"]), TotalBackingState: "not_established"},
			"QSR": {LiquidBaseUnits: liquid["QSR"].String(), PendingBaseUnits: pending["QSR"].String(), PayoutLiquidityDeficit: observationDeficit(pending["QSR"], liquid["QSR"]), TotalBackingState: "reader_observed", UserLiabilityBaseUnits: liability.String(), BackingDeficitBaseUnits: observationDeficit(liability, liquid["QSR"])},
		}}
	return out
}
