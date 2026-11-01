package bridge

import (
	"context"
	"errors"
	"time"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

type ChainObservation struct {
	Height    uint64 `json:"height"`
	Hash      string `json:"hash"`
	Timestamp uint64 `json:"timestamp"`
}

type SignerMemberObservation struct {
	ID              uint64           `json:"id"`
	State           string           `json:"state"`
	CheckedAt       int64            `json:"checkedAt"`
	L1              ChainObservation `json:"l1"`
	L2              ChainObservation `json:"l2"`
	DerivedMomentum uint64           `json:"derivedMomentum"`
}

// A monitoring source must bind replies to its provisioned member authority.
// Member keys, authentication tokens, URLs and raw diagnostics are omitted.
type SignerObservations struct {
	State               string                    `json:"state"`
	ObservedAt          int64                     `json:"observedAt"`
	ConfigurationSHA256 string                    `json:"configurationSha256"`
	Threshold           int                       `json:"threshold"`
	Members             []SignerMemberObservation `json:"members"`
}

type SignerMonitoringSource interface {
	ObserveSigners(context.Context) SignerObservations
}

func (b *Bridge) observeSigners(ctx context.Context) SignerObservations {
	out := SignerObservations{State: "not_configured", ObservedAt: time.Now().Unix()}
	if b.cfg.Vault == nil || b.cfg.Vault.Signer == nil {
		return out
	}
	if source, ok := b.cfg.Vault.Signer.(SignerMonitoringSource); ok {
		return source.ObserveSigners(ctx)
	}
	return out
}

// The point is reader-reported. Transport bounds and required fields do not
// establish independent canonicality or a consensus proof.
func ReadMomentumObservation(ctx context.Context, client *znn.Client, chain uint64) (ChainObservation, error) {
	var out ChainObservation
	if client == nil || chain == 0 {
		return out, errors.New("member momentum observation unavailable")
	}
	fields, err := observationRPC(ctx, client.URL(), "ledger.getFrontierMomentum", []any{})
	if err != nil {
		return out, errors.New("member momentum observation unavailable")
	}
	id, ierr := observationField[uint64](fields["chainIdentifier"])
	height, herr := observationField[uint64](fields["height"])
	timestamp, terr := observationField[uint64](fields["timestamp"])
	hash, berr := observationField[znn.Hash](fields["hash"])
	if ierr != nil || herr != nil || terr != nil || berr != nil || id != chain || height == 0 || timestamp == 0 || hash == (znn.Hash{}) {
		return out, errors.New("member momentum observation unavailable")
	}
	return ChainObservation{Height: height, Timestamp: timestamp, Hash: hash.String()}, nil
}
