package committee

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// The files a resharing passes between people, and the checks each one carries.
//
// A resharing is shaped like the ceremony — a public plan, a public package per
// dealer, a private value per recipient — but it differs in two ways that the
// file formats have to carry:
//
//   - The **group key already exists**, so the plan names it. Every participant
//     checks that what comes out is the vault they started with; that check is
//     the whole point, and it belongs in the file rather than in someone's head.
//   - **Incoming members may be new**, so they have no round-1 encryption key
//     to receive values at. They publish one first (`ReshareKeyFile`), and the
//     dealers seal to it.

// ResharePlan is the public parameter file for one resharing. Whoever writes it
// is a courier, not a trusted party: every value in it is checked by everyone.
type ResharePlan struct {
	ID        string        `json:"reshareId"`
	L1ChainID uint64        `json:"l1ChainId"`
	GroupKey  []byte        `json:"groupKey"`
	Address   znn.Address   `json:"address"`
	Quorum    []Identifier  `json:"quorum"`
	Threshold int           `json:"threshold"`
	Members   []Participant `json:"members"`
}

// NewResharePlan builds a plan against the group being preserved.
func NewResharePlan(g *GroupFile, quorum []Identifier, threshold int, names []string) (*ResharePlan, error) {
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	p := &ResharePlan{
		ID: hex.EncodeToString(id), L1ChainID: g.L1ChainID,
		GroupKey: append([]byte(nil), g.GroupKey...), Address: g.Address,
		Quorum: SortIdentifiers(quorum), Threshold: threshold,
	}
	for i, n := range names {
		p.Members = append(p.Members, Participant{ID: Identifier(i + 1), Name: n})
	}
	return p, p.Validate()
}

func (p *ResharePlan) Validate() error {
	if b, err := hex.DecodeString(p.ID); err != nil || len(b) != 32 {
		return errors.New("reshare: reshareId must be 32 bytes of hex")
	}
	if p.L1ChainID == 0 {
		return errors.New("reshare: l1ChainId is required")
	}
	if len(p.GroupKey) != ed25519.PublicKeySize {
		return errors.New("reshare: groupKey is not an Ed25519 key")
	}
	if znn.PubKeyToAddress(p.GroupKey) != p.Address {
		return errors.New("reshare: address does not match groupKey — this plan would move the vault")
	}
	if p.Threshold < 2 || p.Threshold > len(p.Members) {
		return fmt.Errorf("reshare: a threshold of %d for %d members", p.Threshold, len(p.Members))
	}
	if err := checkSet(p.Quorum); err != nil {
		return fmt.Errorf("reshare: the quorum %w", err)
	}
	ids := p.MemberIDs()
	if err := checkSet(ids); err != nil {
		return fmt.Errorf("reshare: the member set %w", err)
	}
	return nil
}

// MemberIDs is the incoming set, in canonical order.
func (p *ResharePlan) MemberIDs() []Identifier {
	out := make([]Identifier, 0, len(p.Members))
	for _, m := range p.Members {
		out = append(out, m.ID)
	}
	return SortIdentifiers(out)
}

// Binding is the synthetic ceremony a resharing's private values are sealed
// against, so a value from one resharing cannot be replayed into another.
func (p *ResharePlan) Binding() *Ceremony {
	return &Ceremony{ID: p.ID, L1ChainID: p.L1ChainID, Threshold: p.Threshold, Participants: p.Members}
}

// ReshareKeyFile is an incoming member's encryption key. Public.
type ReshareKeyFile struct {
	ReshareID string     `json:"reshareId"`
	ID        Identifier `json:"id"`
	BoxKey    []byte     `json:"boxKey"`
}

// ReshareDealFile is one dealer's public commitments.
type ReshareDealFile struct {
	ReshareID string `json:"reshareId"`
	ReshareDeal
}

// ReshareState is a dealer's secret between dealing and sending.
type ReshareState struct {
	ReshareID string     `json:"reshareId"`
	ID        Identifier `json:"id"`
	Coeffs    [][]byte   `json:"coeffs"`
}

// ReshareSecretFile is an incoming member's box secret, kept sealed.
type ReshareSecretFile struct {
	ReshareID string     `json:"reshareId"`
	ID        Identifier `json:"id"`
	BoxSecret []byte     `json:"boxSecret"`
}

// NewBoxKey generates an encryption keypair for receiving private values.
func NewBoxKey(r io.Reader) (pub, sec *[32]byte, err error) {
	return box.GenerateKey(r)
}

// BoxKeyFrom rebuilds a secret key from its stored bytes.
func BoxKeyFrom(b []byte) (*[32]byte, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("reshare: a box secret is 32 bytes, got %d", len(b))
	}
	var k [32]byte
	copy(k[:], b)
	return &k, nil
}

// GroupFileFrom turns a computed group into the file everyone publishes.
func GroupFileFrom(p *ResharePlan, g *Group) *GroupFile {
	return &GroupFile{
		CeremonyID: p.ID, L1ChainID: p.L1ChainID, Threshold: g.Threshold,
		Participants: p.Members, GroupKey: g.GroupKey,
		Address: znn.PubKeyToAddress(g.GroupKey), VerificationShares: g.VerificationShares,
		Transcript: "reshared from " + hex.EncodeToString(p.GroupKey[:8]),
	}
}
