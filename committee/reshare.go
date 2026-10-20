package committee

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"sort"

	"filippo.io/edwards25519"
)

// Resharing: changing who holds the vault without changing the vault
// (DECISIONS.md D15).
//
// A FROST share is a point on a polynomial whose value at zero is the group
// secret. Running a second key ceremony produces a *different* polynomial and
// therefore a different group key — a different Zenon address, which for this
// rollup is a rollup-config change at an activation height, with every user's
// deposit address moving under them. That is what makes "add a signer" or
// "remove a signer who left" expensive today.
//
// Resharing changes the polynomial while keeping its value at zero:
//
//  1. A quorum Q of current members, |Q| ≥ the old threshold, each compute
//     wᵢ = λᵢ(Q)·sᵢ — their share times its Lagrange coefficient at zero over
//     that quorum. By Lagrange interpolation Σ wᵢ = s, the group secret.
//  2. Each of them deals a fresh sharing of their own wᵢ to the *new* member
//     set at the *new* threshold, publishing commitments to it.
//  3. Each new member sums what it received. The implied polynomial is the sum
//     of the dealers', so its value at zero is Σ wᵢ = s: **the group key, the
//     verification of every past signature, and the vault's NoM address are
//     unchanged.**
//
// What makes it safe rather than merely convenient is that a dealer cannot
// deal something other than its own share. A dealer's constant-term commitment
// must equal λᵢ times its *public* verification share from the old group, and
// every new member checks that before accepting anything. A dealer that tries
// to substitute a value is rejected by everyone, and the sum of the accepted
// constant terms is checked against the old group key — so a quorum cannot
// quietly reshare a different vault either.
//
// The old shares are not invalidated by arithmetic: a quorum of *old* members
// can still sign until they destroy them. Resharing is therefore a procedure —
// reshare, verify the new group reproduces the address, then every old member
// destroys their share — and `docs/COMMITTEE.md` is where that procedure lives.

// ReshareDeal is one current member's public contribution: commitments to the
// polynomial it is dealing over its own share.
type ReshareDeal struct {
	From        Identifier `json:"from"`
	Commitments [][]byte   `json:"commitments"`
}

// ReshareSecret is the dealer's private half, kept between the two rounds.
type ReshareSecret struct {
	From   Identifier
	coeffs []*edwards25519.Scalar
}

// Reshare is the dealing half, run by a member of the outgoing quorum.
//
// quorum is exactly the set of old members taking part — the Lagrange
// coefficient depends on it, so every dealer must use the same set, and the
// result is wrong (and caught) if they do not. members is the incoming set and
// threshold the incoming threshold.
func Reshare(r io.Reader, share *Share, quorum []Identifier, members []Identifier, threshold int) (*ReshareSecret, *ReshareDeal, error) {
	if share == nil {
		return nil, nil, errors.New("committee: resharing needs this member's own share")
	}
	if threshold < 2 {
		return nil, nil, errors.New("committee: a threshold below 2 is one key, not a committee")
	}
	if len(members) < threshold {
		return nil, nil, fmt.Errorf("committee: %d incoming members for a threshold of %d", len(members), threshold)
	}
	if err := checkSet(quorum); err != nil {
		return nil, nil, fmt.Errorf("committee: the outgoing quorum %w", err)
	}
	if err := checkSet(members); err != nil {
		return nil, nil, fmt.Errorf("committee: the incoming set %w", err)
	}
	if !contains(quorum, share.ID) {
		return nil, nil, fmt.Errorf("committee: member %d is not in the quorum it is dealing for", share.ID)
	}
	lambda, err := lagrangeAt(quorum, share.ID)
	if err != nil {
		return nil, nil, err
	}

	// The constant term is this member's contribution to the secret; the rest
	// is fresh randomness, which is what makes the new shares independent of
	// the old ones.
	sec := &ReshareSecret{From: share.ID, coeffs: make([]*edwards25519.Scalar, threshold)}
	sec.coeffs[0] = edwards25519.NewScalar().Multiply(lambda, share.secret)
	for i := 1; i < threshold; i++ {
		c, err := randomScalar(r)
		if err != nil {
			return nil, nil, err
		}
		sec.coeffs[i] = c
	}
	deal := &ReshareDeal{From: share.ID, Commitments: make([][]byte, threshold)}
	for i, c := range sec.coeffs {
		deal.Commitments[i] = new(edwards25519.Point).ScalarBaseMult(c).Bytes()
	}
	return sec, deal, nil
}

// Evaluate is the private value this dealer sends one incoming member.
func (s *ReshareSecret) Evaluate(to Identifier) ([]byte, error) {
	x, err := to.scalar()
	if err != nil {
		return nil, err
	}
	return horner(s.coeffs, x).Bytes(), nil
}

// SecretBytes and RestoreReshareSecret persist a dealer's state between rounds.
func (s *ReshareSecret) SecretBytes() [][]byte {
	out := make([][]byte, len(s.coeffs))
	for i, c := range s.coeffs {
		out[i] = c.Bytes()
	}
	return out
}

func RestoreReshareSecret(from Identifier, coeffs [][]byte) (*ReshareSecret, error) {
	s := &ReshareSecret{From: from}
	for _, b := range coeffs {
		c, err := edwards25519.NewScalar().SetCanonicalBytes(b)
		if err != nil {
			return nil, err
		}
		s.coeffs = append(s.coeffs, c)
	}
	if len(s.coeffs) < 2 {
		return nil, errors.New("committee: a reshare secret has at least two coefficients")
	}
	return s, nil
}

// VerifyReshareDeal checks one dealer's commitments against what the old group
// already says about that dealer. This is the check that stops a dealer
// reshaping the vault: its constant term is fixed by its old verification
// share, which every member of the old ceremony has.
func VerifyReshareDeal(old *Group, quorum []Identifier, deal *ReshareDeal, threshold int) error {
	if deal == nil {
		return errors.New("committee: missing reshare deal")
	}
	if len(deal.Commitments) != threshold {
		return fmt.Errorf("committee: member %d committed to %d coefficients, the new threshold is %d",
			deal.From, len(deal.Commitments), threshold)
	}
	for i, c := range deal.Commitments {
		if _, err := new(edwards25519.Point).SetBytes(c); err != nil {
			return fmt.Errorf("committee: member %d commitment %d is not a point", deal.From, i)
		}
	}
	vs, ok := old.VerificationShares[deal.From]
	if !ok {
		return fmt.Errorf("committee: member %d is not in the outgoing group", deal.From)
	}
	V, err := new(edwards25519.Point).SetBytes(vs)
	if err != nil {
		return fmt.Errorf("committee: member %d has a malformed verification share", deal.From)
	}
	lambda, err := lagrangeAt(quorum, deal.From)
	if err != nil {
		return err
	}
	want := new(edwards25519.Point).ScalarMult(lambda, V)
	got, err := new(edwards25519.Point).SetBytes(deal.Commitments[0])
	if err != nil {
		return err
	}
	if got.Equal(want) != 1 {
		return fmt.Errorf("committee: member %d is dealing a value that is not its own share", deal.From)
	}
	return nil
}

// ReshareGroup is the incoming group, computed from the deals alone — so it
// can be checked before anybody accepts a share, and by anybody.
//
// It also proves the point of the exercise: the group key it returns is the
// old one, or the deals are refused.
func ReshareGroup(old *Group, quorum []Identifier, deals map[Identifier]*ReshareDeal, members []Identifier, threshold int) (*Group, error) {
	if old == nil || len(old.GroupKey) != ed25519.PublicKeySize {
		return nil, errors.New("committee: resharing needs the outgoing group")
	}
	if err := checkSet(quorum); err != nil {
		return nil, fmt.Errorf("committee: the outgoing quorum %w", err)
	}
	if err := checkSet(members); err != nil {
		return nil, fmt.Errorf("committee: the incoming set %w", err)
	}
	if len(quorum) < old.Threshold {
		return nil, fmt.Errorf("committee: %d members are dealing, the outgoing threshold is %d", len(quorum), old.Threshold)
	}
	if len(deals) != len(quorum) {
		return nil, fmt.Errorf("committee: %d deals for a quorum of %d", len(deals), len(quorum))
	}
	for _, id := range quorum {
		deal, ok := deals[id]
		if !ok {
			return nil, fmt.Errorf("committee: no deal from member %d", id)
		}
		if deal.From != id {
			return nil, fmt.Errorf("committee: deal filed under %d claims to be %d", id, deal.From)
		}
		if err := VerifyReshareDeal(old, quorum, deal, threshold); err != nil {
			return nil, err
		}
	}

	// The new polynomial is the sum of the dealers', so its value at zero is
	// the sum of their constant terms — which must be the key the vault
	// already has.
	key := edwards25519.NewIdentityPoint()
	for _, id := range quorum {
		p, _ := new(edwards25519.Point).SetBytes(deals[id].Commitments[0])
		key.Add(key, p)
	}
	if string(key.Bytes()) != string(old.GroupKey) {
		return nil, errors.New("committee: these deals would move the group key, which is the one thing resharing must not do")
	}

	g := &Group{Threshold: threshold, GroupKey: append(ed25519.PublicKey(nil), old.GroupKey...),
		VerificationShares: map[Identifier][]byte{}}
	for _, id := range members {
		x, err := id.scalar()
		if err != nil {
			return nil, err
		}
		acc := edwards25519.NewIdentityPoint()
		for _, from := range quorum {
			p, err := commitmentAt(deals[from].Commitments, x)
			if err != nil {
				return nil, err
			}
			acc.Add(acc, p)
		}
		g.VerificationShares[id] = acc.Bytes()
	}
	return g, nil
}

// ReshareFinish is the receiving half, run by an incoming member: it checks
// every value it was sent against that dealer's commitments, sums them, and
// returns the new share and the group it belongs to.
//
// received maps a dealer to the value that dealer evaluated at self.
func ReshareFinish(old *Group, quorum []Identifier, deals map[Identifier]*ReshareDeal, members []Identifier,
	threshold int, self Identifier, received map[Identifier][]byte) (*Share, *Group, error) {
	g, err := ReshareGroup(old, quorum, deals, members, threshold)
	if err != nil {
		return nil, nil, err
	}
	if !contains(members, self) {
		return nil, nil, fmt.Errorf("committee: member %d is not in the incoming set", self)
	}
	x, err := self.scalar()
	if err != nil {
		return nil, nil, err
	}
	secret := edwards25519.NewScalar()
	for _, from := range quorum {
		v, ok := received[from]
		if !ok {
			return nil, nil, fmt.Errorf("committee: nothing received from member %d", from)
		}
		s, err := edwards25519.NewScalar().SetCanonicalBytes(v)
		if err != nil {
			return nil, nil, fmt.Errorf("committee: member %d sent a malformed value", from)
		}
		want, err := commitmentAt(deals[from].Commitments, x)
		if err != nil {
			return nil, nil, err
		}
		if new(edwards25519.Point).ScalarBaseMult(s).Equal(want) != 1 {
			return nil, nil, fmt.Errorf("committee: member %d sent a value that does not match its commitments", from)
		}
		secret.Add(secret, s)
	}
	share := &Share{ID: self, secret: secret, GroupKey: g.GroupKey}
	if string(share.VerificationShare()) != string(g.VerificationShares[self]) {
		return nil, nil, errors.New("committee: the new share does not match its public verification share")
	}
	return share, g, nil
}

// checkSet refuses a member list that is empty, has a zero identifier, or
// names anyone twice — all of which would make the Lagrange arithmetic wrong
// rather than merely fail.
func checkSet(ids []Identifier) error {
	if len(ids) == 0 {
		return errors.New("is empty")
	}
	seen := map[Identifier]bool{}
	for _, id := range ids {
		if _, err := id.scalar(); err != nil {
			return errors.New("contains identifier 0")
		}
		if seen[id] {
			return fmt.Errorf("names member %d twice", id)
		}
		seen[id] = true
	}
	return nil
}

func contains(ids []Identifier, id Identifier) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// SortIdentifiers puts a member set in a canonical order, so every participant
// hashes and Lagrange-interpolates over the same list.
func SortIdentifiers(ids []Identifier) []Identifier {
	out := append([]Identifier(nil), ids...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
