package committee

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"sort"

	"filippo.io/edwards25519"
)

// Distributed key generation: the FROST paper's KeyGen (Komlo & Goldberg 2020,
// Figure 1) — Pedersen's DKG with a Schnorr proof of knowledge of each
// participant's constant term — which is also what Zcash Foundation's
// frost-core implements as dkg::part1/part2/part3. No machine ever holds the
// group secret: it is the sum of every participant's constant term, and each
// of those stays with its author.
//
// Round 1  every participant publishes commitments to a random degree-(t-1)
//          polynomial and a proof that they know its constant term.
// Round 2  every participant sends each other participant, privately, their
//          polynomial evaluated at the recipient's identifier.
// Finish   each participant checks what they received against the sender's
//          commitments and sums it into their share.
//
// The proof binds the ceremony id, so a round-1 package cannot be replayed
// into another ceremony, and the proof is what stops a participant choosing
// their constant term after seeing everyone else's (a rogue-key attack).

// DKGSecret is a participant's round-1 secret: their polynomial.
type DKGSecret struct {
	ID     Identifier
	coeffs []*edwards25519.Scalar
}

// Round1 is a participant's public round-1 package.
type Round1 struct {
	ID          Identifier `json:"id"`
	Commitments [][]byte   `json:"commitments"`
	ProofR      []byte     `json:"proofR"`
	ProofZ      []byte     `json:"proofZ"`
}

func DKGRound1(r io.Reader, ceremonyID []byte, id Identifier, threshold int) (*DKGSecret, *Round1, error) {
	if threshold < 2 {
		return nil, nil, errors.New("committee: a threshold below 2 is one key, not a committee")
	}
	if _, err := id.scalar(); err != nil {
		return nil, nil, err
	}
	sec := &DKGSecret{ID: id, coeffs: make([]*edwards25519.Scalar, threshold)}
	pkg := &Round1{ID: id, Commitments: make([][]byte, threshold)}
	for i := range sec.coeffs {
		c, err := randomScalar(r)
		if err != nil {
			return nil, nil, err
		}
		sec.coeffs[i] = c
		pkg.Commitments[i] = new(edwards25519.Point).ScalarBaseMult(c).Bytes()
	}
	k, err := randomScalar(r)
	if err != nil {
		return nil, nil, err
	}
	R := new(edwards25519.Point).ScalarBaseMult(k)
	c, err := dkgChallenge(ceremonyID, id, pkg.Commitments[0], R.Bytes())
	if err != nil {
		return nil, nil, err
	}
	z := edwards25519.NewScalar().Multiply(sec.coeffs[0], c)
	z.Add(z, k)
	pkg.ProofR, pkg.ProofZ = R.Bytes(), z.Bytes()
	return sec, pkg, nil
}

func dkgChallenge(ceremonyID []byte, id Identifier, constant, R []byte) (*edwards25519.Scalar, error) {
	x, err := id.scalar()
	if err != nil {
		return nil, err
	}
	m := append(append([]byte{}, ceremonyID...), x.Bytes()...)
	m = append(m, constant...)
	m = append(m, R...)
	return reduce(hashWithContext("dkg", m)), nil
}

// VerifyRound1 checks a package's shape and its proof of knowledge.
func VerifyRound1(ceremonyID []byte, pkg *Round1, threshold int) error {
	if pkg == nil {
		return errors.New("committee: missing round-1 package")
	}
	if len(pkg.Commitments) != threshold {
		return fmt.Errorf("committee: participant %d committed to %d coefficients, the threshold is %d", pkg.ID, len(pkg.Commitments), threshold)
	}
	for i, c := range pkg.Commitments {
		if _, err := new(edwards25519.Point).SetBytes(c); err != nil {
			return fmt.Errorf("committee: participant %d commitment %d is not a point", pkg.ID, i)
		}
	}
	R, err := new(edwards25519.Point).SetBytes(pkg.ProofR)
	if err != nil {
		return fmt.Errorf("committee: participant %d proof is malformed", pkg.ID)
	}
	z, err := edwards25519.NewScalar().SetCanonicalBytes(pkg.ProofZ)
	if err != nil {
		return fmt.Errorf("committee: participant %d proof is malformed", pkg.ID)
	}
	c, err := dkgChallenge(ceremonyID, pkg.ID, pkg.Commitments[0], pkg.ProofR)
	if err != nil {
		return err
	}
	phi0, _ := new(edwards25519.Point).SetBytes(pkg.Commitments[0])
	// R == z·B − c·φ0
	rhs := new(edwards25519.Point).ScalarBaseMult(z)
	rhs.Subtract(rhs, new(edwards25519.Point).ScalarMult(c, phi0))
	if rhs.Equal(R) != 1 {
		return fmt.Errorf("committee: participant %d's proof of knowledge does not verify", pkg.ID)
	}
	return nil
}

// Evaluate is the private value this participant sends to another in round 2.
func (s *DKGSecret) Evaluate(to Identifier) ([]byte, error) {
	x, err := to.scalar()
	if err != nil {
		return nil, err
	}
	return horner(s.coeffs, x).Bytes(), nil
}

func horner(coeffs []*edwards25519.Scalar, x *edwards25519.Scalar) *edwards25519.Scalar {
	y := edwards25519.NewScalar().Set(coeffs[len(coeffs)-1])
	for k := len(coeffs) - 2; k >= 0; k-- {
		y.Multiply(y, x)
		y.Add(y, coeffs[k])
	}
	return y
}

// commitmentAt is Σ_k φ_k·x^k: the public image of a polynomial's value at x.
func commitmentAt(commitments [][]byte, x *edwards25519.Scalar) (*edwards25519.Point, error) {
	acc := edwards25519.NewIdentityPoint()
	pow := one()
	for i, c := range commitments {
		P, err := new(edwards25519.Point).SetBytes(c)
		if err != nil {
			return nil, fmt.Errorf("committee: commitment %d is not a point", i)
		}
		acc.Add(acc, new(edwards25519.Point).ScalarMult(pow, P))
		pow = edwards25519.NewScalar().Multiply(pow, x)
	}
	return acc, nil
}

// Group is the public result of a ceremony, identical for every participant.
type Group struct {
	Threshold          int
	GroupKey           ed25519.PublicKey
	VerificationShares map[Identifier][]byte
}

// PublicGroup computes the group key and every verification share from the
// round-1 packages alone.
func PublicGroup(round1 map[Identifier]*Round1, threshold int) (*Group, error) {
	if len(round1) < threshold {
		return nil, fmt.Errorf("committee: %d participants for a threshold of %d", len(round1), threshold)
	}
	g := &Group{Threshold: threshold, VerificationShares: map[Identifier][]byte{}}
	key := edwards25519.NewIdentityPoint()
	for _, pkg := range round1 {
		phi0, err := new(edwards25519.Point).SetBytes(pkg.Commitments[0])
		if err != nil {
			return nil, err
		}
		key.Add(key, phi0)
	}
	if key.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, errors.New("committee: the group key is the identity")
	}
	g.GroupKey = key.Bytes()
	for id := range round1 {
		x, err := id.scalar()
		if err != nil {
			return nil, err
		}
		acc := edwards25519.NewIdentityPoint()
		for _, pkg := range round1 {
			p, err := commitmentAt(pkg.Commitments, x)
			if err != nil {
				return nil, err
			}
			acc.Add(acc, p)
		}
		g.VerificationShares[id] = acc.Bytes()
	}
	return g, nil
}

// DKGFinish checks every value received against its sender's commitments and
// sums them, with this participant's own, into a signing share.
// received maps sender to the value that sender evaluated at self.ID.
func DKGFinish(ceremonyID []byte, self *DKGSecret, round1 map[Identifier]*Round1, received map[Identifier][]byte) (*Share, *Group, error) {
	threshold := len(self.coeffs)
	if _, ok := round1[self.ID]; !ok {
		return nil, nil, errors.New("committee: this participant's own round-1 package is missing")
	}
	ids := make([]Identifier, 0, len(round1))
	for id, pkg := range round1 {
		if id != pkg.ID {
			return nil, nil, fmt.Errorf("committee: package filed under %d claims to be %d", id, pkg.ID)
		}
		if err := VerifyRound1(ceremonyID, pkg, threshold); err != nil {
			return nil, nil, err
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	x, _ := self.ID.scalar()
	secret := horner(self.coeffs, x)
	for _, from := range ids {
		if from == self.ID {
			continue
		}
		v, ok := received[from]
		if !ok {
			return nil, nil, fmt.Errorf("committee: nothing received from participant %d", from)
		}
		s, err := edwards25519.NewScalar().SetCanonicalBytes(v)
		if err != nil {
			return nil, nil, fmt.Errorf("committee: participant %d sent a malformed value", from)
		}
		want, err := commitmentAt(round1[from].Commitments, x)
		if err != nil {
			return nil, nil, err
		}
		if new(edwards25519.Point).ScalarBaseMult(s).Equal(want) != 1 {
			return nil, nil, fmt.Errorf("committee: participant %d sent a value that does not match their commitments", from)
		}
		secret.Add(secret, s)
	}
	g, err := PublicGroup(round1, threshold)
	if err != nil {
		return nil, nil, err
	}
	share := &Share{ID: self.ID, secret: secret, GroupKey: g.GroupKey}
	if string(share.VerificationShare()) != string(g.VerificationShares[self.ID]) {
		return nil, nil, errors.New("committee: this share does not match the public verification share")
	}
	return share, g, nil
}

// SecretBytes and RestoreDKGSecret persist round-1 state between rounds.
func (s *DKGSecret) SecretBytes() [][]byte {
	out := make([][]byte, len(s.coeffs))
	for i, c := range s.coeffs {
		out[i] = c.Bytes()
	}
	return out
}

func RestoreDKGSecret(id Identifier, coeffs [][]byte) (*DKGSecret, error) {
	s := &DKGSecret{ID: id}
	for _, b := range coeffs {
		c, err := edwards25519.NewScalar().SetCanonicalBytes(b)
		if err != nil {
			return nil, err
		}
		s.coeffs = append(s.coeffs, c)
	}
	if len(s.coeffs) < 2 {
		return nil, errors.New("committee: round-1 state has no polynomial")
	}
	return s, nil
}

// SecretBytes exports the share's scalar for encrypted storage.
func (s *Share) SecretBytes() []byte { return s.secret.Bytes() }
