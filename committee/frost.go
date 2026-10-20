// Package committee is the vault's custody: FROST(Ed25519, SHA-512) threshold
// signing per RFC 9591, the distributed key generation ceremony that creates a
// committee without any machine ever holding the whole key, and the signer and
// coordinator that let the bridge pay from a quorum.
//
// A FROST quorum's aggregate is a stock Ed25519 signature — RFC 9591's H2 is
// Ed25519's own challenge, SHA-512(R ‖ A ‖ M), with no context string — so the
// group key is an ordinary z1… address and go-zenon cannot tell it is held by
// more than one party. Measured on the go-zenon devnet 2026-09-13
// (zenon-docs/protocol/facts/threshold-signatures.md).
//
// The signing core is ported from projects/amm/frost, with one correction: RFC
// 9591 §4.4 prefixes the binding-factor input with the group public key, which
// that code omitted. Its signatures still verified, because verification never
// sees the binding factors; they were not RFC 9591 signatures. The RFC's own
// test vector (Appendix E.1) now pins this implementation.
package committee

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"sort"

	"filippo.io/edwards25519"
)

const contextString = "FROST-ED25519-SHA512-v1"

// Identifier is a participant's x-coordinate. It must be non-zero: the
// polynomial's value at zero is the group secret.
type Identifier uint16

func (id Identifier) scalar() (*edwards25519.Scalar, error) {
	if id == 0 {
		return nil, errors.New("committee: identifier 0 is the secret itself, not a participant")
	}
	var b [32]byte
	b[0] = byte(id)
	b[1] = byte(id >> 8)
	return edwards25519.NewScalar().SetCanonicalBytes(b[:])
}

// Share is one signer's long-term secret and the group key it belongs to.
type Share struct {
	ID       Identifier
	secret   *edwards25519.Scalar
	GroupKey ed25519.PublicKey
}

// NewShare rebuilds a share from its stored secret scalar.
func NewShare(id Identifier, secret []byte, groupKey ed25519.PublicKey) (*Share, error) {
	if _, err := id.scalar(); err != nil {
		return nil, err
	}
	if len(groupKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("committee: group key is %d bytes", len(groupKey))
	}
	s, err := edwards25519.NewScalar().SetCanonicalBytes(secret)
	if err != nil {
		return nil, fmt.Errorf("committee: share is not a canonical scalar: %w", err)
	}
	return &Share{ID: id, secret: s, GroupKey: append(ed25519.PublicKey(nil), groupKey...)}, nil
}

// VerificationShare is the public key of a share: secret·B.
func (s *Share) VerificationShare() []byte {
	return new(edwards25519.Point).ScalarBaseMult(s.secret).Bytes()
}

// Commitment is a signer's round-one output. Public.
type Commitment struct {
	ID      Identifier `json:"id"`
	Hiding  []byte     `json:"hiding"`
	Binding []byte     `json:"binding"`
}

// Nonces is the secret half of round one. Used once, then destroyed: two
// signatures under one nonce pair reveal the share.
type Nonces struct {
	hiding, binding *edwards25519.Scalar
}

// Commit is round one.
func (s *Share) Commit() (*Nonces, *Commitment, error) {
	return s.commit(rand.Reader)
}

func (s *Share) commit(r io.Reader) (*Nonces, *Commitment, error) {
	h, err := nonceGenerate(r, s.secret)
	if err != nil {
		return nil, nil, err
	}
	b, err := nonceGenerate(r, s.secret)
	if err != nil {
		return nil, nil, err
	}
	return &Nonces{hiding: h, binding: b}, &Commitment{
		ID:      s.ID,
		Hiding:  new(edwards25519.Point).ScalarBaseMult(h).Bytes(),
		Binding: new(edwards25519.Point).ScalarBaseMult(b).Bytes(),
	}, nil
}

// SignatureShare is a signer's round-two output.
type SignatureShare struct {
	ID Identifier `json:"id"`
	Z  []byte     `json:"z"`
}

// Sign is round two over msg, given every participating signer's commitment.
func (s *Share) Sign(msg []byte, nonces *Nonces, commitments []*Commitment) (*SignatureShare, error) {
	if nonces == nil || nonces.hiding == nil {
		return nil, errors.New("committee: nonces already used")
	}
	list, err := normalize(commitments)
	if err != nil {
		return nil, err
	}
	if indexOf(list, s.ID) < 0 {
		return nil, fmt.Errorf("committee: signer %d is not in the commitment list", s.ID)
	}
	factors, err := bindingFactors(s.GroupKey, msg, list)
	if err != nil {
		return nil, err
	}
	R, err := groupCommitment(list, factors)
	if err != nil {
		return nil, err
	}
	c := challenge(R, s.GroupKey, msg)
	lambda, err := lagrange(list, s.ID)
	if err != nil {
		return nil, err
	}
	z := edwards25519.NewScalar().Multiply(nonces.binding, factors[s.ID])
	z.Add(z, nonces.hiding)
	term := edwards25519.NewScalar().Multiply(lambda, s.secret)
	term.Multiply(term, c)
	z.Add(z, term)
	nonces.hiding, nonces.binding = nil, nil
	return &SignatureShare{ID: s.ID, Z: z.Bytes()}, nil
}

// Aggregate combines signature shares into one Ed25519 signature and verifies
// it. verificationShares, when given, lets a bad share be attributed to its
// signer (RFC 9591 §5.4) instead of failing anonymously.
func Aggregate(msg []byte, groupKey ed25519.PublicKey, commitments []*Commitment, shares []*SignatureShare, verificationShares map[Identifier][]byte) ([]byte, error) {
	list, err := normalize(commitments)
	if err != nil {
		return nil, err
	}
	if len(shares) != len(list) {
		return nil, fmt.Errorf("committee: %d commitments but %d signature shares", len(list), len(shares))
	}
	factors, err := bindingFactors(groupKey, msg, list)
	if err != nil {
		return nil, err
	}
	R, err := groupCommitment(list, factors)
	if err != nil {
		return nil, err
	}
	c := challenge(R, groupKey, msg)
	seen := map[Identifier]bool{}
	z := edwards25519.NewScalar()
	for _, sh := range shares {
		if sh == nil || indexOf(list, sh.ID) < 0 {
			return nil, errors.New("committee: a signature share is missing or from a signer that did not commit")
		}
		if seen[sh.ID] {
			return nil, fmt.Errorf("committee: signer %d sent two signature shares", sh.ID)
		}
		seen[sh.ID] = true
		zi, err := edwards25519.NewScalar().SetCanonicalBytes(sh.Z)
		if err != nil {
			return nil, fmt.Errorf("committee: signature share from %d is not a canonical scalar", sh.ID)
		}
		if vs, ok := verificationShares[sh.ID]; ok {
			if err := verifyShare(list, factors, c, sh.ID, zi, vs); err != nil {
				return nil, err
			}
		}
		z.Add(z, zi)
	}
	sig := append(append([]byte{}, R.Bytes()...), z.Bytes()...)
	if !ed25519.Verify(groupKey, msg, sig) {
		return nil, errors.New("committee: aggregate signature does not verify — a signature share is bad")
	}
	return sig, nil
}

// verifyShare checks z·B == D + ρ·E + λ·c·Y for one signer.
func verifyShare(list []*Commitment, factors map[Identifier]*edwards25519.Scalar, c *edwards25519.Scalar, id Identifier, z *edwards25519.Scalar, vs []byte) error {
	Y, err := new(edwards25519.Point).SetBytes(vs)
	if err != nil {
		return fmt.Errorf("committee: verification share of %d is not a point", id)
	}
	com := list[indexOf(list, id)]
	D, err := new(edwards25519.Point).SetBytes(com.Hiding)
	if err != nil {
		return err
	}
	E, err := new(edwards25519.Point).SetBytes(com.Binding)
	if err != nil {
		return err
	}
	lambda, err := lagrange(list, id)
	if err != nil {
		return err
	}
	rhs := new(edwards25519.Point).ScalarMult(factors[id], E)
	rhs.Add(rhs, D)
	lc := edwards25519.NewScalar().Multiply(lambda, c)
	rhs.Add(rhs, new(edwards25519.Point).ScalarMult(lc, Y))
	if new(edwards25519.Point).ScalarBaseMult(z).Equal(rhs) != 1 {
		return fmt.Errorf("committee: signer %d sent an invalid signature share", id)
	}
	return nil
}

func challenge(R *edwards25519.Point, groupKey ed25519.PublicKey, msg []byte) *edwards25519.Scalar {
	h := sha512.New()
	h.Write(R.Bytes())
	h.Write(groupKey)
	h.Write(msg)
	return reduce(h.Sum(nil))
}

// bindingFactors is RFC 9591 §4.4: ρ_i = H1(PK ‖ H4(msg) ‖ H5(commitments) ‖ i).
func bindingFactors(groupKey ed25519.PublicKey, msg []byte, list []*Commitment) (map[Identifier]*edwards25519.Scalar, error) {
	prefix := append([]byte{}, groupKey...)
	prefix = append(prefix, hashWithContext("msg", msg)...)
	prefix = append(prefix, hashWithContext("com", encodeCommitments(list))...)
	out := make(map[Identifier]*edwards25519.Scalar, len(list))
	for _, c := range list {
		x, err := c.ID.scalar()
		if err != nil {
			return nil, err
		}
		out[c.ID] = reduce(hashWithContext("rho", append(append([]byte{}, prefix...), x.Bytes()...)))
	}
	return out, nil
}

func groupCommitment(list []*Commitment, factors map[Identifier]*edwards25519.Scalar) (*edwards25519.Point, error) {
	R := edwards25519.NewIdentityPoint()
	for _, c := range list {
		D, err := new(edwards25519.Point).SetBytes(c.Hiding)
		if err != nil {
			return nil, fmt.Errorf("committee: hiding commitment from %d is not a point", c.ID)
		}
		E, err := new(edwards25519.Point).SetBytes(c.Binding)
		if err != nil {
			return nil, fmt.Errorf("committee: binding commitment from %d is not a point", c.ID)
		}
		R.Add(R, D)
		R.Add(R, new(edwards25519.Point).ScalarMult(factors[c.ID], E))
	}
	return R, nil
}

func lagrange(list []*Commitment, id Identifier) (*edwards25519.Scalar, error) {
	ids := make([]Identifier, len(list))
	for i, c := range list {
		ids[i] = c.ID
	}
	return lagrangeAt(ids, id)
}

func lagrangeAt(ids []Identifier, id Identifier) (*edwards25519.Scalar, error) {
	xi, err := id.scalar()
	if err != nil {
		return nil, err
	}
	num, den := one(), one()
	for _, other := range ids {
		if other == id {
			continue
		}
		xj, err := other.scalar()
		if err != nil {
			return nil, err
		}
		num.Multiply(num, xj)
		den.Multiply(den, edwards25519.NewScalar().Subtract(xj, xi))
	}
	return num.Multiply(num, den.Invert(den)), nil
}

func encodeCommitments(list []*Commitment) []byte {
	out := make([]byte, 0, len(list)*96)
	for _, c := range list {
		x, _ := c.ID.scalar()
		out = append(out, x.Bytes()...)
		out = append(out, c.Hiding...)
		out = append(out, c.Binding...)
	}
	return out
}

func normalize(list []*Commitment) ([]*Commitment, error) {
	if len(list) == 0 {
		return nil, errors.New("committee: no commitments")
	}
	out := append([]*Commitment(nil), list...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	for i, c := range out {
		if c == nil || c.ID == 0 {
			return nil, errors.New("committee: a commitment has no participant")
		}
		if len(c.Hiding) != 32 || len(c.Binding) != 32 {
			return nil, fmt.Errorf("committee: commitment from %d is malformed", c.ID)
		}
		if i > 0 && out[i-1].ID == c.ID {
			return nil, fmt.Errorf("committee: signer %d committed twice", c.ID)
		}
	}
	return out, nil
}

func indexOf(list []*Commitment, id Identifier) int {
	for i, c := range list {
		if c.ID == id {
			return i
		}
	}
	return -1
}

func hashWithContext(label string, b []byte) []byte {
	h := sha512.New()
	h.Write([]byte(contextString))
	h.Write([]byte(label))
	h.Write(b)
	return h.Sum(nil)
}

func reduce(wide []byte) *edwards25519.Scalar {
	s, err := edwards25519.NewScalar().SetUniformBytes(wide)
	if err != nil {
		panic("committee: " + err.Error())
	}
	return s
}

func randomScalar(r io.Reader) (*edwards25519.Scalar, error) {
	b := make([]byte, 64)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("committee: reading randomness: %w", err)
	}
	return reduce(b), nil
}

// nonceGenerate is RFC 9591 §4.1: H3(random ‖ secret), so a weak RNG alone
// does not repeat a nonce.
func nonceGenerate(r io.Reader, secret *edwards25519.Scalar) (*edwards25519.Scalar, error) {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, fmt.Errorf("committee: reading randomness: %w", err)
	}
	return reduce(hashWithContext("nonce", append(seed, secret.Bytes()...))), nil
}

func one() *edwards25519.Scalar {
	var b [32]byte
	b[0] = 1
	s, _ := edwards25519.NewScalar().SetCanonicalBytes(b[:])
	return s
}
