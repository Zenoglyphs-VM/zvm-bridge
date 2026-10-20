package committee

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func dkgForTest(t *testing.T, threshold, n int) ([]*Share, ed25519.PublicKey) {
	t.Helper()
	cid := []byte("test ceremony")
	secrets := map[Identifier]*DKGSecret{}
	round1 := map[Identifier]*Round1{}
	for i := 1; i <= n; i++ {
		s, p, err := DKGRound1(rand.Reader, cid, Identifier(i), threshold)
		if err != nil {
			t.Fatal(err)
		}
		secrets[s.ID], round1[p.ID] = s, p
	}
	var shares []*Share
	var key ed25519.PublicKey
	for i := 1; i <= n; i++ {
		self := Identifier(i)
		received := map[Identifier][]byte{}
		for from, s := range secrets {
			if from != self {
				v, _ := s.Evaluate(self)
				received[from] = v
			}
		}
		sh, g, err := DKGFinish(cid, secrets[self], round1, received)
		if err != nil {
			t.Fatal(err)
		}
		if key != nil && string(key) != string(g.GroupKey) {
			t.Fatal("participants disagree on the group key")
		}
		key = g.GroupKey
		shares = append(shares, sh)
	}
	return shares, key
}

func sign(t *testing.T, msg []byte, signers []*Share, key ed25519.PublicKey) ([]byte, error) {
	t.Helper()
	nonces := make([]*Nonces, len(signers))
	coms := make([]*Commitment, len(signers))
	for i, s := range signers {
		nonces[i], coms[i], _ = s.Commit()
	}
	shares := make([]*SignatureShare, len(signers))
	for i, s := range signers {
		z, err := s.Sign(msg, nonces[i], coms)
		if err != nil {
			return nil, err
		}
		shares[i] = z
	}
	return Aggregate(msg, key, coms, shares, nil)
}

func TestDKGEveryQuorumSigns(t *testing.T) {
	shares, key := dkgForTest(t, 3, 5)
	msg := []byte("an account block hash")
	quorums := [][]int{{0, 1, 2}, {0, 2, 4}, {1, 3, 4}, {0, 1, 2, 3, 4}}
	for _, q := range quorums {
		var set []*Share
		for _, i := range q {
			set = append(set, shares[i])
		}
		sig, err := sign(t, msg, set, key)
		if err != nil {
			t.Fatalf("quorum %v: %v", q, err)
		}
		if !ed25519.Verify(key, msg, sig) {
			t.Fatalf("quorum %v: stock ed25519 rejects the signature", q)
		}
	}
}

func TestDKGBelowThresholdCannotSign(t *testing.T) {
	shares, key := dkgForTest(t, 3, 5)
	if _, err := sign(t, []byte("m"), shares[:2], key); err == nil {
		t.Fatal("two of a 3-of-5 committee produced a valid signature")
	}
}

func TestDKGRejectsForgedProof(t *testing.T) {
	cid := []byte("c")
	_, p, _ := DKGRound1(rand.Reader, cid, 1, 2)
	_, other, _ := DKGRound1(rand.Reader, cid, 2, 2)
	p.Commitments[0] = other.Commitments[0] // claim someone else's constant term
	if err := VerifyRound1(cid, p, 2); err == nil {
		t.Fatal("accepted a proof for a constant term the participant does not know")
	}
	_, q, _ := DKGRound1(rand.Reader, cid, 1, 2)
	if err := VerifyRound1([]byte("another ceremony"), q, 2); err == nil {
		t.Fatal("accepted a round-1 package replayed from another ceremony")
	}
}

func TestDKGNamesACheatingDealer(t *testing.T) {
	cid := []byte("c")
	secrets := map[Identifier]*DKGSecret{}
	round1 := map[Identifier]*Round1{}
	for i := 1; i <= 3; i++ {
		s, p, _ := DKGRound1(rand.Reader, cid, Identifier(i), 2)
		secrets[s.ID], round1[p.ID] = s, p
	}
	received := map[Identifier][]byte{}
	for from, s := range secrets {
		if from != 1 {
			received[from], _ = s.Evaluate(1)
		}
	}
	received[3][0] ^= 1
	_, _, err := DKGFinish(cid, secrets[1], round1, received)
	if err == nil || !strings.Contains(err.Error(), "participant 3") {
		t.Fatalf("want participant 3 named, got %v", err)
	}
}
