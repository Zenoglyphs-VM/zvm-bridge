package committee

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

// reshareForTest runs a whole resharing: a quorum of the old members deals to
// the new set, and every new member checks and assembles its share.
func reshareForTest(t *testing.T, old []*Share, group *Group, quorum []Identifier,
	members []Identifier, threshold int) ([]*Share, *Group) {
	t.Helper()
	byID := map[Identifier]*Share{}
	for _, s := range old {
		byID[s.ID] = s
	}
	secrets := map[Identifier]*ReshareSecret{}
	deals := map[Identifier]*ReshareDeal{}
	for _, id := range quorum {
		sec, deal, err := Reshare(rand.Reader, byID[id], quorum, members, threshold)
		if err != nil {
			t.Fatalf("dealing from %d: %v", id, err)
		}
		secrets[id], deals[id] = sec, deal
	}
	var out []*Share
	var g *Group
	for _, to := range members {
		received := map[Identifier][]byte{}
		for _, from := range quorum {
			v, err := secrets[from].Evaluate(to)
			if err != nil {
				t.Fatal(err)
			}
			received[from] = v
		}
		share, ng, err := ReshareFinish(group, quorum, deals, members, threshold, to, received)
		if err != nil {
			t.Fatalf("member %d: %v", to, err)
		}
		out, g = append(out, share), ng
	}
	return out, g
}

// The whole point: the set of holders changes, the vault does not.
func TestResharingKeepsTheGroupKey(t *testing.T) {
	old, key := dkgForTest(t, 2, 3)
	group := &Group{Threshold: 2, GroupKey: key, VerificationShares: map[Identifier][]byte{}}
	for _, s := range old {
		group.VerificationShares[s.ID] = s.VerificationShare()
	}

	// Two of the three deal to a new set of five at a threshold of three: a
	// member leaves, three arrive, and the address stays.
	members := []Identifier{1, 2, 4, 5, 6}
	fresh, ng := reshareForTest(t, old, group, []Identifier{1, 2}, members, 3)

	if string(ng.GroupKey) != string(key) {
		t.Fatal("resharing moved the group key, which is the vault's address")
	}
	if ng.Threshold != 3 || len(fresh) != 5 {
		t.Fatalf("new group is %d-of-%d", ng.Threshold, len(fresh))
	}

	// A quorum of the new set signs, and it verifies under the *old* key.
	msg := []byte("ZVMW payout")
	sig, err := sign(t, msg, fresh[:3], ng.GroupKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(key, msg, sig) {
		t.Fatal("a signature from the new committee does not verify under the vault's key")
	}
	// A different quorum of the new set, including the members who were not
	// there before, signs the same way.
	sig, err = sign(t, msg, []*Share{fresh[2], fresh[3], fresh[4]}, ng.GroupKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(key, msg, sig) {
		t.Fatal("the newly added members cannot sign for the vault")
	}
	// And the new threshold is real: two of five is not enough.
	if _, err := sign(t, msg, fresh[:2], ng.GroupKey); err == nil {
		t.Fatal("two of five signed at a threshold of three")
	}
}

// A dealer cannot use resharing to hand the vault to a key of its own: its
// constant term is pinned by the verification share the old group published.
func TestResharingRefusesADealerThatSubstitutesItsShare(t *testing.T) {
	old, key := dkgForTest(t, 2, 3)
	group := &Group{Threshold: 2, GroupKey: key, VerificationShares: map[Identifier][]byte{}}
	for _, s := range old {
		group.VerificationShares[s.ID] = s.VerificationShare()
	}
	quorum := []Identifier{1, 2}
	members := []Identifier{1, 2, 3}

	deals := map[Identifier]*ReshareDeal{}
	for _, id := range quorum {
		var share *Share
		for _, s := range old {
			if s.ID == id {
				share = s
			}
		}
		_, deal, err := Reshare(rand.Reader, share, quorum, members, 2)
		if err != nil {
			t.Fatal(err)
		}
		deals[id] = deal
	}
	// Member 2 deals somebody else's secret instead of its own.
	rogue, _, err := dkgRogueShare(t)
	if err != nil {
		t.Fatal(err)
	}
	_, badDeal, err := Reshare(rand.Reader, rogue, []Identifier{rogue.ID}, members, 2)
	if err != nil {
		t.Fatal(err)
	}
	badDeal.From = 2
	deals[2] = badDeal

	if err := VerifyReshareDeal(group, quorum, deals[2], 2); err == nil {
		t.Fatal("a dealer substituted its share and was not caught")
	} else if !strings.Contains(err.Error(), "not its own share") {
		t.Fatalf("the error should name the cause: %v", err)
	}
	if _, err := ReshareGroup(group, quorum, deals, members, 2); err == nil {
		t.Fatal("the group accepted a substituted deal")
	}
}

// And a dealer cannot send one member a value that disagrees with what it told
// everyone else.
func TestResharingRefusesAValueThatDoesNotMatchItsCommitments(t *testing.T) {
	old, key := dkgForTest(t, 2, 3)
	group := &Group{Threshold: 2, GroupKey: key, VerificationShares: map[Identifier][]byte{}}
	for _, s := range old {
		group.VerificationShares[s.ID] = s.VerificationShare()
	}
	quorum := []Identifier{1, 2}
	members := []Identifier{1, 2, 3}
	byID := map[Identifier]*Share{}
	for _, s := range old {
		byID[s.ID] = s
	}
	secrets := map[Identifier]*ReshareSecret{}
	deals := map[Identifier]*ReshareDeal{}
	for _, id := range quorum {
		sec, deal, err := Reshare(rand.Reader, byID[id], quorum, members, 2)
		if err != nil {
			t.Fatal(err)
		}
		secrets[id], deals[id] = sec, deal
	}
	received := map[Identifier][]byte{}
	for _, from := range quorum {
		v, err := secrets[from].Evaluate(3)
		if err != nil {
			t.Fatal(err)
		}
		received[from] = v
	}
	// Flip a byte of what member 1 sent.
	received[1][0] ^= 1
	if _, _, err := ReshareFinish(group, quorum, deals, members, 2, 3, received); err == nil {
		t.Fatal("a value that does not match the dealer's commitments was accepted")
	}
}

func TestResharingRefusesAMalformedSet(t *testing.T) {
	old, key := dkgForTest(t, 2, 3)
	group := &Group{Threshold: 2, GroupKey: key, VerificationShares: map[Identifier][]byte{}}
	for _, s := range old {
		group.VerificationShares[s.ID] = s.VerificationShare()
	}
	for _, c := range []struct {
		name    string
		quorum  []Identifier
		members []Identifier
		want    string
	}{
		{"a member named twice", []Identifier{1, 1}, []Identifier{1, 2, 3}, "twice"},
		{"identifier zero", []Identifier{1, 2}, []Identifier{0, 2, 3}, "identifier 0"},
		{"an empty incoming set", []Identifier{1, 2}, nil, "incoming members"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := Reshare(rand.Reader, old[0], c.quorum, c.members, 2)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error should name %q: %v", c.want, err)
			}
		})
	}
}

// dkgRogueShare is a share from an unrelated ceremony, for the substitution test.
func dkgRogueShare(t *testing.T) (*Share, ed25519.PublicKey, error) {
	t.Helper()
	shares, key := dkgForTest(t, 2, 2)
	return shares[0], key, nil
}
