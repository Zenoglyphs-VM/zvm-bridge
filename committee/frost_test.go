package committee

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 9591 Appendix E.1, FROST(Ed25519, SHA-512), participants 1 and 3 of 3.
func TestRFC9591Vector(t *testing.T) {
	groupKey := ed25519.PublicKey(unhex(t, "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673"))
	msg := unhex(t, "74657374")
	p1, err := NewShare(1, unhex(t, "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509"), groupKey)
	if err != nil {
		t.Fatal(err)
	}
	p3, err := NewShare(3, unhex(t, "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02"), groupKey)
	if err != nil {
		t.Fatal(err)
	}
	n1, c1, err := p1.commit(bytes.NewReader(append(
		unhex(t, "0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec"),
		unhex(t, "69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501")...)))
	if err != nil {
		t.Fatal(err)
	}
	n3, c3, err := p3.commit(bytes.NewReader(append(
		unhex(t, "86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f"),
		unhex(t, "13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775")...)))
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]byte{
		"P1 hiding": c1.Hiding, "P1 binding": c1.Binding, "P3 hiding": c3.Hiding, "P3 binding": c3.Binding,
	} {
		want := map[string]string{
			"P1 hiding":  "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3",
			"P1 binding": "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932",
			"P3 hiding":  "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91",
			"P3 binding": "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552",
		}[name]
		if hex.EncodeToString(got) != want {
			t.Fatalf("%s commitment = %x, want %s", name, got, want)
		}
	}
	coms := []*Commitment{c1, c3}
	s1, err := p1.Sign(msg, n1, coms)
	if err != nil {
		t.Fatal(err)
	}
	s3, err := p3.Sign(msg, n3, coms)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(s1.Z) != "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603" {
		t.Fatalf("P1 sig share = %x", s1.Z)
	}
	if hex.EncodeToString(s3.Z) != "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007" {
		t.Fatalf("P3 sig share = %x", s3.Z)
	}
	sig, err := Aggregate(msg, groupKey, coms, []*SignatureShare{s1, s3}, map[Identifier][]byte{
		1: p1.VerificationShare(), 3: p3.VerificationShare(),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbebd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b"
	if hex.EncodeToString(sig) != want {
		t.Fatalf("signature = %x", sig)
	}
}

func TestNoncesAreSingleUse(t *testing.T) {
	shares, groupKey := dkgForTest(t, 2, 3)
	msg := []byte("block hash")
	n1, c1, _ := shares[0].Commit()
	_, c2, _ := shares[1].Commit()
	if _, err := shares[0].Sign(msg, n1, []*Commitment{c1, c2}); err != nil {
		t.Fatal(err)
	}
	if _, err := shares[0].Sign(msg, n1, []*Commitment{c1, c2}); err == nil {
		t.Fatal("signed twice with one nonce pair")
	}
	_ = groupKey
}

func TestBadShareIsAttributed(t *testing.T) {
	shares, groupKey := dkgForTest(t, 2, 3)
	msg := []byte("block hash")
	n1, c1, _ := shares[0].Commit()
	n2, c2, _ := shares[1].Commit()
	coms := []*Commitment{c1, c2}
	s1, _ := shares[0].Sign(msg, n1, coms)
	s2, _ := shares[1].Sign(msg, n2, coms)
	s2.Z[0] ^= 1
	vs := map[Identifier][]byte{1: shares[0].VerificationShare(), 2: shares[1].VerificationShare()}
	_, err := Aggregate(msg, groupKey, coms, []*SignatureShare{s1, s2}, vs)
	if err == nil || !strings.Contains(err.Error(), "signer 2") {
		t.Fatalf("want signer 2 named, got %v", err)
	}
}

func TestPayoutTiersHoldLargeWithdrawalsLonger(t *testing.T) {
	p := &Policy{PayoutDepth: 30, Tiers: []Tier{
		{Token: znn.ZNN, Amount: 1_000 * 100_000_000, Depth: 90},
		{Token: znn.QSR, Amount: 100_000 * 100_000_000, Depth: 90},
	}}
	cases := []struct {
		zts    znn.TokenStandard
		amount uint64
		want   uint64
	}{
		{znn.ZNN, 1 * 100_000_000, 30},
		{znn.ZNN, 999 * 100_000_000, 30},
		{znn.ZNN, 1_000 * 100_000_000, 90},
		{znn.ZNN, 5_000 * 100_000_000, 90},
		{znn.QSR, 1_000 * 100_000_000, 30},   // under the QSR threshold
		{znn.QSR, 100_000 * 100_000_000, 90}, // at it
	}
	for _, c := range cases {
		if got := p.depthFor(c.zts, c.amount); got != c.want {
			t.Errorf("%d of %s: depth %d, want %d", c.amount, c.zts, got, c.want)
		}
	}
}
