package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Zenoglyphs-VM/zvm-bridge/committee"
)

// `zvm committee reshare` — change who holds the vault without changing the
// vault (DECISIONS.md D15, docs/COMMITTEE.md).
//
// It is shaped like the ceremony, and for the same reasons: a public plan
// everyone checks, a public package per dealer, a private value per recipient,
// and a result each participant computes for themselves rather than being
// handed. The differences are that the group key already exists — so every
// step checks that it has not moved — and that an incoming member may be new,
// so it publishes an encryption key before anyone deals to it.
//
//	reshare plan    write the parameters (any courier)
//	reshare keys    an incoming member publishes an encryption key
//	reshare deal    an outgoing member deals its own share to the new set
//	reshare finish  an incoming member checks everything and writes its share
func committeeReshare(args []string) error {
	subs := map[string]func([]string) error{
		"plan":   reshareplan,
		"keys":   reshareKeys,
		"deal":   reshareDeal,
		"finish": reshareFinish,
	}
	if len(args) == 0 || subs[args[0]] == nil {
		fmt.Fprintln(os.Stderr, `usage: zvm committee reshare <step> [flags]

  plan     write the reshare parameters against the group being preserved
  keys     incoming member: publish an encryption key to receive values at
  deal     outgoing member: deal your own share to the incoming set
  finish   incoming member: check every deal and write your new share

The group key does not move, so the vault's address does not either. The
outgoing shares keep working until their holders destroy them: that is the
window the procedure in docs/COMMITTEE.md tells you to keep short.`)
		return errors.New("missing or unknown step")
	}
	return subs[args[0]](args[1:])
}

func parseIDs(s string) ([]committee.Identifier, error) {
	var out []committee.Identifier
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("%q is not an identifier", part)
		}
		out = append(out, committee.Identifier(n))
	}
	return out, nil
}

func reshareplan(args []string) error {
	fs := flag.NewFlagSet("committee reshare plan", flag.ExitOnError)
	groupPath := fs.String("group", "group.json", "the group file of the committee being reshared")
	quorum := fs.String("quorum", "", "identifiers of the outgoing members who will deal, e.g. 1,2")
	threshold := fs.Int("threshold", 0, "the incoming threshold")
	members := fs.String("members", "", "names of the incoming members, in identifier order")
	out := fs.String("out", "reshare.json", "where to write the plan")
	fs.Parse(args)

	g, err := committee.LoadGroup(*groupPath)
	if err != nil {
		return err
	}
	ids, err := parseIDs(*quorum)
	if err != nil {
		return fmt.Errorf("-quorum: %w", err)
	}
	if len(ids) < g.Threshold {
		return fmt.Errorf("-quorum names %d members; the outgoing threshold is %d", len(ids), g.Threshold)
	}
	var names []string
	for _, n := range strings.Split(*members, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	p, err := committee.NewResharePlan(g, ids, *threshold, names)
	if err != nil {
		return err
	}
	if err := committee.WriteJSON(*out, p); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", *out)
	fmt.Printf("  vault      %s (unchanged — that is the point)\n", p.Address)
	fmt.Printf("  dealing    %v, the outgoing threshold is %d\n", p.Quorum, g.Threshold)
	fmt.Printf("  incoming   %d members at a threshold of %d\n", len(p.Members), p.Threshold)
	fmt.Println("\nEvery incoming member now runs `reshare keys`; then every dealer runs `reshare deal`.")
	return nil
}

func reshareKeys(args []string) error {
	fs := flag.NewFlagSet("committee reshare keys", flag.ExitOnError)
	planPath := fs.String("plan", "reshare.json", "the reshare plan")
	id := fs.Uint("id", 0, "your identifier in the incoming set")
	passPath := fs.String("passphrase-file", "", "file holding the passphrase that seals your secret (or ZVM_COMMITTEE_PASSPHRASE)")
	outDir := fs.String("out", "reshare-keys", "directory to write <id>.reshare-key.json into")
	secretPath := fs.String("secret", "", "where to write your sealed box secret (default <id>.reshare-secret)")
	fs.Parse(args)

	var p committee.ResharePlan
	if err := readJSONFile(*planPath, &p); err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	self := committee.Identifier(*id)
	if !containsID(p.MemberIDs(), self) {
		return fmt.Errorf("identifier %d is not in this plan's incoming set", self)
	}
	pass, err := committee.ReadPassphrase(*passPath)
	if err != nil {
		return err
	}
	pub, sec, err := committee.NewBoxKey(rand.Reader)
	if err != nil {
		return err
	}
	if *secretPath == "" {
		*secretPath = fmt.Sprintf("%d.reshare-secret", self)
	}
	if err := committee.WriteSealed(*secretPath, pass, &committee.ReshareSecretFile{
		ReshareID: p.ID, ID: self, BoxSecret: sec[:],
	}); err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		return err
	}
	out := filepath.Join(*outDir, fmt.Sprintf("%d.reshare-key.json", self))
	if err := committee.WriteJSON(out, &committee.ReshareKeyFile{ReshareID: p.ID, ID: self, BoxKey: pub[:]}); err != nil {
		return err
	}
	fmt.Printf("wrote %s (public) and %s (sealed)\n", out, *secretPath)
	fmt.Println("Send the public one to every dealer.")
	return nil
}

func reshareDeal(args []string) error {
	fs := flag.NewFlagSet("committee reshare deal", flag.ExitOnError)
	planPath := fs.String("plan", "reshare.json", "the reshare plan")
	id := fs.Uint("id", 0, "your identifier in the outgoing committee")
	sharePath := fs.String("share", "", "your sealed share (default <id>.share)")
	passPath := fs.String("passphrase-file", "", "file holding your share's passphrase (or ZVM_COMMITTEE_PASSPHRASE)")
	keysDir := fs.String("keys", "reshare-keys", "directory of incoming members' <id>.reshare-key.json")
	dealDir := fs.String("out", "reshare-deals", "directory to write your <id>.reshare-deal.json into")
	valueDir := fs.String("values", "reshare-values", "directory to write <from>-to-<to>.reshare.json into")
	fs.Parse(args)

	var p committee.ResharePlan
	if err := readJSONFile(*planPath, &p); err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	self := committee.Identifier(*id)
	if !containsID(p.Quorum, self) {
		return fmt.Errorf("identifier %d is not in this plan's dealing quorum %v", self, p.Quorum)
	}
	if *sharePath == "" {
		*sharePath = fmt.Sprintf("%d.share", self)
	}
	pass, err := committee.ReadPassphrase(*passPath)
	if err != nil {
		return err
	}
	var sf committee.ShareFile
	if err := committee.ReadSealed(*sharePath, pass, &sf); err != nil {
		return err
	}
	if sf.ID != self {
		return fmt.Errorf("%s holds participant %d's share, not %d's", *sharePath, sf.ID, self)
	}
	if string(sf.GroupKey) != string(p.GroupKey) {
		return errors.New("your share belongs to another committee than this plan names")
	}
	share, err := committee.NewShare(sf.ID, sf.Secret, sf.GroupKey)
	if err != nil {
		return err
	}

	members := p.MemberIDs()
	sec, deal, err := committee.Reshare(rand.Reader, share, p.Quorum, members, p.Threshold)
	if err != nil {
		return err
	}
	for _, d := range []string{*dealDir, *valueDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	dealOut := filepath.Join(*dealDir, fmt.Sprintf("%d.reshare-deal.json", self))
	if err := committee.WriteJSON(dealOut, &committee.ReshareDealFile{ReshareID: p.ID, ReshareDeal: *deal}); err != nil {
		return err
	}
	fmt.Printf("wrote %s (public)\n", dealOut)

	binding := p.Binding()
	// A dealer needs no long-term key: it makes one ephemeral pair for this
	// resharing and publishes the public half beside each sealed value, so a
	// member who was not in the original ceremony can still open what it is
	// sent.
	boxPub, boxSec, err := committee.NewBoxKey(rand.Reader)
	if err != nil {
		return err
	}
	for _, to := range members {
		var kf committee.ReshareKeyFile
		keyPath := filepath.Join(*keysDir, fmt.Sprintf("%d.reshare-key.json", to))
		if err := readJSONFile(keyPath, &kf); err != nil {
			return fmt.Errorf("the encryption key for member %d: %w", to, err)
		}
		if kf.ReshareID != p.ID || kf.ID != to || len(kf.BoxKey) != 32 {
			return fmt.Errorf("%s is mislabelled or has no key", keyPath)
		}
		v, err := sec.Evaluate(to)
		if err != nil {
			return err
		}
		var recipient [32]byte
		copy(recipient[:], kf.BoxKey)
		f, err := committee.SealValue(binding, self, to, v, &recipient, boxSec)
		if err != nil {
			return err
		}
		// The recipient needs this dealer's ephemeral public key to open it.
		out := filepath.Join(*valueDir, fmt.Sprintf("%d-to-%d.reshare.json", self, to))
		if err := committee.WriteJSON(out, &reshareValue{Round2File: *f, SenderKey: boxPub[:]}); err != nil {
			return err
		}
		fmt.Printf("wrote %s (encrypted to member %d)\n", out, to)
	}
	return nil
}

// reshareValue is a sealed value plus the ephemeral key it was sealed with, so
// a newcomer can open it without having been in the original ceremony.
type reshareValue struct {
	committee.Round2File
	SenderKey []byte `json:"senderKey"`
}

func reshareFinish(args []string) error {
	fs := flag.NewFlagSet("committee reshare finish", flag.ExitOnError)
	planPath := fs.String("plan", "reshare.json", "the reshare plan")
	oldGroupPath := fs.String("old-group", "group.json", "the outgoing committee's group file")
	id := fs.Uint("id", 0, "your identifier in the incoming set")
	passPath := fs.String("passphrase-file", "", "file holding your passphrase (or ZVM_COMMITTEE_PASSPHRASE)")
	secretPath := fs.String("secret", "", "your sealed box secret from `reshare keys` (default <id>.reshare-secret)")
	dealDir := fs.String("deals", "reshare-deals", "directory of <from>.reshare-deal.json")
	valueDir := fs.String("values", "reshare-values", "directory of <from>-to-<you>.reshare.json")
	sharePath := fs.String("share", "", "where to write your new sealed share (default <id>.share.new)")
	groupPath := fs.String("group", "", "where to write the new group file (default group-<id>.new.json)")
	fs.Parse(args)

	var p committee.ResharePlan
	if err := readJSONFile(*planPath, &p); err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	old, err := committee.LoadGroup(*oldGroupPath)
	if err != nil {
		return err
	}
	if string(old.GroupKey) != string(p.GroupKey) {
		return errors.New("the group file and the plan name different committees")
	}
	self := committee.Identifier(*id)
	if !containsID(p.MemberIDs(), self) {
		return fmt.Errorf("identifier %d is not in this plan's incoming set", self)
	}
	pass, err := committee.ReadPassphrase(*passPath)
	if err != nil {
		return err
	}
	if *secretPath == "" {
		*secretPath = fmt.Sprintf("%d.reshare-secret", self)
	}
	var sf committee.ReshareSecretFile
	if err := committee.ReadSealed(*secretPath, pass, &sf); err != nil {
		return err
	}
	boxSec, err := committee.BoxKeyFrom(sf.BoxSecret)
	if err != nil {
		return err
	}

	binding := p.Binding()
	deals := map[committee.Identifier]*committee.ReshareDeal{}
	received := map[committee.Identifier][]byte{}
	for _, from := range p.Quorum {
		var df committee.ReshareDealFile
		if err := readJSONFile(filepath.Join(*dealDir, fmt.Sprintf("%d.reshare-deal.json", from)), &df); err != nil {
			return fmt.Errorf("the deal from member %d: %w", from, err)
		}
		if df.ReshareID != p.ID || df.From != from {
			return fmt.Errorf("the deal filed under %d is mislabelled", from)
		}
		d := df.ReshareDeal
		deals[from] = &d

		var vf reshareValue
		vp := filepath.Join(*valueDir, fmt.Sprintf("%d-to-%d.reshare.json", from, self))
		if err := readJSONFile(vp, &vf); err != nil {
			return fmt.Errorf("the value from member %d: %w", from, err)
		}
		if vf.CeremonyID != p.ID || vf.From != from || vf.To != self || len(vf.SenderKey) != 32 {
			return fmt.Errorf("%s is mislabelled", vp)
		}
		var sender [32]byte
		copy(sender[:], vf.SenderKey)
		v, err := committee.OpenValue(binding, &vf.Round2File, &sender, boxSec)
		if err != nil {
			return err
		}
		received[from] = v
	}

	share, group, err := committee.ReshareFinish(
		&committee.Group{Threshold: old.Threshold, GroupKey: old.GroupKey, VerificationShares: old.VerificationShares},
		p.Quorum, deals, p.MemberIDs(), p.Threshold, self, received)
	if err != nil {
		return err
	}
	gf := committee.GroupFileFrom(&p, group)
	if err := gf.Validate(); err != nil {
		return err
	}
	if gf.Address != p.Address {
		return fmt.Errorf("the reshared committee is %s, not %s: stop and destroy nothing", gf.Address, p.Address)
	}
	if *sharePath == "" {
		*sharePath = fmt.Sprintf("%d.share.new", self)
	}
	if *groupPath == "" {
		*groupPath = fmt.Sprintf("group-%d.new.json", self)
	}
	if err := committee.WriteSealed(*sharePath, pass, &committee.ShareFile{
		Group: *group, ID: self, Secret: share.SecretBytes(),
	}); err != nil {
		return err
	}
	if err := committee.WriteJSON(*groupPath, gf); err != nil {
		return err
	}
	fmt.Printf("wrote %s (sealed) and %s\n", *sharePath, *groupPath)
	fmt.Printf("  vault      %s — unchanged\n", gf.Address)
	fmt.Printf("  committee  %d of %d\n", gf.Threshold, len(gf.Participants))
	fmt.Println("\nCompare this group file with every other member's before anyone destroys an old share.")
	return nil
}

func containsID(ids []committee.Identifier, id committee.Identifier) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}
