package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"filippo.io/edwards25519"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"

	"github.com/Zenoglyphs-VM/zvm-bridge/committee"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func init() {
	register("committee", "the vault committee's key ceremony (FROST DKG) and signer daemon; docs/COMMITTEE.md", runCommittee)
}

func runCommittee(args []string) error {
	subs := map[string]func([]string) error{
		"new":     committeeNew,
		"round1":  committeeRound1,
		"round2":  committeeRound2,
		"finish":  committeeFinish,
		"audit":   committeeAudit,
		"signer":  committeeSigner,
		"reshare": committeeReshare,
	}
	if len(args) == 0 || subs[args[0]] == nil {
		fmt.Fprintln(os.Stderr, `usage: zvm committee <step> [flags]

  new      write the ceremony parameters (any courier)
  round1   generate your polynomial and encryption key; publish <id>.round1.json
  round2   check everyone's round 1, confirm the fingerprint, send private values
  finish   check what you received, write your sealed share and group.json
  audit    recompute group.json from the public round-1 files (anyone)
  signer   serve your share to the bridge, signing only what policy allows

The full procedure is docs/COMMITTEE.md.`)
		return errors.New("missing or unknown step")
	}
	return subs[args[0]](args[1:])
}

func committeeNew(args []string) error {
	fs := flag.NewFlagSet("committee new", flag.ExitOnError)
	chain := fs.Uint64("l1-chain-id", 0, "NoM chain identifier the vault will live on (1 mainnet, 3 testnet, 69 a ZVM devnet)")
	threshold := fs.Int("threshold", 0, "signers needed to move the vault")
	names := fs.String("names", "", "comma-separated participant names, in identifier order")
	out := fs.String("out", "ceremony.json", "where to write the parameters")
	fs.Parse(args)
	c, err := committee.NewCeremony(*chain, *threshold, strings.Split(*names, ","))
	if err != nil {
		return err
	}
	if err := committee.WriteJSON(*out, c); err != nil {
		return err
	}
	fmt.Printf("ceremony %s: %d-of-%d on NoM chain %d\n", c.ID, c.Threshold, len(c.Participants), c.L1ChainID)
	for _, p := range c.Participants {
		fmt.Printf("  participant %d  %s\n", p.ID, p.Name)
	}
	fmt.Printf("wrote %s — every participant checks it before round 1\n", *out)
	return nil
}

type participantFlags struct {
	ceremony, state, passphrase *string
	id                          *uint
}

func addParticipantFlags(fs *flag.FlagSet) participantFlags {
	return participantFlags{
		ceremony:   fs.String("ceremony", "ceremony.json", "ceremony parameters"),
		id:         fs.Uint("id", 0, "your participant identifier"),
		state:      fs.String("state", "", "your sealed round-1 state (default <id>.state)"),
		passphrase: fs.String("passphrase-file", "", "file holding the passphrase that seals your state and share (or ZVM_COMMITTEE_PASSPHRASE)"),
	}
}

func (p participantFlags) load() (*committee.Ceremony, committee.Identifier, string, []byte, error) {
	c, err := committee.LoadCeremony(*p.ceremony)
	if err != nil {
		return nil, 0, "", nil, err
	}
	id := committee.Identifier(*p.id)
	if !c.Has(id) {
		return nil, 0, "", nil, fmt.Errorf("-id %d is not a participant in %s", *p.id, *p.ceremony)
	}
	state := *p.state
	if state == "" {
		state = fmt.Sprintf("%d.state", id)
	}
	pass, err := committee.ReadPassphrase(*p.passphrase)
	return c, id, state, pass, err
}

func committeeRound1(args []string) error {
	fs := flag.NewFlagSet("committee round1", flag.ExitOnError)
	pf := addParticipantFlags(fs)
	outDir := fs.String("out", ".", "directory to write <id>.round1.json into")
	fs.Parse(args)
	c, id, statePath, pass, err := pf.load()
	if err != nil {
		return err
	}
	sec, pkg, err := committee.DKGRound1(rand.Reader, c.Bound(), id, c.Threshold)
	if err != nil {
		return err
	}
	boxPub, boxSec, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := committee.WriteSealed(statePath, pass, committee.State{
		CeremonyID: c.ID, ID: id, Coeffs: sec.SecretBytes(), BoxSecret: boxSec[:],
	}); err != nil {
		return fmt.Errorf("writing %s: %w", statePath, err)
	}
	out := filepath.Join(*outDir, fmt.Sprintf("%d.round1.json", id))
	if err := committee.WriteJSON(out, committee.Round1File{CeremonyID: c.ID, Round1: *pkg, BoxKey: boxPub[:]}); err != nil {
		return err
	}
	fmt.Printf("participant %d: sealed state in %s (keep it; it is needed twice more)\n", id, statePath)
	fmt.Printf("publish %s to the other participants\n", out)
	return nil
}

func loadState(c *committee.Ceremony, id committee.Identifier, path string, pass []byte) (*committee.DKGSecret, *[32]byte, error) {
	var st committee.State
	if err := committee.ReadSealed(path, pass, &st); err != nil {
		return nil, nil, err
	}
	if st.CeremonyID != c.ID || st.ID != id {
		return nil, nil, fmt.Errorf("%s is participant %d's state for ceremony %s", path, st.ID, st.CeremonyID)
	}
	sec, err := committee.RestoreDKGSecret(id, st.Coeffs)
	if err != nil {
		return nil, nil, err
	}
	var bs [32]byte
	copy(bs[:], st.BoxSecret)
	return sec, &bs, nil
}

// loadTranscript reads round 1, checks this participant's own package is the
// one they made, and requires the fingerprint to have been compared.
func loadTranscript(c *committee.Ceremony, sec *committee.DKGSecret, boxSec *[32]byte, dir, confirm string) (map[committee.Identifier]*committee.Round1File, []byte, error) {
	round1, err := committee.LoadRound1Dir(c, dir)
	if err != nil {
		return nil, nil, err
	}
	tr, err := committee.Transcript(c, round1)
	if err != nil {
		return nil, nil, err
	}
	own := round1[sec.ID]
	coeff0, _ := edwards25519.NewScalar().SetCanonicalBytes(sec.SecretBytes()[0])
	var boxPub [32]byte
	curve25519Base(&boxPub, boxSec)
	if string(own.Commitments[0]) != string(new(edwards25519.Point).ScalarBaseMult(coeff0).Bytes()) || subtle.ConstantTimeCompare(own.BoxKey, boxPub[:]) != 1 {
		return nil, nil, fmt.Errorf("the round-1 package filed as yours (participant %d) is not the one your state made — stop the ceremony", sec.ID)
	}
	fp := committee.Fingerprint(tr)
	if confirm == "" {
		fmt.Printf("transcript fingerprint: %s\n", fp)
		fmt.Println("compare it with every other participant over a channel you trust, then re-run with -confirm " + fp)
		return nil, nil, errors.New("fingerprint not confirmed")
	}
	if confirm != fp {
		return nil, nil, fmt.Errorf("the transcript is %s, not %s — someone holds different round-1 packages; stop the ceremony", fp, confirm)
	}
	return round1, tr, nil
}

func committeeRound2(args []string) error {
	fs := flag.NewFlagSet("committee round2", flag.ExitOnError)
	pf := addParticipantFlags(fs)
	r1 := fs.String("round1", "round1", "directory holding every participant's <id>.round1.json")
	outDir := fs.String("out", "round2", "directory to write <from>-to-<to>.round2.json into")
	confirm := fs.String("confirm", "", "the transcript fingerprint, once compared out of band")
	fs.Parse(args)
	c, id, statePath, pass, err := pf.load()
	if err != nil {
		return err
	}
	sec, boxSec, err := loadState(c, id, statePath, pass)
	if err != nil {
		return err
	}
	round1, _, err := loadTranscript(c, sec, boxSec, *r1, *confirm)
	if err != nil {
		return err
	}
	ids := sortedIDs(round1)
	for _, to := range ids {
		if to == id {
			continue
		}
		v, err := sec.Evaluate(to)
		if err != nil {
			return err
		}
		var recipient [32]byte
		copy(recipient[:], round1[to].BoxKey)
		f, err := committee.SealValue(c, id, to, v, &recipient, boxSec)
		if err != nil {
			return err
		}
		out := filepath.Join(*outDir, fmt.Sprintf("%d-to-%d.round2.json", id, to))
		if err := committee.WriteJSON(out, f); err != nil {
			return err
		}
		fmt.Printf("wrote %s (encrypted to participant %d)\n", out, to)
	}
	return nil
}

func committeeFinish(args []string) error {
	fs := flag.NewFlagSet("committee finish", flag.ExitOnError)
	pf := addParticipantFlags(fs)
	r1 := fs.String("round1", "round1", "directory of round-1 files")
	r2 := fs.String("round2", "round2", "directory of round-2 files")
	confirm := fs.String("confirm", "", "the transcript fingerprint")
	sharePath := fs.String("share", "", "where to write your sealed share (default <id>.share)")
	groupPath := fs.String("group", "", "where to write the public group file (default group-<id>.json)")
	fs.Parse(args)
	c, id, statePath, pass, err := pf.load()
	if err != nil {
		return err
	}
	sec, boxSec, err := loadState(c, id, statePath, pass)
	if err != nil {
		return err
	}
	round1, tr, err := loadTranscript(c, sec, boxSec, *r1, *confirm)
	if err != nil {
		return err
	}
	received := map[committee.Identifier][]byte{}
	for _, from := range sortedIDs(round1) {
		if from == id {
			continue
		}
		var f committee.Round2File
		if err := readJSONFile(filepath.Join(*r2, fmt.Sprintf("%d-to-%d.round2.json", from, id)), &f); err != nil {
			return fmt.Errorf("the value from participant %d: %w", from, err)
		}
		if f.CeremonyID != c.ID || f.From != from || f.To != id {
			return fmt.Errorf("the round-2 file from participant %d is mislabelled", from)
		}
		var sender [32]byte
		copy(sender[:], round1[from].BoxKey)
		v, err := committee.OpenValue(c, &f, &sender, boxSec)
		if err != nil {
			return err
		}
		received[from] = v
	}
	packages := map[committee.Identifier]*committee.Round1{}
	for k, v := range round1 {
		packages[k] = &v.Round1
	}
	share, g, err := committee.DKGFinish(c.Bound(), sec, packages, received)
	if err != nil {
		return err
	}
	if *sharePath == "" {
		*sharePath = fmt.Sprintf("%d.share", id)
	}
	if *groupPath == "" {
		*groupPath = fmt.Sprintf("group-%d.json", id)
	}
	if err := committee.WriteSealed(*sharePath, pass, committee.ShareFile{Group: *g, ID: id, Secret: share.SecretBytes()}); err != nil {
		return err
	}
	gf := groupFile(c, g, tr)
	if err := committee.WriteJSON(*groupPath, gf); err != nil {
		return err
	}
	fmt.Printf("participant %d: sealed share in %s\n", id, *sharePath)
	fmt.Printf("vault address  %s\n", gf.Address)
	fmt.Printf("group file     %s — every participant's must be byte-identical; compare the address out of band\n", *groupPath)
	fmt.Printf("now destroy %s: the share replaces it\n", statePath)
	return nil
}

func groupFile(c *committee.Ceremony, g *committee.Group, tr []byte) *committee.GroupFile {
	return &committee.GroupFile{
		CeremonyID: c.ID, L1ChainID: c.L1ChainID, Threshold: g.Threshold, Participants: c.Participants,
		GroupKey: g.GroupKey, Address: znn.PubKeyToAddress(g.GroupKey), VerificationShares: g.VerificationShares,
		Transcript: committee.Fingerprint(tr),
	}
}

func committeeAudit(args []string) error {
	fs := flag.NewFlagSet("committee audit", flag.ExitOnError)
	ceremony := fs.String("ceremony", "ceremony.json", "ceremony parameters")
	r1 := fs.String("round1", "round1", "directory of the public round-1 files")
	groupPath := fs.String("group", "group.json", "the group file to check")
	fs.Parse(args)
	c, err := committee.LoadCeremony(*ceremony)
	if err != nil {
		return err
	}
	round1, err := committee.LoadRound1Dir(c, *r1)
	if err != nil {
		return err
	}
	tr, err := committee.Transcript(c, round1)
	if err != nil {
		return err
	}
	packages := map[committee.Identifier]*committee.Round1{}
	for k, v := range round1 {
		packages[k] = &v.Round1
	}
	g, err := committee.PublicGroup(packages, c.Threshold)
	if err != nil {
		return err
	}
	want := groupFile(c, g, tr)
	got, err := committee.LoadGroup(*groupPath)
	if err != nil {
		return err
	}
	if got.Address != want.Address || string(got.GroupKey) != string(want.GroupKey) || got.Transcript != want.Transcript || got.Threshold != want.Threshold || len(got.VerificationShares) != len(want.VerificationShares) {
		return fmt.Errorf("%s does not follow from the public transcript: it names %s, the transcript gives %s", *groupPath, got.Address, want.Address)
	}
	for id, vs := range want.VerificationShares {
		if string(got.VerificationShares[id]) != string(vs) {
			return fmt.Errorf("verification share %d in %s does not follow from the transcript", id, *groupPath)
		}
	}
	fmt.Printf("ok: %s is the %d-of-%d vault of ceremony %s (fingerprint %s)\n", want.Address, want.Threshold, len(c.Participants), c.ID, want.Transcript)
	return nil
}

func committeeSigner(args []string) error {
	fs := flag.NewFlagSet("committee signer", flag.ExitOnError)
	groupPath := fs.String("group", "/committee/group.json", "public group file")
	sharePath := fs.String("share", "/committee/share", "your sealed share")
	passFile := fs.String("passphrase-file", "", "passphrase file (or ZVM_COMMITTEE_PASSPHRASE)")
	tokenFile := fs.String("token-file", "/committee/token", "bearer token the coordinator presents")
	configPath := fs.String("config", "/config/rollup.json", "rollup config")
	l1URL := fs.String("l1", "http://l1-rpc:35997", "YOUR NoM node — not the coordinator's")
	ethURL := fs.String("eth", "http://op-geth:8545", "YOUR ZVM node — not the coordinator's")
	dbPath := fs.String("db", "/data/signer.db", "record of payouts this signer has signed")
	listen := fs.String("listen", ":8601", "listen address")
	payoutDepth := fs.Uint64("payout-depth", 6, "momentums a withdrawal must be below NoM's frontier before it is paid")
	tiers := fs.String("payout-tiers", "", "hold large withdrawals longer: ZNN:1000:90,QSR:100000:90 (token:whole units:momentums)")
	outflow := fs.String("outflow-limit", "", "most this signer will help move in a window: ZNN:10000:24h,QSR:1000000:24h (token:whole units:duration)")
	fs.Parse(args)

	g, err := committee.LoadGroup(*groupPath)
	if err != nil {
		return err
	}
	pass, err := committee.ReadPassphrase(*passFile)
	if err != nil {
		return err
	}
	var sf committee.ShareFile
	if err := committee.ReadSealed(*sharePath, pass, &sf); err != nil {
		return err
	}
	share, err := committee.NewShare(sf.ID, sf.Secret, sf.GroupKey)
	if err != nil {
		return err
	}
	if string(sf.GroupKey) != string(g.GroupKey) || string(share.VerificationShare()) != string(g.VerificationShares[sf.ID]) {
		return errors.New("the share does not belong to the group file")
	}
	cfg, err := rollup.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Vault != g.Address || cfg.L1ChainID != g.L1ChainID {
		return fmt.Errorf("the rollup config's vault is %s on chain %d; this committee holds %s on chain %d", cfg.Vault, cfg.L1ChainID, g.Address, g.L1ChainID)
	}
	token, err := os.ReadFile(*tokenFile)
	if err != nil {
		return err
	}
	token = []byte(strings.TrimSpace(string(token)))
	if len(token) < 32 {
		return errors.New("the signer token must be at least 32 characters")
	}
	ctx, cancel := signalContext()
	defer cancel()
	eth, err := waitFor(ctx, "ZVM rpc", func() (*ethclient.Client, error) {
		c, err := ethclient.DialContext(ctx, *ethURL)
		if err != nil {
			return nil, err
		}
		_, err = c.BlockNumber(ctx)
		return c, err
	})
	if err != nil {
		return err
	}
	db, err := openSQLite(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	limits, err := parseOutflow(*outflow)
	if err != nil {
		return err
	}
	parsed, err := parseTiers(*tiers)
	if err != nil {
		return err
	}
	policy := &committee.Policy{Rollup: cfg, L1: znn.NewClient(*l1URL), Eth: eth, PayoutDepth: *payoutDepth,
		Tiers: parsed, Outflow: limits, DB: db}
	for _, t := range parsed {
		slog.Info("payout tier", "token", t.Token, "atLeast", t.Amount, "depth", t.Depth)
	}
	if err := policy.Init(); err != nil {
		return err
	}
	s := &committee.Signer{Share: share, Group: g, Policy: policy, Token: token, Log: slog.Default().With("svc", "signer", "id", share.ID)}
	srv := &http.Server{Addr: *listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		c, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		srv.Shutdown(c)
	}()
	slog.Info("committee signer", "id", share.ID, "vault", g.Address, "threshold", g.Threshold, "listen", *listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func sortedIDs[T any](m map[committee.Identifier]T) []committee.Identifier {
	ids := make([]committee.Identifier, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func curve25519Base(pub, secret *[32]byte) {
	out, err := curve25519.X25519(secret[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	copy(pub[:], out)
}

func readJSONFile(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// parseTiers reads "ZNN:1000:90,QSR:100000:90" — at or above 1,000 ZNN, wait 90
// momentums. The amounts are whole units, as a person would write them.
func parseTiers(spec string) ([]committee.Tier, error) {
	var out []committee.Tier
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Split(part, ":")
		if len(fields) != 3 {
			return nil, fmt.Errorf("-payout-tiers %q: want token:amount:momentums", part)
		}
		var token znn.TokenStandard
		switch strings.ToUpper(fields[0]) {
		case "ZNN":
			token = znn.ZNN
		case "QSR":
			token = znn.QSR
		default:
			return nil, fmt.Errorf("-payout-tiers %q: token must be ZNN or QSR", part)
		}
		whole, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("-payout-tiers %q: %w", part, err)
		}
		depth, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("-payout-tiers %q: %w", part, err)
		}
		out = append(out, committee.Tier{Token: token, Amount: whole * 100_000_000, Depth: depth})
	}
	return out, nil
}

// parseOutflow reads "ZNN:10000:24h" — this signer will not help move more
// than 10,000 ZNN in any 24 hours. The tiers delay one large withdrawal; this
// bounds the total, which is what a thousand small ones get around.
func parseOutflow(spec string) ([]committee.OutflowLimit, error) {
	var out []committee.OutflowLimit
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Split(part, ":")
		if len(fields) != 3 {
			return nil, fmt.Errorf("-outflow-limit %q: want token:amount:window", part)
		}
		var token znn.TokenStandard
		switch strings.ToUpper(fields[0]) {
		case "ZNN":
			token = znn.ZNN
		case "QSR":
			token = znn.QSR
		default:
			return nil, fmt.Errorf("-outflow-limit %q: token must be ZNN or QSR", part)
		}
		whole, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("-outflow-limit %q: %w", part, err)
		}
		window, err := time.ParseDuration(fields[2])
		if err != nil {
			return nil, fmt.Errorf("-outflow-limit %q: %w", part, err)
		}
		if window <= 0 {
			return nil, fmt.Errorf("-outflow-limit %q: the window must be positive", part)
		}
		out = append(out, committee.OutflowLimit{Token: token, Amount: whole * 100_000_000, Window: window})
	}
	return out, nil
}
