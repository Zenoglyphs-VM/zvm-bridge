package committee

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// Ceremony is the parameter file every participant checks before round 1.
// It is public. Whoever writes it is a courier, not a trusted party: it names
// the network, the threshold and who takes part, and nothing else.
type Ceremony struct {
	ID           string        `json:"ceremonyId"`
	L1ChainID    uint64        `json:"l1ChainId"`
	Threshold    int           `json:"threshold"`
	Participants []Participant `json:"participants"`
}

type Participant struct {
	ID   Identifier `json:"id"`
	Name string     `json:"name"`
}

func NewCeremony(l1ChainID uint64, threshold int, names []string) (*Ceremony, error) {
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	c := &Ceremony{ID: hex.EncodeToString(id), L1ChainID: l1ChainID, Threshold: threshold}
	for i, n := range names {
		c.Participants = append(c.Participants, Participant{ID: Identifier(i + 1), Name: strings.TrimSpace(n)})
	}
	return c, c.Validate()
}

func (c *Ceremony) Validate() error {
	if b, err := hex.DecodeString(c.ID); err != nil || len(b) != 32 {
		return errors.New("ceremony: ceremonyId must be 32 bytes of hex")
	}
	if c.L1ChainID == 0 {
		return errors.New("ceremony: l1ChainId is required")
	}
	n := len(c.Participants)
	if c.Threshold < 2 || c.Threshold > n {
		return fmt.Errorf("ceremony: threshold %d does not fit %d participants", c.Threshold, n)
	}
	seen := map[Identifier]bool{}
	for _, p := range c.Participants {
		if p.ID == 0 || seen[p.ID] {
			return fmt.Errorf("ceremony: participant id %d is zero or repeated", p.ID)
		}
		if p.Name == "" {
			return fmt.Errorf("ceremony: participant %d has no name", p.ID)
		}
		seen[p.ID] = true
	}
	return nil
}

func (c *Ceremony) idBytes() []byte { b, _ := hex.DecodeString(c.ID); return b }

// Bound is what the proofs and encryption bind to: the ceremony id and the
// network, so a package cannot move between ceremonies or chains.
func (c *Ceremony) Bound() []byte {
	return binary.BigEndian.AppendUint64(append([]byte("zvm-committee-v1"), c.idBytes()...), c.L1ChainID)
}

func (c *Ceremony) Has(id Identifier) bool {
	for _, p := range c.Participants {
		if p.ID == id {
			return true
		}
	}
	return false
}

func LoadCeremony(path string) (*Ceremony, error) {
	var c Ceremony
	if err := readJSON(path, &c); err != nil {
		return nil, err
	}
	return &c, c.Validate()
}

// Round1File is a participant's public round-1 output: the DKG package plus
// the key round-2 values to them are encrypted to.
type Round1File struct {
	CeremonyID string `json:"ceremonyId"`
	Round1
	BoxKey []byte `json:"boxKey"`
}

// Round2File carries one private value from one participant to another.
type Round2File struct {
	CeremonyID string     `json:"ceremonyId"`
	From       Identifier `json:"from"`
	To         Identifier `json:"to"`
	Nonce      []byte     `json:"nonce"`
	Box        []byte     `json:"box"`
}

// Transcript hashes the ceremony and every round-1 package. Participants
// compare its fingerprint over a channel they trust (a call, in person) before
// anyone sends round 2: that comparison is what authenticates the box keys, and
// so what stops a courier substituting its own.
func Transcript(c *Ceremony, round1 map[Identifier]*Round1File) ([]byte, error) {
	h := sha256.New()
	h.Write(c.Bound())
	h.Write(binary.BigEndian.AppendUint16(nil, uint16(c.Threshold)))
	ps := append([]Participant(nil), c.Participants...)
	sort.Slice(ps, func(i, j int) bool { return ps[i].ID < ps[j].ID })
	for _, p := range ps {
		f, ok := round1[p.ID]
		if !ok {
			return nil, fmt.Errorf("ceremony: no round-1 package from participant %d (%s)", p.ID, p.Name)
		}
		h.Write(binary.BigEndian.AppendUint16(nil, uint16(p.ID)))
		h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(p.Name))))
		h.Write([]byte(p.Name))
		h.Write(f.BoxKey)
		for _, cm := range f.Commitments {
			h.Write(cm)
		}
		h.Write(f.ProofR)
		h.Write(f.ProofZ)
	}
	if len(round1) != len(ps) {
		return nil, fmt.Errorf("ceremony: %d round-1 packages for %d participants", len(round1), len(ps))
	}
	return h.Sum(nil), nil
}

// Fingerprint is the transcript in a form people can read aloud.
func Fingerprint(transcript []byte) string {
	s := hex.EncodeToString(transcript[:16])
	var parts []string
	for i := 0; i < len(s); i += 4 {
		parts = append(parts, s[i:i+4])
	}
	return strings.Join(parts, "-")
}

// LoadRound1Dir reads every round-1 file in dir that belongs to the ceremony,
// verifying each package's proof.
func LoadRound1Dir(c *Ceremony, dir string) (map[Identifier]*Round1File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[Identifier]*Round1File{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".round1.json") {
			continue
		}
		var f Round1File
		if err := readJSON(dir+"/"+e.Name(), &f); err != nil {
			return nil, err
		}
		if f.CeremonyID != c.ID {
			return nil, fmt.Errorf("%s belongs to ceremony %s", e.Name(), f.CeremonyID)
		}
		if !c.Has(f.ID) {
			return nil, fmt.Errorf("%s is from participant %d, who is not in the ceremony", e.Name(), f.ID)
		}
		if _, dup := out[f.ID]; dup {
			return nil, fmt.Errorf("two round-1 packages from participant %d", f.ID)
		}
		if len(f.BoxKey) != 32 {
			return nil, fmt.Errorf("%s has no encryption key", e.Name())
		}
		if err := VerifyRound1(c.Bound(), &f.Round1, c.Threshold); err != nil {
			return nil, err
		}
		out[f.ID] = &f
	}
	return out, nil
}

func SealValue(c *Ceremony, from, to Identifier, value []byte, recipient *[32]byte, sender *[32]byte) (*Round2File, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	msg := append(round2Header(c, from, to), value...)
	return &Round2File{CeremonyID: c.ID, From: from, To: to, Nonce: nonce[:], Box: box.Seal(nil, msg, &nonce, recipient, sender)}, nil
}

func OpenValue(c *Ceremony, f *Round2File, sender *[32]byte, recipient *[32]byte) ([]byte, error) {
	if len(f.Nonce) != 24 {
		return nil, errors.New("round 2: malformed nonce")
	}
	var nonce [24]byte
	copy(nonce[:], f.Nonce)
	msg, ok := box.Open(nil, f.Box, &nonce, sender, recipient)
	if !ok {
		return nil, fmt.Errorf("round 2: the value from participant %d does not decrypt", f.From)
	}
	hdr := round2Header(c, f.From, f.To)
	if !bytes.HasPrefix(msg, hdr) || len(msg) != len(hdr)+32 {
		return nil, fmt.Errorf("round 2: the value from participant %d is not bound to this ceremony", f.From)
	}
	return msg[len(hdr):], nil
}

func round2Header(c *Ceremony, from, to Identifier) []byte {
	b := c.Bound()
	b = binary.BigEndian.AppendUint16(b, uint16(from))
	return binary.BigEndian.AppendUint16(b, uint16(to))
}

// State is a participant's secret between round 1 and finish.
type State struct {
	CeremonyID string     `json:"ceremonyId"`
	ID         Identifier `json:"id"`
	Coeffs     [][]byte   `json:"coeffs"`
	BoxSecret  []byte     `json:"boxSecret"`
}

// ShareFile is a participant's signing share. Written only encrypted.
type ShareFile struct {
	Group
	ID     Identifier `json:"id"`
	Secret []byte     `json:"secret"`
}

// GroupFile is the public result: what the coordinator, the rollup config and
// every auditor need. Every participant writes the same one.
type GroupFile struct {
	CeremonyID         string                `json:"ceremonyId"`
	L1ChainID          uint64                `json:"l1ChainId"`
	Threshold          int                   `json:"threshold"`
	Participants       []Participant         `json:"participants"`
	GroupKey           []byte                `json:"groupKey"`
	Address            znn.Address           `json:"address"`
	VerificationShares map[Identifier][]byte `json:"verificationShares"`
	Transcript         string                `json:"transcript"`
}

func (g *GroupFile) Validate() error {
	if len(g.GroupKey) != ed25519.PublicKeySize {
		return errors.New("group: groupKey is not an Ed25519 key")
	}
	if znn.PubKeyToAddress(g.GroupKey) != g.Address {
		return errors.New("group: address does not match groupKey")
	}
	if g.Threshold < 2 || len(g.VerificationShares) < g.Threshold {
		return errors.New("group: threshold and verification shares do not fit")
	}
	return nil
}

func LoadGroup(path string) (*GroupFile, error) {
	var g GroupFile
	if err := readJSON(path, &g); err != nil {
		return nil, err
	}
	return &g, g.Validate()
}

// --- encryption at rest ---

type sealed struct {
	Version int    `json:"version"`
	KDF     string `json:"kdf"`
	N       int    `json:"n"`
	R       int    `json:"r"`
	P       int    `json:"p"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	Box     []byte `json:"box"`
}

const scryptN = 1 << 17

// WriteSealed writes v as JSON, encrypted under a key scrypt derives from the
// passphrase. The file is created 0600 and refuses to overwrite.
func WriteSealed(path string, passphrase []byte, v any) error {
	if len(passphrase) < 12 {
		return errors.New("the passphrase must be at least 12 bytes")
	}
	plain, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s := sealed{Version: 1, KDF: "scrypt", N: scryptN, R: 8, P: 1, Salt: make([]byte, 32), Nonce: make([]byte, 24)}
	if _, err := rand.Read(s.Salt); err != nil {
		return err
	}
	if _, err := rand.Read(s.Nonce); err != nil {
		return err
	}
	key, err := scrypt.Key(passphrase, s.Salt, s.N, s.R, s.P, 32)
	if err != nil {
		return err
	}
	var k [32]byte
	var n [24]byte
	copy(k[:], key)
	copy(n[:], s.Nonce)
	s.Box = secretbox.Seal(nil, plain, &n, &k)
	out, _ := json.MarshalIndent(s, "", "  ")
	return writeNew(path, out, 0o600)
}

func ReadSealed(path string, passphrase []byte, v any) error {
	var s sealed
	if err := readJSON(path, &s); err != nil {
		return err
	}
	if s.Version != 1 || s.KDF != "scrypt" || len(s.Nonce) != 24 {
		return fmt.Errorf("%s: not a sealed committee file", path)
	}
	key, err := scrypt.Key(passphrase, s.Salt, s.N, s.R, s.P, 32)
	if err != nil {
		return err
	}
	var k [32]byte
	var n [24]byte
	copy(k[:], key)
	copy(n[:], s.Nonce)
	plain, ok := secretbox.Open(nil, s.Box, &n, &k)
	if !ok {
		return fmt.Errorf("%s: wrong passphrase, or the file was altered", path)
	}
	return json.Unmarshal(plain, v)
}

func WriteJSON(path string, v any) error {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeNew(path, append(out, '\n'), 0o644)
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// ReadPassphrase takes a passphrase from a file, trimming one trailing newline.
func ReadPassphrase(path string) ([]byte, error) {
	if path == "" {
		if env := os.Getenv("ZVM_COMMITTEE_PASSPHRASE"); env != "" {
			return []byte(env), nil
		}
		return nil, errors.New("a passphrase is required: -passphrase-file or ZVM_COMMITTEE_PASSPHRASE")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return bytes.TrimRight(b, "\r\n"), nil
}
