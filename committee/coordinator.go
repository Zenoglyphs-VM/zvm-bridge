package committee

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

// Quorum signs account blocks by asking the committee's signers. It is
// untrusted: it holds no share, and a signer refuses anything its own policy
// does not allow.
type Quorum struct {
	group   *GroupFile
	signers map[Identifier]string
	token   string
	client  *http.Client
}

// NewQuorum reads each signer's /info and checks it belongs to the group.
func NewQuorum(ctx context.Context, group *GroupFile, urls []string, token string) (*Quorum, error) {
	q := &Quorum{group: group, signers: map[Identifier]string{}, token: token, client: &http.Client{Timeout: 30 * time.Second}}
	for _, u := range urls {
		u = strings.TrimRight(strings.TrimSpace(u), "/")
		var info InfoResponse
		if err := q.call(ctx, u, http.MethodGet, "/info", nil, &info); err != nil {
			return nil, fmt.Errorf("signer %s: %w", u, err)
		}
		if info.GroupKey != hex.EncodeToString(group.GroupKey) || info.CeremonyID != group.CeremonyID {
			return nil, fmt.Errorf("signer %s holds a share of another committee", u)
		}
		if _, ok := group.VerificationShares[info.ID]; !ok {
			return nil, fmt.Errorf("signer %s claims participant %d, who is not in the group", u, info.ID)
		}
		if _, dup := q.signers[info.ID]; dup {
			return nil, fmt.Errorf("two signers claim participant %d", info.ID)
		}
		q.signers[info.ID] = u
	}
	if len(q.signers) < group.Threshold {
		return nil, fmt.Errorf("%d signers configured for a threshold of %d", len(q.signers), group.Threshold)
	}
	return q, nil
}

func (q *Quorum) Address() znn.Address { return q.group.Address }

type result[T any] struct {
	id  Identifier
	val T
	err error
}

// SignBlock runs both rounds with every reachable signer and the first quorum
// that agrees. A signer that refuses is left out and the rest tried, so one
// lagging node does not stall the vault while a quorum still agrees.
func (q *Quorum) SignBlock(ctx context.Context, b *znn.AccountBlock) error {
	b.PublicKey = append([]byte(nil), q.group.GroupKey...)
	b.Hash = b.ComputeHash()
	available := make([]Identifier, 0, len(q.signers))
	for id := range q.signers {
		available = append(available, id)
	}
	var refusals []string
	for len(available) >= q.group.Threshold {
		session := randomSession()
		coms := fanOut(available, func(id Identifier) (*Commitment, error) {
			var c Commitment
			err := q.call(ctx, q.signers[id], http.MethodPost, "/commit", CommitRequest{Session: session}, &c)
			if err == nil && c.ID != id {
				err = fmt.Errorf("answered as participant %d", c.ID)
			}
			return &c, err
		})
		var committed []*Commitment
		for _, r := range coms {
			if r.err != nil {
				refusals = append(refusals, fmt.Sprintf("%d: %v", r.id, r.err))
				continue
			}
			committed = append(committed, r.val)
		}
		if len(committed) < q.group.Threshold {
			break
		}
		sort.Slice(committed, func(i, j int) bool { return committed[i].ID < committed[j].ID })
		chosen := committed[:q.group.Threshold]
		ids := make([]Identifier, len(chosen))
		for i, c := range chosen {
			ids[i] = c.ID
		}
		shares := fanOut(ids, func(id Identifier) (*SignatureShare, error) {
			var s SignatureShare
			err := q.call(ctx, q.signers[id], http.MethodPost, "/sign", SignRequest{Session: session, Block: b, Commitments: chosen}, &s)
			return &s, err
		})
		var sigShares []*SignatureShare
		failed := map[Identifier]bool{}
		for _, r := range shares {
			if r.err != nil {
				refusals = append(refusals, fmt.Sprintf("%d: %v", r.id, r.err))
				failed[r.id] = true
				continue
			}
			sigShares = append(sigShares, r.val)
		}
		if len(failed) == 0 {
			sig, err := Aggregate(b.Hash[:], q.group.GroupKey, chosen, sigShares, q.group.VerificationShares)
			if err != nil {
				return err
			}
			if !ed25519.Verify(q.group.GroupKey, b.Hash[:], sig) {
				return fmt.Errorf("committee: aggregate does not verify")
			}
			b.Signature = sig
			return nil
		}
		next := available[:0:0]
		for _, id := range available {
			if !failed[id] {
				next = append(next, id)
			}
		}
		available = next
	}
	return fmt.Errorf("committee: no quorum of %d signed block %d (%s)", q.group.Threshold, b.Height, strings.Join(refusals, "; "))
}

func fanOut[T any](ids []Identifier, f func(Identifier) (T, error)) []result[T] {
	out := make([]result[T], len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := f(id)
			out[i] = result[T]{id: id, val: v, err: err}
		}()
	}
	wg.Wait()
	return out
}

func (q *Quorum) call(ctx context.Context, base, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+q.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := q.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", strings.TrimSpace(string(data)))
	}
	return json.Unmarshal(data, out)
}
