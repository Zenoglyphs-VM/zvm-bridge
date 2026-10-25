package bridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func TestSignerMomentumObservationRequiresCompleteBoundedReaderEvidence(t *testing.T) {
	for _, phase := range []string{"valid", "missing", "null", "wrong-chain", "zero-height", "missing-time", "duplicate", "oversized", "rpc-error"} {
		t.Run(phase, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					Method string `json:"method"`
				}
				if json.NewDecoder(r.Body).Decode(&request) != nil || request.Method != "ledger.getFrontierMomentum" {
					t.Error("unexpected member RPC")
				}
				fields := map[string]any{"chainIdentifier": 70, "height": 20, "timestamp": 1000, "hash": znn.Hash{0: 1}}
				switch phase {
				case "missing":
					fields = map[string]any{}
				case "null":
					fields["height"] = nil
				case "wrong-chain":
					fields["chainIdentifier"] = 71
				case "zero-height":
					fields["height"] = 0
				case "missing-time":
					delete(fields, "timestamp")
				case "duplicate":
					w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{},"result":{}}`))
					return
				case "oversized":
					w.Write([]byte(strings.Repeat(" ", 129<<10)))
					return
				case "rpc-error":
					w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"fixture"}}`))
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": fields})
			}))
			defer srv.Close()
			out, err := ReadMomentumObservation(context.Background(), znn.NewClient(srv.URL), 70)
			if phase == "valid" {
				if err != nil || out.Height != 20 || out.Timestamp != 1000 {
					t.Fatalf("valid point refused: %+v %v", out, err)
				}
			} else if err == nil || out.Height != 0 {
				t.Fatal("incomplete member point manufactured freshness")
			}
		})
	}
}
