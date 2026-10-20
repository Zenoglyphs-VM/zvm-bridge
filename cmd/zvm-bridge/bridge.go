package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	_ "modernc.org/sqlite"

	"github.com/Zenoglyphs-VM/zvm-bridge/bridge"
	"github.com/Zenoglyphs-VM/zvm-bridge/committee"
	"github.com/Zenoglyphs-VM/zvm-core/devnet"
	"github.com/Zenoglyphs-VM/zvm-core/ethrpc"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func init() {
	register("bridge", "the vault committee: receive deposits and pay finalized withdrawals", runBridge)
}

func openSQLite(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(15000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	return db, nil
}

func runBridge(args []string) error {
	fs := flag.NewFlagSet("bridge", flag.ExitOnError)
	configPath := fs.String("config", "/config/rollup.json", "rollup config")
	l1URL := fs.String("l1", "http://l1-rpc:35997", "NoM node JSON-RPC")
	ethURL := fs.String("eth", "http://op-geth:8545", "ZVM JSON-RPC")
	dbPath := fs.String("db", "/data/bridge.db", "journal database")
	listen := fs.String("listen", ":8548", "status listen address")
	vaultIndex := fs.Uint("vault-index", devnet.Vault, "dev mnemonic index of the vault key")
	poll := fs.Duration("poll", 3*time.Second, "poll interval")
	minReceive := fs.String("min-receive", "", "do not receive deposits below this promptly, as ZNN:1,QSR:10 (token:whole units); they are received when no withdrawal is waiting (docs/PLASMA.md)")
	groupPath := fs.String("group", "", "committee group file: sign with a FROST quorum instead of a dev key (docs/COMMITTEE.md)")
	signerURLs := fs.String("signers", "", "comma-separated committee signer URLs, with -group")
	tokenFile := fs.String("signer-token-file", "", "bearer token for the signers, with -group")
	fundPlasma := fs.Bool("fund-plasma", false, "fuse the QSR the withdrawal fee has earned to the vault's own plasma (D8, docs/PLASMA.md)")
	fundEvery := fs.Duration("fund-every", 5*time.Minute, "how often to check whether there is fee revenue to fuse")
	fs.Parse(args)

	cfg, err := rollup.Load(*configPath)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	eth, err := waitFor(ctx, "ZVM rpc", func() (*ethclient.Client, error) {
		c, err := ethrpc.Dial(ctx, *ethURL)
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
	l1 := znn.NewClient(*l1URL)
	var vault *znn.Account
	if *groupPath == "" {
		key := devnet.Key(uint32(*vaultIndex))
		if key.Address != cfg.Vault {
			return errors.New("the vault key does not match the rollup config's vault address")
		}
		vault = znn.NewAccount(key, l1, cfg.L1ChainID)
	} else {
		g, err := committee.LoadGroup(*groupPath)
		if err != nil {
			return err
		}
		if g.Address != cfg.Vault || g.L1ChainID != cfg.L1ChainID {
			return fmt.Errorf("the committee holds %s on chain %d, the rollup config's vault is %s on chain %d", g.Address, g.L1ChainID, cfg.Vault, cfg.L1ChainID)
		}
		token, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("-signer-token-file: %w", err)
		}
		q, err := waitFor(ctx, "committee signers", func() (*committee.Quorum, error) {
			return committee.NewQuorum(ctx, g, strings.Split(*signerURLs, ","), strings.TrimSpace(string(token)))
		})
		if err != nil {
			return err
		}
		vault = znn.NewSignerAccount(q, l1, cfg.L1ChainID)
		slog.Info("vault held by committee", "address", g.Address, "threshold", g.Threshold, "signers", *signerURLs)
	}
	vault.AssumeFused = true
	floors, err := parseMinReceive(*minReceive)
	if err != nil {
		return err
	}
	br, err := bridge.New(bridge.Config{Rollup: cfg, L1: l1, Eth: eth, Vault: vault, DB: db, Poll: *poll,
		MinReceive: floors, FundPlasma: *fundPlasma, FundEvery: *fundEvery, Log: slog.Default().With("svc", "bridge")})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		s, err := br.Status(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, http.StatusOK, s)
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		c, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		srv.Shutdown(c)
	}()
	go func() {
		slog.Info("bridge listening", "addr", *listen, "vault", cfg.Vault)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("bridge http", "err", err)
		}
	}()
	return br.Run(ctx)
}

// parseMinReceive reads "ZNN:1,QSR:10" — the amount, in whole tokens, below
// which a deposit of that token is not received promptly. Same shape as
// -payout-tiers, and the same 8 decimals.
func parseMinReceive(spec string) (map[znn.TokenStandard]*big.Int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	out := map[znn.TokenStandard]*big.Int{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		token, amount, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("-min-receive %q: want token:amount", part)
		}
		var zts znn.TokenStandard
		switch strings.ToUpper(strings.TrimSpace(token)) {
		case "ZNN":
			zts = znn.ZNN
		case "QSR":
			zts = znn.QSR
		default:
			return nil, fmt.Errorf("-min-receive %q: token must be ZNN or QSR", part)
		}
		whole, err := strconv.ParseUint(strings.TrimSpace(amount), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("-min-receive %q: %w", part, err)
		}
		out[zts] = new(big.Int).SetUint64(whole * 100_000_000)
	}
	return out, nil
}
