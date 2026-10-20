package main

import (
	"context"
	"flag"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/Zenoglyphs-VM/zvm-bridge/bridge"
	"github.com/Zenoglyphs-VM/zvm-core/derive"
	"github.com/Zenoglyphs-VM/zvm-core/devnet"
	"github.com/Zenoglyphs-VM/zvm-core/rollup"
	"github.com/Zenoglyphs-VM/zvm-core/znn"
)

func init() {
	register("withdraw", "withdraw ZNN or QSR from the ZVM to a NoM address, from a Zenon or an EVM key", runWithdraw)
}

func runWithdraw(args []string) error {
	fs := flag.NewFlagSet("withdraw", flag.ExitOnError)
	cf := addClientFlags(fs)
	lane := fs.String("lane", "native", "native (a Zenon key, -index) or evm (a secp256k1 key, -key-index)")
	keyIndex := fs.Uint("key-index", 0, "dev EVM key index for -lane evm")
	submitURL := fs.String("submit", "", "where -lane evm sends the raw transaction (default: -eth)")
	to := fs.String("to", "", "NoM recipient (z1…)")
	amount := fs.String("amount", "1", "amount in whole units")
	token := fs.String("token", "ZNN", "ZNN or QSR")
	follow := fs.Bool("follow", false, "wait until the vault has paid it and the ZVM has derived the payout")
	fs.Parse(args)
	if err := needEndpoints(fs, "l1", "eth"); err != nil {
		return err
	}

	cfg, err := rollup.Load(*cf.config)
	if err != nil {
		return err
	}
	recipient, err := znn.ParseAddress(*to)
	if err != nil {
		return err
	}
	units, err := parseUnits(*amount, 8)
	if err != nil {
		return err
	}
	var data []byte
	value := new(big.Int)
	switch strings.ToUpper(*token) {
	case "ZNN":
		data = bridge.EncodeWithdrawZNN(recipient)
		value.Mul(units, rollup.ZNNScale)
	case "QSR":
		data = bridge.EncodeWithdrawQSR(recipient, units)
	default:
		return fmt.Errorf("token must be ZNN or QSR")
	}

	ctx := context.Background()
	eth, err := ethclient.Dial(*cf.eth)
	if err != nil {
		return err
	}
	bridgeAddr := rollup.BridgeAddr
	var txHash common.Hash
	switch *lane {
	case "native":
		call := derive.Call{To: &bridgeAddr, Value: value, Gas: 250_000, Data: data}
		acct := znn.NewAccount(devnet.Key(uint32(*cf.index)), znn.NewClient(*cf.l1), cfg.L1ChainID)
		b, tx, err := derive.PublishCall(ctx, cfg, acct, znn.ZNN, call)
		if err != nil {
			return err
		}
		txHash = tx.Hash()
		fmt.Printf("NoM block   %s from %s\n", b.Hash, b.Address)
	case "evm":
		key := devnet.EVMKey(uint32(*keyIndex))
		from := crypto.PubkeyToAddress(key.PublicKey)
		submit := eth
		if *submitURL != "" {
			if submit, err = ethclient.Dial(*submitURL); err != nil {
				return err
			}
		}
		nonce, err := eth.NonceAt(ctx, from, nil)
		if err != nil {
			return err
		}
		head, err := eth.HeaderByNumber(ctx, nil)
		if err != nil {
			return err
		}
		gas, err := eth.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &bridgeAddr, Value: value, Data: data})
		if err != nil {
			return fmt.Errorf("estimating gas (does the account hold enough?): %w", err)
		}
		tip := rollup.DefaultTip()
		tx, err := types.SignNewTx(key, types.LatestSignerForChainID(cfg.L2ChainIDBig()), &types.DynamicFeeTx{
			ChainID: cfg.L2ChainIDBig(), Nonce: nonce, GasTipCap: tip,
			GasFeeCap: cfg.SuggestedFeeCap(head.BaseFee, tip),
			Gas:       gas * 12 / 10, To: &bridgeAddr, Value: value, Data: data,
		})
		if err != nil {
			return err
		}
		if err := submit.SendTransaction(ctx, tx); err != nil {
			return err
		}
		txHash = tx.Hash()
		fmt.Printf("from        %s\n", from.Hex())
	default:
		return fmt.Errorf("-lane must be native or evm")
	}
	fmt.Printf("L2 tx       %s\n", txHash.Hex())
	started := time.Now()
	r, err := waitReceipt(ctx, eth, txHash, *cf.wait)
	if err != nil {
		return err
	}
	if r.Status != types.ReceiptStatusSuccessful {
		return fmt.Errorf("withdrawal reverted in block %d", r.BlockNumber)
	}
	var id uint64
	for _, l := range r.Logs {
		if l.Address == rollup.BridgeAddr && len(l.Topics) == 4 && l.Topics[0] == bridge.TopicWithdrawalInitiated {
			id = new(big.Int).SetBytes(l.Topics[1][:]).Uint64()
		}
	}
	fmt.Printf("withdrawal  id %d recorded in L2 block %d (%.0fs)\n", id, r.BlockNumber, time.Since(started).Seconds())
	if !*follow || id == 0 {
		return nil
	}
	l1 := znn.NewClient(*cf.l1)
	deadline := time.Now().Add(6 * time.Minute)
	for time.Now().Before(deadline) {
		w, err := bridge.ReadWithdrawal(ctx, eth, id)
		if err == nil && w.PaidIn != (common.Hash{}) {
			fmt.Printf("paid        NoM block %x, derived back into the ZVM %.0fs after the withdrawal\n", w.PaidIn[:], time.Since(started).Seconds())
			if list, err := l1.UnreceivedBlocks(ctx, recipient, 0, 10); err == nil {
				for _, b := range list.List {
					if b.Hash == znn.Hash(w.PaidIn) {
						fmt.Printf("recipient   %s has it as an unreceived %s %s send (a receive block settles it)\n",
							recipient, formatUnits(b.AmountBig(), 8), strings.ToUpper(*token))
					}
				}
			}
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("withdrawal %d not paid within 6 minutes", id)
}
