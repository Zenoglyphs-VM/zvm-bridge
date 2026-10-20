# zvm-bridge guide

The peg between NoM and the ZVM, and the committee that authorises it.

ZNN and QSR are not minted on the ZVM. They are *deposited*: a send to the vault
address on NoM credits the same amount on the ZVM, and a withdrawal burns there
and is paid out here once it is finalized. The vault is an ordinary Zenon
address — the interesting part is that no single machine holds its key.

```
bridge/     watch the vault, credit deposits, pay finalized withdrawals
committee/  FROST-ed25519: the key ceremony, resharing, and the signer daemon
```

A quorum holds the vault address through FROST threshold signatures over
ed25519, which NoM verifies as an ordinary single-signer account because that is
exactly what it looks like on chain. NoM has no multisig; it does not need one.

```sh
go build ./...
go test ./...

zvm-bridge -config l2/rollup.json -l1 http://127.0.0.1:45997 \
           -eth http://127.0.0.1:8545 -db /data/bridge.db -listen :8548
```

| | |
|---|---|
| `zvm-bridge` | the daemon: deposits in, finalized withdrawals out |
| `zvm-bridge committee` | the key ceremony (DKG) and the signer daemon |
| `zvm-bridge reshare` | move the same address to a new set of signers |
| `zvm-bridge withdraw` | withdraw from the ZVM to a NoM address, from a Zenon or an EVM key |
| `GET /status` | vault balances, pending deposits, withdrawals waiting on finality |

The ceremony, the signer policy and what resharing does and does not change are
in `operations/COMMITTEE.md` in zvm-docs. Read it before running a
ceremony: the one thing that cannot be undone is losing enough shares to fall
below the threshold, and the vault's balance is on the other side of that.

## Two things worth knowing before operating one

- **Finality is not confirmation.** A withdrawal is paid only after its burn is
  final by the chain's `finalityDepth`. Paying earlier would mean paying out a
  block that can still be rebuilt differently.
- **Plasma is not free and the payer is not the beneficiary.** The vault pays to
  publish payouts it does not benefit from; `bridge/plasma.go` is what keeps it
  fused, and `docs/PLASMA.md` lists the other places this asymmetry shows up.

Consensus lives in [`zvm-core`](https://github.com/Zenoglyphs-VM/zvm-core); the chain this pegs to is derived
by [`zvm-node`](https://github.com/Zenoglyphs-VM/zvm-node).
