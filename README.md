# zvm-bridge

The peg between NoM and the ZVM, and the committee that authorises it.

A send to the vault on NoM credits the same amount on the ZVM. A withdrawal
burns there and is paid out of the vault once final. The vault is an ordinary
Zenon address held by a FROST-ed25519 quorum, which NoM verifies as a single
signer, so no machine holds its key.

```sh
git clone --recurse-submodules https://github.com/Zenoglyphs-VM/zvm-bridge
go build ./...
go test ./...
docker build -t zvm-bridge .

zvm-bridge -config l2/rollup.json -l1 http://127.0.0.1:45997 \
           -eth http://127.0.0.1:8545 -db /data/bridge.db -listen :8548
```

| | |
|---|---|
| `zvm-bridge` | deposits in, final withdrawals out |
| `zvm-bridge committee` | the key ceremony and the signer daemon |
| `zvm-bridge reshare` | move the vault to a new set of signers |
| `zvm-bridge withdraw` | withdraw from the ZVM to a NoM address |
| `GET /status` | vault balances, pending deposits and withdrawals |

No node is built in. `withdraw`'s `-l1` and `-eth` default to `NOM_NODE` and
`ZVM_RPC`; `.env.example` has a local zvm-devnet's.

Read `operations/COMMITTEE.md` in
[zvm-docs](https://github.com/Zenoglyphs-VM/zvm-docs) before running a ceremony:
losing shares below the threshold cannot be undone. Consensus lives in
[zvm-core](https://github.com/Zenoglyphs-VM/zvm-core), a submodule here.

MIT licence. The full guide, with how it works and why:
[docs/GUIDE.md](docs/GUIDE.md).
