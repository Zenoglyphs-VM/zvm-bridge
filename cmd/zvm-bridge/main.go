// Command zvm-bridge is the peg between NoM and the ZVM: it watches the vault
// address for deposits, credits them on the ZVM, and pays out withdrawals once
// they are finalized. The `committee` subcommand is the other half — the FROST
// key ceremony and the signer daemon that authorises those payouts (see
// docs/COMMITTEE.md in the zvm deployment repo).
//
// bridge.go, committee.go, withdraw.go and reshare.go are verbatim copies of
// the same files in cmd/zvm, which is still the source of truth. The harness
// below is the one cmd/zvm uses, so they can be re-copied without edits.
package main

import (
	"fmt"
	"log/slog"
	"os"
	"sort"
)

type command struct {
	summary string
	run     func(args []string) error
}

var commands = map[string]command{}

func register(name, summary string, run func(args []string) error) {
	commands[name] = command{summary: summary, run: run}
}

// defaultCommand runs when no subcommand is named, so that the container
// entrypoint is just `zvm-bridge -l1 ... -eth ...`.
const defaultCommand = "bridge"

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	name, args := defaultCommand, os.Args[1:]
	if len(args) > 0 {
		if _, ok := commands[args[0]]; ok {
			name, args = args[0], args[1:]
		} else if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
			usage()
			os.Exit(2)
		}
	}
	cmd := commands[name]
	if err := cmd.run(args); err != nil {
		fmt.Fprintf(os.Stderr, "zvm-bridge %s: %v\n", name, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: zvm-bridge [command] [flags]   (default: %s)\n\n", defaultCommand)
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(os.Stderr, "  %-14s %s\n", n, commands[n].summary)
	}
}
