// companytax downloads Xero evidence and prepares a draft UK company tax working paper.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "companytax:", err)
		os.Exit(1)
	}
}

func run() error {
	home, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("companytax", flag.ContinueOnError)
	state := fs.String("state", filepath.Join(home, "companytax"), "private directory for Xero tokens")
	config := fs.String("config", "companytax.json", "company and tax review configuration")
	out := fs.String("out", "companytax-output", "new output directory (must not exist)")
	data := fs.String("data", "companytax-data", "Xero snapshot directory for review/generate")
	answers := fs.String("answers", "", "saved review answers (default DATA/review.json)")
	edit := fs.Bool("edit", false, "revisit saved review answers")
	if len(os.Args) < 2 {
		return errors.New("usage: companytax init|login|tenants|prepare|review|generate [--config FILE] [--data DIR] [--out DIR] [--state DIR]")
	}
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	switch os.Args[1] {
	case "init":
		return writeNew(*config, []byte(exampleConfig))
	case "review":
		return reviewCommand(*state, *config, *data, *answers, *edit, os.Stdin, os.Stdout)
	case "generate":
		return generateCommand(*data, *answers, *out)
	case "login", "tenants", "prepare":
	default:
		return errors.New("unknown command; use init, login, tenants, prepare, review or generate")
	}
	if err := os.MkdirAll(*state, 0700); err != nil {
		return err
	}
	// A single process owns the rotating refresh token at a time.
	lock, err := os.OpenFile(filepath.Join(*state, "lock"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("state is locked; if no companytax process is running remove %s", filepath.Join(*state, "lock"))
	}
	lock.Close()
	defer os.Remove(filepath.Join(*state, "lock"))
	client := newXero(*state)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if os.Args[1] == "login" {
		return client.login(ctx)
	}
	if err := client.load(); err != nil {
		return err
	}
	if os.Args[1] == "tenants" {
		list, err := client.connections(ctx)
		if err != nil {
			return err
		}
		for _, c := range list {
			fmt.Printf("%s\t%s\n", c.ID, c.Name)
		}
		return nil
	}
	var cfg Config
	b, err := os.ReadFile(*config)
	if err != nil {
		return err
	}
	if err := decodeStrict(b, &cfg); err != nil {
		return err
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	return prepare(ctx, client, cfg, *out)
}

func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func saveJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeNew(path, append(b, '\n'))
}

const exampleConfig = `{
  "company_name": "MICRO XYZ LTD",
  "company_number": "16607360",
  "tenant_id": "",
  "accounts_from": "2025-07-25",
  "accounts_to": "2026-07-31",
  "trading_start": "",
  "ordinary_trading_only_confirmed": false,
  "associated_companies": null,
  "period_reviews": []
}
`
