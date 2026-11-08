// Validate a downloaded QUL archive and retain it unchanged for embedding.
package main

import (
	"aslam/db"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func run() error {
	input := flag.String("input", "", "Downloaded QUL English Ibn Kathir zip")
	output := flag.String("output", "data/tafsir.zip", "Validated archive destination")
	flag.Parse()
	if *input == "" {
		return fmt.Errorf("-input is required")
	}
	archive, err := os.ReadFile(*input)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "tafsir-validation-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	os.Setenv("ASLAM_KEY", hex.EncodeToString(key))
	os.Setenv("ASLAM_DB", filepath.Join(dir, "validation.db"))
	if err := db.Init(); err != nil {
		return err
	}
	defer db.Close()
	if err := db.ImportTafsir(archive); err != nil {
		return err
	}
	if err := os.WriteFile(*output, archive, 0644); err != nil {
		return err
	}
	fmt.Println("Validated complete Quran coverage and saved", *output)
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
