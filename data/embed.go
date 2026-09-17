// Package data embeds the reference datasets imported into SQLite at startup.
package data

import _ "embed"

//go:embed islamqa.zip
var IslamQA []byte

//go:embed ghazali.zip
var Ghazali []byte

//go:embed sources.zip
var Sources []byte

//go:embed adhkar.zip
var Adhkar []byte

//go:embed salihin.zip
var Riyad []byte

//go:embed arabic.zip
var Arabic []byte

//go:embed prophets.json
var Prophets []byte

//go:embed seerah.zip
var Seerah []byte
