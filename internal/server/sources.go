package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"aslam/data"
	"aslam/db"
)

func seedUsers() {
	if db.UserCount() > 0 {
		return
	}
	emails := os.Getenv("ADMIN_EMAILS")
	if emails == "" {
		emails = os.Getenv("ALLOWED_EMAILS")
	}
	if emails == "" {
		return
	}
	for _, email := range strings.Split(emails, ",") {
		email = strings.TrimSpace(strings.ToLower(email))
		if email != "" {
			if err := db.AddUser(email, "", "admin", "seed"); err != nil {
				log.Printf("Failed to seed user %s: %v", email, err)
			} else {
				log.Printf("Seeded admin user: %s", email)
			}
		}
	}
}

const islamqaVersion = "3"

func loadIslamQA() {
	if db.GetSetting("islamqa_version") == islamqaVersion {
		log.Printf("IslamQA v%s already loaded (%d entries)", islamqaVersion, db.IslamQACount())
		return
	}

	log.Printf("IslamQA dataset changed (want v%s), reloading...", islamqaVersion)
	db.ClearIslamQA()

	r, err := zip.NewReader(bytes.NewReader(data.IslamQA), int64(len(data.IslamQA)))
	if err != nil {
		log.Printf("Failed to open embedded archive.zip: %v", err)
		return
	}

	total := 0
	for _, f := range r.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			log.Printf("Failed to open %s in zip: %v", f.Name, err)
			continue
		}

		var entries []struct {
			Question string `json:"question"`
			Answer   string `json:"answer"`
			Category string `json:"category"`
		}
		if err := json.NewDecoder(rc).Decode(&entries); err != nil {
			rc.Close()
			log.Printf("Failed to decode %s: %v", f.Name, err)
			continue
		}
		rc.Close()

		for _, e := range entries {
			category := e.Category
			if category == "" {
				category = strings.TrimSuffix(filepath.Base(f.Name), ".json")
				category = strings.ReplaceAll(category, "-", " ")
			}
			if err := db.InsertIslamQA(category, e.Question, e.Answer); err != nil {
				log.Printf("Failed to insert IslamQA entry: %v", err)
			} else {
				total++
			}
		}
	}

	db.SetSetting("islamqa_version", islamqaVersion)
	log.Printf("Loaded %d IslamQA entries (v%s)", total, islamqaVersion)
}

// loadEnv reads key=value pairs from a .env file in the working directory and
// sets them as process environment variables (without overwriting any that are
// already set). It tolerates `export KEY=value`, surrounding quotes, and
// `# comments`, so a file that also works when `source`d in a shell is fine.
const ghazaliVersion = "2"

func loadGhazali() {
	if db.GetSetting("ghazali_version") == ghazaliVersion {
		log.Printf("Ghazali v%s already loaded (%d sections)", ghazaliVersion, db.GhazaliCount())
		return
	}

	log.Printf("Loading Ghazali dataset v%s...", ghazaliVersion)
	db.ClearGhazali()

	r, err := zip.NewReader(bytes.NewReader(data.Ghazali), int64(len(data.Ghazali)))
	if err != nil {
		log.Printf("Failed to open ghazali.zip: %v", err)
		return
	}

	total := 0
	for _, f := range r.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var entries []struct {
			Volume      int    `json:"volume"`
			VolumeTitle string `json:"volume_title"`
			Chapter     string `json:"chapter"`
			Part        int    `json:"part"`
			Content     string `json:"content"`
		}
		if err := json.NewDecoder(rc).Decode(&entries); err != nil {
			rc.Close()
			log.Printf("Failed to decode ghazali.json: %v", err)
			continue
		}
		rc.Close()
		for _, e := range entries {
			if err := db.InsertGhazali(e.Volume, e.VolumeTitle, e.Chapter, e.Part, e.Content); err != nil {
				log.Printf("Failed to insert Ghazali section: %v", err)
			} else {
				total++
			}
		}
	}

	db.SetSetting("ghazali_version", ghazaliVersion)
	log.Printf("Loaded %d Ghazali sections (v%s)", total, ghazaliVersion)
}

const sourcesVersion = "5"

func loadSources() {
	if db.GetSetting("sources_version") == sourcesVersion {
		log.Printf("Sources v%s already loaded (quran=%d, hadith=%d, names=%d)",
			sourcesVersion, db.QuranCount(), db.HadithCount(), db.NamesCount())
		return
	}

	log.Printf("Loading sources v%s...", sourcesVersion)
	db.ClearQuran()
	db.ClearHadith()
	db.ClearNames()

	r, err := zip.NewReader(bytes.NewReader(data.Sources), int64(len(data.Sources)))
	if err != nil {
		log.Printf("Failed to open sources.zip: %v", err)
		return
	}

	for _, f := range r.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			log.Printf("Failed to open %s in sources.zip: %v", f.Name, err)
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			log.Printf("Failed to read %s: %v", f.Name, err)
			continue
		}

		base := filepath.Base(f.Name)
		switch base {
		case "quran.json":
			var quranData struct {
				Chapters []struct {
					Name   string `json:"name"`
					Number int    `json:"number"`
					Verses []struct {
						Chapter  int    `json:"chapter"`
						Number   int    `json:"number"`
						Text     string `json:"text"`
						Arabic   string `json:"arabic"`
						Comments string `json:"comments"`
					} `json:"verses"`
				} `json:"chapters"`
			}
			if err := json.Unmarshal(data, &quranData); err != nil {
				log.Printf("Failed to parse quran.json: %v", err)
				continue
			}
			total := 0
			for _, ch := range quranData.Chapters {
				for _, v := range ch.Verses {
					if err := db.InsertQuranVerse(ch.Number, ch.Name, v.Number, v.Text, v.Arabic, v.Comments); err != nil {
						log.Printf("Failed to insert quran verse %d:%d: %v", ch.Number, v.Number, err)
					} else {
						total++
					}
				}
			}
			log.Printf("Loaded %d Quran verses", total)

		case "hadith.json":
			var hadithData struct {
				Name  string `json:"name"`
				Books []struct {
					Name    string `json:"name"`
					Number  int    `json:"number"`
					Hadiths []struct {
						Number   int    `json:"number"`
						Narrator string `json:"narrator"`
						English  string `json:"english"`
						Arabic   string `json:"arabic"`
					} `json:"hadiths"`
				} `json:"books"`
			}
			if err := json.Unmarshal(data, &hadithData); err != nil {
				log.Printf("Failed to parse hadith.json: %v", err)
				continue
			}
			total := 0
			for _, book := range hadithData.Books {
				for _, h := range book.Hadiths {
					if err := db.InsertHadith(book.Name, book.Number, h.Number, h.Narrator, h.English, h.Arabic); err != nil {
						log.Printf("Failed to insert hadith %d: %v", h.Number, err)
					} else {
						total++
					}
				}
			}
			log.Printf("Loaded %d hadiths", total)

		case "names.json":
			var names []struct {
				Number      int    `json:"number"`
				English     string `json:"english"`
				Arabic      string `json:"arabic"`
				Meaning     string `json:"meaning"`
				Description string `json:"description"`
				Summary     string `json:"summary"`
			}
			if err := json.Unmarshal(data, &names); err != nil {
				log.Printf("Failed to parse names.json: %v", err)
				continue
			}
			total := 0
			for _, n := range names {
				if err := db.InsertName(n.Number, n.English, n.Arabic, n.Meaning, n.Description, n.Summary); err != nil {
					log.Printf("Failed to insert name %d: %v", n.Number, err)
				} else {
					total++
				}
			}
			log.Printf("Loaded %d Names of Allah", total)
		}
	}

	// Rebuild FTS indexes to ensure they're populated
	db.RebuildSourcesFTS()

	db.SetSetting("sources_version", sourcesVersion)
	log.Printf("Sources v%s loaded", sourcesVersion)
}

const adhkarVersion = "2"

func loadAdhkar() {
	if db.GetSetting("adhkar_version") == adhkarVersion {
		log.Printf("Adhkar v%s already loaded (%d entries)", adhkarVersion, db.AdhkarCount())
		return
	}

	log.Printf("Loading Adhkar dataset v%s...", adhkarVersion)
	db.ClearAdhkar()

	r, err := zip.NewReader(bytes.NewReader(data.Adhkar), int64(len(data.Adhkar)))
	if err != nil {
		log.Printf("Failed to open adhkar.zip: %v", err)
		return
	}

	total := 0
	for _, f := range r.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var entries []struct {
			Title       string `json:"title"`
			Arabic      string `json:"arabic"`
			Latin       string `json:"latin"`
			Translation string `json:"translation"`
			Notes       string `json:"notes"`
			Benefits    string `json:"benefits"`
			Fawaid      string `json:"fawaid"`
			Source      string `json:"source"`
			Category    string `json:"category"`
		}
		if err := json.NewDecoder(rc).Decode(&entries); err != nil {
			rc.Close()
			log.Printf("Failed to decode %s: %v", f.Name, err)
			continue
		}
		rc.Close()
		for _, e := range entries {
			benefits := e.Benefits
			if benefits == "" {
				benefits = e.Fawaid
			}
			if err := db.InsertAdhkar(e.Category, e.Title, e.Arabic, e.Latin, e.Translation, e.Notes, benefits, e.Source); err != nil {
				log.Printf("Failed to insert adhkar entry: %v", err)
			} else {
				total++
			}
		}
	}

	db.SetSetting("adhkar_version", adhkarVersion)
	log.Printf("Loaded %d adhkar entries (v%s)", total, adhkarVersion)
}

const riyadVersion = "3"

func loadRiyad() {
	if db.GetSetting("riyad_version") == riyadVersion {
		log.Printf("Riyad us-Salihin v%s already loaded (%d hadiths)", riyadVersion, db.RiyadCount())
		return
	}

	log.Printf("Loading Riyad us-Salihin dataset v%s...", riyadVersion)
	db.ClearRiyad()

	r, err := zip.NewReader(bytes.NewReader(data.Riyad), int64(len(data.Riyad)))
	if err != nil {
		log.Printf("Failed to open salihin.zip: %v", err)
		return
	}

	total := 0
	for _, f := range r.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var data struct {
			Books []struct {
				Name    string `json:"name"`
				Hadiths []struct {
					Number   int    `json:"number"`
					Narrator string `json:"narrator"`
					English  string `json:"english"`
					Arabic   string `json:"arabic"`
				} `json:"hadiths"`
			} `json:"books"`
		}
		if err := json.NewDecoder(rc).Decode(&data); err != nil {
			rc.Close()
			log.Printf("Failed to decode %s: %v", f.Name, err)
			continue
		}
		rc.Close()
		for _, book := range data.Books {
			for _, h := range book.Hadiths {
				if err := db.InsertRiyad(book.Name, h.Number, h.Narrator, h.English, h.Arabic); err != nil {
					log.Printf("Failed to insert Riyad hadith %d: %v", h.Number, err)
				} else {
					total++
				}
			}
		}
	}

	db.SetSetting("riyad_version", riyadVersion)
	log.Printf("Loaded %d Riyad us-Salihin hadiths (v%s)", total, riyadVersion)
}

const arabicVersion = "1"

func loadArabic() {
	if db.GetSetting("arabic_version") == arabicVersion {
		log.Printf("Arabic vocab v%s already loaded (%d words)", arabicVersion, db.ArabicCount())
		return
	}

	log.Printf("Loading Arabic vocab dataset v%s...", arabicVersion)
	db.ClearArabic()

	r, err := zip.NewReader(bytes.NewReader(data.Arabic), int64(len(data.Arabic)))
	if err != nil {
		log.Printf("Failed to open arabic.zip: %v", err)
		return
	}

	total := 0
	for _, f := range r.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var entries []struct {
			Arabic          string `json:"arabic"`
			Transliteration string `json:"transliteration"`
			English         string `json:"english"`
			Frequency       int    `json:"frequency"`
			ExampleRef      string `json:"example_ref"`
			Type            string `json:"type"`
		}
		if err := json.NewDecoder(rc).Decode(&entries); err != nil {
			rc.Close()
			log.Printf("Failed to decode %s: %v", f.Name, err)
			continue
		}
		rc.Close()
		for _, e := range entries {
			if err := db.InsertArabicWord(e.Arabic, e.Transliteration, e.English, e.Frequency, e.ExampleRef, e.Type); err != nil {
				log.Printf("Failed to insert Arabic word: %v", err)
			} else {
				total++
			}
		}
	}

	db.SetSetting("arabic_version", arabicVersion)
	log.Printf("Loaded %d Arabic vocab words (v%s)", total, arabicVersion)
}

const prophetsVersion = "4"

func loadProphets() {
	if db.GetSetting("prophets_version") == prophetsVersion {
		log.Printf("Prophets v%s already loaded (%d entries)", prophetsVersion, db.ProphetCount())
		return
	}

	log.Printf("Loading Prophets dataset v%s...", prophetsVersion)
	db.ClearProphets()

	var prophets []struct {
		Name     string `json:"name"`
		Arabic   string `json:"arabic"`
		Title    string `json:"title"`
		Sections []struct {
			Narrative string `json:"narrative"`
			Verses    []struct {
				Ref     string `json:"ref"`
				Chapter int    `json:"chapter"`
				Start   int    `json:"start"`
				End     int    `json:"end"`
				Context string `json:"context"`
			} `json:"verses"`
		} `json:"sections"`
	}
	if err := json.Unmarshal(data.Prophets, &prophets); err != nil {
		log.Printf("Failed to parse prophets.json: %v", err)
		return
	}

	total := 0
	for i, p := range prophets {
		slug := strings.ToLower(p.Name)
		slug = strings.ReplaceAll(slug, " ", "-")
		slug = strings.ReplaceAll(slug, "'", "")
		sectionsJSON, _ := json.Marshal(p.Sections)
		summary := ""
		if len(p.Sections) > 0 {
			summary = p.Sections[0].Narrative
			if len(summary) > 200 {
				summary = summary[:200] + "..."
			}
		}
		if err := db.InsertProphet(slug, p.Name, p.Arabic, p.Title, summary, string(sectionsJSON), "", i); err != nil {
			log.Printf("Failed to insert prophet %s: %v", p.Name, err)
		} else {
			total++
		}
	}

	db.SetSetting("prophets_version", prophetsVersion)
	log.Printf("Loaded %d prophets (v%s)", total, prophetsVersion)

}
