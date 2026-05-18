package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"aslam/db"
)

func startDailyContentWorker() {
	go fetchDailyContent()

	ticker := time.NewTicker(10 * time.Minute)
	go func() {
		for range ticker.C {
			fetchDailyContent()
		}
	}()

	log.Println("Daily content worker: started (every 10 minutes)")
}

func fetchDailyContent() {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get("https://reminder.dev/api/latest")
	if err != nil {
		log.Printf("Daily content: failed to fetch: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Daily content: unexpected status %d", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Daily content: failed to read body: %v", err)
		return
	}

	var data struct {
		Verse   string `json:"verse"`
		Hadith  string `json:"hadith"`
		Name    string `json:"name"`
		Message string `json:"message"`
		Links   struct {
			Verse  string `json:"verse"`
			Hadith string `json:"hadith"`
			Name   string `json:"name"`
		} `json:"links"`
		Updated string `json:"updated"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		log.Printf("Daily content: failed to parse JSON: %v", err)
		return
	}

	// Only save if content has changed
	existing, _ := db.GetLatestReminderContent()
	if existing != nil {
		oldVerse, _ := existing["Verse"].(string)
		if oldVerse == data.Verse {
			return
		}
	}

	verseLink := "https://reminder.dev" + data.Links.Verse
	hadithLink := "https://reminder.dev" + data.Links.Hadith
	nameLink := "https://reminder.dev" + data.Links.Name

	if err := db.SaveReminderContent(data.Verse, data.Hadith, data.Name, data.Message, verseLink, hadithLink, nameLink); err != nil {
		log.Printf("Daily content: failed to save: %v", err)
		return
	}

	log.Println("Daily content: new content saved")
}
