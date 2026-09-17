package server

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"aslam/db"

	prayer "github.com/hablullah/go-prayer"
)

func handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Redirect www to non-www
	if r.Host == "www.aslam.org" {
		http.Redirect(w, r, "https://aslam.org"+r.URL.Path, http.StatusMovedPermanently)
		return
	}

	// If auth is not configured, go straight to home
	if googleClientID == "" {
		handleHome(w, r)
		return
	}

	// If user is authenticated, redirect to /home
	session := getSession(r)
	if session != nil && db.IsUser(session.Email) {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	}

	// Show landing page
	tmpl.ExecuteTemplate(w, "landing.html", nil)
}

func getPrayerTimesForUser(userID int64) map[string]string {
	lat := 51.5074
	lng := -0.1278
	tzName := "Europe/London"

	if userID > 0 {
		if u, err := db.GetUserByID(userID); err == nil {
			if u.Latitude != 0 {
				lat = u.Latitude
			}
			if u.Longitude != 0 {
				lng = u.Longitude
			}
			if u.Timezone != "" {
				tzName = u.Timezone
			}
		}
	}

	if envLat := os.Getenv("LATITUDE"); envLat != "" {
		if v, err := strconv.ParseFloat(envLat, 64); err == nil && lat == 51.5074 {
			lat = v
		}
	}
	if envLng := os.Getenv("LONGITUDE"); envLng != "" {
		if v, err := strconv.ParseFloat(envLng, 64); err == nil && lng == -0.1278 {
			lng = v
		}
	}
	if envTZ := os.Getenv("TIMEZONE"); envTZ != "" && tzName == "Europe/London" {
		tzName = envTZ
	}

	tz, _ := time.LoadLocation(tzName)
	if tz == nil {
		tz = time.UTC
	}

	// Moonsighting Committee: Fajr 18°, Isha 18°
	moonsighting := &prayer.TwilightConvention{FajrAngle: 18, IshaAngle: 18}

	now := time.Now().In(tz)
	schedules, err := prayer.Calculate(prayer.Config{
		Latitude:            lat,
		Longitude:           lng,
		Timezone:            tz,
		TwilightConvention:  moonsighting,
		AsrConvention:       prayer.Shafii,
		HighLatitudeAdapter: prayer.AngleBased(),
	}, now.Year())
	if err != nil {
		return nil
	}

	day := now.YearDay() - 1
	if day < 0 || day >= len(schedules) {
		return nil
	}
	s := schedules[day]

	// High latitude adjustments (UK/Europe summer)
	// Cap Fajr at no earlier than Sunrise - 90 minutes
	fajrTime := s.Fajr
	minFajr := s.Sunrise.Add(-90 * time.Minute)
	if fajrTime.Before(minFajr) {
		fajrTime = minFajr
	}

	// Cap Isha at Maghrib + 90 minutes
	ishaTime := s.Isha
	maxIsha := s.Maghrib.Add(90 * time.Minute)
	if ishaTime.After(maxIsha) {
		ishaTime = maxIsha
	}

	return map[string]string{
		"Fajr":    fajrTime.Format("15:04"),
		"Sunrise": s.Sunrise.Format("15:04"),
		"Dhuhr":   s.Zuhr.Format("15:04"),
		"Asr":     s.Asr.Format("15:04"),
		"Maghrib": s.Maghrib.Format("15:04"),
		"Isha":    ishaTime.Format("15:04"),
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	convs, _ := db.GetRecentConversations(10, userID, true, isAdminReq(r))
	dailyContent, _ := db.GetLatestReminderContent()
	randomQA, _ := db.GetRandomIslamQA()

	hasLocation := false
	if userID > 0 {
		if u, err := db.GetUserByID(userID); err == nil {
			hasLocation = u.Latitude != 0 || u.Longitude != 0
		}
	}

	renderTemplate(w, r, "home.html", map[string]interface{}{
		"Conversations":   convs,
		"DailyContent":    dailyContent,
		"RandomQA":        randomQA,
		"PrayerTimes":     getPrayerTimesForUser(userID),
		"HasLocation":     hasLocation,
		"ReadingProgress": db.GetAllReadingProgress(userID),
	})
}
