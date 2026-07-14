package http

import (
	"encoding/hex"
	"encoding/json"
	nethttp "net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/qunulabs/mediport/internal/auth"
	"github.com/qunulabs/mediport/internal/crypto"
	"github.com/qunulabs/mediport/internal/store"
	"github.com/qunulabs/mediport/internal/web"
)

// jwtSigningKey signs the session JWT issued at login. Demo-only key.
var jwtSigningKey = []byte("mediport-demo-signing-key")

// IndexHandler renders the MediPort login page.
func IndexHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.URL.Path != "/" {
		nethttp.NotFound(w, r)
		return
	}
	if err := web.Render(w, "login.html", web.LoginPageData{}); err != nil {
		nethttp.Error(w, "failed to render page", nethttp.StatusInternalServerError)
		return
	}
}

// LoginHandler hashes the submitted password, mints a session token, and
// issues a signed JWT carrying the session for the client to present on
// subsequent requests. It then hands the browser off to the dashboard.
func LoginHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.Method != nethttp.MethodPost {
		nethttp.Error(w, "method not allowed", nethttp.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		nethttp.Error(w, "invalid form", nethttp.StatusBadRequest)
		return
	}

	username := r.FormValue("username")

	// PLANTED WEAKNESS: password is hashed with MD5 (see internal/auth.HashPassword).
	hashed := auth.HashPassword(r.FormValue("password"))
	// PLANTED WEAKNESS: session token comes from math/rand (see internal/auth.SessionToken).
	sessionToken := auth.SessionToken()

	// Uses the vulnerable dgrijalva/jwt-go library (CVE-2020-26160).
	claims := jwt.MapClaims{
		"sub":     username,
		"session": sessionToken,
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(jwtSigningKey)
	if err != nil {
		nethttp.Error(w, "failed to sign session token", nethttp.StatusInternalServerError)
		return
	}

	// PLANTED WEAKNESS: hardcoded DB credentials (see internal/store.DSN).
	dsnRef := store.DSN()
	_ = dsnRef // demo: store connection would be opened with this DSN
	_ = hashed // demo: would be compared against the stored hash

	nethttp.SetCookie(w, &nethttp.Cookie{Name: "mediport_session", Value: signed, Path: "/"})
	if username != "" {
		nethttp.SetCookie(w, &nethttp.Cookie{Name: "mediport_user", Value: username, Path: "/"})
	}

	nethttp.Redirect(w, r, "/dashboard", nethttp.StatusFound)
}

// sampleRecord is a stand-in patient record payload used purely to
// demonstrate the (broken) at-rest encryption path.
var sampleRecord = []byte("PATIENT:jane.doe;DOB:1990-01-01;DX:hypertension")

// DashboardHandler renders the patient portal home: a patient banner and a
// recent-records panel showing the (weakly) encrypted record at rest.
func DashboardHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	patientName := "Jane Doe"
	if c, err := r.Cookie("mediport_user"); err == nil && c.Value != "" {
		patientName = c.Value
	}

	// PLANTED WEAKNESS: AES-128 in ECB mode with a hardcoded key (see internal/crypto.EncryptRecord).
	padded := crypto.PadToBlockSize(sampleRecord)
	encrypted := crypto.EncryptRecord(padded)

	data := web.DashboardPageData{
		Active:      "dashboard",
		PatientName: patientName,
		MRN:         "MRN-2024-0148",
		DOB:         "1990-01-01",
		Diagnosis:   "Hypertension (I10)",
		RecordDate:  "2024-11-03",
		CipherHex:   hex.EncodeToString(encrypted),
	}

	if err := web.Render(w, "dashboard.html", data); err != nil {
		nethttp.Error(w, "failed to render page", nethttp.StatusInternalServerError)
		return
	}
}

// SecurityHandler renders the Security Diagnostics page: the live TLS
// session read off the nginx-injected headers, plus the DEMO_STATE-curated
// certificate, application cryptography, and dependency posture.
func SecurityHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	diag := web.BuildDiagnostics(r)
	data := web.SecurityPageData{Active: "security", Diagnostics: diag}

	if err := web.Render(w, "security.html", data); err != nil {
		nethttp.Error(w, "failed to render page", nethttp.StatusInternalServerError)
		return
	}
}

// APIDiagnosticsHandler returns the same diagnostics payload as JSON, built
// from the exact same BuildDiagnostics call the HTML page uses.
func APIDiagnosticsHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	diag := web.BuildDiagnostics(r)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(diag); err != nil {
		nethttp.Error(w, "failed to encode diagnostics", nethttp.StatusInternalServerError)
		return
	}
}

// RecordsHandler now lives inside the dashboard's "Recent records" panel;
// this route stays for backwards compatibility and forwards there.
func RecordsHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	nethttp.Redirect(w, r, "/dashboard", nethttp.StatusFound)
}
