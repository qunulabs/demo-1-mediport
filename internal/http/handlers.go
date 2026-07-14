package http

import (
	"encoding/hex"
	"fmt"
	nethttp "net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/qunulabs/mediport/internal/auth"
	"github.com/qunulabs/mediport/internal/crypto"
	"github.com/qunulabs/mediport/internal/store"
)

// jwtSigningKey signs the session JWT issued at login. Demo-only key.
var jwtSigningKey = []byte("mediport-demo-signing-key")

const landingPage = `<!DOCTYPE html>
<html>
<head><title>MediPort</title></head>
<body>
<h1>MediPort Patient Portal</h1>
<p>Welcome to MediPort. This is a demo patient portal.</p>
<form action="/login" method="post">
  <input type="text" name="username" placeholder="username" />
  <input type="password" name="password" placeholder="password" />
  <button type="submit">Log in</button>
</form>
<p><a href="/records">View sample records (requires login in a real deployment)</a></p>
</body>
</html>`

// IndexHandler renders the MediPort landing page.
func IndexHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(landingPage))
}

// LoginHandler hashes the submitted password, mints a session token, and
// issues a signed JWT carrying the session for the client to present on
// subsequent requests.
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
	password := r.FormValue("password")

	hashed := auth.HashPassword(password)
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

	dsnRef := store.DSN()
	_ = dsnRef // demo: store connection would be opened with this DSN

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body><h1>Logged in</h1><p>user: %s</p><p>password hash: %s</p><p>session: %s</p><p>jwt: %s</p></body></html>",
		username, hashed, sessionToken, signed)
}

// sampleRecord is a stand-in patient record payload used purely to
// demonstrate the (broken) at-rest encryption path.
var sampleRecord = []byte("PATIENT:jane.doe;DOB:1990-01-01;DX:hypertension")

// RecordsHandler encrypts a sample patient record and renders it as hex.
func RecordsHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	padded := crypto.PadToBlockSize(sampleRecord)
	encrypted := crypto.EncryptRecord(padded)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body><h1>MediPort Records</h1><p>encrypted record (hex): %s</p></body></html>",
		hex.EncodeToString(encrypted))
}
