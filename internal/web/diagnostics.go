package web

import (
	"net/http"
	"os"
	"strings"
)

// LiveTLS is read from the request headers injected by the nginx proxy in
// front of the app. This is the genuinely "live" half of the diagnostics
// page - it is never curated by DEMO_STATE.
type LiveTLS struct {
	Protocol       string `json:"protocol"`
	Cipher         string `json:"cipher"`
	Curve          string `json:"curve"`
	Detected       bool   `json:"detected"`
	StrongProtocol bool   `json:"strong_protocol"`
	StrongCipher   bool   `json:"strong_cipher"`
	QuantumSafe    bool   `json:"quantum_safe"`
	Weak           bool   `json:"weak"`
}

// Certificate is the curated (DEMO_STATE-driven) certificate posture.
type Certificate struct {
	SignatureAlgorithm string `json:"signature_algorithm"`
	KeySpec            string `json:"key_spec"`
	Issuer             string `json:"issuer"`
	PostQuantum        bool   `json:"post_quantum"`
	Weak               bool   `json:"weak"`
}

// CryptoRow is one row of the "Application Cryptography" card (password
// hashing, record encryption, session RNG, secrets management).
type CryptoRow struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Weak  bool   `json:"weak"`
}

// Dependency is the vulnerable-library row.
type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Note    string `json:"note"`
	Weak    bool   `json:"weak"`
}

// Diagnostics is the single source of truth rendered by both the
// /security HTML page and the GET /api/diagnostics JSON endpoint.
type Diagnostics struct {
	State         string      `json:"state"`
	Live          LiveTLS     `json:"live_tls"`
	Cert          Certificate `json:"certificate"`
	AppCrypto     []CryptoRow `json:"application_cryptography"`
	AppCryptoWeak bool        `json:"application_cryptography_weak"`
	Dependency    Dependency  `json:"dependency"`
	OverallWeak   bool        `json:"overall_weak"`
	PostureLabel  string      `json:"posture_label"`
	WeakChecks    int         `json:"weak_checks"`
	TotalChecks   int         `json:"total_checks"`
}

// BuildDiagnostics reads the live TLS headers off r and the DEMO_STATE
// env var, and assembles the full diagnostics payload. It is the single
// place that decides what "weak" and "strong" mean for this demo, so the
// HTML pages and the JSON API can never drift from each other.
func BuildDiagnostics(r *http.Request) Diagnostics {
	live := buildLiveTLS(r)
	state := demoState()

	var cert Certificate
	var appCrypto []CryptoRow
	var dep Dependency

	if state == "remediated" {
		cert = Certificate{
			SignatureAlgorithm: "ML-DSA-65 (Dilithium3)",
			KeySpec:            "Post-quantum, NIST FIPS 204",
			Issuer:             "QPKI Issuing CA",
			PostQuantum:        true,
			Weak:               false,
		}
		appCrypto = []CryptoRow{
			{Label: "Password hashing", Value: "bcrypt (cost 12)", Weak: false},
			{Label: "Record encryption", Value: "AES-256-GCM", Weak: false},
			{Label: "Session token RNG", Value: "crypto/rand", Weak: false},
			{Label: "Secrets management", Value: "Vault-managed (KMS-backed)", Weak: false},
		}
		dep = Dependency{
			Name:    "golang-jwt/jwt",
			Version: "v5.2.1",
			Note:    "No known CVEs",
			Weak:    false,
		}
	} else {
		state = "vulnerable"
		// The before-state certificate is a TRUSTED classical chain (RSA-2048 /
		// SHA-256) minted locally, issued by the MediPort Legacy Root CA - not the
		// old SHA-1 self-signed cert. SHA-256 / RSA-2048 is not itself weak, so this
		// card is marked accordingly; the before-state weakness is carried entirely
		// by the Live TLS card (TLS 1.2, CBC-SHA1 ciphers, static-RSA key exchange)
		// and the application-cryptography rows. Claiming a SHA-1 cert here would be
		// a lie about what is actually served.
		cert = Certificate{
			SignatureAlgorithm: "RSA 2048 / SHA-256",
			KeySpec:            "Classical",
			Issuer:             "MediPort Legacy Root CA",
			PostQuantum:        false,
			Weak:               false,
		}
		appCrypto = []CryptoRow{
			{Label: "Password hashing", Value: "MD5", Weak: true},
			{Label: "Record encryption", Value: "AES-128-ECB, hardcoded key", Weak: true},
			{Label: "Session token RNG", Value: "math/rand (PRNG)", Weak: true},
			{Label: "Secrets management", Value: "Hardcoded in source", Weak: true},
		}
		dep = Dependency{
			Name:    "dgrijalva/jwt-go",
			Version: "v3.2.0",
			Note:    "CVE-2020-26160",
			Weak:    true,
		}
	}

	appCryptoWeak := false
	for _, row := range appCrypto {
		if row.Weak {
			appCryptoWeak = true
			break
		}
	}

	weakChecks := 0
	totalChecks := 0
	if live.Detected {
		totalChecks++
		if live.Weak {
			weakChecks++
		}
	}
	totalChecks++
	if cert.Weak {
		weakChecks++
	}
	for _, row := range appCrypto {
		totalChecks++
		if row.Weak {
			weakChecks++
		}
	}
	totalChecks++
	if dep.Weak {
		weakChecks++
	}

	overallWeak := weakChecks > 0
	posture := "HARDENED"
	if overallWeak {
		posture = "AT RISK"
	}

	return Diagnostics{
		State:         state,
		Live:          live,
		Cert:          cert,
		AppCrypto:     appCrypto,
		AppCryptoWeak: appCryptoWeak,
		Dependency:    dep,
		OverallWeak:   overallWeak,
		PostureLabel:  posture,
		WeakChecks:    weakChecks,
		TotalChecks:   totalChecks,
	}
}

func buildLiveTLS(r *http.Request) LiveTLS {
	protocol := r.Header.Get("X-Demo-TLS-Protocol")
	cipher := r.Header.Get("X-Demo-TLS-Cipher")
	curve := r.Header.Get("X-Demo-TLS-Curve")

	detected := protocol != "" || cipher != "" || curve != ""
	strongProtocol := protocol == "TLSv1.3"
	strongCipher := strings.Contains(cipher, "GCM") || strings.Contains(strings.ToUpper(cipher), "CHACHA20")
	quantumSafe := isQuantumSafeGroup(curve)
	weak := detected && (!strongProtocol || !strongCipher)

	return LiveTLS{
		Protocol:       protocol,
		Cipher:         cipher,
		Curve:          curve,
		Detected:       detected,
		StrongProtocol: strongProtocol,
		StrongCipher:   strongCipher,
		QuantumSafe:    quantumSafe,
		Weak:           weak,
	}
}

// isQuantumSafeGroup reports whether the negotiated TLS key-exchange group is a
// post-quantum (hybrid) group. nginx reports the group either by name
// ("X25519MLKEM768") or, when OpenSSL has no friendly name for it, by its numeric
// TLS code point (e.g. "0x11ec"), so we match both forms. The groups in scope are
// the ML-KEM / Kyber hybrids.
func isQuantumSafeGroup(curve string) bool {
	c := strings.ToLower(strings.TrimSpace(curve))
	if c == "" {
		return false
	}
	if strings.Contains(c, "mlkem") || strings.Contains(c, "kyber") {
		return true
	}
	switch c {
	case "0x11ec", // X25519MLKEM768
		"0x11eb", // SecP256r1MLKEM768
		"0x11ed", // SecP384r1MLKEM1024
		"0x6399", // X25519Kyber768Draft00
		"0x639a": // SecP256r1Kyber768Draft00
		return true
	}
	return false
}

func demoState() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("DEMO_STATE")), "remediated") {
		return "remediated"
	}
	return "vulnerable"
}
