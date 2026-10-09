package web

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

// The negotiated group is the single string Act 4 builds to. nginx reports the
// hybrid PQC groups by IANA code point because OpenSSL 3.5 has no friendly name
// for them, and the card used to print that code point verbatim.
func TestGroupDisplayNameNamesTheHybridGroups(t *testing.T) {
	cases := map[string]string{
		"0x11ec": "X25519MLKEM768 (hybrid ML-KEM)",
		"0X11EC": "X25519MLKEM768 (hybrid ML-KEM)",
		"X25519": "X25519 (classical)",
		"":       "",
		// An unknown group is shown, not swallowed: an audience seeing a raw value
		// is better off than one seeing a blank.
		"0xbeef": "0xbeef",
	}
	for in, want := range cases {
		if got := groupDisplayName(in); got != want {
			t.Errorf("groupDisplayName(%q) = %q, want %q", in, got, want)
		}
	}
}

// Every group isQuantumSafeGroup recognises by code point must also have a
// display name, or the payoff card can report QUANTUM-SAFE beside a bare hex
// value - which is exactly the defect this pairing exists to prevent.
func TestEveryQuantumSafeCodePointHasADisplayName(t *testing.T) {
	for _, cp := range []string{"0x11ec", "0x11eb", "0x11ed", "0x6399", "0x639a"} {
		if !isQuantumSafeGroup(cp) {
			t.Fatalf("%s is not recognised as quantum-safe", cp)
		}
		name := groupDisplayName(cp)
		if name == cp {
			t.Errorf("%s has no display name", cp)
		}
		if !strings.Contains(name, "ML-KEM") && !strings.Contains(name, "Kyber") {
			t.Errorf("%s renders as %q, which does not name the PQC family", cp, name)
		}
	}
}

// The Application Cryptography rows are read aloud in Act 1 and then matched
// against the repository scan in Act 2. A row naming a weakness the source does
// not carry is the same defect as a weakness the scan cannot see, so pin the
// before-state row set.
func TestVulnerableStateNamesEveryPlantedWeakness(t *testing.T) {
	t.Setenv("DEMO_STATE", "vulnerable")
	d := BuildDiagnostics(&http.Request{Header: http.Header{}})

	if d.State != "vulnerable" {
		t.Fatalf("state = %q", d.State)
	}
	want := map[string]string{
		"Password hashing":     "MD5",
		"Record encryption":    "constant IV",
		"Session token RNG":    "math/rand",
		"Secrets management":   "Hardcoded in source",
		"Internal service TLS": "Verification disabled",
	}
	seen := map[string]bool{}
	for _, row := range d.AppCrypto {
		substr, ok := want[row.Label]
		if !ok {
			t.Errorf("unexpected row %q", row.Label)
			continue
		}
		seen[row.Label] = true
		if !strings.Contains(row.Value, substr) {
			t.Errorf("row %q = %q, want it to mention %q", row.Label, row.Value, substr)
		}
		if !row.Weak {
			t.Errorf("row %q is not marked weak in the before state", row.Label)
		}
	}
	for label := range want {
		if !seen[label] {
			t.Errorf("row %q is missing from the before state", label)
		}
	}
}

// The remediated state must answer every before-state row, or the flip shows an
// audience a card that lost a line rather than one that fixed it.
func TestRemediatedStateAnswersEveryRow(t *testing.T) {
	t.Setenv("DEMO_STATE", "vulnerable")
	before := BuildDiagnostics(&http.Request{Header: http.Header{}})
	if err := os.Setenv("DEMO_STATE", "remediated"); err != nil {
		t.Fatal(err)
	}
	after := BuildDiagnostics(&http.Request{Header: http.Header{}})

	if len(before.AppCrypto) != len(after.AppCrypto) {
		t.Fatalf("before has %d rows, after has %d", len(before.AppCrypto), len(after.AppCrypto))
	}
	for i, row := range after.AppCrypto {
		if row.Label != before.AppCrypto[i].Label {
			t.Errorf("row %d: after is %q, before is %q", i, row.Label, before.AppCrypto[i].Label)
		}
		if row.Weak {
			t.Errorf("row %q is still marked weak after remediation", row.Label)
		}
	}
	if after.OverallWeak || after.PostureLabel != "HARDENED" {
		t.Errorf("remediated posture = %q (weak=%v)", after.PostureLabel, after.OverallWeak)
	}
}

// Dashboard dates are calendar dates, so they render without any timezone shift,
// and anything that is not a date breaks the render loudly.
func TestDashboardDatesRenderAsFriendlyCalendarDates(t *testing.T) {
	date := funcMap["date"].(func(string) (string, error))
	cases := map[string]string{
		"1990-01-01": "Mon, 1 Jan 1990",
		"2024-11-03": "Sun, 3 Nov 2024",
		"2024-12-03": "Tue, 3 Dec 2024",
	}
	for in, want := range cases {
		got, err := date(in)
		if err != nil || got != want {
			t.Errorf("date(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := date("03/11/2024"); err == nil {
		t.Error("a non-ISO date rendered instead of failing")
	}
}
