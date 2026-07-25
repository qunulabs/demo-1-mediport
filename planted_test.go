package main

import (
	"os"
	"regexp"
	"testing"
)

// MediPort is a deliberately insecure application, and Act 2 of the demo stakes
// its credibility on qshield's repository scan FINDING the weaknesses the
// presenter has just narrated. Round 2 measured one of five: every weakness was
// present in the source and three were written in shapes no rule could attribute.
//
// So the weaknesses are not enough on their own - their SHAPE matters, and this
// file pins it. Each case names the qshield rule it feeds and what specifically
// must not be "tidied up". A refactor that reads better and silences the scan is
// the failure mode these tests exist to catch, because nothing else in the repo
// would notice: the app still compiles, still runs, and is still insecure.
func TestPlantedWeaknessesKeepTheShapeTheScannerCanSee(t *testing.T) {
	cases := []struct {
		name string
		file string
		want *regexp.Regexp
		rule string
		why  string
	}{
		{
			name: "MD5 password hashing",
			file: "internal/auth/password.go",
			want: regexp.MustCompile(`"crypto/md5"`),
			rule: "GO-WEAK-HASH",
			why:  "the rule keys off the crypto/md5 import",
		},
		{
			name: "math/rand session token",
			file: "internal/auth/token.go",
			want: regexp.MustCompile(`(?m)^\s*token\s*:?=\s*rand\.`),
			rule: "GO-INSECURE-RANDOM",
			why: "the rule needs the random value assigned to a SINK-NAMED variable " +
				"(key/token/nonce/iv/salt/...); inlining the call into a Sprintf hides it",
		},
		{
			name: "constant IV in the record encryptor",
			file: "internal/crypto/records.go",
			want: regexp.MustCompile(`cipher\.NewCBCEncrypter\([^,]+,\s*\[\]byte\("`),
			rule: "GO-STATIC-IV-NONCE",
			why: "the rule proves the IV constant SYNTACTICALLY, so it must stay an " +
				"inline []byte(\"...\") argument and not move into a variable",
		},
		{
			name: "hardcoded cloud credential",
			file: "internal/store/db.go",
			want: regexp.MustCompile(`"AKIA[0-9A-Z]{16}"`),
			rule: "embedded:aws-access-key-id",
			why: "the secret sweep matches curated SHAPES, not the word 'password'; " +
				"the DSN alone matches nothing",
		},
		{
			name: "hardcoded DB password",
			file: "internal/store/db.go",
			want: regexp.MustCompile(`password=\w+`),
			rule: "none - this one is for the code walk",
			why:  "it is the line a human reader is pointed at in Act 2",
		},
		{
			name: "TLS verification disabled",
			file: "internal/http/upstream.go",
			want: regexp.MustCompile(`InsecureSkipVerify:\s*true`),
			rule: "GO-TLS-SKIP-VERIFY (Tier-1, auto-applicable)",
			why: "one of the two findings Act 3 APPLIES live; the rule walks the " +
				"tls.Config literal, so the field must stay inline",
		},
		{
			name: "obsolete TLS floor",
			file: "internal/http/upstream.go",
			want: regexp.MustCompile(`MinVersion:\s*tls\.VersionTLS10`),
			rule: "GO-TLS-MIN-VERSION (Tier-1, auto-applicable)",
			why:  "the other finding Act 3 applies; TLS10/11 is what makes it Tier-1",
		},
		{
			name: "vulnerable jwt-go",
			file: "go.mod",
			want: regexp.MustCompile(`dgrijalva/jwt-go v3\.2\.0`),
			rule: "CVE-2020-26160 (SBOM vulnerabilities)",
			why:  "the version is the finding; a bump silently ends that half of Act 2",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatalf("read %s: %v", tc.file, err)
			}
			if !tc.want.Match(b) {
				t.Errorf("%s no longer matches %s.\n  qshield rule: %s\n  why it matters: %s",
					tc.file, tc.want, tc.rule, tc.why)
			}
		})
	}
}

// The ECB loop this demo used to carry was the more egregious weakness, and it is
// gone for a reason worth recording: Go has no ECB API, so ECB is written by
// driving the raw block cipher directly, and qshield's Go rule set has no rule for
// that shape. If a GO-RAW-BLOCK-CIPHER rule ever ships, reverting to ECB is a
// better story than a constant IV - until then this asserts the swap stayed done,
// so a revert has to be deliberate.
func TestRecordEncryptorDoesNotDriveTheRawBlockCipher(t *testing.T) {
	b, err := os.ReadFile("internal/crypto/records.go")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`block\.Encrypt\(`).Match(b) {
		t.Error("records.go drives the raw block cipher again (ECB). No Go rule detects " +
			"that shape, so the weakness would be real and invisible to the Act 2 scan. " +
			"Check whether qshield has shipped a raw-block-cipher rule first.")
	}
}
