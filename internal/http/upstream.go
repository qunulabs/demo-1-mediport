package http

import (
	"crypto/tls"
	nethttp "net/http"
	"time"
)

// recordsServiceURL is the internal records service the portal fetches archived
// results from. Nothing is fetched in the demo; the client below exists to carry
// the planted TLS misconfiguration in live, reachable code.
const recordsServiceURL = "https://records-internal.mediport.invalid/v1/results"

// recordsClient talks to the internal records service.
//
// PLANTED WEAKNESS, twice over:
//
//   - InsecureSkipVerify: true - certificate verification is disabled, so any
//     machine that can answer on that name can impersonate the records service
//     and read or forge patient results.
//   - MinVersion: tls.VersionTLS10 - the connection will accept TLS 1.0, twenty
//     years obsolete and vulnerable to BEAST and POODLE-class attacks.
//
// Both are here because they are what qshield's Codefix can REPAIR rather than
// merely advise on. Flipping a boolean literal and swapping a version constant
// are provably safe edits, so GO-TLS-SKIP-VERIFY and GO-TLS-MIN-VERSION are
// Tier-1 rules and Act 3 can apply them live in front of an audience. Before
// this, every finding on the repository was advice-only and the demo had no
// automated code remediation to show at all.
//
// Keep both fields INLINE in this composite literal. Both rules walk the
// tls.Config literal itself; a config assembled field by field, or built by a
// helper, is past what an AST-only pass can attribute.
var recordsClient = &nethttp.Client{
	Timeout: 5 * time.Second,
	Transport: &nethttp.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS10,
		},
	},
}

// FetchArchivedResults asks the internal records service for a patient's
// archived results.
//
// The demo never runs that service, and the dashboard therefore never calls this
// on the request path: a DNS miss plus a 5s timeout on every page load is exactly
// the kind of pause the demo brief rules out. Its caller is behind an env flag
// that the demo does not set (see DashboardHandler). That costs the scan nothing -
// qshield's Go rules are AST-only and read the tls.Config literal above whether or
// not anything reaches it - and it keeps this from being dead code a future
// cleanup deletes along with the planted weakness.
func FetchArchivedResults(mrn string) (found bool) {
	req, err := nethttp.NewRequest(nethttp.MethodGet, recordsServiceURL+"?mrn="+mrn, nil)
	if err != nil {
		return false
	}
	resp, err := recordsClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == nethttp.StatusOK
}
