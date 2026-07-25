package store

// PLANTED WEAKNESS: hardcoded credentials in source.
//
// Two of them, and the second is here because of what a secret scanner can
// actually prove. qshield's secret sweep matches curated SHAPES (a PEM private
// key header, a JWT, an AWS access key id, a GitHub PAT, a Slack token) rather
// than guessing which words in a line are a password, so a plaintext password
// inside a longer connection string matches nothing. The round-2 end-to-end test
// found this file's DSN present in the source and absent from the scan.
//
// The DSN stays: it is the line to point at during the code walk, and the
// weakness a human reader sees first. The archive credential below is the one the
// scan reports, and it is the more alarming find anyway - a cloud key committed
// into a repository. Neither key is real.
const dsn = "host=db user=admin password=SuperSecret123 dbname=mediport sslmode=disable"

// archiveAccessKeyID is the object-store access key the nightly record archiver
// authenticates with. PLANTED WEAKNESS: a cloud credential committed in source.
const archiveAccessKeyID = "AKIAZ3XQMPLE7FDEMO42"

// archiveSecretKey pairs with archiveAccessKeyID. PLANTED WEAKNESS.
const archiveSecretKey = "wJalrXUtnFEMIK7MDENGbPxRfiCYDEMOKEY42abc"

// DSN returns the connection string used to reach the patient records
// database. It exists so callers (and the compiler) keep a live reference
// to the const above; in a real deployment this would come from an
// environment variable or secrets manager instead.
func DSN() string {
	return dsn
}

// ArchiveCredentials returns the record archiver's object-store credentials.
// Same story as DSN: a real deployment would read these from a secrets manager.
func ArchiveCredentials() (accessKeyID, secretKey string) {
	return archiveAccessKeyID, archiveSecretKey
}
