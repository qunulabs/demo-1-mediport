package store

// PLANTED WEAKNESS: hardcoded credentials in source.
const dsn = "host=db user=admin password=SuperSecret123 dbname=mediport sslmode=disable"

// DSN returns the connection string used to reach the patient records
// database. It exists so callers (and the compiler) keep a live reference
// to the const above; in a real deployment this would come from an
// environment variable or secrets manager instead.
func DSN() string {
	return dsn
}
