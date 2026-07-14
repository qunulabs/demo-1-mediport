// Package web renders MediPort's server-side HTML pages (and the shared
// diagnostics payload behind them) from templates and CSS embedded into the
// binary at build time. Nothing here fetches from the network - every
// asset ships inside the executable.
package web

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/style.css
var styleCSS string

var funcMap = template.FuncMap{
	"css": func() template.CSS { return template.CSS(styleCSS) },
	"icon": func(name string) template.HTML {
		switch name {
		case "logo":
			return template.HTML(svgLogoMark)
		case "pulse":
			return template.HTML(svgPulseLine)
		case "check":
			return template.HTML(svgIconCheck)
		case "warn":
			return template.HTML(svgIconWarn)
		case "unknown":
			return template.HTML(svgIconUnknown)
		case "shield-check":
			return template.HTML(svgShieldCheck)
		case "shield-warn":
			return template.HTML(svgShieldWarn)
		case "records":
			return template.HTML(svgRecordsIcon)
		case "lock":
			return template.HTML(svgLockIcon)
		case "arrow-right":
			return template.HTML(svgArrowRight)
		default:
			return ""
		}
	},
	"statusIcon": func(weak bool) template.HTML {
		if weak {
			return template.HTML(svgIconWarn)
		}
		return template.HTML(svgIconCheck)
	},
	"statusWord": func(weak bool) string {
		if weak {
			return "Weak"
		}
		return "Strong"
	},
}

var tmpl = template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html"))

// Render executes the named top-level page template (e.g. "login.html")
// against data and writes it to w as text/html.
func Render(w http.ResponseWriter, name string, data any) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return tmpl.ExecuteTemplate(w, name, data)
}

// LoginPageData is the (currently empty) data passed to login.html; kept as
// a named type so the handler and template stay in lock-step if the login
// page grows server-rendered state (e.g. an error banner) later.
type LoginPageData struct {
	Error string
}

// DashboardPageData renders the patient portal home.
type DashboardPageData struct {
	Active      string
	PatientName string
	MRN         string
	DOB         string
	Diagnosis   string
	RecordDate  string
	CipherHex   string
}

// SecurityPageData wraps Diagnostics with page-chrome fields (nav state)
// that don't belong in the JSON API payload.
type SecurityPageData struct {
	Active      string
	Diagnostics Diagnostics
}
