package web

// Inline SVG fragments used across templates. Keeping them as Go string
// constants (rather than external files) satisfies the no-external-assets
// rule while letting templates stay declarative.
const (
	svgLogoMark = `<svg viewBox="0 0 32 32" width="32" height="32" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
<rect width="32" height="32" rx="9" fill="currentColor"/>
<path d="M16 9v14M9 16h14" stroke="#fff" stroke-width="3" stroke-linecap="round"/>
</svg>`

	// A single ECG-style pulse line, used as a decorative divider that ties
	// the "healthcare portal" subject to the "vitals monitor" motif used on
	// the Security Diagnostics page.
	svgPulseLine = `<svg class="pulse-line" viewBox="0 0 360 40" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
<path d="M0 20 H120 L132 20 L142 4 L154 36 L166 20 L176 20 H360" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`

	svgIconCheck = `<svg viewBox="0 0 20 20" width="16" height="16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
<circle cx="10" cy="10" r="9" fill="currentColor" fill-opacity="0.14"/>
<path d="M6 10.2l2.6 2.6L14.2 7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`

	svgIconWarn = `<svg viewBox="0 0 20 20" width="16" height="16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
<circle cx="10" cy="10" r="9" fill="currentColor" fill-opacity="0.14"/>
<path d="M10 6.2v4.6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
<circle cx="10" cy="13.6" r="1" fill="currentColor"/>
</svg>`

	svgIconUnknown = `<svg viewBox="0 0 20 20" width="16" height="16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
<circle cx="10" cy="10" r="9" fill="currentColor" fill-opacity="0.14"/>
<path d="M7.8 8a2.2 2.2 0 1 1 3.1 2c-.7.5-1 .8-1 1.6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
<circle cx="9.9" cy="13.8" r="0.9" fill="currentColor"/>
</svg>`

	svgShieldCheck = `<svg viewBox="0 0 24 24" width="22" height="22" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
<path d="M12 3l7 3v5.2c0 4.6-3 8.4-7 9.8-4-1.4-7-5.2-7-9.8V6l7-3z" fill="currentColor" fill-opacity="0.16" stroke="currentColor" stroke-width="1.6"/>
<path d="M8.7 12.2l2.2 2.2 4.2-4.6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`

	svgShieldWarn = `<svg viewBox="0 0 24 24" width="22" height="22" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
<path d="M12 3l7 3v5.2c0 4.6-3 8.4-7 9.8-4-1.4-7-5.2-7-9.8V6l7-3z" fill="currentColor" fill-opacity="0.16" stroke="currentColor" stroke-width="1.6"/>
<path d="M12 8.4v4.4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
<circle cx="12" cy="15.6" r="1.05" fill="currentColor"/>
</svg>`

	svgRecordsIcon = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
<rect x="4" y="3" width="16" height="18" rx="2" stroke="currentColor" stroke-width="1.6"/>
<path d="M8 8h8M8 12h8M8 16h5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
</svg>`

	svgLockIcon = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
<rect x="5" y="10.5" width="14" height="9.5" rx="2" stroke="currentColor" stroke-width="1.6"/>
<path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" stroke="currentColor" stroke-width="1.6"/>
<circle cx="12" cy="15" r="1.3" fill="currentColor"/>
</svg>`

	svgArrowRight = `<svg viewBox="0 0 20 20" width="16" height="16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
<path d="M4 10h11M11 5.5L15.5 10 11 14.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`
)
