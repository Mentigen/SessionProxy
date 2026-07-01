package proxy

import "net/http"

// identityHeaders is stripped from every upstream response before it
// reaches the guest. Set-Cookie is the one that matters for FR4 (the guest
// must never receive the owner's cookie in any form); the rest are a
// defensive list of headers that could otherwise leak which account is
// actually authenticated upstream.
var identityHeaders = []string{
	"Set-Cookie",
	"Set-Cookie2",
	"Authorization",
	"X-Powered-By",
}

// StripIdentityHeaders removes owner-identifying headers from an upstream
// response in place. It must run inside ReverseProxy's ModifyResponse,
// before headers are copied to the guest's connection.
//
// Scope note: this is a header-level guarantee only. A target site that
// embeds a session token in a response body (HTML/JSON) is not covered -
// that is a best-effort concern the app does not attempt to solve generally.
// See README section on the application layer for this documented boundary.
func StripIdentityHeaders(header http.Header) {
	for _, h := range identityHeaders {
		header.Del(h)
	}
}
