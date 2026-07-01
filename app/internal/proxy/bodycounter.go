package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
)

// countingResponseWriter wraps the http.ResponseWriter passed into
// ReverseProxy.ServeHTTP so bytes_transferred can be measured exactly as
// they leave the process, regardless of whether the upstream response set a
// correct Content-Length (it is -1 for chunked/streamed responses, so
// trusting resp.ContentLength would undercount or fail outright).
type countingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func newCountingResponseWriter(w http.ResponseWriter) *countingResponseWriter {
	return &countingResponseWriter{ResponseWriter: w, status: http.StatusOK}
}

func (c *countingResponseWriter) WriteHeader(status int) {
	c.status = status
	c.ResponseWriter.WriteHeader(status)
}

func (c *countingResponseWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.bytes += int64(n)
	return n, err
}

// Flush lets the wrapped writer participate in streamed responses; the
// reverse proxy flushes periodically for long-lived upstream connections.
func (c *countingResponseWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack is required for the type to still satisfy http.Hijacker if the
// underlying writer does; httputil.ReverseProxy checks for this on upgrade
// requests (e.g. websockets), which SessionProxy does not target today but
// should not silently break if a target site attempts one.
func (c *countingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := c.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("proxy: underlying ResponseWriter does not support hijacking")
	}
	return hj.Hijack()
}
