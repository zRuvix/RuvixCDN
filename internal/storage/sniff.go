package storage

import "net/http"

// sniffDetect wraps http.DetectContentType so tests can stub it if needed.
func sniffDetect(b []byte) string {
	return http.DetectContentType(b)
}
