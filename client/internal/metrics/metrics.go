package metrics

import (
	"expvar"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// Metrics holds process-wide relay counters. All fields are atomics; safe for
// concurrent use. Payload bytes are never stored, only counted.
type Metrics struct {
	ActiveConnections  atomic.Int64
	TotalConnections   atomic.Int64
	FailedConnections  atomic.Int64
	BytesTCPToWS       atomic.Int64
	BytesWSToTCP       atomic.Int64
	DurationCount      atomic.Int64
	DurationNanosTotal atomic.Int64
}

// Global registry used by the management handlers.
var Default = &Metrics{}

func init() {
	expvar.Publish("relay_active_connections", expvar.Func(func() any { return Default.ActiveConnections.Load() }))
	expvar.Publish("relay_total_connections", expvar.Func(func() any { return Default.TotalConnections.Load() }))
}

// Handler returns a mux serving /health and /metrics on a private interface.
func Handler(m *Metrics) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"ok","active_connections":%d,"total_connections":%d}`+"\n",
			m.ActiveConnections.Load(), m.TotalConnections.Load())
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		active := m.ActiveConnections.Load()
		total := m.TotalConnections.Load()
		failed := m.FailedConnections.Load()
		t2w := m.BytesTCPToWS.Load()
		w2t := m.BytesWSToTCP.Load()
		durCount := m.DurationCount.Load()
		durTotal := m.DurationNanosTotal.Load()
		avg := 0.0
		if durCount > 0 {
			avg = float64(durTotal) / float64(durCount) / float64(time.Second)
		}
		_, _ = fmt.Fprintf(w, `# HELP relay_active_connections Current active relay sessions.
# TYPE relay_active_connections gauge
relay_active_connections %d
# HELP relay_total_connections Total accepted relay sessions.
# TYPE relay_total_connections counter
relay_total_connections %d
# HELP relay_failed_connections Total failed relay sessions.
# TYPE relay_failed_connections counter
relay_failed_connections %d
# HELP relay_bytes_tcp_to_ws Total bytes forwarded TCP -> WebSocket.
# TYPE relay_bytes_tcp_to_ws counter
relay_bytes_tcp_to_ws %d
# HELP relay_bytes_ws_to_tcp Total bytes forwarded WebSocket -> TCP.
# TYPE relay_bytes_ws_to_tcp counter
relay_bytes_ws_to_tcp %d
# HELP relay_connection_duration_seconds Average session duration in seconds.
# TYPE relay_connection_duration_seconds gauge
relay_connection_duration_seconds %f
# HELP relay_connection_duration_count Total finished sessions observed.
# TYPE relay_connection_duration_count counter
relay_connection_duration_count %d
`, active, total, failed, t2w, w2t, avg, durCount)
	})
	return mux
}

// ObserveDuration records a finished session duration.
func (m *Metrics) ObserveDuration(d time.Duration) {
	m.DurationCount.Add(1)
	m.DurationNanosTotal.Add(int64(d))
}
