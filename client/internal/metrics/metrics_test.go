package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthAndMetrics(t *testing.T) {
	m := &Metrics{}
	m.TotalConnections.Add(5)
	m.ActiveConnections.Add(2)
	m.BytesTCPToWS.Add(100)
	m.BytesWSToTCP.Add(200)
	m.ObserveDuration(1500 * time.Millisecond)

	srv := httptest.NewServer(Handler(m))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf("health: %s", body)
	}

	resp, err = http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, want := range []string{"relay_active_connections 2", "relay_total_connections 5", "relay_bytes_tcp_to_ws 100", "relay_bytes_ws_to_tcp 200"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("metrics missing %q in:\n%s", want, body)
		}
	}
}
