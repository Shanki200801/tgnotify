package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Smoke test: built binary, `run` with a failing command emitting a huge \r line.
func TestRunFailureAlertFits(t *testing.T) {
	var texts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]interface{}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &b)
		if s, ok := b["text"].(string); ok {
			texts = append(texts, s)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
	}))
	defer srv.Close()
	bin := filepath.Join(t.TempDir(), "tgnotify")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	cmd := exec.Command(bin, "run", "--", "sh", "-c", `printf '%20000s\r' | tr ' ' x; exit 3`)
	cmd.Env = append(os.Environ(), "TGNOTIFY_API_BASE="+srv.URL, "TGNOTIFY_TOKEN=x", "TGNOTIFY_CHAT_ID=42",
		"TGNOTIFY_CONFIG="+filepath.Join(t.TempDir(), "none.json"))
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	err := cmd.Run()
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 3 {
		t.Fatalf("want exit 3, got %v", err)
	}
	if len(texts) != 1 || len([]rune(texts[0])) > 4000 ||
		strings.Count(texts[0], "<pre>") != strings.Count(texts[0], "</pre>") {
		t.Fatalf("bad alert: %d msgs, len %d", len(texts), len(texts[0]))
	}
}
