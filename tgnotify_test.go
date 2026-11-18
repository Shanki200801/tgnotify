package tgnotify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type stub struct {
	mu      sync.Mutex
	calls   []string
	bodies  []map[string]interface{}
	updates []interface{}
	nextID  int64
}

func (s *stub) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		parts := strings.Split(r.URL.Path, "/")
		method := parts[len(parts)-1]
		s.calls = append(s.calls, method)
		var body map[string]interface{}
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &body)
		}
		s.bodies = append(s.bodies, body)
		var result interface{} = true
		switch method {
		case "sendMessage", "sendDocument":
			s.nextID++
			result = map[string]int64{"message_id": s.nextID}
		case "getUpdates":
			result = s.updates
			s.updates = nil
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "result": result})
	}
}

func setup(t *testing.T) (*stub, *Client) {
	s := &stub{nextID: 100}
	srv := httptest.NewServer(s.handler(t))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	os.Setenv("TGNOTIFY_STATE", filepath.Join(dir, "state.json"))
	return s, NewWithConfig(Config{Token: "SECRET", ChatID: "42", APIBase: srv.URL})
}

func TestFormatEscapes(t *testing.T) {
	got := Format("a<b> & c", Options{Title: "T<1>", Level: "error"})
	want := "🚨 <b>T&lt;1&gt;</b>\na&lt;b&gt; &amp; c"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSplit(t *testing.T) {
	s := strings.Repeat("x", 10) + "\n" + strings.Repeat("y", 10)
	got := Split(s, 15)
	if len(got) != 2 || got[0] != strings.Repeat("x", 10)+"\n" {
		t.Fatalf("bad split %q", got)
	}
	got = Split("aaaa&amp;bb", 6) // must not cut inside &amp;
	if got[0] != "aaaa" {
		t.Fatalf("cut inside entity: %q", got)
	}
}

func TestSendLongWithButtonsOnLast(t *testing.T) {
	s, c := setup(t)
	ids, err := c.Send(context.Background(), strings.Repeat("z", 9000), Options{
		Buttons: [][]Button{{{Text: "Open", URL: "https://x"}}},
	})
	if err != nil || len(ids) != 3 {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
	if s.bodies[0]["reply_markup"] != nil || s.bodies[2]["reply_markup"] == nil {
		t.Fatal("buttons should only be on last chunk")
	}
}

func TestErrorRedactsToken(t *testing.T) {
	c := NewWithConfig(Config{Token: "SECRET", ChatID: "1", APIBase: "http://127.0.0.1:1"})
	_, err := c.Send(context.Background(), "hi", Options{})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("token leaked or no error: %v", err)
	}
}

func cbUpdate(id int64, chat int64, msg int64, data, label string) map[string]interface{} {
	return map[string]interface{}{
		"update_id": id,
		"callback_query": map[string]interface{}{
			"id": "cb", "data": data, "from": map[string]string{"username": "me"},
			"message": map[string]interface{}{
				"message_id": msg, "chat": map[string]int64{"id": chat},
				"reply_markup": map[string]interface{}{"inline_keyboard": [][]map[string]string{
					{{"text": label, "callback_data": data}},
				}},
			},
		},
	}
}

func TestPromptCollect(t *testing.T) {
	s, c := setup(t)
	ctx := context.Background()
	id, err := c.Prompt(ctx, "Apply to Acme?", []string{"Yes", "No"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	kb := s.bodies[0]["reply_markup"].(map[string]interface{})["inline_keyboard"].([]interface{})
	data := kb[0].([]interface{})[0].(map[string]interface{})["callback_data"].(string)
	if len(data) > 64 || !strings.HasPrefix(data, "tg:") {
		t.Fatalf("bad callback_data %q", data)
	}
	s.updates = []interface{}{
		cbUpdate(7, 999, id, data, "Yes"), // foreign chat: ignored
		cbUpdate(8, 42, id, data, "Yes"),
	}
	got, err := c.Collect(ctx)
	if err != nil || len(got) != 1 || got[0].Choice != "Yes" || got[0].MessageID != id {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if st := loadState(); st.Offset != 9 || len(st.Answers) != 0 {
		t.Fatalf("state %+v", st)
	}
}

func TestAskKeepsOtherAnswers(t *testing.T) {
	s, c := setup(t)
	ctx := context.Background()
	s.nextID = 200
	go func() {
		time.Sleep(50 * time.Millisecond)
		s.mu.Lock()
		s.updates = []interface{}{
			cbUpdate(1, 42, 555, "tg:aaaa:0", "Other"),
			cbUpdate(2, 42, 201, "tg:bbbb:1", "No"),
		}
		s.mu.Unlock()
	}()
	a, err := c.Ask(ctx, "Q?", []string{"Yes", "No"}, 3*time.Second, Options{})
	if err != nil || a.Choice != "No" {
		t.Fatalf("a=%+v err=%v", a, err)
	}
	rest, _ := c.Collect(ctx, 555)
	if len(rest) != 1 || rest[0].Choice != "Other" {
		t.Fatalf("other answer lost: %+v", rest)
	}
}

func TestConfigEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("TGNOTIFY_CONFIG", filepath.Join(dir, "c.json"))
	defer os.Unsetenv("TGNOTIFY_CONFIG")
	if err := SaveConfig(Config{Token: "f", ChatID: "1"}); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(dir, "c.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm %v", fi.Mode().Perm())
	}
	os.Setenv("TGNOTIFY_CHAT_ID", "99")
	defer os.Unsetenv("TGNOTIFY_CHAT_ID")
	c, err := LoadConfig()
	if err != nil || c.Token != "f" || c.ChatID != "99" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestLatestTapWins(t *testing.T) {
	s, c := setup(t)
	s.updates = []interface{}{
		cbUpdate(1, 42, 300, "tg:abcd:0", "Approve"),
		cbUpdate(2, 42, 300, "tg:abcd:1", "Skip"),
	}
	got, err := c.Collect(context.Background(), 300)
	if err != nil || len(got) != 1 || got[0].Choice != "Skip" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestTrimsSecrets(t *testing.T) {
	s, c := setup(t)
	c2 := NewWithConfig(Config{Token: "SECRET\n", ChatID: " 42\n", APIBase: c.APIBase})
	if _, err := c2.Send(context.Background(), "hi", Options{}); err != nil {
		t.Fatal(err)
	}
	if s.bodies[len(s.bodies)-1]["chat_id"] != "42" {
		t.Fatalf("chat_id not trimmed: %v", s.bodies[len(s.bodies)-1]["chat_id"])
	}
}
