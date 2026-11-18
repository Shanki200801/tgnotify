// Package tgnotify sends Telegram alerts and collects button answers.
//
// Config, state file and wire format are shared with the Python and
// TypeScript implementations in this repo; see README.md ("Contract").
package tgnotify

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultAPIBase = "https://api.telegram.org"
	maxText        = 4000 // Telegram limit is 4096; leave headroom.
	maxCaption     = 1000 // Telegram limit is 1024.
	callbackPrefix = "tg:"
)

// ErrConflict is returned when another poller or a webhook owns getUpdates.
var ErrConflict = errors.New("tgnotify: getUpdates conflict (409): another poller is running or a webhook is set on this bot")

// ErrTimeout is returned by Ask when no answer arrives in time.
var ErrTimeout = errors.New("tgnotify: timed out waiting for an answer")

// Config holds the bot token and target chat.
type Config struct {
	Token   string `json:"token"`
	ChatID  string `json:"chat_id"`
	APIBase string `json:"api_base,omitempty"`
}

// ConfigDir returns ~/.config/tgnotify (respects XDG_CONFIG_HOME).
func ConfigDir() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "tgnotify")
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".config", "tgnotify")
}

// ConfigPath returns TGNOTIFY_CONFIG or the default config file path.
func ConfigPath() string {
	if p := os.Getenv("TGNOTIFY_CONFIG"); p != "" {
		return p
	}
	return filepath.Join(ConfigDir(), "config.json")
}

// StatePath returns TGNOTIFY_STATE or the default state file path.
func StatePath() string {
	if p := os.Getenv("TGNOTIFY_STATE"); p != "" {
		return p
	}
	return filepath.Join(ConfigDir(), "state.json")
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// LoadConfig resolves config: env vars override the config file.
func LoadConfig() (Config, error) {
	var c Config
	if b, err := os.ReadFile(ConfigPath()); err == nil {
		if err := json.Unmarshal(b, &c); err != nil {
			return c, fmt.Errorf("tgnotify: bad config %s: %v", ConfigPath(), err)
		}
	}
	if v := firstEnv("TGNOTIFY_TOKEN", "TELEGRAM_BOT_TOKEN"); v != "" {
		c.Token = v
	}
	if v := firstEnv("TGNOTIFY_CHAT_ID", "TELEGRAM_CHAT_ID"); v != "" {
		c.ChatID = v
	}
	if v := os.Getenv("TGNOTIFY_API_BASE"); v != "" {
		c.APIBase = v
	}
	if c.APIBase == "" {
		c.APIBase = DefaultAPIBase
	}
	c.Token, c.ChatID = strings.TrimSpace(c.Token), strings.TrimSpace(c.ChatID)
	if c.Token == "" || c.ChatID == "" {
		return c, fmt.Errorf("tgnotify: not configured; run `tgnotify setup` or set TGNOTIFY_TOKEN and TGNOTIFY_CHAT_ID")
	}
	return c, nil
}

// SaveConfig writes the config file with 0600 permissions.
func SaveConfig(c Config) error {
	p := ConfigPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	out := Config{Token: c.Token, ChatID: c.ChatID}
	if c.APIBase != "" && c.APIBase != DefaultAPIBase {
		out.APIBase = c.APIBase
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(p, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Chmod(p, 0o600)
}

// Client talks to the Telegram Bot API.
type Client struct {
	Config
	HTTP *http.Client
}

// New returns a client from LoadConfig.
func New() (*Client, error) {
	c, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	return NewWithConfig(c), nil
}

// NewWithConfig returns a client for an explicit config.
func NewWithConfig(c Config) *Client {
	c.Token, c.ChatID = strings.TrimSpace(c.Token), strings.TrimSpace(c.ChatID)
	if c.APIBase == "" {
		c.APIBase = DefaultAPIBase
	}
	return &Client{Config: c, HTTP: &http.Client{Timeout: 70 * time.Second}}
}

func (c *Client) redact(err error) error {
	if err == nil || c.Token == "" {
		return err
	}
	msg := strings.ReplaceAll(err.Error(), c.Token, "<token>")
	q := strconv.Quote(c.Token) // errors may print the URL quoted/escaped
	return errors.New(strings.ReplaceAll(msg, q[1:len(q)-1], "<token>"))
}

type apiResp struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   int             `json:"error_code"`
	Description string          `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

// Call invokes a Bot API method with a JSON body and decodes result into out.
func (c *Client) Call(ctx context.Context, method string, params interface{}, out interface{}) error {
	body, err := json.Marshal(params)
	if err != nil {
		return err
	}
	return c.do(ctx, method, func() (io.Reader, string) {
		return bytes.NewReader(body), "application/json"
	}, out)
}

func (c *Client) do(ctx context.Context, method string, body func() (io.Reader, string), out interface{}) error {
	url := strings.TrimRight(c.APIBase, "/") + "/bot" + c.Token + "/" + method
	for attempt := 0; ; attempt++ {
		r, ctype := body()
		req, err := http.NewRequestWithContext(ctx, "POST", url, r)
		if err != nil {
			return c.redact(err)
		}
		req.Header.Set("Content-Type", ctype)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return c.redact(err)
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return c.redact(err)
		}
		var ar apiResp
		if err := json.Unmarshal(raw, &ar); err != nil {
			return fmt.Errorf("tgnotify: %s: HTTP %d, non-JSON response", method, resp.StatusCode)
		}
		if ar.OK {
			if out != nil {
				return json.Unmarshal(ar.Result, out)
			}
			return nil
		}
		if ar.ErrorCode == 409 {
			return ErrConflict
		}
		if ar.ErrorCode == 429 && attempt < 3 {
			wait := ar.Parameters.RetryAfter
			if wait <= 0 {
				wait = 1
			}
			select {
			case <-time.After(time.Duration(wait) * time.Second):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return fmt.Errorf("tgnotify: %s failed (%d): %s", method, ar.ErrorCode, ar.Description)
	}
}

// Button is an inline keyboard button. Set URL for a link button.
type Button struct {
	Text         string `json:"text"`
	URL          string `json:"url,omitempty"`
	CallbackData string `json:"callback_data,omitempty"`
}

// Options control message formatting.
type Options struct {
	Title   string
	Level   string     // info | success | warn | error | "" (no icon)
	Silent  bool       // no notification sound
	HTML    bool       // text is already Telegram-HTML; don't escape
	Buttons [][]Button // inline keyboard rows (attached to the last chunk)
	Preview bool       // show link previews (off by default)
}

var levelIcon = map[string]string{
	"info": "ℹ️", "success": "✅", "warn": "⚠️", "warning": "⚠️", "error": "🚨",
}

// EscapeHTML escapes text for Telegram's HTML parse mode.
func EscapeHTML(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// Format builds the HTML body for a message (header + escaped text).
func Format(text string, o Options) string {
	head := ""
	if icon := levelIcon[strings.ToLower(o.Level)]; icon != "" {
		head = icon + " "
	}
	if o.Title != "" {
		head += "<b>" + EscapeHTML(o.Title) + "</b>"
	}
	body := text
	if !o.HTML {
		body = EscapeHTML(text)
	}
	switch {
	case head == "":
		return body
	case body == "":
		return strings.TrimSpace(head)
	default:
		return head + "\n" + body
	}
}

// Split splits s into chunks of at most limit runes, preferring newlines.
func Split(s string, limit int) []string {
	var out []string
	r := []rune(s)
	for len(r) > limit {
		cut := limit
		for i := limit; i > limit/2; i-- {
			if r[i-1] == '\n' {
				cut = i
				break
			}
		}
		// Don't split inside an HTML entity like &amp;
		for i := cut - 1; i >= 0 && i > cut-6; i-- {
			if r[i] == ';' {
				break
			}
			if r[i] == '&' {
				cut = i
				break
			}
		}
		out = append(out, string(r[:cut]))
		r = r[cut:]
	}
	if len(r) > 0 || len(out) == 0 {
		out = append(out, string(r))
	}
	return out
}

type message struct {
	MessageID int64 `json:"message_id"`
}

// Send sends a text message, splitting long text. Returns message ids.
func (c *Client) Send(ctx context.Context, text string, o Options) ([]int64, error) {
	chunks := Split(Format(text, o), maxText)
	var ids []int64
	for i, chunk := range chunks {
		p := map[string]interface{}{
			"chat_id":              c.ChatID,
			"text":                 chunk,
			"parse_mode":           "HTML",
			"disable_notification": o.Silent,
			"link_preview_options": map[string]bool{"is_disabled": !o.Preview},
		}
		if i == len(chunks)-1 && len(o.Buttons) > 0 {
			p["reply_markup"] = map[string]interface{}{"inline_keyboard": o.Buttons}
		}
		var m message
		if err := c.Call(ctx, "sendMessage", p, &m); err != nil {
			return ids, err
		}
		ids = append(ids, m.MessageID)
	}
	return ids, nil
}

// SendFile uploads a file as a document with an optional caption.
func (c *Client) SendFile(ctx context.Context, path, caption string, o Options) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	capHTML := ""
	if caption != "" || o.Title != "" {
		capHTML = Split(Format(caption, o), maxCaption)[0]
	}
	build := func() (io.Reader, string) {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		_ = w.WriteField("chat_id", c.ChatID)
		if capHTML != "" {
			_ = w.WriteField("caption", capHTML)
			_ = w.WriteField("parse_mode", "HTML")
		}
		if o.Silent {
			_ = w.WriteField("disable_notification", "true")
		}
		fw, _ := w.CreateFormFile("document", filepath.Base(path))
		_, _ = fw.Write(data)
		_ = w.Close()
		return &buf, w.FormDataContentType()
	}
	var m message
	if err := c.do(ctx, "sendDocument", build, &m); err != nil {
		return 0, err
	}
	return m.MessageID, nil
}

// ---- Questions with buttons --------------------------------------------

// Answer is a recorded button tap.
type Answer struct {
	MessageID int64  `json:"message_id"`
	Nonce     string `json:"nonce"`
	Index     int    `json:"index"`
	Choice    string `json:"choice"`
	User      string `json:"user,omitempty"`
	At        int64  `json:"at"`
}

// State is persisted between runs so taps aren't lost by batch jobs.
type State struct {
	Offset  int64    `json:"offset"`
	Answers []Answer `json:"answers"`
}

func loadState() State {
	var s State
	if b, err := os.ReadFile(StatePath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func saveState(s State) error {
	p := StatePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func nonce() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Prompt sends a question with one button per option and returns its
// message id. Collect answers later.
func (c *Client) Prompt(ctx context.Context, question string, options []string, o Options) (int64, error) {
	if len(options) == 0 {
		return 0, errors.New("tgnotify: prompt needs at least one option")
	}
	n := nonce()
	perRow := 3
	if len(options) == 2 || len(options) == 4 {
		perRow = 2
	}
	var rows [][]Button
	for i, opt := range options {
		if i%perRow == 0 {
			rows = append(rows, nil)
		}
		rows[len(rows)-1] = append(rows[len(rows)-1], Button{
			Text: opt, CallbackData: callbackPrefix + n + ":" + strconv.Itoa(i),
		})
	}
	o.Buttons = rows
	ids, err := c.Send(ctx, question, o)
	if err != nil {
		return 0, err
	}
	return ids[len(ids)-1], nil
}

type update struct {
	UpdateID      int64 `json:"update_id"`
	CallbackQuery *struct {
		ID   string `json:"id"`
		Data string `json:"data"`
		From struct {
			Username  string `json:"username"`
			FirstName string `json:"first_name"`
		} `json:"from"`
		Message *struct {
			MessageID int64 `json:"message_id"`
			Chat      struct {
				ID int64 `json:"id"`
			} `json:"chat"`
			ReplyMarkup *struct {
				InlineKeyboard [][]Button `json:"inline_keyboard"`
			} `json:"reply_markup"`
		} `json:"message"`
	} `json:"callback_query"`
	Message *struct {
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
	} `json:"message"`
}

// poll fetches updates once (long-polling up to wait seconds), records any
// button taps for our chat into the state file, and acknowledges them.
func (c *Client) poll(ctx context.Context, wait int) error {
	s := loadState()
	var ups []update
	p := map[string]interface{}{"timeout": wait, "allowed_updates": []string{"callback_query"}}
	if s.Offset > 0 {
		p["offset"] = s.Offset
	}
	if err := c.Call(ctx, "getUpdates", p, &ups); err != nil {
		return err
	}
	for _, u := range ups {
		if u.UpdateID >= s.Offset {
			s.Offset = u.UpdateID + 1
		}
		cq := u.CallbackQuery
		if cq == nil || cq.Message == nil || !strings.HasPrefix(cq.Data, callbackPrefix) {
			continue
		}
		if strconv.FormatInt(cq.Message.Chat.ID, 10) != c.ChatID {
			continue // not our chat: ignore
		}
		parts := strings.Split(strings.TrimPrefix(cq.Data, callbackPrefix), ":")
		if len(parts) != 2 {
			_ = c.Call(ctx, "answerCallbackQuery", map[string]string{"callback_query_id": cq.ID}, nil)
			continue // e.g. "tg:done"
		}
		idx, _ := strconv.Atoi(parts[1])
		choice := ""
		if cq.Message.ReplyMarkup != nil {
			for _, row := range cq.Message.ReplyMarkup.InlineKeyboard {
				for _, b := range row {
					if b.CallbackData == cq.Data {
						choice = b.Text
					}
				}
			}
		}
		user := cq.From.Username
		if user == "" {
			user = cq.From.FirstName
		}
		s.Answers = append(s.Answers, Answer{
			MessageID: cq.Message.MessageID, Nonce: parts[0], Index: idx,
			Choice: choice, User: user, At: time.Now().Unix(),
		})
		_ = c.Call(ctx, "answerCallbackQuery", map[string]string{
			"callback_query_id": cq.ID, "text": "Got it: " + choice,
		}, nil)
		_ = c.Call(ctx, "editMessageReplyMarkup", map[string]interface{}{
			"chat_id": c.ChatID, "message_id": cq.Message.MessageID,
			"reply_markup": map[string]interface{}{"inline_keyboard": [][]Button{{
				{Text: "✔ " + choice, CallbackData: callbackPrefix + "done"},
			}}},
		}, nil)
	}
	return saveState(s)
}

// Collect polls once (non-blocking) and returns, removing from state, the
// answers for the given message ids (all answers if ids is empty).
// Telegram keeps unfetched updates ~24h: run Collect at least daily.
func (c *Client) Collect(ctx context.Context, ids ...int64) ([]Answer, error) {
	if err := c.poll(ctx, 0); err != nil {
		return nil, err
	}
	return takeAnswers(ids), nil
}

func takeAnswers(ids []int64) []Answer {
	s := loadState()
	want := map[int64]bool{}
	for _, id := range ids {
		want[id] = true
	}
	// Latest tap per message wins (user may tap twice or change their mind).
	latest := map[int64]int{}
	var got, keep []Answer
	for _, a := range s.Answers {
		if len(ids) == 0 || want[a.MessageID] {
			if i, ok := latest[a.MessageID]; ok {
				got[i] = a
				continue
			}
			latest[a.MessageID] = len(got)
			got = append(got, a)
		} else {
			keep = append(keep, a)
		}
	}
	if len(got) > 0 {
		s.Answers = keep
		_ = saveState(s)
	}
	return got
}

// Ask sends a question and blocks until a button is tapped or timeout.
func (c *Client) Ask(ctx context.Context, question string, options []string, timeout time.Duration, o Options) (Answer, error) {
	id, err := c.Prompt(ctx, question, options, o)
	if err != nil {
		return Answer{}, err
	}
	deadline := time.Now().Add(timeout)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return Answer{}, ErrTimeout
		}
		wait := int(left.Seconds())
		if wait > 30 {
			wait = 30
		}
		if wait < 1 {
			wait = 1
		}
		if err := c.poll(ctx, wait); err != nil {
			return Answer{}, err
		}
		if got := takeAnswers([]int64{id}); len(got) > 0 {
			return got[0], nil
		}
		if ctx.Err() != nil {
			return Answer{}, ctx.Err()
		}
	}
}

// ---- Package-level helpers ----------------------------------------------

// Notify sends a message using LoadConfig. Handy one-liner for apps.
func Notify(text string, o Options) error {
	c, err := New()
	if err != nil {
		return err
	}
	_, err = c.Send(context.Background(), text, o)
	return err
}
